// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
//
// Regression tests for the file-transfer path: chunking, encryption, assembly and
// the adversarial cases that previously produced a silently corrupt file or a
// permanently pending promise. These run against the built dist/ artifact in plain
// Node 24 — no browser and no network required.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { CryptoEngine, FileChunker, FileAssembler, CHUNK_SIZE, MAX_CHUNKS, PQCrypto } =
  await import(join(__dirname, '../dist/index.mjs'));

/** A sender engine and a receiver engine sharing one AES-256-GCM key. */
async function keyedPair() {
  const sender = new CryptoEngine();
  const keyB64 = await sender.generateKey();
  const receiver = new CryptoEngine();
  await receiver.importKey(keyB64);
  return { sender, receiver, keyB64 };
}

function patterned(size) {
  const b = new Uint8Array(size);
  for (let i = 0; i < size; i++) b[i] = (i * 7 + 13) & 0xff;
  return b;
}

/** Full chunk -> encrypt -> decrypt -> assemble round trip, as the SDK does it. */
async function roundTrip(bytes, mime = 'application/octet-stream') {
  const file = new File([bytes], 'f.bin', { type: mime });
  const { sender, receiver } = await keyedPair();
  const chunker = new FileChunker(file);
  const assembler = new FileAssembler(
    { name: file.name, size: file.size, mime: file.type, chunks: chunker.totalChunks },
    receiver
  );
  let index = 0;
  let chunk;
  while ((chunk = await chunker.getNextChunk()) !== null) {
    const { iv, ciphertext } = await sender.encryptChunk(chunk);
    await assembler.addChunk(index++, iv, ciphertext);
  }
  const out = assembler.assemble();
  return { out, chunksSent: index, totalChunks: chunker.totalChunks };
}

describe('AES-256-GCM chunk encryption', () => {
  test('round-trips binary and unicode payloads', async () => {
    const { sender, receiver } = await keyedPair();
    const plaintext = new TextEncoder().encode('hello \u{1F510} éè 你好').buffer;
    const { iv, ciphertext } = await sender.encryptChunk(plaintext);
    assert.equal(iv.length, 12, 'IV is 96 bits');
    assert.equal(ciphertext.byteLength, plaintext.byteLength + 16, 'GCM tag is appended');
    const back = await receiver.decryptChunk(iv, ciphertext);
    assert.deepEqual(new Uint8Array(back), new Uint8Array(plaintext));
  });

  test('every chunk gets a distinct IV (nonce reuse would be catastrophic)', async () => {
    const { sender } = await keyedPair();
    const seen = new Set();
    const n = 2000;
    for (let i = 0; i < n; i++) {
      const { iv } = await sender.encryptChunk(new ArrayBuffer(8));
      seen.add(Buffer.from(iv).toString('hex'));
    }
    assert.equal(seen.size, n, `${n} encryptions must yield ${n} distinct IVs`);
  });

  test('tampered ciphertext, tampered tag, truncation and a flipped IV all reject', async () => {
    const { sender, receiver } = await keyedPair();
    const { iv, ciphertext } = await sender.encryptChunk(patterned(256).buffer);

    const flipBody = new Uint8Array(ciphertext.slice(0));
    flipBody[0] ^= 1;
    await assert.rejects(() => receiver.decryptChunk(iv, flipBody.buffer), 'body tamper');

    const flipTag = new Uint8Array(ciphertext.slice(0));
    flipTag[flipTag.length - 1] ^= 1;
    await assert.rejects(() => receiver.decryptChunk(iv, flipTag.buffer), 'tag tamper');

    await assert.rejects(
      () => receiver.decryptChunk(iv, ciphertext.slice(0, ciphertext.byteLength - 1)),
      'truncation'
    );

    const badIv = new Uint8Array(iv);
    badIv[0] ^= 1;
    await assert.rejects(() => receiver.decryptChunk(badIv, ciphertext), 'IV tamper');
  });

  test('a wrong key cannot decrypt', async () => {
    const { sender } = await keyedPair();
    const other = new CryptoEngine();
    await other.generateKey();
    const { iv, ciphertext } = await sender.encryptChunk(patterned(64).buffer);
    await assert.rejects(() => other.decryptChunk(iv, ciphertext));
  });
});

describe('FileChunker / FileAssembler round trips', () => {
  const sizes = [
    0,
    1,
    2,
    1024,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 7,
    5 * CHUNK_SIZE,
  ];
  for (const size of sizes) {
    test(`${size} bytes round-trips byte-exactly`, async () => {
      const data = patterned(size);
      const { out, chunksSent, totalChunks } = await roundTrip(data);
      assert.equal(chunksSent, totalChunks, 'chunker count matches chunks emitted');
      assert.equal(out.blob.size, size, 'assembled blob length');
      const got = new Uint8Array(await out.blob.arrayBuffer());
      assert.deepEqual(got, data, 'assembled bytes');
    });
  }

  test('a zero-byte file emits exactly one chunk and completes', async () => {
    // Regression: sender metadata used Math.ceil(0 / CHUNK_SIZE) === 0 while the
    // chunker emits one empty chunk, so an empty transfer could never complete.
    const chunker = new FileChunker(new File([new Uint8Array(0)], 'empty.txt'));
    assert.equal(chunker.totalChunks, 1);
    const { out } = await roundTrip(new Uint8Array(0), 'text/plain');
    assert.equal(out.blob.size, 0);
  });

  test('out-of-order chunk arrival reassembles correctly', async () => {
    const { sender, receiver } = await keyedPair();
    const parts = [0, 1, 2, 3].map((i) => new Uint8Array(CHUNK_SIZE).fill(65 + i));
    const enc = [];
    for (const p of parts) enc.push(await sender.encryptChunk(p.buffer));
    const asm = new FileAssembler(
      { name: 'a', size: 4 * CHUNK_SIZE, mime: '', chunks: 4 },
      receiver
    );
    for (const i of [3, 1, 0, 2]) await asm.addChunk(i, enc[i].iv, enc[i].ciphertext);
    const got = new Uint8Array(await asm.assemble().blob.arrayBuffer());
    const want = new Uint8Array(4 * CHUNK_SIZE);
    parts.forEach((p, i) => want.set(p, i * CHUNK_SIZE));
    assert.deepEqual(got, want);
  });
});

describe('FileAssembler adversarial cases', () => {
  async function fourChunks() {
    const { sender, receiver } = await keyedPair();
    const enc = [];
    for (let i = 0; i < 4; i++) {
      enc.push(await sender.encryptChunk(new Uint8Array(CHUNK_SIZE).fill(65 + i).buffer));
    }
    const asm = new FileAssembler(
      { name: 'a', size: 4 * CHUNK_SIZE, mime: '', chunks: 4 },
      receiver
    );
    return { asm, enc };
  }

  test('a duplicate chunk cannot mask a missing one (no silent corruption)', async () => {
    // Regression: receivedChunks counted arrivals, so [0,1,1,2] with chunk 3 missing
    // reported complete and assembled a short file containing the text "undefined".
    const { asm, enc } = await fourChunks();
    await asm.addChunk(0, enc[0].iv, enc[0].ciphertext);
    await asm.addChunk(1, enc[1].iv, enc[1].ciphertext);
    await asm.addChunk(1, enc[1].iv, enc[1].ciphertext); // duplicate retransmission
    const complete = await asm.addChunk(2, enc[2].iv, enc[2].ciphertext);
    assert.equal(complete, false, 'must not report complete with chunk 3 missing');
    assert.equal(asm.isComplete(), false);
    assert.throws(() => asm.assemble(), /incomplete/i, 'assemble must refuse');
  });

  test('a duplicate chunk is idempotent once all chunks have arrived', async () => {
    const { asm, enc } = await fourChunks();
    for (let i = 0; i < 4; i++) await asm.addChunk(i, enc[i].iv, enc[i].ciphertext);
    assert.equal(await asm.addChunk(2, enc[2].iv, enc[2].ciphertext), true);
    assert.equal(asm.assemble().blob.size, 4 * CHUNK_SIZE);
  });

  test('an out-of-range chunk index is rejected, not allocated', async () => {
    // Regression: chunkIndex travels in the clear and was used to index a sparse
    // array, so one 64-byte chunk with index 2_000_000 produced a ~17 MB blob and
    // over 1 GB of resident memory.
    const { sender, receiver } = await keyedPair();
    const e = await sender.encryptChunk(new Uint8Array(64).fill(1).buffer);
    const asm = new FileAssembler({ name: 'a', size: 64, mime: '', chunks: 1 }, receiver);
    await assert.rejects(() => asm.addChunk(2_000_000, e.iv, e.ciphertext), /out of range/);
    await assert.rejects(() => asm.addChunk(-1, e.iv, e.ciphertext), /out of range/);
  });

  test('assembled length is checked against metadata.size', async () => {
    const { sender, receiver } = await keyedPair();
    const e = await sender.encryptChunk(new Uint8Array(64).fill(1).buffer);
    const asm = new FileAssembler({ name: 'a', size: 999_999, mime: '', chunks: 1 }, receiver);
    await asm.addChunk(0, e.iv, e.ciphertext);
    assert.throws(() => asm.assemble(), /corrupt/i);
  });

  test('hostile metadata is rejected by the constructor', async () => {
    const { receiver } = await keyedPair();
    for (const chunks of [-1, 1.5, NaN, undefined, null, MAX_CHUNKS + 1, 1e12, '4']) {
      assert.throws(
        () => new FileAssembler({ name: 'a', size: 1, mime: '', chunks }, receiver),
        /Invalid file metadata/,
        `chunks=${String(chunks)} must be rejected`
      );
    }
    assert.throws(
      () => new FileAssembler({ name: 'a', size: -5, mime: '', chunks: 1 }, receiver),
      /Invalid file metadata/
    );
  });
});

describe('Post-quantum claims match the implementation', () => {
  test('isMLKEMSupported() does not claim post-quantum protection', () => {
    // It previously returned true for any environment exposing crypto.subtle,
    // which told applications ML-KEM was in use when no lattice code exists.
    assert.equal(PQCrypto.isMLKEMSupported(), false);
  });

  test('getCapabilities() reports classical key exchange', () => {
    const caps = new CryptoEngine().getCapabilities();
    assert.equal(caps.usesPostQuantumKeyExchange, false);
    assert.equal(caps.supportsAESGCM, true);
    assert.equal(caps.supportsECDH, true);
  });

  test('useHybridKeyExchange is false regardless of the option passed', () => {
    assert.equal(new CryptoEngine().useHybridKeyExchange, false);
    assert.equal(new CryptoEngine({ useHybridKeyExchange: true }).useHybridKeyExchange, false);
  });

  test('hybridKeyExchange is plain P-256 ECDH and agrees between peers', async () => {
    const a = new CryptoEngine();
    const b = new CryptoEngine();
    await a.negotiateKey(await b.getLocalPublicKey());
    await b.negotiateKey(await a.getLocalPublicKey());
    const { iv, ciphertext } = await a.encryptChunk(new TextEncoder().encode('ecdh').buffer);
    const back = await b.decryptChunk(iv, ciphertext);
    assert.equal(new TextDecoder().decode(back), 'ecdh');
  });

  test('probeMLKEM() is a real feature probe and returns a boolean', async () => {
    const supported = await PQCrypto.probeMLKEM();
    assert.equal(typeof supported, 'boolean');
    // Node 24 does implement ML-KEM-768 in WebCrypto, but PeerVault never uses it.
    assert.equal(new CryptoEngine().getCapabilities().usesPostQuantumKeyExchange, false);
  });
});
