// Regression tests for AAD-bound frame headers and streaming disk assembly.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { CryptoEngine, FileAssembler, createFileSystemSink } =
  await import(join(__dirname, '../dist/index.mjs'));

async function keyedPair() {
  const sender = new CryptoEngine();
  const keyB64 = await sender.generateKey();
  const receiver = new CryptoEngine();
  await receiver.importKey(keyB64);
  return { sender, receiver };
}

function header(fileIndex, chunkIndex, iv = new Uint8Array(12).fill(7)) {
  const bytes = new Uint8Array(21);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, 1);
  view.setUint32(1, fileIndex, true);
  view.setUint32(5, chunkIndex, true);
  bytes.set(iv, 9);
  return bytes;
}

describe('AAD-bound chunk headers', () => {
  test('a valid ciphertext rejects under a different fileIndex', async () => {
    const { sender, receiver } = await keyedPair();
    const plaintext = new TextEncoder().encode('authenticated payload').buffer;
    const iv = new Uint8Array(12).fill(9);
    const frameHeader = header(0, 0, iv);
    const { ciphertext } = await sender.encryptChunk(plaintext, frameHeader, iv);

    const assembler = new FileAssembler(
      { name: 'a.bin', size: plaintext.byteLength, mime: 'application/octet-stream', chunks: 1 },
      receiver
    );

    const tampered = header(1, 0, iv);
    await assert.rejects(
      () => assembler.addChunk(0, iv, ciphertext, tampered),
      /operation failed/i
    );

    const tamperedIv = new Uint8Array(12).fill(10);
    const ivHeader = header(0, 0, tamperedIv);
    await assert.rejects(
      () => assembler.addChunk(0, iv, ciphertext, ivHeader),
      /operation failed/i
    );

    await assembler.addChunk(0, iv, ciphertext, frameHeader);
    const out = assembler.assemble();
    assert.equal(out.size, plaintext.byteLength);
    assert.equal(out.blob.size, plaintext.byteLength);
  });
});

describe('full-header authentication', () => {
  test('flipping any one of the 21 header bytes rejects before assembly', async () => {
    const { sender, receiver } = await keyedPair();
    const plaintext = new TextEncoder().encode('header integrity').buffer;
    const iv = new Uint8Array(12).fill(3);
    const good = header(0, 0, iv);
    const { ciphertext } = await sender.encryptChunk(plaintext, good, iv);
    const assembler = new FileAssembler(
      { name: 'h.bin', size: plaintext.byteLength, mime: 'application/octet-stream', chunks: 1 },
      receiver
    );

    for (let position = 0; position < 21; position++) {
      const tampered = header(0, 0, iv);
      tampered[position] ^= 1;
      await assert.rejects(
        () => assembler.addChunk(0, iv, ciphertext, tampered),
        /operation failed/i,
        `header byte ${position} must be authenticated`
      );
    }

    await assembler.addChunk(0, iv, ciphertext, good);
    assert.equal(assembler.assemble().size, plaintext.byteLength);
  });

  test('200 randomized header mutations all reject', async () => {
    const { sender, receiver } = await keyedPair();
    const plaintext = new TextEncoder().encode('fuzz').buffer;
    const iv = new Uint8Array(12).fill(5);
    const good = header(0, 0, iv);
    const { ciphertext } = await sender.encryptChunk(plaintext, good, iv);
    const assembler = new FileAssembler(
      { name: 'f.bin', size: plaintext.byteLength, mime: 'application/octet-stream', chunks: 1 },
      receiver
    );

    let state = 0x9e3779b9;
    const next = () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };

    for (let iteration = 0; iteration < 200; iteration++) {
      const tampered = header(0, 0, iv);
      tampered[next() % 21] ^= (next() % 255) + 1;
      await assert.rejects(
        () => assembler.addChunk(0, iv, ciphertext, tampered),
        /operation failed/i,
        `mutation ${iteration} must be rejected`
      );
    }
  });
});

describe('streaming disk sink', () => {
  test('writes chunks by index and finishes without a Blob', async () => {
    const { sender, receiver } = await keyedPair();
    const chunkSize = 8;
    const writes = [];
    let closed = false;

    const sink = {
      async writeChunk(index, data) {
        writes.push({ index, bytes: data.byteLength });
      },
      async close() {
        closed = true;
      },
    };

    const assembler = new FileAssembler(
      { name: 'b.bin', size: chunkSize * 2, mime: 'application/octet-stream', chunks: 2 },
      receiver,
      sink
    );

    for (let i = 0; i < 2; i++) {
      const payload = new Uint8Array(chunkSize).fill(i + 1).buffer;
      const iv = new Uint8Array(12).fill(i + 1);
      const frameHeader = header(0, i, iv);
      const { ciphertext } = await sender.encryptChunk(payload, frameHeader, iv);
      await assembler.addChunk(i, iv, ciphertext, frameHeader);
    }

    assert.equal(assembler.streaming, true);
    assert.equal(assembler.isComplete(), true);
    assert.throws(() => assembler.assemble(), /disk sink active/);

    const out = await assembler.finishStreaming();
    assert.equal(out.streamed, true);
    assert.equal(out.blob, undefined);
    assert.equal(closed, true);
    assert.deepEqual(writes.map((w) => w.index), [0, 1]);
  });

  test('createFileSystemSink returns null without the File System Access API', async () => {
    assert.equal(await createFileSystemSink('unused.bin'), null);
  });
});
