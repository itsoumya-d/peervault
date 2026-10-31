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

function header(fileIndex, chunkIndex) {
  const bytes = new Uint8Array(9);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, 1);
  view.setUint32(1, fileIndex, true);
  view.setUint32(5, chunkIndex, true);
  return bytes;
}

describe('AAD-bound chunk headers', () => {
  test('a valid ciphertext rejects under a different fileIndex', async () => {
    const { sender, receiver } = await keyedPair();
    const plaintext = new TextEncoder().encode('authenticated payload').buffer;
    const frameHeader = header(0, 0);
    const { iv, ciphertext } = await sender.encryptChunk(plaintext, frameHeader);

    const assembler = new FileAssembler(
      { name: 'a.bin', size: plaintext.byteLength, mime: 'application/octet-stream', chunks: 1 },
      receiver
    );

    const tampered = header(1, 0);
    await assert.rejects(
      () => assembler.addChunk(0, iv, ciphertext, tampered),
      /operation failed/i
    );

    await assembler.addChunk(0, iv, ciphertext, frameHeader);
    const out = assembler.assemble();
    assert.equal(out.size, plaintext.byteLength);
    assert.equal(out.blob.size, plaintext.byteLength);
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
      const frameHeader = header(0, i);
      const { iv, ciphertext } = await sender.encryptChunk(payload, frameHeader);
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
