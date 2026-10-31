// Resumable-transfer bitmap: persistence, missing-chunk enumeration, and
// FileAssembler integration. No browser or network required.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { ChunkBitmap, FileAssembler } = await import(join(__dirname, '../dist/index.mjs'));

describe('ChunkBitmap', () => {
  test('marks, clears, counts, and enumerates missing indices', () => {
    const bitmap = new ChunkBitmap(10);
    assert.equal(bitmap.count, 0);
    assert.deepEqual(bitmap.missing(), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    bitmap.mark(0).mark(3).mark(9);
    assert.equal(bitmap.has(0), true);
    assert.equal(bitmap.has(1), false);
    assert.equal(bitmap.count, 3);
    assert.deepEqual(bitmap.missing(), [1, 2, 4, 5, 6, 7, 8]);
    assert.deepEqual(bitmap.missing(2), [1, 2]);
    assert.deepEqual([...bitmap.missingIterator()], [1, 2, 4, 5, 6, 7, 8]);

    bitmap.clear(3);
    assert.equal(bitmap.has(3), false);
    assert.equal(bitmap.count, 2);
  });

  test('base64 and JSON round-trips preserve every bit', () => {
    for (const size of [0, 1, 7, 8, 9, 17, 100, 1000]) {
      const bitmap = new ChunkBitmap(size);
      for (let i = 0; i < size; i += 3) bitmap.mark(i);
      const restored = ChunkBitmap.fromBase64(bitmap.toBase64(), size);
      assert.deepEqual(restored.toBytes(), bitmap.toBytes());
      assert.equal(restored.count, bitmap.count);

      const fromJson = ChunkBitmap.fromJSON(bitmap.toJSON());
      assert.deepEqual(fromJson.toBytes(), bitmap.toBytes());
      assert.equal(fromJson.size, size);
    }
  });

  test('clone is isolated from the original', () => {
    const bitmap = new ChunkBitmap(8);
    bitmap.mark(1);
    const clone = bitmap.clone();
    clone.mark(2);
    assert.equal(bitmap.has(2), false);
    assert.equal(clone.has(2), true);
  });

  test('rejects invalid sizes, byte lengths, and indices', () => {
    assert.throws(() => new ChunkBitmap(-1), RangeError);
    assert.throws(() => new ChunkBitmap(1.5), RangeError);
    assert.throws(() => new ChunkBitmap(9, new Uint8Array(1)), TypeError);
    const bitmap = new ChunkBitmap(4);
    assert.throws(() => bitmap.mark(4), RangeError);
    assert.throws(() => bitmap.has(-1), RangeError);
    assert.throws(() => bitmap.missing(-1), RangeError);
    assert.throws(() => ChunkBitmap.fromJSON({ size: 4 }), TypeError);
  });
});

describe('FileAssembler bitmap integration', () => {
  function fakeCrypto() {
    return {
      async decryptChunk(_iv, ciphertext) {
        return ciphertext;
      }
    };
  }

  test('exposes missing chunks and a persistable received bitmap', async () => {
    const assembler = new FileAssembler(
      { name: 'x.bin', size: 4, mime: 'application/octet-stream', chunks: 4 },
      fakeCrypto()
    );
    const iv = new Uint8Array(12);

    await assembler.addChunk(0, iv, new Uint8Array([1]).buffer, new Uint8Array(21));
    await assembler.addChunk(2, iv, new Uint8Array([2]).buffer, new Uint8Array(21));
    await assembler.addChunk(2, iv, new Uint8Array([2]).buffer, new Uint8Array(21));

    assert.equal(assembler.progress.received, 2);
    assert.deepEqual(assembler.missingChunks(), [1, 3]);
    assert.deepEqual(assembler.missingChunks(1), [1]);

    const bitmap = assembler.receivedBitmap();
    assert.equal(bitmap.has(0), true);
    assert.equal(bitmap.has(1), false);
    assert.equal(bitmap.has(2), true);

    const restored = ChunkBitmap.fromBase64(bitmap.toBase64(), 4);
    assert.deepEqual(restored.missing(), [1, 3]);
    assert.equal(restored.count, 2);
  });
});
