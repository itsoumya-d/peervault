// Streaming sink adapters: offset math, OPFS discovery, and failure behavior.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { createWritableSink, createOpfsSink, CHUNK_SIZE } = await import(
  join(__dirname, '../dist/index.mjs')
);

function fakeWritable() {
  const writes = [];
  let closed = false;
  return {
    writes,
    get closed() { return closed; },
    async write(entry) { writes.push(entry); },
    async close() { closed = true; }
  };
}

describe('createWritableSink', () => {
  test('writes chunks at chunkSize offsets and closes once', async () => {
    const writable = fakeWritable();
    const sink = createWritableSink(writable, 1024);
    await sink.writeChunk(0, new ArrayBuffer(4));
    await sink.writeChunk(3, new ArrayBuffer(2));
    await sink.close();

    assert.deepEqual(writable.writes.map((entry) => entry.position), [0, 3072]);
    assert.deepEqual(writable.writes.map((entry) => entry.type), ['write', 'write']);
    assert.equal(writable.writes[0].data.byteLength, 4);
    assert.equal(writable.closed, true);
  });

  test('rejects an invalid writable', () => {
    assert.throws(() => createWritableSink(null), TypeError);
    assert.throws(() => createWritableSink({ write() {} }), TypeError);
  });
});

describe('createOpfsSink', () => {
  test('opens an OPFS file and streams chunks', async () => {
    const writable = fakeWritable();
    const calls = [];
    const original = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      value: {
        storage: {
          async getDirectory() {
            return {
              async getFileHandle(name, options) {
                calls.push({ name, options });
                return { async createWritable() { return writable; } };
              }
            };
          }
        }
      }
    });

    try {
      const sink = await createOpfsSink('resume.bin');
      assert.ok(sink);
      await sink.writeChunk(1, new ArrayBuffer(8));
      await sink.close();
      assert.deepEqual(calls, [{ name: 'resume.bin', options: { create: true } }]);
      assert.equal(writable.writes[0].position, CHUNK_SIZE);
      assert.equal(writable.closed, true);
    } finally {
      if (original) Object.defineProperty(globalThis, 'navigator', original);
      else delete globalThis.navigator;
    }
  });

  test('returns null without OPFS and rejects an empty file name', async () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {} });
    try {
      assert.equal(await createOpfsSink('x.bin'), null);
    } finally {
      if (original) Object.defineProperty(globalThis, 'navigator', original);
      else delete globalThis.navigator;
    }
    await assert.rejects(() => createOpfsSink(''), TypeError);
  });
});
