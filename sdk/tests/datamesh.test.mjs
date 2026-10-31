// SPDX-License-Identifier: AGPL-3.0-or-later
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const {
  CryptoEngine,
  MeshNode,
  decodeFloat32,
  encodeFloat32,
} = await import(join(__dirname, '../dist/index.mjs'));

function transportPair(a, b) {
  const toB = { send: (data) => b.handleMessage(data, toA) };
  const toA = { send: (data) => a.handleMessage(data, toB) };
  return { toA, toB };
}

describe('datamesh vector/memory sync', () => {
  test('float32 base64 round-trips', () => {
    const vector = new Float32Array([0.25, -0.5, 1]);
    const decoded = decodeFloat32(encodeFloat32(vector));
    assert.deepEqual(Array.from(decoded), Array.from(vector));
  });

  test('two nodes converge on the union of vectors and memories', () => {
    const a = new MeshNode('node-a');
    const b = new MeshNode('node-b');
    a.upsertVector('v1', new Float32Array([1, 0, 0]));
    a.upsertMemory('m1', 'prefer executable tests', 1.0);
    b.upsertVector('v2', new Float32Array([0, 1, 0]));
    b.upsertMemory('m2', 'avoid direct renames', 0.8);

    const { toB } = transportPair(a, b);
    a.startSync(toB);

    assert.equal(a.stats.vectors, 2);
    assert.equal(b.stats.vectors, 2);
    assert.equal(a.stats.memories, 2);
    assert.equal(b.stats.memories, 2);
    assert.equal(a.getMemory('m2').text, 'avoid direct renames');
  });

  test('last writer wins by version and origin tie-breaker', () => {
    const a = new MeshNode('a');
    const b = new MeshNode('b');
    a.upsertVector('same', new Float32Array([1, 0]));
    a.upsertVector('same', new Float32Array([1, 1]));
    b.upsertVector('same', new Float32Array([0, 1]));

    const { toB } = transportPair(a, b);
    a.startSync(toB);

    assert.equal(a.getVector('same').version, 2);
    assert.equal(a.getVector('same').origin, 'a');
    assert.equal(b.getVector('same').origin, 'a');

    const c = new MeshNode('c');
    const d = new MeshNode('d');
    c.upsertVector('tie', new Float32Array([1]));
    d.upsertVector('tie', new Float32Array([2]));
    const cPair = transportPair(c, d);
    c.startSync(cPair.toB);
    assert.equal(c.getVector('tie').origin, 'd');
    assert.equal(d.getVector('tie').origin, 'd');
  });

  test('malformed messages are rejected', () => {
    const node = new MeshNode('a');
    const transport = { send: () => {} };
    assert.throws(() => node.handleMessage('not json', transport), /not valid JSON/);
    assert.throws(
      () => node.handleMessage(JSON.stringify({ type: 'nope', state: {} }), transport),
      /unknown message type/
    );
  });
});

describe('encrypted datamesh control messages', () => {
  test('AES-GCM control messages round-trip and reject tampering', async () => {
    const sender = new CryptoEngine();
    const key = await sender.generateKey();
    const receiver = new CryptoEngine();
    await receiver.importKey(key);

    const message = JSON.stringify({ type: 'datamesh-state', state: { nodeId: 'a', vectors: [], memories: [] } });
    const ciphertext = await sender.encryptMessage(message);
    assert.equal(await receiver.decryptMessage(ciphertext), message);

    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] ^= 1;
    await assert.rejects(() => receiver.decryptMessage(tampered.buffer));
  });

  test('a different key cannot decrypt a mesh message', async () => {
    const sender = new CryptoEngine();
    await sender.generateKey();
    const other = new CryptoEngine();
    await other.generateKey();
    const ciphertext = await sender.encryptMessage('secret mesh payload');
    await assert.rejects(() => other.decryptMessage(ciphertext));
  });
});
