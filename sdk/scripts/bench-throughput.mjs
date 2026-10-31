// SPDX-License-Identifier: AGPL-3.0-or-later
// Chunk-encryption and datamesh serialization throughput. No network involved.
import { performance } from 'node:perf_hooks';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { CryptoEngine, MeshNode } = await import(join(here, '..', 'dist', 'index.mjs'));

const sender = new CryptoEngine();
const key = await sender.generateKey();
const receiver = new CryptoEngine();
await receiver.importKey(key);

const chunk = new Uint8Array(64 * 1024);
for (let i = 0; i < chunk.length; i++) chunk[i] = i & 0xff;
const iterations = 300;

const encryptStart = performance.now();
let ciphertextBytes = 0;
for (let i = 0; i < iterations; i++) {
  const { ciphertext } = await sender.encryptChunk(chunk.buffer);
  ciphertextBytes += ciphertext.byteLength;
}
const encryptMs = performance.now() - encryptStart;

const encrypted = [];
for (let i = 0; i < 50; i++) encrypted.push(await sender.encryptChunk(chunk.buffer));
const decryptStart = performance.now();
for (let i = 0; i < iterations; i++) {
  const item = encrypted[i % encrypted.length];
  await receiver.decryptChunk(item.iv, item.ciphertext);
}
const decryptMs = performance.now() - decryptStart;

const node = new MeshNode('bench-node');
const vector = new Float32Array(768);
for (let i = 0; i < vector.length; i++) vector[i] = Math.sin(i);
const meshStart = performance.now();
for (let i = 0; i < 1000; i++) node.upsertVector(`v-${i}`, vector);
const state = node.serialize();
const serializeMs = performance.now() - meshStart;
const other = new MeshNode('other-node');
const applyStart = performance.now();
other.apply(state);
const applyMs = performance.now() - applyStart;

const report = {
  chunk_bytes: chunk.byteLength,
  iterations,
  encrypt: {
    total_ms: Number(encryptMs.toFixed(2)),
    mb_per_sec: Number(((chunk.byteLength * iterations) / (1024 * 1024) / (encryptMs / 1000)).toFixed(1)),
    ciphertext_bytes: ciphertextBytes,
  },
  decrypt: {
    total_ms: Number(decryptMs.toFixed(2)),
    mb_per_sec: Number(((chunk.byteLength * iterations) / (1024 * 1024) / (decryptMs / 1000)).toFixed(1)),
  },
  datamesh: {
    vectors: 1000,
    dimensions: 768,
    serialize_ms: Number(serializeMs.toFixed(2)),
    apply_ms: Number(applyMs.toFixed(2)),
    state_json_bytes: JSON.stringify(state).length,
  },
  note: 'Local crypto/serialization only; not P2P network throughput.',
};
console.log(JSON.stringify(report, null, 2));
writeFileSync(join(here, '..', 'bench-throughput.json'), JSON.stringify(report, null, 2) + '\n');
