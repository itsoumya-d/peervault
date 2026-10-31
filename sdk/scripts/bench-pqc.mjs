// Benchmark the bundled ML-KEM-768 core and the full hybrid handshake.
// Run with: npm run bench:pqc
import { performance } from 'node:perf_hooks';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MlKem768,
  HybridHandshake,
} from '../dist/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(
  here,
  '..',
  '..',
  'pqc',
  'target',
  'wasm32-unknown-unknown',
  'release',
  'peervault_mlkem768.wasm'
);

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[index];
}

async function main() {
  const wasmBytes = readFileSync(wasmPath).byteLength;
  const kem = await MlKem768.load();

  const keyPair = kem.generateKeyPair();
  const encapsulation = kem.encapsulate(keyPair.publicKey);

  const iterations = 250;
  for (let i = 0; i < 20; i++) {
    kem.generateKeyPair();
    kem.encapsulate(keyPair.publicKey);
    kem.decapsulate(encapsulation.ciphertext, keyPair.secretKey);
  }

  let start = performance.now();
  for (let i = 0; i < iterations; i++) kem.generateKeyPair();
  const keygenMs = performance.now() - start;

  start = performance.now();
  for (let i = 0; i < iterations; i++) kem.encapsulate(keyPair.publicKey);
  const encapsMs = performance.now() - start;

  start = performance.now();
  for (let i = 0; i < iterations; i++) {
    kem.decapsulate(encapsulation.ciphertext, keyPair.secretKey);
  }
  const decapsMs = performance.now() - start;

  const shareKey = crypto.getRandomValues(new Uint8Array(32));
  const handshakeIterations = 50;
  const latencies = [];
  for (let i = 0; i < 5; i++) {
    const sender = await HybridHandshake.create('sender', shareKey);
    const receiver = await HybridHandshake.create('receiver', shareKey);
    const finish = await sender.acceptHello(await receiver.createHello());
    await sender.acceptReady(await receiver.acceptFinish(finish));
  }
  start = performance.now();
  for (let i = 0; i < handshakeIterations; i++) {
    const iterationStart = performance.now();
    const sender = await HybridHandshake.create('sender', shareKey);
    const receiver = await HybridHandshake.create('receiver', shareKey);
    const finish = await sender.acceptHello(await receiver.createHello());
    await sender.acceptReady(await receiver.acceptFinish(finish));
    latencies.push(performance.now() - iterationStart);
  }
  const handshakeMs = performance.now() - start;

  const report = {
    wasm_bytes: wasmBytes,
    keygen: {
      iterations,
      total_ms: Number(keygenMs.toFixed(2)),
      ops_per_sec: Number(((iterations / keygenMs) * 1000).toFixed(0)),
      mean_ms: Number((keygenMs / iterations).toFixed(3)),
    },
    encapsulate: {
      iterations,
      total_ms: Number(encapsMs.toFixed(2)),
      ops_per_sec: Number(((iterations / encapsMs) * 1000).toFixed(0)),
      mean_ms: Number((encapsMs / iterations).toFixed(3)),
    },
    decapsulate: {
      iterations,
      total_ms: Number(decapsMs.toFixed(2)),
      ops_per_sec: Number(((iterations / decapsMs) * 1000).toFixed(0)),
      mean_ms: Number((decapsMs / iterations).toFixed(3)),
    },
    hybrid_handshake: {
      iterations: handshakeIterations,
      total_ms: Number(handshakeMs.toFixed(2)),
      ops_per_sec: Number(((handshakeIterations / handshakeMs) * 1000).toFixed(0)),
      mean_ms: Number((handshakeMs / handshakeIterations).toFixed(3)),
      p50_ms: Number(percentile(latencies, 50).toFixed(3)),
      p95_ms: Number(percentile(latencies, 95).toFixed(3)),
    },
  };

  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
