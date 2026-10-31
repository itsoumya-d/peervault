// Synthetic streaming-memory benchmark. Uses sparse files, a discarding sink,
// and no-op crypto so it can measure SDK bookkeeping rather than WebCrypto or
// network buffering. Run with: node --expose-gc scripts/bench-streaming-memory.mjs
import { performance } from 'node:perf_hooks';

const { PeerVaultSender, FileAssembler, CHUNK_SIZE } = await import('../dist/index.mjs');

const SIZE = 1024 * 1024 * 1024;
const CHUNKS = Math.ceil(SIZE / CHUNK_SIZE);
const sampleEvery = 100;

class SparseFile {
  constructor(size) {
    this.size = size;
    this.name = 'sparse.bin';
    this.type = 'application/octet-stream';
  }
  slice(start, end) {
    const length = Math.max(0, Math.min(this.size, end) - start);
    return { async arrayBuffer() { return new ArrayBuffer(length); } };
  }
}

function phaseMemory() {
  return process.memoryUsage().rss;
}

function maybeGc(index) {
  if (index % 500 === 0 && typeof global.gc === 'function') global.gc();
}

async function senderPhase() {
  const baseline = phaseMemory();
  let peak = baseline;
  let sent = 0;
  const sender = new PeerVaultSender('ws://unused.invalid');
  sender.files = [new SparseFile(SIZE)];
  sender.dc = {
    readyState: 'open',
    bufferedAmount: 0,
    send() {
      sent += 1;
      if (sent % sampleEvery === 0) peak = Math.max(peak, phaseMemory());
      maybeGc(sent);
    },
    close() {}
  };
  sender.cryptoEngine = {
    async encryptChunk(data) {
      return { iv: new Uint8Array(12), ciphertext: data };
    }
  };
  const started = performance.now();
  await sender.transferFile(0, SIZE, CHUNKS);
  const elapsed = performance.now() - started;
  return {
    phase: 'sender',
    chunks: sent,
    bytes: SIZE,
    duration_ms: Math.round(elapsed),
    baseline_rss_mb: +(baseline / 1048576).toFixed(2),
    peak_rss_mb: +(peak / 1048576).toFixed(2),
    delta_mb: +((peak - baseline) / 1048576).toFixed(2)
  };
}

async function receiverPhase() {
  const baseline = phaseMemory();
  let peak = baseline;
  const sink = {
    async writeChunk() {},
    async close() {}
  };
  const crypto = {
    async decryptChunk(_iv, ciphertext) { return ciphertext; }
  };
  const assembler = new FileAssembler(
    { name: 'sparse.bin', size: SIZE, mime: 'application/octet-stream', chunks: CHUNKS },
    crypto,
    sink
  );
  const iv = new Uint8Array(12);
  const aad = new Uint8Array(21);
  const started = performance.now();
  for (let index = 0; index < CHUNKS; index++) {
    await assembler.addChunk(index, iv, new ArrayBuffer(CHUNK_SIZE), aad);
    if (index % sampleEvery === 0) peak = Math.max(peak, phaseMemory());
    maybeGc(index);
  }
  await assembler.finishStreaming();
  const elapsed = performance.now() - started;
  return {
    phase: 'receiver',
    chunks: CHUNKS,
    bytes: SIZE,
    duration_ms: Math.round(elapsed),
    baseline_rss_mb: +(baseline / 1048576).toFixed(2),
    peak_rss_mb: +(peak / 1048576).toFixed(2),
    delta_mb: +((peak - baseline) / 1048576).toFixed(2)
  };
}

const sender = await senderPhase();
const receiver = await receiverPhase();
console.log(JSON.stringify({
  file_size_bytes: SIZE,
  chunk_size: CHUNK_SIZE,
  chunks: CHUNKS,
  note: 'Synthetic sparse-file/discarding-sink measurement; not a real WebRTC transfer.',
  sender,
  receiver
}, null, 2));
