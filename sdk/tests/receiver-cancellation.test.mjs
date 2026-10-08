// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// Exercise the built receiver with real AES-GCM and in-memory browser transports.
// No relay, ICE provider, browser, or credentials are used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CryptoEngine, PeerVaultReceiver } from '../dist/index.mjs';

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function receiverFixture(t) {
  const joined = deferred();
  const sockets = [];
  const peers = [];
  class FakeSocket {
    static OPEN = 1;
    readyState = 1;
    constructor() {
      sockets.push(this);
      queueMicrotask(() => this.onopen?.());
    }
    send(raw) {
      if (JSON.parse(raw).type === 'join_room') joined.resolve();
    }
    close() {
      this.readyState = 3;
      this.onclose?.();
    }
  }
  class FakePeer {
    constructor() { peers.push(this); }
    close() { this.closed = true; }
  }
  for (const [name, value] of Object.entries({ WebSocket: FakeSocket, RTCPeerConnection: FakePeer })) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
    t.after(() => {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    });
  }

  const sender = new CryptoEngine();
  const key = await sender.generateKey();
  const receiver = new PeerVaultReceiver('wss://relay.invalid/ws', `room#${key}`, {
    connectTimeoutMs: 1000,
    iceServers: [],
  });
  t.after(() => receiver.cancel());
  const events = [];
  for (const name of ['progress', 'file_complete', 'complete', 'error']) {
    receiver.on(name, (value) => {
      events.push({ name, value });
      if (name === 'file_complete') t.after(() => URL.revokeObjectURL(value.url));
    });
  }
  const connecting = receiver.connect();
  // Attach immediately so a deliberately rejected connect cannot be unhandled.
  connecting.catch(() => {});
  await joined.promise;
  const channel = {
    readyState: 'open',
    close() { this.readyState = 'closed'; this.onclose?.(); },
    message(data) { this.onmessage?.({ data }); },
  };
  peers[0].ondatachannel({ channel });
  channel.onopen();

  async function metadata(parts) {
    channel.message(JSON.stringify({
      type: 'metadata',
      files: [{ name: 'example.bin', size: parts.reduce((n, p) => n + p.length, 0), mime: '', chunks: parts.length }],
    }));
    await connecting;
    const frames = [];
    for (let i = 0; i < parts.length; i++) {
      const { iv, ciphertext } = await sender.encryptChunk(Uint8Array.from(parts[i]).buffer);
      const frame = new ArrayBuffer(21 + ciphertext.byteLength);
      const view = new DataView(frame);
      view.setUint8(0, 1);
      view.setUint32(1, 0, true);
      view.setUint32(5, i, true);
      new Uint8Array(frame).set(iv, 9);
      new Uint8Array(frame).set(new Uint8Array(ciphertext), 21);
      frames.push(frame);
    }
    return frames;
  }
  return { receiver, channel, events, metadata, connecting, sockets, peers };
}

function holdDecryption(t) {
  const entered = deferred();
  const release = deferred();
  const decrypt = CryptoEngine.prototype.decryptChunk;
  let calls = 0;
  t.mock.method(CryptoEngine.prototype, 'decryptChunk', async function (...args) {
    calls++;
    entered.resolve();
    await release.promise;
    return decrypt.apply(this, args);
  });
  t.after(() => release.resolve());
  return { entered: entered.promise, release: () => release.resolve(), calls: () => calls };
}

const finish = (channel) => channel.message(JSON.stringify({ type: 'complete', fileIndex: 0 }));
// Only inspect the internal queue to deterministically await its drain. All input
// enters via public connect/download/cancel and the browser's onmessage interface.
const drain = (receiver) => receiver.queue;

test('cancelling during decryption prevents queued chunks, progress and completion', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const frames = await metadata([[1, 2], [3, 4]]);
  await receiver.download();
  const gate = holdDecryption(t);
  channel.message(frames[0]);
  channel.message(frames[1]);
  finish(channel);
  await gate.entered;
  receiver.cancel();
  gate.release();
  await drain(receiver);
  assert.deepEqual(events, [], 'cancelled work must not publish received data');
  assert.equal(gate.calls(), 1, 'queued chunks must not start decryption after cancel');
});

test('cancelling buffered data makes download reject instead of replaying it', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const [frame] = await metadata([[10, 20]]);
  channel.message(frame);
  finish(channel);
  receiver.cancel();
  await assert.rejects(receiver.download(), /cancelled/i);
  await drain(receiver);
  assert.deepEqual(events, []);
});

test('cancel from a progress listener prevents file completion in the same callback', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const [frame] = await metadata([[5, 6]]);
  receiver.on('progress', () => receiver.cancel());
  await receiver.download();
  channel.message(frame);
  finish(channel);
  await drain(receiver);
  assert.deepEqual(events.map((event) => event.name), ['progress']);
});

test('cancel from a file_complete listener prevents overall completion', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const [frame] = await metadata([[7, 8]]);
  receiver.on('file_complete', () => receiver.cancel());
  await receiver.download();
  channel.message(frame);
  finish(channel);
  await drain(receiver);
  assert.deepEqual(events.map((event) => event.name), ['progress', 'file_complete']);
});

test('late queued browser messages and peer errors are ignored after cancel', async (t) => {
  const { receiver, channel, events, metadata, peers } = await receiverFixture(t);
  const [frame] = await metadata([[9]]);
  await receiver.download();
  const onmessage = channel.onmessage;
  receiver.cancel();
  onmessage({ data: frame });
  onmessage({ data: '{invalid json' });
  channel.onerror({ error: new Error('late transport failure') });
  peers[0].ondatachannel({ channel });
  channel.onopen();
  await drain(receiver);
  assert.deepEqual(events, []);
  assert.equal(channel.readyState, 'closed');
});

test('cancel rejects pending metadata connection with a cancellation error', async (t) => {
  const { receiver, connecting } = await receiverFixture(t);
  receiver.cancel();
  await assert.rejects(connecting, /cancelled/i);
  await assert.rejects(receiver.connect(), /cancelled/i);
  assert.doesNotThrow(() => receiver.cancel());
});

test('cancel during key import cannot open a new signaling socket', async (t) => {
  const sender = new CryptoEngine();
  const key = await sender.generateKey();
  const entered = deferred();
  const release = deferred();
  const importKey = CryptoEngine.prototype.importKey;
  t.mock.method(CryptoEngine.prototype, 'importKey', async function (...args) {
    entered.resolve();
    await release.promise;
    return importKey.apply(this, args);
  });
  let sockets = 0;
  t.mock.method(globalThis, 'WebSocket', function () {
    sockets++;
    throw new Error('must not open a socket after cancellation');
  });
  const receiver = new PeerVaultReceiver('wss://relay.invalid/ws', `room#${key}`);
  t.after(() => { release.resolve(); receiver.cancel(); });
  const connecting = receiver.connect();
  connecting.catch(() => {});
  await entered.promise;
  receiver.cancel();
  release.resolve();
  await assert.rejects(connecting, /transfer cancelled/i);
  assert.equal(sockets, 0);
});

test('a decrypt failure settling after cancellation does not emit a late error', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const [frame] = await metadata([[1, 2]]);
  new Uint8Array(frame)[21] ^= 1;
  await receiver.download();
  const gate = holdDecryption(t);
  channel.message(frame);
  finish(channel);
  await gate.entered;
  receiver.cancel();
  gate.release();
  await drain(receiver);
  assert.deepEqual(events, []);
});

test('an active receive still reports corrupted ciphertext and never completes it', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const [frame] = await metadata([[1, 2]]);
  new Uint8Array(frame)[21] ^= 1;
  await receiver.download();
  channel.message(frame);
  finish(channel);
  await drain(receiver);
  assert.deepEqual(events.map((event) => event.name), ['error']);
  assert.ok(events[0].value instanceof Error);
});

test('normal buffered encrypted transfer still completes byte-exactly once', async (t) => {
  const { receiver, channel, events, metadata } = await receiverFixture(t);
  const frames = await metadata([[0, 127, 255], [12, 42]]);
  for (const frame of frames) channel.message(frame);
  finish(channel);
  await receiver.download();
  await drain(receiver);
  finish(channel);
  await drain(receiver);
  assert.deepEqual(events.map((event) => event.name), ['progress', 'progress', 'file_complete', 'complete']);
  assert.deepEqual(new Uint8Array(await events[2].value.blob.arrayBuffer()), new Uint8Array([0, 127, 255, 12, 42]));
});
