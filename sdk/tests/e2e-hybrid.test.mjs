// SPDX-License-Identifier: AGPL-3.0-or-later
// End-to-end transfer over the default hybrid ML-KEM-768 + P-256 handshake.
// Uses in-memory WebSocket/RTCPeerConnection fakes; no relay or browser needed.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { PeerVaultSender, PeerVaultReceiver } = await import(
  join(__dirname, '../dist/index.mjs')
);

class FakeDataChannel {
  constructor(label = 'peervault_transfer') {
    this.label = label;
    this.readyState = 'connecting';
    this.binaryType = 'blob';
    this.bufferedAmount = 0;
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;
    this.peer = null;
  }

  send(data) {
    if (this.readyState !== 'open') throw new Error('fake data channel is not open');
    const copy = typeof data === 'string' ? data : data.slice(0);
    const peer = this.peer;
    queueMicrotask(() => {
      if (peer && peer.readyState === 'open') peer.onmessage?.({ data: copy });
    });
  }

  close() {
    if (this.readyState === 'closed') return;
    this.readyState = 'closed';
    this.onclose?.();
  }

  _open() {
    this.readyState = 'open';
    this.onopen?.();
  }
}

class FakeRTCPeerConnection {
  static instances = [];

  constructor() {
    this.iceConnectionState = 'new';
    this.connectionState = 'new';
    this.localDescription = null;
    this.remoteDescription = null;
    this.channel = null;
    this.ondatachannel = null;
    this.onicecandidate = null;
    this.oniceconnectionstatechange = null;
    this.onconnectionstatechange = null;
    FakeRTCPeerConnection.instances.push(this);
  }

  createDataChannel(label) {
    this.channel = new FakeDataChannel(label);
    return this.channel;
  }

  async createOffer() {
    return { type: 'offer', sdp: 'fake-offer' };
  }

  async createAnswer() {
    return { type: 'answer', sdp: 'fake-answer' };
  }

  async setLocalDescription(description) {
    this.localDescription = { type: description.type, sdp: description.sdp };
    if (description.type === 'answer') {
      const senderChannel = this.remoteSender?.channel;
      const receiverChannel = this.channel;
      queueMicrotask(() => {
        senderChannel?._open();
        receiverChannel?._open();
      });
    }
  }

  async setRemoteDescription(description) {
    this.remoteDescription = description;
    if (description.type === 'offer') {
      const sender = FakeRTCPeerConnection.instances.find((pc) => pc !== this && pc.channel);
      this.remoteSender = sender;
      const receiverChannel = new FakeDataChannel();
      receiverChannel.peer = sender.channel;
      sender.channel.peer = receiverChannel;
      this.channel = receiverChannel;
      queueMicrotask(() => this.ondatachannel?.({ channel: receiverChannel }));
    }
  }

  async addIceCandidate() {}

  close() {
    this.connectionState = 'closed';
    this.channel?.close();
  }
}

let roomCounter = 0;

class FakeSocket {
  static OPEN = 1;
  static CONNECTING = 0;
  static CLOSING = 2;
  static CLOSED = 3;
  static rooms = new Map();

  constructor() {
    this.readyState = 0;
    this.roomId = null;
    queueMicrotask(() => {
      if (this.readyState !== 3) {
        this.readyState = 1;
        this.onopen?.();
      }
    });
  }

  send(raw) {
    const message = JSON.parse(raw);

    if (message.type === 'create_room') {
      const roomId = `room-${++roomCounter}`;
      this.roomId = roomId;
      FakeSocket.rooms.set(roomId, { sender: this });
      queueMicrotask(() =>
        this.onmessage?.({ data: JSON.stringify({ type: 'room_created', roomId }) })
      );
      return;
    }

    if (message.type === 'join_room') {
      const room = FakeSocket.rooms.get(message.roomId);
      if (!room) {
        queueMicrotask(() =>
          this.onmessage?.({
            data: JSON.stringify({ type: 'error', payload: { message: 'Room not found' } }),
          })
        );
        return;
      }
      room.receiver = this;
      this.roomId = message.roomId;
      queueMicrotask(() => room.sender.onmessage?.({ data: JSON.stringify({ type: 'peer_joined' }) }));
      return;
    }

    if (message.type === 'signal') {
      const room = FakeSocket.rooms.get(this.roomId);
      if (!room) return;
      const other = room.sender === this ? room.receiver : room.sender;
      queueMicrotask(() => other?.onmessage?.({ data: raw }));
    }
  }

  close() {
    this.readyState = 3;
    this.onclose?.();
  }
}

function installFakes(t) {
  const names = ['WebSocket', 'RTCPeerConnection', 'RTCSessionDescription', 'RTCIceCandidate'];
  const previous = new Map();
  const values = {
    WebSocket: FakeSocket,
    RTCPeerConnection: FakeRTCPeerConnection,
    RTCSessionDescription: class {
      constructor(init) {
        Object.assign(this, init);
      }
    },
    RTCIceCandidate: class {
      constructor(init) {
        Object.assign(this, init);
      }
    },
  };

  for (const name of names) {
    previous.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, {
      configurable: true,
      writable: true,
      value: values[name],
    });
  }

  t.after(() => {
    for (const name of names) {
      const descriptor = previous.get(name);
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
    FakeRTCPeerConnection.instances = [];
    FakeSocket.rooms.clear();
  });
}

function patterned(size) {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = (i * 31 + 17) & 0xff;
  return bytes;
}

describe('default hybrid transfer path', () => {
  test('200 KB transfers byte-exactly after an ML-KEM-768 handshake', async (t) => {
    installFakes(t);
    const payload = patterned(200_000);
    const sender = new PeerVaultSender('ws://fake', {
      createRoomTimeoutMs: 5_000,
      handshakeTimeoutMs: 10_000,
      iceServers: [],
    });
    t.after(() => sender.cancel());
    sender.addFiles([new File([payload], 'payload.bin', { type: 'application/octet-stream' })]);

    const link = await sender.createShareLink();
    const receiver = new PeerVaultReceiver('ws://fake', link, {
      connectTimeoutMs: 10_000,
      handshakeTimeoutMs: 10_000,
      iceServers: [],
    });
    t.after(() => receiver.cancel());

    const completion = new Promise((resolve, reject) => {
      receiver.on('file_complete', resolve);
      receiver.on('error', reject);
      sender.on('error', reject);
    });

    const files = await receiver.connect();
    assert.equal(files.length, 1);
    assert.equal(files[0].name, 'payload.bin');

    await receiver.download();
    const received = await completion;
    t.after(() => URL.revokeObjectURL(received.url));

    const bytes = new Uint8Array(await received.blob.arrayBuffer());
    assert.equal(bytes.byteLength, payload.byteLength);
    assert.deepEqual(bytes, payload);
  });
});
