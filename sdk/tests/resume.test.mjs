// Resumable-transfer protocol: sender re-sends requested chunks, receiver asks
// for missing chunks. Uses in-memory DataChannel fakes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { PeerVaultSender, PeerVaultReceiver, CHUNK_SIZE } = await import(
  join(__dirname, '../dist/index.mjs')
);

function fakeChannel() {
  const frames = [];
  return {
    readyState: 'open',
    bufferedAmount: 0,
    frames,
    send(data) {
      frames.push(data);
    },
    close() {}
  };
}

function senderWithFile(file) {
  const sender = new PeerVaultSender('ws://unused.invalid');
  sender.files = [file];
  sender.dc = fakeChannel();
  sender.cryptoEngine = {
    async encryptChunk(data) {
      return { iv: new Uint8Array(12), ciphertext: new Uint8Array(data) };
    }
  };
  return sender;
}

function parseFrame(buffer) {
  const view = new DataView(buffer);
  return {
    type: view.getUint8(0),
    fileIndex: view.getUint32(1, true),
    chunkIndex: view.getUint32(5, true),
    payloadLength: buffer.byteLength - 21
  };
}

describe('sender chunk resend', () => {
  test('resends only requested indices, in ascending order, without rebuffering the file', async () => {
    const file = new File(
      [new Uint8Array(CHUNK_SIZE * 2 + 100).fill(7)],
      'large.bin',
      { type: 'application/octet-stream' }
    );
    const sender = senderWithFile(file);

    const count = await sender.resendChunks(0, [2, 0, 2]);
    assert.equal(count, 2);
    const frames = sender.dc.frames.map(parseFrame);
    assert.deepEqual(frames.map((frame) => frame.chunkIndex), [0, 2]);
    assert.deepEqual(frames.map((frame) => frame.fileIndex), [0, 0]);
    assert.deepEqual(frames.map((frame) => frame.type), [1, 1]);
    assert.deepEqual(frames.map((frame) => frame.payloadLength), [CHUNK_SIZE, 100]);
  });

  test('control message path validates and resends', async () => {
    const file = new File([new Uint8Array(CHUNK_SIZE + 5)], 'x.bin');
    const sender = senderWithFile(file);

    await sender.handleChunkRequest({ fileIndex: 0, indices: [1] });
    const frames = sender.dc.frames.map(parseFrame);
    assert.equal(frames.length, 1);
    assert.equal(frames[0].chunkIndex, 1);
    assert.equal(frames[0].payloadLength, 5);
  });

  test('rejects invalid file and chunk indices', async () => {
    const sender = senderWithFile(new File([new Uint8Array(10)], 'x.bin'));
    await assert.rejects(() => sender.resendChunks(1, [0]), RangeError);
    await assert.rejects(() => sender.resendChunks(0, []), TypeError);
    await assert.rejects(() => sender.resendChunks(0, [1]), RangeError);
    await assert.rejects(() => sender.resendChunks(0, [-1]), RangeError);
    await assert.rejects(
      () => sender.resendChunks(0, Array.from({ length: 4097 }, (_, i) => i)),
      RangeError
    );
  });
});

describe('receiver missing-chunk request', () => {
  function receiverWithMissing(indices) {
    const receiver = new PeerVaultReceiver('ws://unused.invalid', 'room#key');
    receiver.dc = {
      readyState: 'open',
      sent: [],
      send(raw) {
        this.sent.push(JSON.parse(raw));
      }
    };
    receiver.assemblers = new Map([
      [
        0,
        {
          missingChunks(limit) {
            return indices.slice(0, limit);
          }
        }
      ]
    ]);
    return receiver;
  }

  test('sends a bounded request for missing chunks', () => {
    const receiver = receiverWithMissing([1, 4, 9]);
    assert.equal(receiver.requestMissingChunks(0), 3);
    assert.deepEqual(receiver.dc.sent[0], {
      type: 'pv-request-chunks',
      fileIndex: 0,
      indices: [1, 4, 9]
    });

    assert.equal(receiver.requestMissingChunks(0, 2), 2);
    assert.deepEqual(receiver.dc.sent[1].indices, [1, 4]);
  });

  test('returns zero when nothing is missing and fails closed otherwise', () => {
    const empty = receiverWithMissing([]);
    assert.equal(empty.requestMissingChunks(0), 0);
    assert.equal(empty.dc.sent.length, 0);

    const receiver = receiverWithMissing([1]);
    assert.throws(() => receiver.requestMissingChunks(1), /No assembler/);
    receiver.dc = null;
    assert.throws(() => receiver.requestMissingChunks(0), /not open/);
  });
});
