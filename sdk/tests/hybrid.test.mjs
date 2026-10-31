// SPDX-License-Identifier: AGPL-3.0-or-later
// FIPS 203 ML-KEM-768 known-answer checks and the PeerVault hybrid handshake.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const {
  CryptoEngine,
  HybridHandshake,
  MlKem768,
  base64UrlToBytes,
  bytesToBase64Url,
} = await import(join(__dirname, '../dist/index.mjs'));

function firstKatVector() {
  const path = join(__dirname, '../../pqc/tests/vectors/mlkem768_kat_sample.txt');
  const lines = readFileSync(path, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 7);
  const fields = {};
  for (const line of lines) {
    const [name, , hex] = line.split(/\s+/);
    fields[name] = Buffer.from(hex, 'hex');
  }
  return fields;
}

async function keyedEngines() {
  const sender = new CryptoEngine();
  const key = await sender.generateKey();
  const receiver = new CryptoEngine();
  await receiver.importKey(key);
  return { sender, receiver };
}

describe('bundled ML-KEM-768 wasm core', () => {
  test('matches the FIPS 203 NIST KAT vector byte-for-byte', async () => {
    const vector = firstKatVector();
    const kem = await MlKem768.load();
    const seed = Buffer.concat([vector.d, vector.z]);
    const keyPair = kem.generateKeyPair(new Uint8Array(seed));
    assert.ok(Buffer.from(keyPair.publicKey).equals(vector.pk), 'public key');
    assert.ok(Buffer.from(keyPair.secretKey).equals(vector.sk), 'secret key');

    const encapsulation = kem.encapsulate(keyPair.publicKey, new Uint8Array(vector.m));
    assert.ok(Buffer.from(encapsulation.ciphertext).equals(vector.ct), 'ciphertext');
    assert.ok(Buffer.from(encapsulation.sharedSecret).equals(vector.ss), 'shared secret');

    const decapsulation = kem.decapsulate(new Uint8Array(vector.ct), keyPair.secretKey);
    assert.equal(decapsulation.valid, true);
    assert.ok(Buffer.from(decapsulation.sharedSecret).equals(vector.ss), 'decapsulated secret');
  });

  test('rejects a tampered ciphertext with implicit rejection', async () => {
    const kem = await MlKem768.load();
    const keyPair = kem.generateKeyPair();
    const encapsulation = kem.encapsulate(keyPair.publicKey);
    const tampered = new Uint8Array(encapsulation.ciphertext);
    tampered[17] ^= 0x40;
    const decapsulation = kem.decapsulate(tampered, keyPair.secretKey);
    assert.equal(decapsulation.valid, false);
    assert.ok(
      !Buffer.from(decapsulation.sharedSecret).equals(Buffer.from(encapsulation.sharedSecret))
    );
  });

  test('interoperates with the platform ML-KEM implementation when present', async (t) => {
    if (!globalThis.crypto?.subtle) return t.skip('WebCrypto unavailable');
    try {
      await crypto.subtle.generateKey(
        { name: 'ML-KEM-768' },
        true,
        ['encapsulateBits', 'decapsulateBits']
      );
    } catch {
      return t.skip('platform does not implement ML-KEM-768');
    }

    const kem = await MlKem768.load();
    const keyPair = kem.generateKeyPair();
    const imported = await crypto.subtle.importKey(
      'raw-public',
      keyPair.publicKey,
      { name: 'ML-KEM-768' },
      true,
      ['encapsulateBits']
    );
    const foreign = await crypto.subtle.encapsulateBits(
      { name: 'ML-KEM-768' },
      imported
    );
    const ours = kem.decapsulate(new Uint8Array(foreign.ciphertext), keyPair.secretKey);
    assert.equal(ours.valid, true);
    assert.ok(Buffer.from(ours.sharedSecret).equals(Buffer.from(foreign.sharedKey)));
  });
});

describe('hybrid ML-KEM-768 + P-256 handshake', () => {
  test('both peers derive the same session and transfer key', async () => {
    const { sender, receiver } = await keyedEngines();
    assert.equal(sender.getCapabilities().usesPostQuantumKeyExchange, false);
    assert.equal(receiver.getCapabilities().usesPostQuantumKeyExchange, false);

    const shareKey = sender.getRawKey();
    const senderHandshake = await HybridHandshake.create('sender', shareKey);
    const receiverHandshake = await HybridHandshake.create('receiver', shareKey);

    const hello = await receiverHandshake.createHello();
    const finish = await senderHandshake.acceptHello(hello);
    const ready = await receiverHandshake.acceptFinish(finish);
    await senderHandshake.acceptReady(ready);

    assert.equal(senderHandshake.isReady, true);
    assert.equal(receiverHandshake.isReady, true);
    assert.ok(
      Buffer.from(senderHandshake.session).equals(Buffer.from(receiverHandshake.session)),
      'session keys agree'
    );
    assert.ok(
      Buffer.from(senderHandshake.transcript).equals(Buffer.from(receiverHandshake.transcript)),
      'transcripts agree'
    );

    await sender.deriveHybridTransferKey(senderHandshake.session, senderHandshake.transcript);
    await receiver.deriveHybridTransferKey(
      receiverHandshake.session,
      receiverHandshake.transcript
    );
    assert.equal(sender.getCapabilities().usesPostQuantumKeyExchange, true);
    assert.equal(receiver.getCapabilities().usesPostQuantumKeyExchange, true);

    const plaintext = new TextEncoder().encode('hybrid transport').buffer;
    const { iv, ciphertext } = await sender.encryptChunk(plaintext);
    const back = await receiver.decryptChunk(iv, ciphertext);
    assert.equal(new TextDecoder().decode(back), 'hybrid transport');
  });

  test('a hello authenticated with the wrong share key is rejected', async () => {
    const { sender, receiver } = await keyedEngines();
    const wrongKey = new CryptoEngine();
    await wrongKey.generateKey();

    const senderHandshake = await HybridHandshake.create('sender', sender.getRawKey());
    const receiverHandshake = await HybridHandshake.create('receiver', wrongKey.getRawKey());
    const hello = await receiverHandshake.createHello();
    await assert.rejects(() => senderHandshake.acceptHello(hello), /authentication/);
    assert.equal(receiver.getCapabilities().usesPostQuantumKeyExchange, false);
  });

  test('a tampered ML-KEM ciphertext or key confirmation is rejected', async () => {
    const { sender } = await keyedEngines();
    const shareKey = sender.getRawKey();
    const senderHandshake = await HybridHandshake.create('sender', shareKey);
    const receiverHandshake = await HybridHandshake.create('receiver', shareKey);
    const hello = await receiverHandshake.createHello();
    const finish = JSON.parse(await senderHandshake.acceptHello(hello));

    const tamperedCt = base64UrlToBytes(finish.mlkemCt);
    tamperedCt[0] ^= 1;
    finish.mlkemCt = bytesToBase64Url(tamperedCt);
    await assert.rejects(() => receiverHandshake.acceptFinish(JSON.stringify(finish)));

    const finish2 = JSON.parse(await senderHandshake.acceptHello(hello));
    finish2.confirm = bytesToBase64Url(new Uint8Array(32).fill(1));
    await assert.rejects(
      () => receiverHandshake.acceptFinish(JSON.stringify(finish2)),
      /authentication|confirmation/
    );
  });

  test('sender rejects a forged ready message', async () => {
    const { sender } = await keyedEngines();
    const shareKey = sender.getRawKey();
    const senderHandshake = await HybridHandshake.create('sender', shareKey);
    const receiverHandshake = await HybridHandshake.create('receiver', shareKey);
    const finish = await senderHandshake.acceptHello(await receiverHandshake.createHello());
    const ready = JSON.parse(await receiverHandshake.acceptFinish(finish));

    const forged = { ...ready, confirm: bytesToBase64Url(new Uint8Array(32).fill(2)) };
    await assert.rejects(() => senderHandshake.acceptReady(JSON.stringify(forged)));
  });
});
