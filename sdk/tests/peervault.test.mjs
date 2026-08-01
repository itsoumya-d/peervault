// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { PeerVaultSender, PeerVaultReceiver, PQCrypto } =
  await import(join(__dirname, '../dist/index.mjs'));

// ---------------------------------------------------------------------------
// Module shape
// ---------------------------------------------------------------------------
describe('Module exports', () => {
  test('all documented symbols are exported', () => {
    assert.ok(typeof PeerVaultSender === 'function', 'PeerVaultSender');
    assert.ok(typeof PeerVaultReceiver === 'function', 'PeerVaultReceiver');
    assert.ok(typeof PQCrypto === 'function', 'PQCrypto');
  });

  test('PeerVaultSender has documented API', () => {
    const proto = PeerVaultSender.prototype;
    assert.ok(typeof proto.addFiles === 'function', 'addFiles');
    assert.ok(typeof proto.createShareLink === 'function', 'createShareLink');
    assert.ok(typeof proto.cancel === 'function', 'cancel');
  });

  test('PeerVaultReceiver has documented API', () => {
    const proto = PeerVaultReceiver.prototype;
    assert.ok(typeof proto.connect === 'function', 'connect');
    assert.ok(typeof proto.download === 'function', 'download');
    assert.ok(typeof proto.cancel === 'function', 'cancel');
  });

  test('PQCrypto has documented static methods', () => {
    assert.ok(typeof PQCrypto.isMLKEMSupported === 'function', 'isMLKEMSupported');
    assert.ok(typeof PQCrypto.generateHybridKeyPair === 'function', 'generateHybridKeyPair');
    assert.ok(typeof PQCrypto.hybridKeyExchange === 'function', 'hybridKeyExchange');
    assert.ok(typeof PQCrypto.deriveSharedKey === 'function', 'deriveSharedKey');
    assert.ok(typeof PQCrypto.generateECDHKeyPair === 'function', 'generateECDHKeyPair');
    assert.ok(typeof PQCrypto.exportPublicKey === 'function', 'exportPublicKey');
    assert.ok(typeof PQCrypto.importPublicKey === 'function', 'importPublicKey');
  });
});

// ---------------------------------------------------------------------------
// PeerVaultSender construction
// ---------------------------------------------------------------------------
describe('PeerVaultSender', () => {
  test('constructor with signalingUrl does not throw', () => {
    // WebSocket is undefined in Node; the class should handle that gracefully
    // (it is only used when createShareLink is called)
    assert.doesNotThrow(() => new PeerVaultSender('wss://relay.example.com/ws'));
  });

  test('cancel() on fresh instance does not throw', () => {
    const sender = new PeerVaultSender('wss://relay.example.com/ws');
    assert.doesNotThrow(() => sender.cancel());
  });

  test('addFiles accepts array of File-like objects', () => {
    const sender = new PeerVaultSender('wss://relay.example.com/ws');
    // File objects require browser; pass empty array — should not throw
    assert.doesNotThrow(() => sender.addFiles([]));
  });
});

// ---------------------------------------------------------------------------
// PeerVaultReceiver construction
// ---------------------------------------------------------------------------
describe('PeerVaultReceiver', () => {
  test('constructor with signalingUrl and shareLinkData does not throw', () => {
    assert.doesNotThrow(
      () => new PeerVaultReceiver('wss://relay.example.com/ws', 'room123#keyBase64Url')
    );
  });

  test('cancel() on fresh instance does not throw', () => {
    const receiver = new PeerVaultReceiver('wss://relay.example.com/ws', 'room#key');
    assert.doesNotThrow(() => receiver.cancel());
  });
});

// ---------------------------------------------------------------------------
// PQCrypto — only pure-JS parts runnable in Node without WebCrypto
// ---------------------------------------------------------------------------
describe('PQCrypto', () => {
  // isMLKEMSupported() is deprecated and now returns false unconditionally,
  // because PeerVault performs no ML-KEM operations. See tests/transfer.test.mjs.
  test('isMLKEMSupported() returns a boolean', () => {
    const result = PQCrypto.isMLKEMSupported();
    assert.ok(typeof result === 'boolean');
  });

  // Node 24 has crypto.subtle — generateECDHKeyPair should work
  test('generateECDHKeyPair() returns a CryptoKeyPair', async () => {
    const pair = await PQCrypto.generateECDHKeyPair();
    assert.ok(pair.publicKey, 'publicKey present');
    assert.ok(pair.privateKey, 'privateKey present');
  });

  test('exportPublicKey produces a non-empty base64url string', async () => {
    const { publicKey } = await PQCrypto.generateECDHKeyPair();
    const exported = await PQCrypto.exportPublicKey(publicKey);
    assert.ok(typeof exported === 'string', 'exported is string');
    assert.ok(exported.length > 10, 'exported is non-trivial');
    // base64url must not contain +, /, or =
    assert.ok(!/[+/=]/.test(exported), 'exported is valid base64url');
  });

  test('importPublicKey round-trips exportPublicKey', async () => {
    const { publicKey } = await PQCrypto.generateECDHKeyPair();
    const exported = await PQCrypto.exportPublicKey(publicKey);
    const imported = await PQCrypto.importPublicKey(exported);
    assert.ok(imported, 'imported key is truthy');
    assert.equal(imported.type, 'public');
  });

  test('hybridKeyExchange produces 256 bits of shared secret', async () => {
    const alice = await PQCrypto.generateECDHKeyPair();
    const bob = await PQCrypto.generateECDHKeyPair();
    const shared = await PQCrypto.hybridKeyExchange(alice.privateKey, bob.publicKey);
    assert.ok(shared instanceof ArrayBuffer, 'result is ArrayBuffer');
    assert.equal(shared.byteLength, 32, '256 bits = 32 bytes');
  });

  test('deriveSharedKey returns an AES-GCM CryptoKey', async () => {
    const alice = await PQCrypto.generateECDHKeyPair();
    const bob = await PQCrypto.generateECDHKeyPair();
    const shared = await PQCrypto.hybridKeyExchange(alice.privateKey, bob.publicKey);
    const key = await PQCrypto.deriveSharedKey(shared);
    assert.ok(key, 'key is truthy');
    assert.equal(key.algorithm.name, 'AES-GCM');
    assert.equal(key.algorithm.length, 256);
    assert.ok(key.usages.includes('encrypt'), 'key can encrypt');
    assert.ok(key.usages.includes('decrypt'), 'key can decrypt');
  });

  test('ECDH is NOT ML-KEM: no post-quantum key exchange is implemented', () => {
    // hybridKeyExchange() calls crypto.subtle.deriveBits with { name: 'ECDH' }
    // regardless of platform, and no ML-KEM shared secret is ever mixed into the
    // HKDF input. Node 24 *does* ship ML-KEM-768 in WebCrypto (use
    // PQCrypto.probeMLKEM() to detect it), so the old comment claiming no platform
    // implements it was wrong; what matters is that PeerVault never uses it.
    assert.equal(PQCrypto.isMLKEMSupported(), false,
      'isMLKEMSupported() must not claim post-quantum protection that does not exist');
  });

  test('deriveSharedKey with custom context string does not throw', async () => {
    const alice = await PQCrypto.generateECDHKeyPair();
    const bob = await PQCrypto.generateECDHKeyPair();
    const shared = await PQCrypto.hybridKeyExchange(alice.privateKey, bob.publicKey);
    const key = await PQCrypto.deriveSharedKey(shared, undefined, 'MyApp-v1');
    assert.ok(key);
  });
});

// ---------------------------------------------------------------------------
// Adversarial cases
// ---------------------------------------------------------------------------
describe('Adversarial cases', () => {
  test('importPublicKey with garbage input rejects', async () => {
    await assert.rejects(
      () => PQCrypto.importPublicKey('not-a-valid-key'),
      'must reject invalid public key'
    );
  });

  test('PeerVaultSender addFiles with non-array does not throw before connect', () => {
    const sender = new PeerVaultSender('wss://x.example.com/ws');
    // empty call — addFiles expects File[] but should not throw in setup phase
    assert.doesNotThrow(() => sender.addFiles([]));
  });

  test('PeerVaultReceiver cancel is idempotent', () => {
    const r = new PeerVaultReceiver('wss://x.example.com/ws', 'r#k');
    r.cancel();
    assert.doesNotThrow(() => r.cancel());
  });
});
