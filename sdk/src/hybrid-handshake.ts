// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath
//
// Hybrid post-quantum handshake for PeerVault.
//
// The receiver advertises an ephemeral P-256 key and an ML-KEM-768 key. The
// sender encapsulates to both and returns its own P-256 key plus the KEM
// ciphertext. Both sides derive:
//
//   session_key = HKDF-SHA256(ECDH_secret || ML-KEM_secret,
//                             salt = SHA-256(transcript),
//                             info = "peervault/hybrid-session/v1")
//
// The transfer key is then bound to the share-link secret:
//
//   file_key = HKDF-SHA256(share_link_key || session_key,
//                          salt = transcript_hash,
//                          info = "peervault/file-key/v1")
//
// Every handshake message carries an HMAC-SHA256 over its canonical encoding,
// keyed by the share-link secret. A malicious signaling relay therefore cannot
// substitute its own ephemeral keys: it does not know the URL fragment key.

import { MlKem768, MlKem768KeyPair } from './mlkem';
import { PQCrypto } from './pq-crypto';

const PROTOCOL_VERSION = 1;
const encoder = new TextEncoder();

export type HybridRole = 'sender' | 'receiver';

export interface HybridHandshakeJSON {
  type: string;
  v: number;
  [key: string]: unknown;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function hmacSha256(key: Uint8Array, message: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
  return new Uint8Array(signature);
}

async function sha256(message: string): Promise<Uint8Array> {
  const bytes = encoder.encode(message);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes)));
}

function helloCanonical(ecdh: string, mlkem: string, nonce: string): string {
  return `pv-hybrid-hello|${PROTOCOL_VERSION}|${ecdh}|${mlkem}|${nonce}`;
}

function finishCanonical(ecdh: string, mlkemCt: string, confirm: string): string {
  return `pv-hybrid-finish|${PROTOCOL_VERSION}|${ecdh}|${mlkemCt}|${confirm}`;
}

function readyCanonical(confirm: string): string {
  return `pv-hybrid-ready|${PROTOCOL_VERSION}|${confirm}`;
}

function transcriptCanonical(hello: string, ecdh: string, mlkemCt: string): string {
  return `pv-hybrid-transcript|${PROTOCOL_VERSION}|${hello}|${ecdh}|${mlkemCt}`;
}

function parseMessage(raw: string, expectedType: string): HybridHandshakeJSON {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('PeerVault: hybrid handshake message is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('PeerVault: hybrid handshake message is not an object');
  }
  const message = parsed as HybridHandshakeJSON;
  if (message.type !== expectedType) {
    throw new Error(`PeerVault: expected ${expectedType}, received ${String(message.type)}`);
  }
  if (message.v !== PROTOCOL_VERSION) {
    throw new Error(`PeerVault: unsupported hybrid handshake version ${String(message.v)}`);
  }
  return message;
}

function requiredString(message: HybridHandshakeJSON, field: string): string {
  const value = message[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`PeerVault: hybrid handshake field "${field}" is missing`);
  }
  return value;
}

export class HybridHandshake {
  private ecdhKeyPair: CryptoKeyPair | null = null;
  private ecdhPublic = '';
  private mlkemKeyPair: MlKem768KeyPair | null = null;
  private mlkemPublic = '';
  private nonce: Uint8Array | null = null;
  private helloCanonical = '';
  private sessionKeyBytes: Uint8Array | null = null;
  private transcriptHashBytes: Uint8Array | null = null;
  private confirmB64 = '';
  private ready = false;

  private constructor(
    private readonly role: HybridRole,
    private readonly shareLinkKey: Uint8Array,
    private readonly kem: MlKem768
  ) {}

  static async create(role: HybridRole, shareLinkKey: Uint8Array): Promise<HybridHandshake> {
    if (shareLinkKey.byteLength !== 32) {
      throw new Error('PeerVault: the share-link key must be 32 bytes');
    }
    const kem = await MlKem768.load();
    const handshake = new HybridHandshake(role, shareLinkKey.slice(), kem);
    handshake.ecdhKeyPair = await PQCrypto.generateECDHKeyPair();
    handshake.ecdhPublic = await PQCrypto.exportPublicKey(handshake.ecdhKeyPair.publicKey);

    if (role === 'receiver') {
      handshake.mlkemKeyPair = kem.generateKeyPair();
      handshake.mlkemPublic = bytesToBase64Url(handshake.mlkemKeyPair.publicKey);
      handshake.nonce = crypto.getRandomValues(new Uint8Array(16));
      handshake.helloCanonical = helloCanonical(
        handshake.ecdhPublic,
        handshake.mlkemPublic,
        bytesToBase64Url(handshake.nonce)
      );
    }
    return handshake;
  }

  get isReady(): boolean {
    return this.ready;
  }

  get session(): Uint8Array {
    if (!this.sessionKeyBytes) throw new Error('PeerVault: hybrid session is not established');
    return this.sessionKeyBytes.slice();
  }

  get transcript(): Uint8Array {
    if (!this.transcriptHashBytes) throw new Error('PeerVault: hybrid transcript is not established');
    return this.transcriptHashBytes.slice();
  }

  /** Receiver -> sender. */
  async createHello(): Promise<string> {
    if (this.role !== 'receiver' || !this.nonce) {
      throw new Error('PeerVault: only the receiver creates a hybrid hello');
    }
    const mac = await hmacSha256(this.shareLinkKey, this.helloCanonical);
    return JSON.stringify({
      type: 'pv-hybrid-hello',
      v: PROTOCOL_VERSION,
      ecdh: this.ecdhPublic,
      mlkem: this.mlkemPublic,
      nonce: bytesToBase64Url(this.nonce),
      mac: bytesToBase64Url(mac),
    });
  }

  /** Sender receives the hello and returns the finish message. */
  async acceptHello(raw: string): Promise<string> {
    if (this.role !== 'sender') throw new Error('PeerVault: only the sender accepts a hello');
    if (!this.ecdhKeyPair) throw new Error('PeerVault: sender key pair is missing');

    const message = parseMessage(raw, 'pv-hybrid-hello');
    const remoteEcdh = requiredString(message, 'ecdh');
    const remoteMlkem = requiredString(message, 'mlkem');
    const nonce = requiredString(message, 'nonce');
    const mac = requiredString(message, 'mac');

    const canonical = helloCanonical(remoteEcdh, remoteMlkem, nonce);
    const expectedMac = await hmacSha256(this.shareLinkKey, canonical);
    if (!timingSafeEqual(expectedMac, base64UrlToBytes(mac))) {
      throw new Error('PeerVault: hybrid hello failed authentication');
    }

    const encapsulation = this.kem.encapsulate(base64UrlToBytes(remoteMlkem));
    const mlkemCt = bytesToBase64Url(encapsulation.ciphertext);
    this.helloCanonical = canonical;

    await this.establish(
      remoteEcdh,
      encapsulation.sharedSecret,
      transcriptCanonical(canonical, this.ecdhPublic, mlkemCt)
    );

    this.confirmB64 = bytesToBase64Url(
      await hmacSha256(this.session, `pv-hybrid-confirm|${PROTOCOL_VERSION}|${bytesToBase64Url(this.transcript)}`)
    );
    const finish = finishCanonical(this.ecdhPublic, mlkemCt, this.confirmB64);
    const finishMac = await hmacSha256(this.shareLinkKey, finish);

    return JSON.stringify({
      type: 'pv-hybrid-finish',
      v: PROTOCOL_VERSION,
      ecdh: this.ecdhPublic,
      mlkemCt,
      confirm: this.confirmB64,
      mac: bytesToBase64Url(finishMac),
    });
  }

  /** Receiver accepts the finish message and returns the ready message. */
  async acceptFinish(raw: string): Promise<string> {
    if (this.role !== 'receiver') throw new Error('PeerVault: only the receiver accepts a finish');
    if (!this.mlkemKeyPair) throw new Error('PeerVault: receiver ML-KEM key pair is missing');

    const message = parseMessage(raw, 'pv-hybrid-finish');
    const remoteEcdh = requiredString(message, 'ecdh');
    const mlkemCt = requiredString(message, 'mlkemCt');
    const confirm = requiredString(message, 'confirm');
    const mac = requiredString(message, 'mac');

    const finish = finishCanonical(remoteEcdh, mlkemCt, confirm);
    const expectedMac = await hmacSha256(this.shareLinkKey, finish);
    if (!timingSafeEqual(expectedMac, base64UrlToBytes(mac))) {
      throw new Error('PeerVault: hybrid finish failed authentication');
    }

    const decapsulation = this.kem.decapsulate(
      base64UrlToBytes(mlkemCt),
      this.mlkemKeyPair.secretKey
    );
    if (!decapsulation.valid) {
      throw new Error('PeerVault: ML-KEM-768 ciphertext failed re-encryption validation');
    }

    await this.establish(
      remoteEcdh,
      decapsulation.sharedSecret,
      transcriptCanonical(this.helloCanonical, remoteEcdh, mlkemCt)
    );

    const expectedConfirm = bytesToBase64Url(
      await hmacSha256(this.session, `pv-hybrid-confirm|${PROTOCOL_VERSION}|${bytesToBase64Url(this.transcript)}`)
    );
    if (!timingSafeEqual(base64UrlToBytes(expectedConfirm), base64UrlToBytes(confirm))) {
      throw new Error('PeerVault: hybrid key confirmation failed');
    }

    this.confirmB64 = confirm;
    this.ready = true;
    const ready = readyCanonical(this.confirmB64);
    const readyMac = await hmacSha256(this.shareLinkKey, ready);

    return JSON.stringify({
      type: 'pv-hybrid-ready',
      v: PROTOCOL_VERSION,
      confirm: this.confirmB64,
      mac: bytesToBase64Url(readyMac),
    });
  }

  /** Sender accepts the receiver's key-confirmation message. */
  async acceptReady(raw: string): Promise<void> {
    if (this.role !== 'sender') throw new Error('PeerVault: only the sender accepts ready');
    if (!this.confirmB64) throw new Error('PeerVault: hybrid session is not established');

    const message = parseMessage(raw, 'pv-hybrid-ready');
    const confirm = requiredString(message, 'confirm');
    const mac = requiredString(message, 'mac');

    const canonical = readyCanonical(confirm);
    const expectedMac = await hmacSha256(this.shareLinkKey, canonical);
    if (!timingSafeEqual(expectedMac, base64UrlToBytes(mac))) {
      throw new Error('PeerVault: hybrid ready message failed authentication');
    }
    if (!timingSafeEqual(base64UrlToBytes(confirm), base64UrlToBytes(this.confirmB64))) {
      throw new Error('PeerVault: hybrid ready key confirmation does not match');
    }
    this.ready = true;
  }

  private async establish(remoteEcdh: string, kemSecret: Uint8Array, transcriptInput: string) {
    if (!this.ecdhKeyPair) throw new Error('PeerVault: ECDH key pair is missing');
    const remotePublic = await PQCrypto.importPublicKey(remoteEcdh);
    const transcriptHash = await sha256(transcriptInput);
    const session = await PQCrypto.hybridKeyExchange(
      this.ecdhKeyPair.privateKey,
      remotePublic,
      kemSecret.slice().buffer,
      transcriptHash.slice().buffer
    );
    this.sessionKeyBytes = new Uint8Array(session);
    this.transcriptHashBytes = transcriptHash;
  }
}

export { base64UrlToBytes, bytesToBase64Url };
