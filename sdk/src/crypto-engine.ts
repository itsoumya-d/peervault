// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath

import { PQCrypto, CryptoCapabilities } from './pq-crypto';

export interface CryptoEngineOptions {
  /**
   * @deprecated Hybrid key exchange is configured on PeerVaultSender and
   * PeerVaultReceiver (`hybridHandshake`, default true). This flag is retained
   * for API compatibility and has no effect.
   */
  useHybridKeyExchange?: boolean;
}

export class CryptoEngine {
  private key: CryptoKey | null = null;
  private localKeyPair: CryptoKeyPair | null = null;
  private rawKey: Uint8Array | null = null;
  private hybridEstablished = false;
  /**
   * @deprecated Always false. Hybrid handshakes are configured on the sender and
   * receiver (default true); check `getCapabilities().usesPostQuantumKeyExchange`
   * after connecting to see whether one actually completed.
   */
  public readonly useHybridKeyExchange: boolean = false;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_options?: CryptoEngineOptions) {
    // Hybrid key exchange is a peer-level concern; see the field docs.
  }

  /** Reports the primitives this engine can run and whether a hybrid session is live. */
  getCapabilities(): CryptoCapabilities {
    const hasSubtle = typeof crypto !== 'undefined' && !!crypto.subtle;
    return {
      supportsMLKEM: PQCrypto.isMLKEMSupported(),
      supportsECDH: hasSubtle,
      supportsAESGCM: hasSubtle,
      usesPostQuantumKeyExchange: this.hybridEstablished,
    };
  }

  async generateKey(): Promise<string> {
    this.key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const rawKey = await crypto.subtle.exportKey('raw', this.key);
    this.rawKey = new Uint8Array(rawKey.slice(0));
    return this.bufferToBase64Url(rawKey);
  }

  async importKey(base64UrlKey: string): Promise<void> {
    const rawKey = this.base64UrlToBuffer(base64UrlKey);
    this.rawKey = new Uint8Array(rawKey.slice(0));
    this.key = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /** The share-link key bytes. Used as the pre-shared authentication secret. */
  getRawKey(): Uint8Array {
    if (!this.rawKey) throw new Error('Key not initialized');
    return this.rawKey.slice();
  }

  /**
   * Derives and installs the transfer key:
   * HKDF-SHA256(share_link_key || hybrid_session, salt = transcript_hash,
   *             info = "peervault/file-key/v1")
   */
  async deriveHybridTransferKey(sessionKey: Uint8Array, transcriptHash: Uint8Array): Promise<void> {
    if (!this.rawKey) throw new Error('Key not initialized');
    const ikm = new Uint8Array(this.rawKey.byteLength + sessionKey.byteLength);
    ikm.set(this.rawKey, 0);
    ikm.set(sessionKey, this.rawKey.byteLength);

    const hkdfKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, [
      'deriveKey',
    ]);
    this.key = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(transcriptHash),
        info: new TextEncoder().encode('peervault/file-key/v1'),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    this.hybridEstablished = true;
  }

  async getLocalPublicKey(): Promise<string> {
    if (!this.localKeyPair) {
      this.localKeyPair = await PQCrypto.generateECDHKeyPair();
    }
    return PQCrypto.exportPublicKey(this.localKeyPair.publicKey);
  }

  async negotiateKey(remotePeerPublicKey: string): Promise<void> {
    if (!this.localKeyPair) {
      this.localKeyPair = await PQCrypto.generateECDHKeyPair();
    }
    const remotePublic = await PQCrypto.importPublicKey(remotePeerPublicKey);
    const sharedSecret = await PQCrypto.hybridKeyExchange(this.localKeyPair.privateKey, remotePublic);
    this.key = await PQCrypto.deriveSharedKey(sharedSecret);
  }

  async encryptChunk(
    data: ArrayBuffer,
    additionalData?: Uint8Array,
    providedIv?: Uint8Array
  ): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    if (!this.key) throw new Error('Key not initialized');

    const iv = providedIv
      ? new Uint8Array(providedIv)
      : crypto.getRandomValues(new Uint8Array(12));
    if (iv.byteLength !== 12) throw new Error('AES-GCM nonce must be 12 bytes');
    const aad = additionalData ? new Uint8Array(additionalData) : undefined;
    const ciphertext = await crypto.subtle.encrypt(
      aad ? { name: 'AES-GCM', iv, additionalData: aad } : { name: 'AES-GCM', iv },
      this.key,
      data
    );

    return { iv, ciphertext };
  }

  /**
   * Encrypt an application control message (for example a datamesh sync
   * payload). The 12-byte IV is prepended and bound as AES-GCM AAD.
   */
  async encryptMessage(message: string): Promise<ArrayBuffer> {
    if (!this.key) throw new Error('Key not initialized');
    const data = new TextEncoder().encode(message).buffer;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: iv },
      this.key,
      data
    );
    const output = new Uint8Array(12 + ciphertext.byteLength);
    output.set(iv, 0);
    output.set(new Uint8Array(ciphertext), 12);
    return output.buffer;
  }

  /** Decrypt a control message produced by encryptMessage(). */
  async decryptMessage(buffer: ArrayBuffer): Promise<string> {
    if (!this.key) throw new Error('Key not initialized');
    const bytes = new Uint8Array(buffer);
    if (bytes.byteLength < 12 + 16) {
      throw new Error('PeerVault: encrypted message is too short');
    }
    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: iv },
      this.key,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  }

  async decryptChunk(
    iv: Uint8Array,
    ciphertext: ArrayBuffer,
    additionalData?: Uint8Array
  ): Promise<ArrayBuffer> {
    if (!this.key) throw new Error('Key not initialized');

    // Copy into an ArrayBuffer-backed view: an incoming Uint8Array may be typed as
    // Uint8Array<ArrayBufferLike>, which is not assignable to BufferSource under
    // `strict` and made `tsc --noEmit` fail on this file.
    const ivBytes = new Uint8Array(iv.byteLength);
    ivBytes.set(iv);
    const aad = additionalData ? new Uint8Array(additionalData) : undefined;

    return crypto.subtle.decrypt(
      aad
        ? { name: 'AES-GCM', iv: ivBytes, additionalData: aad }
        : { name: 'AES-GCM', iv: ivBytes },
      this.key,
      ciphertext
    );
  }

  private bufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private base64UrlToBuffer(base64Url: string): ArrayBuffer {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
