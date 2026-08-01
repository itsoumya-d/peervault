// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

import { PQCrypto, CryptoCapabilities } from './pq-crypto';

export interface CryptoEngineOptions {
  /**
   * @deprecated No hybrid key exchange exists in PeerVault. This flag is retained
   * for API compatibility and has no effect; key agreement is always classical
   * P-256 ECDH, and the file-transfer path uses a random AES-256-GCM key carried in
   * the share link fragment.
   */
  useHybridKeyExchange?: boolean;
}

export class CryptoEngine {
  private key: CryptoKey | null = null;
  private localKeyPair: CryptoKeyPair | null = null;
  /**
   * @deprecated Always false. Previously defaulted to `PQCrypto.isMLKEMSupported()`,
   * which returned true in every modern browser and told applications that a hybrid
   * post-quantum exchange was in use when none was implemented.
   */
  public readonly useHybridKeyExchange: boolean = false;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_options?: CryptoEngineOptions) {
    // useHybridKeyExchange is intentionally fixed at false; see the field docs.
  }

  /**
   * Reports what this engine actually does. `supportsMLKEM` describes the platform,
   * not PeerVault: `usesPostQuantumKeyExchange` is always false.
   */
  getCapabilities(): CryptoCapabilities {
    const hasSubtle = typeof crypto !== 'undefined' && !!crypto.subtle;
    return {
      supportsMLKEM: PQCrypto.isMLKEMSupported(),
      supportsECDH: hasSubtle,
      supportsAESGCM: hasSubtle,
      usesPostQuantumKeyExchange: false,
    };
  }

  async generateKey(): Promise<string> {
    this.key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const rawKey = await crypto.subtle.exportKey('raw', this.key);
    return this.bufferToBase64Url(rawKey);
  }

  async importKey(base64UrlKey: string): Promise<void> {
    const rawKey = this.base64UrlToBuffer(base64UrlKey);
    this.key = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
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

  async encryptChunk(data: ArrayBuffer): Promise<{ iv: Uint8Array; ciphertext: ArrayBuffer }> {
    if (!this.key) throw new Error('Key not initialized');

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.key,
      data
    );

    return { iv, ciphertext };
  }

  async decryptChunk(iv: Uint8Array, ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.key) throw new Error('Key not initialized');

    // Copy into an ArrayBuffer-backed view: an incoming Uint8Array may be typed as
    // Uint8Array<ArrayBufferLike>, which is not assignable to BufferSource under
    // `strict` and made `tsc --noEmit` fail on this file.
    const ivBytes = new Uint8Array(iv.byteLength);
    ivBytes.set(iv);

    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
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
