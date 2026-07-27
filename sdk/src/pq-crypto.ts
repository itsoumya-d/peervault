// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com | +91 7031648617

export interface CryptoCapabilities {
  supportsMLKEM: boolean;
  supportsECDH: boolean;
  supportsAESGCM: boolean;
}

export class PQCrypto {
  static isMLKEMSupported(): boolean {
    return false; // Safe default for browsers that do not yet support ML-KEM synchronously
  }

  static async generateHybridKeyPair(): Promise<{
    ecdh: CryptoKeyPair;
    mlkem?: CryptoKeyPair;
  }> {
    const ecdh = await this.generateECDHKeyPair();
    let mlkem: CryptoKeyPair | undefined;
    
    if (this.isMLKEMSupported()) {
      try {
        mlkem = await crypto.subtle.generateKey(
          { name: 'ML-KEM-768' } as any,
          true,
          ['deriveBits']
        ) as CryptoKeyPair;
      } catch (e) {
        console.warn('ML-KEM generation failed', e);
      }
    }
    
    return { ecdh, mlkem };
  }

  static async hybridKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: remotePublic
      },
      localPrivate,
      256
    );
  }

  static async deriveSharedKey(sharedSecret: ArrayBuffer, salt?: ArrayBuffer): Promise<CryptoKey> {
    const hkdfSalt = salt || new Uint8Array(32).buffer;
    
    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: hkdfSalt,
        info: new Uint8Array(0).buffer
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  static async generateECDHKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveBits']
    );
  }

  static async exportPublicKey(key: CryptoKey): Promise<string> {
    const rawKey = await crypto.subtle.exportKey('raw', key);
    return this.bufferToBase64Url(rawKey);
  }

  static async importPublicKey(base64url: string): Promise<CryptoKey> {
    const rawKey = this.base64UrlToBuffer(base64url);
    return crypto.subtle.importKey(
      'raw',
      rawKey,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      []
    );
  }

  private static bufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private static base64UrlToBuffer(base64Url: string): ArrayBuffer {
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
