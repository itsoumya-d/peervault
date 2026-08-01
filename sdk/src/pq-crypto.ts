// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

/**
 * IMPORTANT — PeerVault does NOT implement post-quantum cryptography.
 *
 * This module provides classical P-256 ECDH + HKDF-SHA-256 primitives. There is no
 * ML-KEM / Kyber lattice implementation anywhere in this package: no NTT, no
 * polynomial arithmetic mod q=3329, no CBD sampling, no FIPS 203 encapsulation.
 *
 * `supportsMLKEM` therefore reports whether ML-KEM is available on the *platform*,
 * never whether PeerVault protects your data with it. It does not. The effective
 * construction for a file transfer is a random AES-256-GCM key carried in the share
 * link's URL fragment. See the README section "Cryptography — What the Code Actually Does".
 */
export interface CryptoCapabilities {
  /**
   * Whether the host platform exposes ML-KEM through WebCrypto.
   * PeerVault does not use ML-KEM even when this is true.
   */
  supportsMLKEM: boolean;
  supportsECDH: boolean;
  supportsAESGCM: boolean;
  /** Always false: PeerVault's key agreement is classical ECDH, never hybrid. */
  usesPostQuantumKeyExchange: boolean;
}

export class PQCrypto {
  /**
   * @deprecated Misleading and never accurate. This used to return true for any
   * environment that merely exposed `crypto.subtle.generateKey`, which made every
   * modern browser report post-quantum support that does not exist. It now returns
   * false unconditionally because PeerVault performs no ML-KEM operations.
   * Use {@link probeMLKEM} if you want to know what the platform supports.
   */
  static isMLKEMSupported(): boolean {
    return false;
  }

  /**
   * Genuine runtime feature probe for platform ML-KEM support. Resolves true only
   * if a real ML-KEM-768 key pair can be generated with KEM key usages.
   *
   * ML-KEM is a key-encapsulation mechanism, so its usages are the
   * `encapsulate`/`decapsulate` family — not `deriveBits`, which is a
   * Diffie-Hellman operation and is rejected even by platforms that fully
   * implement ML-KEM.
   */
  static async probeMLKEM(): Promise<boolean> {
    try {
      if (typeof crypto === 'undefined' || !crypto.subtle) return false;
      await crypto.subtle.generateKey({ name: 'ML-KEM-768' } as unknown as AlgorithmIdentifier, true, [
        'encapsulateBits',
        'decapsulateBits',
      ] as unknown as KeyUsage[]);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Generates the classical P-256 ECDH key pair, plus a platform ML-KEM-768 key
   * pair when one is available.
   *
   * The returned `mlkem` key pair is NOT used by PeerVault: no encapsulation is
   * performed and its shared secret is never mixed into the HKDF input. It is
   * exposed only so that callers can build their own hybrid construction. Treat a
   * present `mlkem` field as "the platform has ML-KEM", never as "this transfer is
   * post-quantum secure".
   */
  static async generateHybridKeyPair(): Promise<{
    ecdh: CryptoKeyPair;
    mlkem?: CryptoKeyPair;
  }> {
    const ecdh = await this.generateECDHKeyPair();
    let mlkem: CryptoKeyPair | undefined;

    try {
      mlkem = (await crypto.subtle.generateKey(
        { name: 'ML-KEM-768' } as unknown as AlgorithmIdentifier,
        true,
        ['encapsulateBits', 'decapsulateBits'] as unknown as KeyUsage[]
      )) as CryptoKeyPair;
    } catch {
      // No platform ML-KEM. Classical ECDH is used either way.
      mlkem = undefined;
    }

    return { ecdh, mlkem };
  }

  /**
   * Plain P-256 ECDH derivation. Kept under its original name for compatibility.
   * Despite the name this is NOT hybrid and NOT post-quantum.
   * @see ecdhKeyExchange
   */
  static async hybridKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey): Promise<ArrayBuffer> {
    return this.ecdhKeyExchange(localPrivate, remotePublic);
  }

  /** P-256 ECDH shared secret (256 bits). Accurately named replacement. */
  static async ecdhKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: remotePublic,
      },
      localPrivate,
      256
    );
  }

  static async deriveSharedKey(
    sharedSecret: ArrayBuffer,
    salt?: ArrayBuffer,
    contextInfo?: string
  ): Promise<CryptoKey> {
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
        info: new TextEncoder().encode(contextInfo || 'PeerVault-ECDH-v1').buffer as ArrayBuffer,
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
        namedCurve: 'P-256',
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
        namedCurve: 'P-256',
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
