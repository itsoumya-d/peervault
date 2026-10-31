// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1619@gmail.com

/**
 * PeerVault ships a FIPS 203 ML-KEM-768 implementation compiled from Rust to
 * WebAssembly (`src/mlkem.ts`). The protocol runs a hybrid handshake that mixes
 * ML-KEM-768, P-256 ECDH and HKDF-SHA256; see `hybrid-handshake.ts`.
 *
 * The helpers below cover the classical and HKDF primitives used by that
 * handshake. `probeMLKEM()` remains available for callers that want to know
 * whether the host platform's WebCrypto exposes its own ML-KEM implementation.
 */
export interface CryptoCapabilities {
  /** Whether PeerVault's bundled ML-KEM-768 wasm implementation can run here. */
  supportsMLKEM: boolean;
  supportsECDH: boolean;
  supportsAESGCM: boolean;
  /** True only after a hybrid ML-KEM-768 + P-256 handshake has completed. */
  usesPostQuantumKeyExchange: boolean;
}

export class PQCrypto {
  /**
   * Reports whether PeerVault's bundled ML-KEM-768 wasm core can execute here.
   * This is about the implementation PeerVault actually uses, not a claim about
   * the host platform's WebCrypto surface. Use {@link probeMLKEM} for that.
   */
  static isMLKEMSupported(): boolean {
    return typeof WebAssembly !== 'undefined';
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
   * pair when WebCrypto exposes one.
   *
   * PeerVault's default handshake does not use this platform key pair; it uses
   * the bundled wasm ML-KEM implementation in `hybrid-handshake.ts`. This helper
   * is retained for callers building their own constructions.
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
   * Derives the hybrid session secret.
   *
   * With no `mlkemSharedSecret`, this is the legacy plain P-256 ECDH behaviour.
   * With an ML-KEM shared secret, it concatenates the ECDH and KEM secrets and
   * runs HKDF-SHA256 with the supplied transcript hash as salt.
   */
  static async hybridKeyExchange(
    localPrivate: CryptoKey,
    remotePublic: CryptoKey,
    mlkemSharedSecret?: ArrayBuffer,
    transcriptHash?: ArrayBuffer
  ): Promise<ArrayBuffer> {
    const ecdh = await this.ecdhKeyExchange(localPrivate, remotePublic);
    if (!mlkemSharedSecret) return ecdh;

    const ecdhBytes = new Uint8Array(ecdh);
    const kemBytes = new Uint8Array(mlkemSharedSecret);
    const ikm = new Uint8Array(ecdhBytes.byteLength + kemBytes.byteLength);
    ikm.set(ecdhBytes, 0);
    ikm.set(kemBytes, ecdhBytes.byteLength);

    const hkdfKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, [
      'deriveBits',
    ]);
    return crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: transcriptHash ? new Uint8Array(transcriptHash) : new Uint8Array(32),
        info: new TextEncoder().encode('peervault/hybrid-session/v1'),
      },
      hkdfKey,
      256
    );
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
