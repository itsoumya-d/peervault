// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath
//
// Thin loader for the bundled FIPS 203 ML-KEM-768 wasm core. The module has no
// imports and no allocator: JavaScript writes into a fixed workspace and reads
// fixed-size outputs back out.

import { MLKEM768_WASM_BASE64 } from './mlkem-wasm.generated';

export const MLKEM768_PUBLIC_KEY_BYTES = 1184;
export const MLKEM768_SECRET_KEY_BYTES = 2400;
export const MLKEM768_CIPHERTEXT_BYTES = 1088;
export const MLKEM768_SHARED_SECRET_BYTES = 32;
export const MLKEM768_SEED_BYTES = 64;

export interface MlKem768KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface MlKem768Encapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export interface MlKem768Decapsulation {
  sharedSecret: Uint8Array;
  /** False when decapsulation hit the FIPS 203 implicit-rejection path. */
  valid: boolean;
}

interface MlKem768Exports {
  memory: WebAssembly.Memory;
  pv_mlkem768_workspace(): number;
  pv_mlkem768_seed_offset(): number;
  pv_mlkem768_pk_offset(): number;
  pv_mlkem768_sk_offset(): number;
  pv_mlkem768_m_offset(): number;
  pv_mlkem768_ct_offset(): number;
  pv_mlkem768_ss_offset(): number;
  pv_mlkem768_pk_bytes(): number;
  pv_mlkem768_sk_bytes(): number;
  pv_mlkem768_ct_bytes(): number;
  pv_mlkem768_ss_bytes(): number;
  pv_mlkem768_seed_bytes(): number;
  pv_mlkem768_keypair(): number;
  pv_mlkem768_encapsulate(): number;
  pv_mlkem768_decapsulate(): number;
}

const textEncoder = new TextEncoder();

function base64ToBytes(value: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  const nodeBuffer = (globalThis as { Buffer?: { from(input: string, encoding: string): Uint8Array } })
    .Buffer;
  if (nodeBuffer) return new Uint8Array(nodeBuffer.from(value, 'base64'));
  throw new Error('PeerVault: no base64 decoder is available for the ML-KEM module');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function randomBytes(length: number): Uint8Array {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('PeerVault: secure random numbers are unavailable');
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

let instancePromise: Promise<MlKem768> | null = null;

export class MlKem768 {
  private constructor(
    private readonly exports: MlKem768Exports,
    private readonly workspaceOffset: number,
    private readonly seedOffset: number,
    private readonly publicKeyOffset: number,
    private readonly secretKeyOffset: number,
    private readonly messageOffset: number,
    private readonly ciphertextOffset: number,
    private readonly sharedSecretOffset: number
  ) {}

  static load(): Promise<MlKem768> {
    if (!instancePromise) {
      instancePromise = MlKem768.instantiate().catch((error) => {
        instancePromise = null;
        throw error;
      });
    }
    return instancePromise;
  }

  private static async instantiate(): Promise<MlKem768> {
    if (typeof WebAssembly === 'undefined') {
      throw new Error('PeerVault: WebAssembly is required for ML-KEM-768');
    }
    const bytes = base64ToBytes(MLKEM768_WASM_BASE64);
    const { instance } = await WebAssembly.instantiate(toArrayBuffer(bytes), {});
    const exports = instance.exports as unknown as MlKem768Exports;

    if (
      exports.pv_mlkem768_pk_bytes() !== MLKEM768_PUBLIC_KEY_BYTES ||
      exports.pv_mlkem768_sk_bytes() !== MLKEM768_SECRET_KEY_BYTES ||
      exports.pv_mlkem768_ct_bytes() !== MLKEM768_CIPHERTEXT_BYTES
    ) {
      throw new Error('PeerVault: ML-KEM wasm module reports unexpected sizes');
    }

    const workspace = exports.pv_mlkem768_workspace();
    return new MlKem768(
      exports,
      workspace,
      workspace + exports.pv_mlkem768_seed_offset(),
      workspace + exports.pv_mlkem768_pk_offset(),
      workspace + exports.pv_mlkem768_sk_offset(),
      workspace + exports.pv_mlkem768_m_offset(),
      workspace + exports.pv_mlkem768_ct_offset(),
      workspace + exports.pv_mlkem768_ss_offset()
    );
  }

  private view(): Uint8Array {
    return new Uint8Array(this.exports.memory.buffer);
  }

  generateKeyPair(seed?: Uint8Array): MlKem768KeyPair {
    const seedBytes = seed ?? randomBytes(MLKEM768_SEED_BYTES);
    if (seedBytes.byteLength !== MLKEM768_SEED_BYTES) {
      throw new Error(`ML-KEM-768 key generation needs ${MLKEM768_SEED_BYTES} seed bytes`);
    }
    const memory = this.view();
    memory.set(seedBytes, this.seedOffset);
    if (this.exports.pv_mlkem768_keypair() !== 0) {
      throw new Error('ML-KEM-768 key generation failed');
    }
    return {
      publicKey: memory.slice(this.publicKeyOffset, this.publicKeyOffset + MLKEM768_PUBLIC_KEY_BYTES),
      secretKey: memory.slice(this.secretKeyOffset, this.secretKeyOffset + MLKEM768_SECRET_KEY_BYTES),
    };
  }

  encapsulate(publicKey: Uint8Array, message?: Uint8Array): MlKem768Encapsulation {
    if (publicKey.byteLength !== MLKEM768_PUBLIC_KEY_BYTES) {
      throw new Error(`ML-KEM-768 public key must be ${MLKEM768_PUBLIC_KEY_BYTES} bytes`);
    }
    const m = message ?? randomBytes(32);
    if (m.byteLength !== 32) throw new Error('ML-KEM-768 encapsulation message must be 32 bytes');

    const memory = this.view();
    memory.set(publicKey, this.publicKeyOffset);
    memory.set(m, this.messageOffset);
    if (this.exports.pv_mlkem768_encapsulate() !== 0) {
      throw new Error('ML-KEM-768 encapsulation failed');
    }
    return {
      ciphertext: memory.slice(this.ciphertextOffset, this.ciphertextOffset + MLKEM768_CIPHERTEXT_BYTES),
      sharedSecret: memory.slice(
        this.sharedSecretOffset,
        this.sharedSecretOffset + MLKEM768_SHARED_SECRET_BYTES
      ),
    };
  }

  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): MlKem768Decapsulation {
    if (ciphertext.byteLength !== MLKEM768_CIPHERTEXT_BYTES) {
      throw new Error(`ML-KEM-768 ciphertext must be ${MLKEM768_CIPHERTEXT_BYTES} bytes`);
    }
    if (secretKey.byteLength !== MLKEM768_SECRET_KEY_BYTES) {
      throw new Error(`ML-KEM-768 secret key must be ${MLKEM768_SECRET_KEY_BYTES} bytes`);
    }
    const memory = this.view();
    memory.set(ciphertext, this.ciphertextOffset);
    memory.set(secretKey, this.secretKeyOffset);
    const valid = this.exports.pv_mlkem768_decapsulate() === 0;
    return {
      sharedSecret: memory.slice(
        this.sharedSecretOffset,
        this.sharedSecretOffset + MLKEM768_SHARED_SECRET_BYTES
      ),
      valid,
    };
  }
}

/** Exposed so the handshake can use a single TextEncoder instance. */
export { textEncoder };
