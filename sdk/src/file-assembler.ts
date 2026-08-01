// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1619@gmail.com

import { CryptoEngine } from './crypto-engine';
import { FileMetadata, ReceivedFile } from './types';

/** Hard ceiling on the declared chunk count, to bound receiver allocation. */
export const MAX_CHUNKS = 1_000_000; // 1e6 x 64 KB = 64 GB declared maximum

export class FileAssembler {
  private chunks: ArrayBuffer[] = [];
  private receivedChunks = 0;
  private receivedBytes = 0;
  private metadata: FileMetadata;
  private cryptoEngine: CryptoEngine;

  constructor(metadata: FileMetadata, cryptoEngine: CryptoEngine) {
    const declared = metadata?.chunks;
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_CHUNKS) {
      throw new Error(
        `Invalid file metadata: chunks must be an integer in [0, ${MAX_CHUNKS}], received ${String(declared)}`
      );
    }
    if (!Number.isSafeInteger(metadata.size) || metadata.size < 0) {
      throw new Error(
        `Invalid file metadata: size must be a non-negative integer, received ${String(metadata.size)}`
      );
    }
    this.metadata = metadata;
    this.cryptoEngine = cryptoEngine;
    this.chunks = new Array(declared);
  }

  /**
   * Decrypt and store one chunk. Resolves true once every distinct chunk index
   * in [0, metadata.chunks) has been received.
   *
   * Duplicate and out-of-range indices are rejected rather than counted. Counting
   * arrivals instead of distinct indices previously allowed a duplicate chunk to
   * mask a missing one, which produced a silently corrupt file.
   */
  async addChunk(index: number, iv: Uint8Array, ciphertext: ArrayBuffer): Promise<boolean> {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.metadata.chunks) {
      throw new Error(`Chunk index ${String(index)} out of range [0, ${this.metadata.chunks})`);
    }

    // AES-GCM authenticates the chunk payload, so a tampered or wrongly-keyed
    // chunk rejects here. The index travels in the clear, hence the bounds check
    // above and the total-length check in assemble().
    const plaintext = await this.cryptoEngine.decryptChunk(iv, ciphertext);

    if (this.chunks[index] !== undefined) {
      // Duplicate retransmission of an already-accepted chunk: ignore it.
      return this.isComplete();
    }

    this.chunks[index] = plaintext;
    this.receivedChunks++;
    this.receivedBytes += plaintext.byteLength;

    return this.isComplete();
  }

  isComplete(): boolean {
    return this.receivedChunks === this.metadata.chunks;
  }

  /** Distinct chunks accepted so far, plus decrypted byte total. */
  get progress(): { received: number; total: number; bytes: number } {
    return { received: this.receivedChunks, total: this.metadata.chunks, bytes: this.receivedBytes };
  }

  assemble(): ReceivedFile {
    if (!this.isComplete()) {
      throw new Error(
        `File incomplete: ${this.receivedChunks} of ${this.metadata.chunks} chunks received`
      );
    }
    for (let i = 0; i < this.metadata.chunks; i++) {
      if (this.chunks[i] === undefined) {
        throw new Error(`File incomplete: chunk ${i} is missing`);
      }
    }
    if (this.receivedBytes !== this.metadata.size) {
      throw new Error(
        `File corrupt: assembled ${this.receivedBytes} bytes but metadata declared ${this.metadata.size}`
      );
    }

    const blob = new Blob(this.chunks, { type: this.metadata.mime });
    const url = URL.createObjectURL(blob);

    return {
      ...this.metadata,
      blob,
      url,
    };
  }
}
