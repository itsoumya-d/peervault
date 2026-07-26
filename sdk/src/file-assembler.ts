// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com | +91 7031648617

import { CryptoEngine } from './crypto-engine';
import { FileMetadata, ReceivedFile } from './types';

export class FileAssembler {
  private chunks: ArrayBuffer[] = [];
  private receivedChunks = 0;
  private metadata: FileMetadata;
  private cryptoEngine: CryptoEngine;

  constructor(metadata: FileMetadata, cryptoEngine: CryptoEngine) {
    this.metadata = metadata;
    this.cryptoEngine = cryptoEngine;
    this.chunks = new Array(metadata.chunks);
  }

  async addChunk(index: number, iv: Uint8Array, ciphertext: ArrayBuffer): Promise<boolean> {
    try {
      const plaintext = await this.cryptoEngine.decryptChunk(iv, ciphertext);
      
      // Verify SHA-256 hash if provided (optional feature)
      // For this implementation, AES-GCM provides built-in authentication/integrity via its auth tag.
      
      this.chunks[index] = plaintext;
      this.receivedChunks++;

      return this.isComplete();
    } catch (error) {
      console.error(`Failed to decrypt chunk ${index}:`, error);
      throw error;
    }
  }

  isComplete(): boolean {
    return this.receivedChunks === this.metadata.chunks;
  }

  assemble(): ReceivedFile {
    if (!this.isComplete()) {
      throw new Error('File incomplete');
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
