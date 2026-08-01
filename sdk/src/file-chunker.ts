// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

export const CHUNK_SIZE = 64 * 1024; // 64KB

export class FileChunker {
  private file: File;
  private offset = 0;
  private sentEmptyFile = false;

  constructor(file: File) {
    this.file = file;
  }

  get totalChunks(): number {
    return this.file.size === 0 ? 1 : Math.ceil(this.file.size / CHUNK_SIZE);
  }

  async getNextChunk(): Promise<ArrayBuffer | null> {
    if (this.file.size === 0) {
      if (this.sentEmptyFile) return null;
      this.sentEmptyFile = true;
      return new ArrayBuffer(0);
    }
    if (this.offset >= this.file.size) {
      return null;
    }

    const slice = this.file.slice(this.offset, this.offset + CHUNK_SIZE);
    this.offset += CHUNK_SIZE;

    return await slice.arrayBuffer();
  }

  async hashChunk(chunk: ArrayBuffer): Promise<ArrayBuffer> {
    return await crypto.subtle.digest('SHA-256', chunk);
  }
}
