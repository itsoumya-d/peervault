// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1619@gmail.com

import { CryptoEngine } from './crypto-engine';
import { CHUNK_SIZE } from './file-chunker';
import { ChunkBitmap } from './chunk-bitmap';
import { FileMetadata, ReceivedFile } from './types';

/** Hard ceiling on the declared chunk count, to bound receiver allocation. */
export const MAX_CHUNKS = 1_000_000; // 1e6 x 64 KB = 64 GB declared maximum

/** Minimal sink implemented by FileSystemWritableFileStream or OPFS adapters. */
export interface WritableFileSink {
  writeChunk(index: number, data: ArrayBuffer): Promise<void>;
  close(): Promise<void>;
}

interface FileSystemWritableFileStreamLike {
  write(data: { type: 'write'; position: number; data: ArrayBuffer }): Promise<void>;
  close(): Promise<void>;
}

interface FileSystemFileHandleLike {
  createWritable(): Promise<FileSystemWritableFileStreamLike>;
}

/**
 * Wrap an existing writable stream as a chunk sink. Exported so callers can
 * supply OPFS, File System Access, or a Node fs adapter without duplicating the
 * offset math.
 */
export function createWritableSink(
  writable: FileSystemWritableFileStreamLike,
  chunkSize = CHUNK_SIZE
): WritableFileSink {
  if (!writable || typeof writable.write !== 'function' || typeof writable.close !== 'function') {
    throw new TypeError('writable must implement write() and close()');
  }
  return {
    async writeChunk(index: number, data: ArrayBuffer): Promise<void> {
      await writable.write({ type: 'write', position: index * chunkSize, data });
    },
    async close(): Promise<void> {
      await writable.close();
    },
  };
}

/**
 * Open a user-selected file and stream decrypted chunks into it at their byte
 * offsets. Must be called from a user gesture (the File System Access API
 * requirement). Returns null where the API is unavailable (Firefox/Safari).
 */
export async function createFileSystemSink(
  suggestedName: string,
  chunkSize = CHUNK_SIZE
): Promise<WritableFileSink | null> {
  const picker = (globalThis as unknown as {
    showSaveFilePicker?: (options?: unknown) => Promise<FileSystemFileHandleLike>;
  }).showSaveFilePicker;
  if (typeof picker !== 'function') return null;

  const handle = await picker({ suggestedName });
  const writable = await handle.createWritable();

  return createWritableSink(writable, chunkSize);
}

/**
 * Open an Origin Private File System file and stream chunks into it. OPFS is
 * origin-private (no picker, no user gesture) and persists across reloads, which
 * makes it the default resume target in Chromium. Returns null where OPFS is
 * unavailable.
 */
export async function createOpfsSink(
  fileName: string,
  chunkSize = CHUNK_SIZE
): Promise<WritableFileSink | null> {
  if (typeof fileName !== 'string' || fileName.length === 0) {
    throw new TypeError('fileName must be a non-empty string');
  }
  const storage = (globalThis as unknown as {
    navigator?: {
      storage?: {
        getDirectory?: () => Promise<{
          getFileHandle: (
            name: string,
            options?: { create?: boolean }
          ) => Promise<FileSystemFileHandleLike>;
        }>;
      };
    };
  }).navigator?.storage;
  if (!storage || typeof storage.getDirectory !== 'function') return null;

  const root = await storage.getDirectory();
  const handle = await root.getFileHandle(fileName, { create: true });
  const writable = await handle.createWritable();

  return createWritableSink(writable, chunkSize);
}

export class FileAssembler {
  private chunks: ArrayBuffer[] = [];
  private bitmap: ChunkBitmap;
  private receivedChunks = 0;
  private receivedBytes = 0;
  private metadata: FileMetadata;
  private cryptoEngine: CryptoEngine;
  private sink?: WritableFileSink;

  constructor(metadata: FileMetadata, cryptoEngine: CryptoEngine, sink?: WritableFileSink) {
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
    this.bitmap = new ChunkBitmap(declared);
    this.sink = sink;
  }

  /**
   * Decrypt and store one chunk. Resolves true once every distinct chunk index
   * in [0, metadata.chunks) has been received.
   *
   * `additionalData` must be the full 21-byte frame header (type, fileIndex,
   * chunkIndex, IV). Binding it to AES-GCM prevents a valid ciphertext from
   * being replayed under a different file, chunk index, or IV.
   *
   * Duplicate and out-of-range indices are rejected rather than counted. When a
   * sink is attached, plaintext is written straight to disk and never retained
   * in memory.
   */
  async addChunk(
    index: number,
    iv: Uint8Array,
    ciphertext: ArrayBuffer,
    additionalData?: Uint8Array
  ): Promise<boolean> {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.metadata.chunks) {
      throw new Error(`Chunk index ${String(index)} out of range [0, ${this.metadata.chunks})`);
    }

    if (this.bitmap.has(index)) {
      // Duplicate retransmission of an already-accepted chunk: ignore it.
      return this.isComplete();
    }

    const plaintext = await this.cryptoEngine.decryptChunk(iv, ciphertext, additionalData);

    // Re-check after the await: a duplicate may have completed while decrypting.
    if (this.bitmap.has(index)) return this.isComplete();

    if (this.sink) {
      await this.sink.writeChunk(index, plaintext);
    } else {
      this.chunks[index] = plaintext;
    }

    this.bitmap.mark(index);
    this.receivedChunks++;
    this.receivedBytes += plaintext.byteLength;

    return this.isComplete();
  }

  isComplete(): boolean {
    return this.receivedChunks === this.metadata.chunks;
  }

  /** True when chunks are being written directly to a file sink. */
  get streaming(): boolean {
    return this.sink !== undefined;
  }

  /** Distinct chunks accepted so far, plus decrypted byte total. */
  get progress(): { received: number; total: number; bytes: number } {
    return { received: this.receivedChunks, total: this.metadata.chunks, bytes: this.receivedBytes };
  }

  /** Clone of the received-chunk bitmap, safe for persistence. */
  receivedBitmap(): ChunkBitmap {
    return this.bitmap.clone();
  }

  /**
   * Missing chunk indices, in ascending order. `limit` bounds the returned
   * array; pass Infinity to enumerate everything.
   */
  missingChunks(limit = 1000): number[] {
    return this.bitmap.missing(limit);
  }

  assemble(): ReceivedFile {
    if (this.sink) {
      throw new Error('FileAssembler: disk sink active; call finishStreaming() instead');
    }
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
    this.assertByteLength();

    const blob = new Blob(this.chunks, { type: this.metadata.mime });
    const url = URL.createObjectURL(blob);

    return {
      ...this.metadata,
      blob,
      url,
    };
  }

  /**
   * Close the disk sink and return metadata for the completed file. No Blob or
   * object URL is created, so peak memory stays at one chunk.
   */
  async finishStreaming(): Promise<ReceivedFile> {
    if (!this.sink) {
      throw new Error('FileAssembler: finishStreaming() requires a disk sink');
    }
    if (!this.isComplete()) {
      throw new Error(
        `File incomplete: ${this.receivedChunks} of ${this.metadata.chunks} chunks received`
      );
    }
    this.assertByteLength();

    const sink = this.sink;
    this.sink = undefined;
    await sink.close();

    return {
      ...this.metadata,
      streamed: true,
    };
  }

  /** Close an open sink without publishing the file (cancellation path). */
  async abort(): Promise<void> {
    const sink = this.sink;
    this.sink = undefined;
    if (sink) {
      try {
        await sink.close();
      } catch {
        // The caller is already cancelling; a close failure has no recovery path.
      }
    }
  }

  private assertByteLength(): void {
    if (this.receivedBytes !== this.metadata.size) {
      throw new Error(
        `File corrupt: assembled ${this.receivedBytes} bytes but metadata declared ${this.metadata.size}`
      );
    }
  }
}
