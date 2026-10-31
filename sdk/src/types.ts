// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1619@gmail.com

export interface FileMetadata {
  name: string;
  size: number;
  mime: string;
  chunks: number;
}

export interface ReceivedFile extends FileMetadata {
  /** Present for in-memory assembly. Absent when the file was streamed to disk. */
  blob?: Blob;
  /** Present for in-memory assembly. Absent when the file was streamed to disk. */
  url?: string;
  /** True when the receiver wrote chunks directly to a user-selected file. */
  streamed?: boolean;
}

export interface TransferProgress {
  fileIndex: number;
  chunkIndex: number;
  totalChunks: number;
  bytesTransferred: number;
  totalBytes: number;
}

export interface SignalingMessage {
  type: string;
  roomId?: string;
  payload?: any;
}
