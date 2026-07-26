// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com | +91 7031648617

export interface FileMetadata {
  name: string;
  size: number;
  mime: string;
  chunks: number;
}

export interface ReceivedFile extends FileMetadata {
  blob: Blob;
  url: string;
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
