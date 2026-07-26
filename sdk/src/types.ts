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
