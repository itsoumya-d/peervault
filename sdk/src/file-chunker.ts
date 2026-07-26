export const CHUNK_SIZE = 64 * 1024; // 64KB

export class FileChunker {
  private file: File;
  private offset = 0;

  constructor(file: File) {
    this.file = file;
  }

  get totalChunks(): number {
    return Math.ceil(this.file.size / CHUNK_SIZE);
  }

  async getNextChunk(): Promise<ArrayBuffer | null> {
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
