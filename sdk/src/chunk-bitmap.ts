// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath
//
// Fixed-size chunk bitmap used by the resumable-transfer protocol. The bitmap
// is the wire/persistence representation of "which chunk indices are present";
// it is intentionally independent of FileAssembler so a receiver can persist it
// and resume after a reconnect.

const MAX_BITMAP_CHUNKS = 10_000_000;

function assertIndex(index: number, size: number): void {
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) {
    throw new RangeError(`chunk index ${String(index)} out of range [0, ${size})`);
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const window = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += window) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + window));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export class ChunkBitmap {
  readonly size: number;
  private readonly bytes: Uint8Array;

  constructor(size: number, bytes?: Uint8Array) {
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_BITMAP_CHUNKS) {
      throw new RangeError(
        `bitmap size must be an integer in [0, ${MAX_BITMAP_CHUNKS}], received ${String(size)}`
      );
    }
    this.size = size;
    const expected = Math.ceil(size / 8);
    if (bytes === undefined) {
      this.bytes = new Uint8Array(expected);
    } else {
      if (!(bytes instanceof Uint8Array) || bytes.length !== expected) {
        throw new TypeError(`bitmap bytes must be a Uint8Array of length ${expected}`);
      }
      this.bytes = new Uint8Array(bytes);
    }
  }

  mark(index: number): this {
    assertIndex(index, this.size);
    this.bytes[index >> 3] |= 1 << (index & 7);
    return this;
  }

  clear(index: number): this {
    assertIndex(index, this.size);
    this.bytes[index >> 3] &= ~(1 << (index & 7));
    return this;
  }

  has(index: number): boolean {
    assertIndex(index, this.size);
    return (this.bytes[index >> 3] & (1 << (index & 7))) !== 0;
  }

  get count(): number {
    let total = 0;
    for (let i = 0; i < this.bytes.length; i++) {
      let value = this.bytes[i];
      value = value - ((value >> 1) & 0x55);
      value = (value & 0x33) + ((value >> 2) & 0x33);
      total += (value + (value >> 4)) & 0x0f;
    }
    return total;
  }

  get complete(): boolean {
    return this.count === this.size;
  }

  missing(limit = Number.POSITIVE_INFINITY): number[] {
    if (limit !== Number.POSITIVE_INFINITY &&
        (!Number.isSafeInteger(limit) || limit < 0)) {
      throw new RangeError('limit must be a non-negative integer or Infinity');
    }
    const out: number[] = [];
    if (limit === 0) return out;
    for (let index = 0; index < this.size; index++) {
      if (!this.has(index)) {
        out.push(index);
        if (out.length >= limit) break;
      }
    }
    return out;
  }

  *missingIterator(): IterableIterator<number> {
    for (let index = 0; index < this.size; index++) {
      if (!this.has(index)) yield index;
    }
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  toBase64(): string {
    return bytesToBase64(this.bytes);
  }

  toJSON(): { size: number; base64: string } {
    return { size: this.size, base64: this.toBase64() };
  }

  clone(): ChunkBitmap {
    return new ChunkBitmap(this.size, this.bytes);
  }

  static fromBase64(value: string, size: number): ChunkBitmap {
    if (typeof value !== 'string') {
      throw new TypeError('bitmap base64 value must be a string');
    }
    return new ChunkBitmap(size, base64ToBytes(value));
  }

  static fromJSON(value: unknown): ChunkBitmap {
    if (!value || typeof value !== 'object') {
      throw new TypeError('bitmap JSON must be an object');
    }
    const record = value as { size?: unknown; base64?: unknown };
    if (typeof record.base64 !== 'string') {
      throw new TypeError('bitmap JSON.base64 must be a string');
    }
    return ChunkBitmap.fromBase64(record.base64, Number(record.size));
  }
}

export { MAX_BITMAP_CHUNKS };
