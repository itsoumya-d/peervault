// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath
//
// Federated state mesh for edgeinfer vector indices and Reflexion episodic
// memories. State is synchronized over a caller-provided transport (typically a
// PeerVault DataChannel) using last-writer-wins by logical version, with the
// origin node id as the deterministic tie-breaker.

export interface MeshVector {
  id: string;
  embedding: Float32Array;
  metadata?: Record<string, unknown>;
  version: number;
  origin: string;
}

export interface MeshMemory {
  id: string;
  text: string;
  weight: number;
  version: number;
  origin: string;
}

export interface MeshState {
  nodeId: string;
  vectors: Array<{
    id: string;
    embedding: string;
    metadata?: Record<string, unknown>;
    version: number;
    origin: string;
  }>;
  memories: MeshMemory[];
}

export interface MeshMessage {
  type: "datamesh-hello" | "datamesh-state";
  state: MeshState;
}

export interface MeshTransport {
  send(data: string): void;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function encodeFloat32(vector: Float32Array): string {
  return bytesToBase64(new Uint8Array(vector.buffer, vector.byteOffset, vector.byteLength));
}

export function decodeFloat32(value: string): Float32Array {
  const bytes = base64ToBytes(value);
  return new Float32Array(bytes.buffer, bytes.byteOffset, bytes.byteLength / 4);
}

function wins(remote: { version: number; origin: string }, local: { version: number; origin: string }): boolean {
  if (remote.version !== local.version) return remote.version > local.version;
  return remote.origin > local.origin;
}

export class MeshNode {
  readonly nodeId: string;
  private clock = 0;
  private vectors = new Map<string, MeshVector>();
  private memories = new Map<string, MeshMemory>();

  constructor(nodeId: string) {
    if (!nodeId) throw new Error("MeshNode requires a nodeId");
    this.nodeId = nodeId;
  }

  upsertVector(
    id: string,
    embedding: Float32Array,
    metadata?: Record<string, unknown>
  ): MeshVector {
    if (embedding.length === 0) throw new Error("embedding must not be empty");
    const entry: MeshVector = {
      id,
      embedding: embedding.slice(),
      metadata,
      version: ++this.clock,
      origin: this.nodeId,
    };
    const existing = this.vectors.get(id);
    if (!existing || wins(entry, existing)) this.vectors.set(id, entry);
    return entry;
  }

  upsertMemory(id: string, text: string, weight: number): MeshMemory {
    if (!text.trim()) throw new Error("memory text must not be empty");
    const entry: MeshMemory = {
      id,
      text,
      weight,
      version: ++this.clock,
      origin: this.nodeId,
    };
    const existing = this.memories.get(id);
    if (!existing || wins(entry, existing)) this.memories.set(id, entry);
    return entry;
  }

  getVector(id: string): MeshVector | undefined {
    return this.vectors.get(id);
  }

  getMemory(id: string): MeshMemory | undefined {
    return this.memories.get(id);
  }

  get stats(): { vectors: number; memories: number; clock: number } {
    return {
      vectors: this.vectors.size,
      memories: this.memories.size,
      clock: this.clock,
    };
  }

  serialize(): MeshState {
    return {
      nodeId: this.nodeId,
      vectors: [...this.vectors.values()].map((vector) => ({
        id: vector.id,
        embedding: encodeFloat32(vector.embedding),
        metadata: vector.metadata,
        version: vector.version,
        origin: vector.origin,
      })),
      memories: [...this.memories.values()].map((memory) => ({ ...memory })),
    };
  }

  apply(state: MeshState): void {
    for (const vector of state.vectors) {
      const entry: MeshVector = {
        id: vector.id,
        embedding: decodeFloat32(vector.embedding),
        metadata: vector.metadata,
        version: vector.version,
        origin: vector.origin,
      };
      const existing = this.vectors.get(entry.id);
      if (!existing || wins(entry, existing)) this.vectors.set(entry.id, entry);
    }
    for (const memory of state.memories) {
      const existing = this.memories.get(memory.id);
      if (!existing || wins(memory, existing)) this.memories.set(memory.id, { ...memory });
    }
  }

  /** Send our full state; the peer replies with its state on hello. */
  startSync(transport: MeshTransport): void {
    transport.send(
      JSON.stringify({ type: "datamesh-hello", state: this.serialize() } satisfies MeshMessage)
    );
  }

  /** Wire this to the DataChannel onmessage handler. */
  handleMessage(raw: string, transport: MeshTransport): void {
    let message: MeshMessage;
    try {
      message = JSON.parse(raw) as MeshMessage;
    } catch {
      throw new Error("PeerVault datamesh: message is not valid JSON");
    }
    if (!message || (message.type !== "datamesh-hello" && message.type !== "datamesh-state")) {
      throw new Error("PeerVault datamesh: unknown message type");
    }
    if (!message.state || typeof message.state.nodeId !== "string") {
      throw new Error("PeerVault datamesh: malformed state");
    }

    this.apply(message.state);
    if (message.type === "datamesh-hello") {
      transport.send(
        JSON.stringify({ type: "datamesh-state", state: this.serialize() } satisfies MeshMessage)
      );
    }
  }
}
