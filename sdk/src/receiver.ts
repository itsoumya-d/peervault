// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1619@gmail.com

import { EventEmitter } from './events';
import { SignalingClient } from './signaling-client';
import { PeerConnection } from './peer-connection';
import { CryptoEngine } from './crypto-engine';
import { FileAssembler } from './file-assembler';
import { FileMetadata, ReceivedFile, TransferProgress } from './types';

interface ReceiverEvents {
  progress: TransferProgress;
  file_complete: ReceivedFile;
  complete: void;
  error: Error;
}

export interface ReceiverOptions {
  /**
   * ICE servers for the peer connection. Defaults to public STUN only, which
   * cannot traverse symmetric or carrier-grade NAT. Supply a TURN entry here for
   * reliable connectivity.
   */
  iceServers?: RTCIceServer[];
  /**
   * Milliseconds to wait for the sender's metadata after joining the room before
   * connect() rejects. Without this, an unreachable peer, a dead relay or a failed
   * ICE negotiation leaves connect() pending forever. Pass 0 to disable.
   */
  connectTimeoutMs?: number;
}

/** Header layout: [1B type][4B fileIndex][4B chunkIndex][12B IV][ciphertext] */
const CHUNK_HEADER_BYTES = 21;

export class PeerVaultReceiver extends EventEmitter<ReceiverEvents> {
  private signaling: SignalingClient;
  private peerConnection: PeerConnection | null = null;
  private cryptoEngine: CryptoEngine;
  private roomId: string;
  private keyBase64Url: string;
  private dc: RTCDataChannel | null = null;
  private connectTimeoutMs: number;
  private iceServers?: RTCIceServer[];

  private metadataList: FileMetadata[] = [];
  private assemblers: Map<number, FileAssembler> = new Map();
  private isDownloading = false;
  private resolveConnect: ((metadata: FileMetadata[]) => void) | null = null;
  private rejectConnect: ((err: Error) => void) | null = null;
  private connectTimer: ReturnType<typeof setTimeout> | null = null;

  /** Chunks that arrived before download() was called, replayed once it is. */
  private pendingChunks: ArrayBuffer[] = [];
  /** Serialises chunk handling so completion is never evaluated against a stale count. */
  private queue: Promise<void> = Promise.resolve();
  /** fileIndex values for which the sender has already sent its 'complete' marker. */
  private completeSignalled = new Set<number>();
  private emittedFiles = new Set<number>();
  private allCompleteEmitted = false;

  constructor(signalingUrl: string, shareLinkData: string, options?: ReceiverOptions) {
    super();
    // shareLinkData expected to be roomId#key
    if (typeof shareLinkData !== 'string') throw new Error('Invalid share link data');
    const [roomId, key] = shareLinkData.split('#');
    if (!roomId || !key) throw new Error('Invalid share link data');

    this.roomId = roomId;
    this.keyBase64Url = key;
    this.iceServers = options?.iceServers;
    this.connectTimeoutMs = options?.connectTimeoutMs ?? 60_000;
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
  }

  async connect(): Promise<FileMetadata[]> {
    await this.cryptoEngine.importKey(this.keyBase64Url);
    await this.signaling.connect();

    return new Promise<FileMetadata[]>((resolve, reject) => {
      this.resolveConnect = resolve;
      this.rejectConnect = reject;

      if (this.connectTimeoutMs > 0) {
        this.connectTimer = setTimeout(() => {
          this.failConnect(
            new Error(
              `PeerVault: timed out after ${this.connectTimeoutMs}ms waiting for the sender. ` +
                'The share link may be stale, the sender may be offline, or the direct peer ' +
                'connection may have been blocked (no TURN server is configured, so symmetric ' +
                'and carrier-grade NAT cannot be traversed).'
            )
          );
        }, this.connectTimeoutMs);
      }

      // Surface relay-level failures ("Room not found or full") instead of hanging.
      this.signaling.on('message', (msg) => {
        if (msg && msg.type === 'error') {
          const detail =
            msg.payload && typeof msg.payload === 'object' && 'message' in (msg.payload as object)
              ? String((msg.payload as { message?: unknown }).message)
              : 'unknown relay error';
          this.failConnect(new Error(`PeerVault relay rejected the request: ${detail}`));
        }
      });
      this.signaling.on('close', () => {
        this.failConnect(
          new Error('PeerVault: signaling connection closed before the transfer started')
        );
      });
      this.signaling.on('error', (e: unknown) => {
        this.failConnect(toError(e, 'PeerVault: signaling connection error'));
      });

      this.peerConnection = new PeerConnection(this.signaling, false, { iceServers: this.iceServers });

      this.peerConnection.on('datachannel_open', (dc: RTCDataChannel) => {
        this.dc = dc;
        this.setupDataChannel(dc);
      });

      this.peerConnection.on('error', (err: Error) => {
        this.emit('error', err);
        this.failConnect(err);
      });

      this.signaling.send({
        type: 'join_room',
        roomId: this.roomId,
      });
    });
  }

  private failConnect(err: Error) {
    this.clearConnectTimer();
    const reject = this.rejectConnect;
    this.rejectConnect = null;
    this.resolveConnect = null;
    if (reject) reject(err);
  }

  private clearConnectTimer() {
    if (this.connectTimer) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
  }

  async download(): Promise<void> {
    if (!this.metadataList.length) throw new Error('No metadata available to download');
    this.isDownloading = true;

    // Chunks may already have arrived between connect() resolving and download()
    // being called. They are buffered rather than dropped; replay them now.
    const buffered = this.pendingChunks;
    this.pendingChunks = [];
    for (const buf of buffered) this.enqueueChunk(buf);
  }

  private setupDataChannel(dc: RTCDataChannel) {
    dc.onmessage = (event) => {
      try {
        if (typeof event.data === 'string') {
          this.handleControlMessage(event.data);
        } else if (event.data instanceof ArrayBuffer) {
          if (this.isDownloading) this.enqueueChunk(event.data);
          else this.pendingChunks.push(event.data);
        }
      } catch (err) {
        this.emit('error', toError(err, 'PeerVault: malformed message from peer'));
      }
    };
    dc.onclose = () => {
      this.failConnect(new Error('PeerVault: data channel closed before the transfer started'));
    };
  }

  private handleControlMessage(raw: string) {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      throw new Error('PeerVault: peer sent a control message that is not valid JSON');
    }
    if (!msg || typeof msg !== 'object') {
      throw new Error('PeerVault: peer sent a non-object control message');
    }
    const m = msg as { type?: unknown; files?: unknown; fileIndex?: unknown };

    if (m.type === 'metadata') {
      if (!Array.isArray(m.files)) {
        throw new Error('PeerVault: metadata message has no files array');
      }
      const files = m.files as FileMetadata[];
      this.assemblers.clear();
      // FileAssembler validates chunks/size and throws on hostile values.
      files.forEach((meta, i) => {
        this.assemblers.set(i, new FileAssembler(meta, this.cryptoEngine));
      });
      this.metadataList = files;
      this.clearConnectTimer();
      if (this.resolveConnect) {
        const resolve = this.resolveConnect;
        this.resolveConnect = null;
        this.rejectConnect = null;
        resolve(this.metadataList);
      }
    } else if (m.type === 'complete') {
      const fileIndex = Number(m.fileIndex);
      if (!Number.isSafeInteger(fileIndex)) {
        throw new Error(
          `PeerVault: complete message has an invalid fileIndex ${String(m.fileIndex)}`
        );
      }
      this.completeSignalled.add(fileIndex);
      // The marker can arrive before the last chunk has finished decrypting, so
      // re-evaluate once the queue has drained rather than reading a stale count.
      this.queue = this.queue
        .then(() => this.tryFinishFile(fileIndex))
        .catch((err) => {
          this.emit('error', toError(err, 'PeerVault: failed to finalise file'));
        });
    }
  }

  private enqueueChunk(buffer: ArrayBuffer) {
    this.queue = this.queue
      .then(() => this.handleChunk(buffer))
      .catch((err) => {
        this.emit('error', toError(err, 'PeerVault: failed to process chunk'));
      });
  }

  private async handleChunk(buffer: ArrayBuffer) {
    if (buffer.byteLength < CHUNK_HEADER_BYTES) {
      throw new Error(
        `PeerVault: chunk frame too short (${buffer.byteLength} bytes, need at least ${CHUNK_HEADER_BYTES})`
      );
    }
    const view = new DataView(buffer);

    const type = view.getUint8(0);
    if (type !== 1) return; // Only process chunk types

    const fileIndex = view.getUint32(1, true);
    const chunkIndex = view.getUint32(5, true);
    const iv = new Uint8Array(buffer, 9, 12);
    const ciphertext = buffer.slice(CHUNK_HEADER_BYTES);

    const assembler = this.assemblers.get(fileIndex);
    if (!assembler) {
      throw new Error(`PeerVault: chunk for unknown fileIndex ${fileIndex}`);
    }

    await assembler.addChunk(chunkIndex, iv, ciphertext);

    const meta = this.metadataList[fileIndex];
    const { received, bytes } = assembler.progress;
    this.emit('progress', {
      fileIndex,
      chunkIndex,
      totalChunks: meta.chunks,
      bytesTransferred: bytes,
      totalBytes: meta.size,
    });

    // Completion is checked here as well as on the 'complete' marker, so the
    // transfer finishes regardless of which of the two happens last.
    if (received === meta.chunks) await this.tryFinishFile(fileIndex);
  }

  private async tryFinishFile(fileIndex: number) {
    if (this.emittedFiles.has(fileIndex)) return;
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler || !assembler.isComplete()) return;
    if (!this.completeSignalled.has(fileIndex)) return;

    const receivedFile = assembler.assemble();
    this.emittedFiles.add(fileIndex);
    this.emit('file_complete', receivedFile);

    if (
      !this.allCompleteEmitted &&
      this.metadataList.length > 0 &&
      this.metadataList.every((_, i) => this.emittedFiles.has(i))
    ) {
      this.allCompleteEmitted = true;
      this.emit('complete', undefined);
    }
  }

  cancel(): void {
    this.clearConnectTimer();
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
}

function toError(e: unknown, fallback: string): Error {
  if (e instanceof Error) return e;
  if (typeof e === 'string') return new Error(e);
  // WebSocket / DataChannel handlers deliver a DOM Event, which has no .message.
  if (e && typeof e === 'object' && 'type' in e) {
    return new Error(`${fallback} (${String((e as { type: unknown }).type)})`);
  }
  return new Error(fallback);
}
