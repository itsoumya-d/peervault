// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath

import { EventEmitter } from './events';
import { SignalingClient } from './signaling-client';
import { PeerConnection } from './peer-connection';
import { CryptoEngine } from './crypto-engine';
import { HybridHandshake } from './hybrid-handshake';
import { FileAssembler, WritableFileSink } from './file-assembler';
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
  /**
   * Optional streaming sink factory. When provided, each file is written
   * directly to the returned sink instead of being accumulated in memory.
   * Called when the sender's metadata arrives; use an OPFS sink or open the
   * picker from the user gesture that starts the transfer.
   */
  sinkFactory?: (metadata: FileMetadata, fileIndex: number) => Promise<WritableFileSink | null>;
  /**
   * Run the ML-KEM-768 + P-256 hybrid handshake before accepting metadata.
   * Default true. Set false only for interoperability with older senders.
   */
  hybridHandshake?: boolean;
  /** Milliseconds to wait for the sender's hybrid finish. Default 15s. */
  handshakeTimeoutMs?: number;
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
  private sinkFactory?: ReceiverOptions['sinkFactory'];
  private hybridHandshakeEnabled: boolean;
  private handshakeTimeoutMs: number;
  private handshake: HybridHandshake | null = null;
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;

  private metadataList: FileMetadata[] = [];
  private assemblers: Map<number, FileAssembler> = new Map();
  private isDownloading = false;
  private isCancelled = false;
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
    this.sinkFactory = options?.sinkFactory;
    this.hybridHandshakeEnabled = options?.hybridHandshake ?? true;
    this.handshakeTimeoutMs = options?.handshakeTimeoutMs ?? 15_000;
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
  }

  async connect(): Promise<FileMetadata[]> {
    this.throwIfCancelled();
    await this.cryptoEngine.importKey(this.keyBase64Url);
    this.throwIfCancelled();
    await this.signaling.connect();
    this.throwIfCancelled();

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
        if (this.isCancelled) {
          dc.close();
          return;
        }
        this.dc = dc;
        this.setupDataChannel(dc);
        // The channel is open here, so the hello can be sent immediately.
        void this.beginHybridHandshake(dc);
      });

      this.peerConnection.on('error', (err: Error) => {
        if (this.isCancelled) return;
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
    this.throwIfCancelled();
    if (!this.metadataList.length) throw new Error('No metadata available to download');
    this.isDownloading = true;

    // Chunks may already have arrived between connect() resolving and download()
    // being called. They are buffered rather than dropped; replay them now.
    const buffered = this.pendingChunks;
    this.pendingChunks = [];
    for (const buf of buffered) this.enqueueChunk(buf);
  }

  /**
   * Ask the sender to resend missing chunks for one file. Intended for a
   * resumed transfer: persist `assembler.receivedBitmap()` (or the sink's
   * state), reconnect, then call this with the new assembler. Returns the
   * number of indices requested.
   */
  requestMissingChunks(fileIndex: number, limit = 1000): number {
    if (!Number.isSafeInteger(fileIndex) || fileIndex < 0) {
      throw new RangeError(`fileIndex ${String(fileIndex)} is invalid`);
    }
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler) throw new Error(`No assembler for fileIndex ${fileIndex}`);
    if (!this.dc || this.dc.readyState !== 'open') {
      throw new Error('PeerVault: data channel is not open');
    }

    const missing = assembler.missingChunks(limit);
    if (missing.length === 0) return 0;
    this.dc.send(
      JSON.stringify({
        type: 'pv-request-chunks',
        fileIndex,
        indices: missing,
      })
    );
    return missing.length;
  }

  private setupDataChannel(dc: RTCDataChannel) {
    dc.onmessage = (event) => {
      if (this.isCancelled) return;
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

  private async beginHybridHandshake(dc: RTCDataChannel): Promise<void> {
    if (!this.hybridHandshakeEnabled) return;
    try {
      const handshake = await HybridHandshake.create(
        'receiver',
        this.cryptoEngine.getRawKey()
      );
      if (this.isCancelled) return;
      this.handshake = handshake;
      const hello = await handshake.createHello();
      if (this.isCancelled || dc.readyState !== 'open') return;
      dc.send(hello);
      if (this.handshakeTimeoutMs > 0) {
        this.handshakeTimer = setTimeout(() => {
          const error = new Error(
            `PeerVault: hybrid handshake timed out after ${this.handshakeTimeoutMs}ms`
          );
          this.emit('error', error);
          this.failConnect(error);
        }, this.handshakeTimeoutMs);
      }
    } catch (error) {
      const failure = toError(error, 'PeerVault: failed to start the hybrid handshake');
      this.emit('error', failure);
      this.failConnect(failure);
    }
  }

  private async handleHybridFinish(raw: string): Promise<void> {
    try {
      if (!this.handshake) throw new Error('PeerVault: received a hybrid finish before setup');
      const ready = await this.handshake.acceptFinish(raw);
      await this.cryptoEngine.deriveHybridTransferKey(
        this.handshake.session,
        this.handshake.transcript
      );
      if (this.dc && this.dc.readyState === 'open') this.dc.send(ready);
      if (this.handshakeTimer) {
        clearTimeout(this.handshakeTimer);
        this.handshakeTimer = null;
      }
    } catch (error) {
      const failure = toError(error, 'PeerVault: hybrid handshake failed');
      this.emit('error', failure);
      this.failConnect(failure);
    }
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

    if (m.type === 'pv-hybrid-finish') {
      this.queue = this.queue
        .then(() => this.handleHybridFinish(raw))
        .catch((err) => {
          if (this.isCancelled) return;
          this.emit('error', toError(err, 'PeerVault: hybrid handshake failed'));
        });
      return;
    }

    if (m.type === 'metadata') {
      if (!Array.isArray(m.files)) {
        throw new Error('PeerVault: metadata message has no files array');
      }
      const files = m.files as FileMetadata[];
      // Sink creation is async (File System Access API), so prepare the
      // assemblers on the serialised queue to keep chunk ordering intact.
      this.queue = this.queue
        .then(() => this.setupFiles(files))
        .catch((err) => {
          if (this.isCancelled) return;
          const error = toError(err, 'PeerVault: failed to prepare files');
          this.emit('error', error);
          this.failConnect(error);
        });
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
          if (this.isCancelled) return;
          this.emit('error', toError(err, 'PeerVault: failed to finalise file'));
        });
    }
  }

  private async setupFiles(files: FileMetadata[]): Promise<void> {
    const assemblers = new Map<number, FileAssembler>();

    for (let i = 0; i < files.length; i++) {
      let sink: WritableFileSink | undefined;
      if (this.sinkFactory) {
        try {
          sink = (await this.sinkFactory(files[i], i)) ?? undefined;
        } catch (err) {
          // Fall back to in-memory assembly if the picker is cancelled or the
          // sink cannot be opened; the transfer itself remains valid.
          this.emit('error', toError(err, 'PeerVault: failed to open disk sink'));
        }
      }
      assemblers.set(i, new FileAssembler(files[i], this.cryptoEngine, sink));
    }

    this.assemblers = assemblers;
    this.metadataList = files;
    this.clearConnectTimer();
    if (this.resolveConnect) {
      const resolve = this.resolveConnect;
      this.resolveConnect = null;
      this.rejectConnect = null;
      resolve(this.metadataList);
    }
  }

  private enqueueChunk(buffer: ArrayBuffer) {
    this.queue = this.queue
      .then(() => this.handleChunk(buffer))
      .catch((err) => {
        if (this.isCancelled) return;
        this.emit('error', toError(err, 'PeerVault: failed to process chunk'));
      });
  }

  private async handleChunk(buffer: ArrayBuffer) {
    if (this.isCancelled) return;
    if (buffer.byteLength < CHUNK_HEADER_BYTES) {
      throw new Error(
        `PeerVault: chunk frame too short (${buffer.byteLength} bytes, need at least ${CHUNK_HEADER_BYTES})`
      );
    }
    const view = new DataView(buffer);

    const type = view.getUint8(0);
    if (type !== 1) {
      throw new Error(`PeerVault: unsupported binary frame type ${type}`);
    }

    const fileIndex = view.getUint32(1, true);
    const chunkIndex = view.getUint32(5, true);
    const iv = new Uint8Array(buffer, 9, 12);
    const ciphertext = buffer.slice(CHUNK_HEADER_BYTES);
    // Authenticate the entire 21-byte frame header, including the IV.
    const additionalData = new Uint8Array(buffer.slice(0, CHUNK_HEADER_BYTES));

    const assembler = this.assemblers.get(fileIndex);
    if (!assembler) {
      throw new Error(`PeerVault: chunk for unknown fileIndex ${fileIndex}`);
    }

    await assembler.addChunk(chunkIndex, iv, ciphertext, additionalData);
    // WebCrypto cannot be aborted. Discard its result if cancel() happened
    // while decrypting, before it can publish progress or create a file URL.
    if (this.isCancelled) return;

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
    if (this.isCancelled) return;
    if (this.emittedFiles.has(fileIndex)) return;
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler || !assembler.isComplete()) return;
    if (!this.completeSignalled.has(fileIndex)) return;

    const receivedFile = assembler.streaming
      ? await assembler.finishStreaming()
      : assembler.assemble();
    this.emittedFiles.add(fileIndex);
    this.emit('file_complete', receivedFile);
    if (this.isCancelled) return; // A file_complete listener may cancel.

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
    if (this.isCancelled) return;
    this.isCancelled = true;
    this.isDownloading = false;
    this.pendingChunks = [];
    for (const assembler of this.assemblers.values()) void assembler.abort();
    this.assemblers.clear();
    this.metadataList = [];
    this.completeSignalled.clear();
    this.failConnect(new Error('PeerVault: transfer cancelled'));
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }

  private throwIfCancelled(): void {
    if (this.isCancelled) throw new Error('PeerVault: transfer cancelled');
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
