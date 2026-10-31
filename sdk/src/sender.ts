// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 Soumya Debnath

import { EventEmitter } from './events';
import { SignalingClient } from './signaling-client';
import { PeerConnection } from './peer-connection';
import { CryptoEngine } from './crypto-engine';
import { HybridHandshake } from './hybrid-handshake';
import { FileChunker, CHUNK_SIZE } from './file-chunker';
import { FileMetadata, TransferProgress, SignalingMessage } from './types';

interface SenderEvents {
  recipient_connected: void;
  progress: TransferProgress;
  complete: void;
  error: Error;
}

export interface SenderOptions {
  /**
   * ICE servers for the peer connection. Defaults to public STUN only, which
   * cannot traverse symmetric or carrier-grade NAT. Supply a TURN entry here for
   * reliable connectivity; this was previously impossible without forking, because
   * PeerConnection is constructed internally.
   */
  iceServers?: RTCIceServer[];
  /**
   * Milliseconds to wait for the relay to acknowledge create_room before
   * createShareLink() rejects. Without this, a silent or overloaded relay leaves
   * the promise pending forever. Pass 0 to disable.
   */
  createRoomTimeoutMs?: number;
  /**
   * Milliseconds the send loop will wait for a stalled peer to drain its buffer
   * before aborting with an error. Pass 0 to wait indefinitely (previous behaviour).
   */
  stallTimeoutMs?: number;
  /**
   * Run the ML-KEM-768 + P-256 hybrid handshake before sending metadata and
   * chunks. Default true. Set false only for interoperability with older peers.
   */
  hybridHandshake?: boolean;
  /** Milliseconds to wait for the receiver's hybrid hello/ready. Default 15s. */
  handshakeTimeoutMs?: number;
}

const MAX_BUFFERED_BYTES = 1024 * 1024 * 16;

export class PeerVaultSender extends EventEmitter<SenderEvents> {
  private signaling: SignalingClient;
  private peerConnection: PeerConnection | null = null;
  private cryptoEngine: CryptoEngine;
  private files: File[] = [];
  private roomId: string | null = null;
  private dc: RTCDataChannel | null = null;
  private isCancelled = false;
  private shareLink: string | null = null;
  private shareLinkPromise: Promise<string> | null = null;
  private createRoomTimeoutMs: number;
  private stallTimeoutMs: number;
  private iceServers?: RTCIceServer[];
  private hybridHandshakeEnabled: boolean;
  private handshakeTimeoutMs: number;
  private handshake: HybridHandshake | null = null;
  private handshakeInit: Promise<HybridHandshake> | null = null;
  private handshakePromise: Promise<void> = Promise.resolve();
  private handshakeResolve: (() => void) | null = null;
  private handshakeReject: ((error: Error) => void) | null = null;
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(signalingUrl: string, options?: SenderOptions) {
    super();
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
    this.iceServers = options?.iceServers;
    this.createRoomTimeoutMs = options?.createRoomTimeoutMs ?? 30_000;
    this.stallTimeoutMs = options?.stallTimeoutMs ?? 120_000;
    this.hybridHandshakeEnabled = options?.hybridHandshake ?? true;
    this.handshakeTimeoutMs = options?.handshakeTimeoutMs ?? 15_000;

    this.signaling.on('message', (msg: SignalingMessage) => {
      if (msg.type === 'room_created' && msg.roomId) {
        this.roomId = msg.roomId;
      } else if (msg.type === 'peer_joined') {
        this.emit('recipient_connected', undefined);
        if (this.peerConnection) {
          this.peerConnection.initiateConnection();
        }
      } else if (msg.type === 'error') {
        const detail =
          msg.payload && typeof msg.payload === 'object' && 'message' in msg.payload
            ? String((msg.payload as { message?: unknown }).message)
            : 'unknown relay error';
        this.emit('error', new Error(`PeerVault relay reported an error: ${detail}`));
      }
    });

    this.signaling.on('error', (err: unknown) =>
      this.emit('error', toError(err, 'PeerVault: signaling connection error'))
    );
  }

  addFiles(files: File[]): void {
    if (!Array.isArray(files)) throw new TypeError('addFiles expects an array of File objects');
    this.files.push(...files);
  }

  /**
   * Creates the room and returns `roomId#keyBase64Url`.
   *
   * Idempotent: calling it twice previously generated a second AES key and
   * silently invalidated any link that had already been shared, so repeat calls
   * now resolve with the same link.
   */
  async createShareLink(): Promise<string> {
    if (this.shareLink) return this.shareLink;
    if (this.shareLinkPromise) return this.shareLinkPromise;

    this.shareLinkPromise = this.doCreateShareLink();
    try {
      this.shareLink = await this.shareLinkPromise;
      return this.shareLink;
    } catch (err) {
      this.shareLinkPromise = null;
      throw err;
    }
  }

  private async doCreateShareLink(): Promise<string> {
    await this.signaling.connect();

    return new Promise<string>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const done = (fn: () => void) => {
        if (timer) clearTimeout(timer);
        this.signaling.off('message', handleRoomCreated);
        fn();
      };

      const handleRoomCreated = async (msg: SignalingMessage) => {
        if (msg.type === 'error') {
          const detail =
            msg.payload && typeof msg.payload === 'object' && 'message' in msg.payload
              ? String((msg.payload as { message?: unknown }).message)
              : 'unknown relay error';
          done(() => reject(new Error(`PeerVault relay rejected create_room: ${detail}`)));
          return;
        }
        if (msg.type !== 'room_created') return;

        try {
          const keyBase64Url = await this.cryptoEngine.generateKey();
          this.setupPeerConnection();
          // Format: protocol://host/r/{roomId}#{base64url_key}
          // The SDK returns roomId#key; the consumer appends it to their base URL.
          const roomId = msg.roomId ?? this.roomId;
          done(() => resolve(`${roomId}#${keyBase64Url}`));
        } catch (err) {
          done(() => reject(toError(err, 'PeerVault: failed to create share link')));
        }
      };

      if (this.createRoomTimeoutMs > 0) {
        timer = setTimeout(() => {
          done(() =>
            reject(
              new Error(
                `PeerVault: relay did not acknowledge create_room within ${this.createRoomTimeoutMs}ms`
              )
            )
          );
        }, this.createRoomTimeoutMs);
      }

      this.signaling.on('message', handleRoomCreated);
      this.signaling.send({ type: 'create_room' });
    });
  }

  private setupPeerConnection() {
    this.peerConnection = new PeerConnection(this.signaling, true, { iceServers: this.iceServers });

    this.peerConnection.on('datachannel_open', (dc: RTCDataChannel) => {
      this.dc = dc;
      dc.onmessage = (event: MessageEvent) => {
        if (typeof event.data === 'string') this.handleControlMessage(event.data);
      };
      this.handshakePromise = this.beginHybridHandshake();
      void this.startTransfer();
    });

    this.peerConnection.on('error', (err: Error) => {
      this.emit('error', err);
    });
  }

  private async beginHybridHandshake(): Promise<void> {
    if (!this.hybridHandshakeEnabled) return;

    this.handshakeInit = HybridHandshake.create('sender', this.cryptoEngine.getRawKey());
    const handshake = await this.handshakeInit;
    this.handshake = handshake;

    await new Promise<void>((resolve, reject) => {
      this.handshakeResolve = resolve;
      this.handshakeReject = reject;
      if (this.handshakeTimeoutMs > 0) {
        this.handshakeTimer = setTimeout(() => {
          this.failHandshake(
            new Error(
              `PeerVault: hybrid handshake timed out after ${this.handshakeTimeoutMs}ms`
            )
          );
        }, this.handshakeTimeoutMs);
      }
    });
  }

  private handleControlMessage(raw: string): void {
    let message: { type?: unknown };
    try {
      message = JSON.parse(raw) as { type?: unknown };
    } catch {
      this.emit('error', new Error('PeerVault: peer sent an invalid JSON control message'));
      return;
    }

    if (message.type === 'pv-hybrid-hello') {
      void this.handleHybridHello(raw);
    } else if (message.type === 'pv-hybrid-ready') {
      void this.handleHybridReady(raw);
    }
  }

  private async handleHybridHello(raw: string): Promise<void> {
    try {
      const handshake =
        this.handshake ?? (this.handshakeInit ? await this.handshakeInit : null);
      if (!handshake) throw new Error('PeerVault: received a hybrid hello before setup');
      const finish = await handshake.acceptHello(raw);
      await this.cryptoEngine.deriveHybridTransferKey(handshake.session, handshake.transcript);
      if (!this.dc || this.dc.readyState !== 'open') {
        throw new Error('DataChannel closed during the hybrid handshake');
      }
      this.dc.send(finish);
    } catch (error) {
      this.failHandshake(toError(error, 'PeerVault: hybrid handshake failed'));
    }
  }

  private async handleHybridReady(raw: string): Promise<void> {
    try {
      const handshake =
        this.handshake ?? (this.handshakeInit ? await this.handshakeInit : null);
      if (!handshake) throw new Error('PeerVault: received hybrid ready before setup');
      await handshake.acceptReady(raw);
      this.resolveHandshake();
    } catch (error) {
      this.failHandshake(toError(error, 'PeerVault: hybrid key confirmation failed'));
    }
  }

  private resolveHandshake(): void {
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    const resolve = this.handshakeResolve;
    this.handshakeResolve = null;
    this.handshakeReject = null;
    if (resolve) resolve();
  }

  private failHandshake(error: Error): void {
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    const reject = this.handshakeReject;
    this.handshakeResolve = null;
    this.handshakeReject = null;
    if (reject) reject(error);
    else this.emit('error', error);
  }

  private async startTransfer() {
    if (!this.dc) return;

    try {
      await this.handshakePromise;

      // Chunk counts must come from the chunker: a zero-byte file still sends one
      // (empty) chunk, so Math.ceil(0 / CHUNK_SIZE) === 0 left the receiver waiting
      // for a chunk count it could never reconcile.
      const chunkers = this.files.map((f) => new FileChunker(f));
      const metadataList: FileMetadata[] = this.files.map((f, i) => ({
        name: f.name,
        size: f.size,
        mime: f.type,
        chunks: chunkers[i].totalChunks,
      }));

      this.dc.send(
        JSON.stringify({
          type: 'metadata',
          files: metadataList,
        })
      );

      for (let i = 0; i < this.files.length; i++) {
        if (this.isCancelled) break;
        await this.transferFile(i, chunkers[i], this.files[i].size, metadataList[i].chunks);
      }

      if (!this.isCancelled) {
        this.emit('complete', undefined);
      }
    } catch (err: unknown) {
      this.emit('error', toError(err, 'PeerVault: transfer failed'));
    }
  }

  private async transferFile(
    fileIndex: number,
    chunker: FileChunker,
    totalBytes: number,
    totalChunks: number
  ) {
    let chunkIndex = 0;
    let bytesTransferred = 0;

    while (!this.isCancelled) {
      const chunkData = await chunker.getNextChunk();
      if (chunkData === null) break;

      // Binary message format:
      // [1 byte: type (1)] [4 bytes: fileIndex] [4 bytes: chunkIndex] [12 bytes: IV] [rest: ciphertext]
      // The full 21-byte header, including the IV, is authenticated as AES-GCM
      // additional data. A tampered file index, chunk index, or IV therefore
      // fails decryption before anything is written.
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const header = new Uint8Array(21);
      const headerView = new DataView(header.buffer);
      headerView.setUint8(0, 1);
      headerView.setUint32(1, fileIndex, true); // Little endian
      headerView.setUint32(5, chunkIndex, true);
      header.set(iv, 9);

      const { ciphertext } = await this.cryptoEngine.encryptChunk(chunkData, header, iv);

      const buffer = new ArrayBuffer(21 + ciphertext.byteLength);
      const u8 = new Uint8Array(buffer);
      u8.set(header, 0);
      u8.set(new Uint8Array(ciphertext), 21);

      await this.waitForDrain();

      if (this.isCancelled) return;
      if (!this.dc || this.dc.readyState !== 'open') throw new Error('DataChannel closed');

      this.dc.send(buffer);

      bytesTransferred += chunkData.byteLength;
      this.emit('progress', {
        fileIndex,
        chunkIndex,
        totalChunks,
        bytesTransferred,
        totalBytes,
      });

      chunkIndex++;
    }

    if (!this.isCancelled && this.dc && this.dc.readyState === 'open') {
      this.dc.send(
        JSON.stringify({
          type: 'complete',
          fileIndex,
        })
      );
    }
  }

  /**
   * Waits for the data channel send buffer to drain. Bounded by stallTimeoutMs and
   * aborted by cancel() or a closing channel, so a stalled peer surfaces an error
   * instead of halting the transfer silently and forever.
   */
  private async waitForDrain(): Promise<void> {
    const start = Date.now();
    while (this.dc && this.dc.bufferedAmount > MAX_BUFFERED_BYTES) {
      if (this.isCancelled) return;
      if (this.dc.readyState !== 'open') throw new Error('DataChannel closed while draining');
      if (this.stallTimeoutMs > 0 && Date.now() - start > this.stallTimeoutMs) {
        throw new Error(
          `PeerVault: peer stalled — ${this.dc.bufferedAmount} bytes still buffered after ${this.stallTimeoutMs}ms`
        );
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  cancel(): void {
    this.isCancelled = true;
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
}

function toError(e: unknown, fallback: string): Error {
  if (e instanceof Error) return e;
  if (typeof e === 'string') return new Error(e);
  // WebSocket handlers deliver a DOM Event, which has no .message.
  if (e && typeof e === 'object' && 'type' in e) {
    return new Error(`${fallback} (${String((e as { type: unknown }).type)})`);
  }
  return new Error(fallback);
}

export { CHUNK_SIZE };
