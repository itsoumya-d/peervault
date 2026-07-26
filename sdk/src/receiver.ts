// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com | +91 7031648617

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

export class PeerVaultReceiver extends EventEmitter<ReceiverEvents> {
  private signaling: SignalingClient;
  private peerConnection: PeerConnection | null = null;
  private cryptoEngine: CryptoEngine;
  private roomId: string;
  private keyBase64Url: string;
  private dc: RTCDataChannel | null = null;
  
  private metadataList: FileMetadata[] = [];
  private assemblers: Map<number, FileAssembler> = new Map();
  private isDownloading = false;
  private resolveConnect: ((metadata: FileMetadata[]) => void) | null = null;

  constructor(signalingUrl: string, shareLinkData: string) {
    super();
    // shareLinkData expected to be roomId#key
    const [roomId, key] = shareLinkData.split('#');
    if (!roomId || !key) throw new Error('Invalid share link data');
    
    this.roomId = roomId;
    this.keyBase64Url = key;
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
  }

  async connect(): Promise<FileMetadata[]> {
    await this.cryptoEngine.importKey(this.keyBase64Url);
    await this.signaling.connect();

    return new Promise((resolve, reject) => {
      this.resolveConnect = resolve;
      
      this.peerConnection = new PeerConnection(this.signaling, false);
      
      this.peerConnection.on('datachannel_open', (dc: RTCDataChannel) => {
        this.dc = dc;
        this.setupDataChannel(dc);
      });

      this.peerConnection.on('error', (err: Error) => {
        this.emit('error', err);
        reject(err);
      });

      this.signaling.send({
        type: 'join_room',
        roomId: this.roomId
      });
    });
  }

  async download(): Promise<void> {
    if (!this.metadataList.length) throw new Error('No metadata available to download');
    this.isDownloading = true;
    
    // Send a ready signal back if we wanted, but the sender 
    // will just start sending once DC is open. 
    // We are passively receiving.
  }

  private setupDataChannel(dc: RTCDataChannel) {
    dc.onmessage = async (event) => {
      if (typeof event.data === 'string') {
        const msg = JSON.parse(event.data);
        if (msg.type === 'metadata') {
          this.metadataList = msg.files;
          msg.files.forEach((meta: FileMetadata, i: number) => {
            this.assemblers.set(i, new FileAssembler(meta, this.cryptoEngine));
          });
          if (this.resolveConnect) {
            this.resolveConnect(this.metadataList);
            this.resolveConnect = null;
          }
        } else if (msg.type === 'complete') {
          const assembler = this.assemblers.get(msg.fileIndex);
          if (assembler && assembler.isComplete()) {
            const receivedFile = assembler.assemble();
            this.emit('file_complete', receivedFile);
          }
          
          let allComplete = true;
          for (let i = 0; i < this.metadataList.length; i++) {
            if (!this.assemblers.get(i)?.isComplete()) {
              allComplete = false;
              break;
            }
          }
          if (allComplete) {
            this.emit('complete', undefined);
          }
        }
      } else if (event.data instanceof ArrayBuffer && this.isDownloading) {
        await this.handleChunk(event.data);
      }
    };
  }

  private async handleChunk(buffer: ArrayBuffer) {
    const view = new DataView(buffer);
    const u8 = new Uint8Array(buffer);
    
    const type = view.getUint8(0);
    if (type !== 1) return; // Only process chunk types

    const fileIndex = view.getUint32(1, true);
    const chunkIndex = view.getUint32(5, true);
    const iv = new Uint8Array(buffer, 9, 12);
    const ciphertext = buffer.slice(21);

    const assembler = this.assemblers.get(fileIndex);
    if (assembler) {
      await assembler.addChunk(chunkIndex, iv, ciphertext);
      
      const meta = this.metadataList[fileIndex];
      this.emit('progress', {
        fileIndex,
        chunkIndex,
        totalChunks: meta.chunks,
        bytesTransferred: Math.min((chunkIndex + 1) * 64 * 1024, meta.size),
        totalBytes: meta.size
      });
    }
  }

  cancel(): void {
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
}
