import { EventEmitter } from './events';
import { SignalingClient } from './signaling-client';
import { PeerConnection } from './peer-connection';
import { CryptoEngine } from './crypto-engine';
import { FileChunker } from './file-chunker';
import { FileMetadata, TransferProgress, SignalingMessage } from './types';

interface SenderEvents {
  recipient_connected: void;
  progress: TransferProgress;
  complete: void;
  error: Error;
}

export class PeerVaultSender extends EventEmitter<SenderEvents> {
  private signaling: SignalingClient;
  private peerConnection: PeerConnection | null = null;
  private cryptoEngine: CryptoEngine;
  private files: File[] = [];
  private roomId: string | null = null;
  private dc: RTCDataChannel | null = null;
  private isCancelled = false;

  constructor(signalingUrl: string) {
    super();
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();

    this.signaling.on('message', (msg: SignalingMessage) => {
      if (msg.type === 'room_created' && msg.roomId) {
        this.roomId = msg.roomId;
      } else if (msg.type === 'peer_joined') {
        this.emit('recipient_connected', undefined);
        if (this.peerConnection) {
          this.peerConnection.initiateConnection();
        }
      }
    });

    this.signaling.on('error', (err: any) => this.emit('error', err));
  }

  addFiles(files: File[]): void {
    this.files.push(...files);
  }

  async createShareLink(): Promise<string> {
    await this.signaling.connect();
    
    return new Promise((resolve, reject) => {
      const handleRoomCreated = async (msg: SignalingMessage) => {
        if (msg.type === 'room_created') {
          this.signaling.off('message', handleRoomCreated);
          
          try {
            const keyBase64Url = await this.cryptoEngine.generateKey();
            this.setupPeerConnection();
            
            // Format: protocol://host/r/{roomId}#{base64url_key}
            // For SDK usage we just return the roomID and Key part, the consumer appends it to their base URL
            resolve(`${this.roomId}#${keyBase64Url}`);
          } catch (err) {
            reject(err);
          }
        }
      };
      
      this.signaling.on('message', handleRoomCreated);
      this.signaling.send({ type: 'create_room' });
    });
  }

  private setupPeerConnection() {
    this.peerConnection = new PeerConnection(this.signaling, true);
    
    this.peerConnection.on('datachannel_open', (dc: RTCDataChannel) => {
      this.dc = dc;
      this.startTransfer();
    });

    this.peerConnection.on('error', (err: Error) => {
      this.emit('error', err);
    });
  }

  private async startTransfer() {
    if (!this.dc) return;

    try {
      const metadataList: FileMetadata[] = this.files.map(f => ({
        name: f.name,
        size: f.size,
        mime: f.type,
        chunks: Math.ceil(f.size / (64 * 1024))
      }));

      this.dc.send(JSON.stringify({
        type: 'metadata',
        files: metadataList
      }));

      for (let i = 0; i < this.files.length; i++) {
        if (this.isCancelled) break;
        await this.transferFile(i, this.files[i], metadataList[i].chunks);
      }

      if (!this.isCancelled) {
        this.emit('complete', undefined);
      }
    } catch (err: any) {
      this.emit('error', err);
    }
  }

  private async transferFile(fileIndex: number, file: File, totalChunks: number) {
    const chunker = new FileChunker(file);
    let chunkIndex = 0;
    let totalBytes = file.size;
    let bytesTransferred = 0;

    while (!this.isCancelled) {
      const chunkData = await chunker.getNextChunk();
      if (!chunkData) break;

      const { iv, ciphertext } = await this.cryptoEngine.encryptChunk(chunkData);

      // Binary message format:
      // [1 byte: type (1)] [4 bytes: fileIndex] [4 bytes: chunkIndex] [12 bytes: IV] [rest: ciphertext]
      const buffer = new ArrayBuffer(1 + 4 + 4 + 12 + ciphertext.byteLength);
      const view = new DataView(buffer);
      const u8 = new Uint8Array(buffer);

      view.setUint8(0, 1);
      view.setUint32(1, fileIndex, true); // Little endian
      view.setUint32(5, chunkIndex, true);
      u8.set(iv, 9);
      u8.set(new Uint8Array(ciphertext), 21);

      // Wait if bufferedAmount is too high
      while (this.dc && this.dc.bufferedAmount > 1024 * 1024 * 16) {
        await new Promise(r => setTimeout(r, 50));
      }

      if (!this.dc || this.dc.readyState !== 'open') throw new Error('DataChannel closed');

      this.dc.send(buffer);
      
      bytesTransferred += chunkData.byteLength;
      this.emit('progress', {
        fileIndex,
        chunkIndex,
        totalChunks,
        bytesTransferred,
        totalBytes
      });

      chunkIndex++;
    }

    if (!this.isCancelled && this.dc) {
      this.dc.send(JSON.stringify({
        type: 'complete',
        fileIndex
      }));
    }
  }

  cancel(): void {
    this.isCancelled = true;
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
}
