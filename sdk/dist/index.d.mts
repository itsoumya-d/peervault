interface FileMetadata {
    name: string;
    size: number;
    mime: string;
    chunks: number;
}
interface ReceivedFile extends FileMetadata {
    blob: Blob;
    url: string;
}
interface TransferProgress {
    fileIndex: number;
    chunkIndex: number;
    totalChunks: number;
    bytesTransferred: number;
    totalBytes: number;
}
interface SignalingMessage {
    type: string;
    roomId?: string;
    payload?: any;
}

declare class EventEmitter<T extends Record<string, any>> {
    private listeners;
    on<K extends keyof T>(event: K, callback: (event: T[K]) => void): void;
    off<K extends keyof T>(event: K, callback: (event: T[K]) => void): void;
    emit<K extends keyof T>(event: K, data: T[K]): void;
}

interface SenderEvents {
    recipient_connected: void;
    progress: TransferProgress;
    complete: void;
    error: Error;
}
declare class PeerVaultSender extends EventEmitter<SenderEvents> {
    private signaling;
    private peerConnection;
    private cryptoEngine;
    private files;
    private roomId;
    private dc;
    private isCancelled;
    constructor(signalingUrl: string);
    addFiles(files: File[]): void;
    createShareLink(): Promise<string>;
    private setupPeerConnection;
    private startTransfer;
    private transferFile;
    cancel(): void;
}

interface ReceiverEvents {
    progress: TransferProgress;
    file_complete: ReceivedFile;
    complete: void;
    error: Error;
}
declare class PeerVaultReceiver extends EventEmitter<ReceiverEvents> {
    private signaling;
    private peerConnection;
    private cryptoEngine;
    private roomId;
    private keyBase64Url;
    private dc;
    private metadataList;
    private assemblers;
    private isDownloading;
    private resolveConnect;
    constructor(signalingUrl: string, shareLinkData: string);
    connect(): Promise<FileMetadata[]>;
    download(): Promise<void>;
    private setupDataChannel;
    private handleChunk;
    cancel(): void;
}

interface CryptoCapabilities {
    supportsMLKEM: boolean;
    supportsECDH: boolean;
    supportsAESGCM: boolean;
}
declare class PQCrypto {
    static isMLKEMSupported(): boolean;
    static generateHybridKeyPair(): Promise<{
        ecdh: CryptoKeyPair;
        mlkem?: CryptoKeyPair;
    }>;
    static hybridKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey): Promise<ArrayBuffer>;
    static deriveSharedKey(sharedSecret: ArrayBuffer, salt?: ArrayBuffer, contextInfo?: string): Promise<CryptoKey>;
    static generateECDHKeyPair(): Promise<CryptoKeyPair>;
    static exportPublicKey(key: CryptoKey): Promise<string>;
    static importPublicKey(base64url: string): Promise<CryptoKey>;
    private static bufferToBase64Url;
    private static base64UrlToBuffer;
}

export { type CryptoCapabilities, type FileMetadata, PQCrypto, PeerVaultReceiver, PeerVaultSender, type ReceivedFile, type SignalingMessage, type TransferProgress };
