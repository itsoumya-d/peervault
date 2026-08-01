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

declare const CHUNK_SIZE: number;
declare class FileChunker {
    private file;
    private offset;
    private sentEmptyFile;
    constructor(file: File);
    get totalChunks(): number;
    getNextChunk(): Promise<ArrayBuffer | null>;
    hashChunk(chunk: ArrayBuffer): Promise<ArrayBuffer>;
}

interface SenderEvents {
    recipient_connected: void;
    progress: TransferProgress;
    complete: void;
    error: Error;
}
interface SenderOptions {
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
}
declare class PeerVaultSender extends EventEmitter<SenderEvents> {
    private signaling;
    private peerConnection;
    private cryptoEngine;
    private files;
    private roomId;
    private dc;
    private isCancelled;
    private shareLink;
    private shareLinkPromise;
    private createRoomTimeoutMs;
    private stallTimeoutMs;
    private iceServers?;
    constructor(signalingUrl: string, options?: SenderOptions);
    addFiles(files: File[]): void;
    /**
     * Creates the room and returns `roomId#keyBase64Url`.
     *
     * Idempotent: calling it twice previously generated a second AES key and
     * silently invalidated any link that had already been shared, so repeat calls
     * now resolve with the same link.
     */
    createShareLink(): Promise<string>;
    private doCreateShareLink;
    private setupPeerConnection;
    private startTransfer;
    private transferFile;
    /**
     * Waits for the data channel send buffer to drain. Bounded by stallTimeoutMs and
     * aborted by cancel() or a closing channel, so a stalled peer surfaces an error
     * instead of halting the transfer silently and forever.
     */
    private waitForDrain;
    cancel(): void;
}

interface ReceiverEvents {
    progress: TransferProgress;
    file_complete: ReceivedFile;
    complete: void;
    error: Error;
}
interface ReceiverOptions {
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
declare class PeerVaultReceiver extends EventEmitter<ReceiverEvents> {
    private signaling;
    private peerConnection;
    private cryptoEngine;
    private roomId;
    private keyBase64Url;
    private dc;
    private connectTimeoutMs;
    private iceServers?;
    private metadataList;
    private assemblers;
    private isDownloading;
    private resolveConnect;
    private rejectConnect;
    private connectTimer;
    /** Chunks that arrived before download() was called, replayed once it is. */
    private pendingChunks;
    /** Serialises chunk handling so completion is never evaluated against a stale count. */
    private queue;
    /** fileIndex values for which the sender has already sent its 'complete' marker. */
    private completeSignalled;
    private emittedFiles;
    private allCompleteEmitted;
    constructor(signalingUrl: string, shareLinkData: string, options?: ReceiverOptions);
    connect(): Promise<FileMetadata[]>;
    private failConnect;
    private clearConnectTimer;
    download(): Promise<void>;
    private setupDataChannel;
    private handleControlMessage;
    private enqueueChunk;
    private handleChunk;
    private tryFinishFile;
    cancel(): void;
}

/**
 * IMPORTANT — PeerVault does NOT implement post-quantum cryptography.
 *
 * This module provides classical P-256 ECDH + HKDF-SHA-256 primitives. There is no
 * ML-KEM / Kyber lattice implementation anywhere in this package: no NTT, no
 * polynomial arithmetic mod q=3329, no CBD sampling, no FIPS 203 encapsulation.
 *
 * `supportsMLKEM` therefore reports whether ML-KEM is available on the *platform*,
 * never whether PeerVault protects your data with it. It does not. The effective
 * construction for a file transfer is a random AES-256-GCM key carried in the share
 * link's URL fragment. See the README section "Cryptography — What the Code Actually Does".
 */
interface CryptoCapabilities {
    /**
     * Whether the host platform exposes ML-KEM through WebCrypto.
     * PeerVault does not use ML-KEM even when this is true.
     */
    supportsMLKEM: boolean;
    supportsECDH: boolean;
    supportsAESGCM: boolean;
    /** Always false: PeerVault's key agreement is classical ECDH, never hybrid. */
    usesPostQuantumKeyExchange: boolean;
}
declare class PQCrypto {
    /**
     * @deprecated Misleading and never accurate. This used to return true for any
     * environment that merely exposed `crypto.subtle.generateKey`, which made every
     * modern browser report post-quantum support that does not exist. It now returns
     * false unconditionally because PeerVault performs no ML-KEM operations.
     * Use {@link probeMLKEM} if you want to know what the platform supports.
     */
    static isMLKEMSupported(): boolean;
    /**
     * Genuine runtime feature probe for platform ML-KEM support. Resolves true only
     * if a real ML-KEM-768 key pair can be generated with KEM key usages.
     *
     * ML-KEM is a key-encapsulation mechanism, so its usages are the
     * `encapsulate`/`decapsulate` family — not `deriveBits`, which is a
     * Diffie-Hellman operation and is rejected even by platforms that fully
     * implement ML-KEM.
     */
    static probeMLKEM(): Promise<boolean>;
    /**
     * Generates the classical P-256 ECDH key pair, plus a platform ML-KEM-768 key
     * pair when one is available.
     *
     * The returned `mlkem` key pair is NOT used by PeerVault: no encapsulation is
     * performed and its shared secret is never mixed into the HKDF input. It is
     * exposed only so that callers can build their own hybrid construction. Treat a
     * present `mlkem` field as "the platform has ML-KEM", never as "this transfer is
     * post-quantum secure".
     */
    static generateHybridKeyPair(): Promise<{
        ecdh: CryptoKeyPair;
        mlkem?: CryptoKeyPair;
    }>;
    /**
     * Plain P-256 ECDH derivation. Kept under its original name for compatibility.
     * Despite the name this is NOT hybrid and NOT post-quantum.
     * @see ecdhKeyExchange
     */
    static hybridKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey): Promise<ArrayBuffer>;
    /** P-256 ECDH shared secret (256 bits). Accurately named replacement. */
    static ecdhKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey): Promise<ArrayBuffer>;
    static deriveSharedKey(sharedSecret: ArrayBuffer, salt?: ArrayBuffer, contextInfo?: string): Promise<CryptoKey>;
    static generateECDHKeyPair(): Promise<CryptoKeyPair>;
    static exportPublicKey(key: CryptoKey): Promise<string>;
    static importPublicKey(base64url: string): Promise<CryptoKey>;
    private static bufferToBase64Url;
    private static base64UrlToBuffer;
}

interface CryptoEngineOptions {
    /**
     * @deprecated No hybrid key exchange exists in PeerVault. This flag is retained
     * for API compatibility and has no effect; key agreement is always classical
     * P-256 ECDH, and the file-transfer path uses a random AES-256-GCM key carried in
     * the share link fragment.
     */
    useHybridKeyExchange?: boolean;
}
declare class CryptoEngine {
    private key;
    private localKeyPair;
    /**
     * @deprecated Always false. Previously defaulted to `PQCrypto.isMLKEMSupported()`,
     * which returned true in every modern browser and told applications that a hybrid
     * post-quantum exchange was in use when none was implemented.
     */
    readonly useHybridKeyExchange: boolean;
    constructor(_options?: CryptoEngineOptions);
    /**
     * Reports what this engine actually does. `supportsMLKEM` describes the platform,
     * not PeerVault: `usesPostQuantumKeyExchange` is always false.
     */
    getCapabilities(): CryptoCapabilities;
    generateKey(): Promise<string>;
    importKey(base64UrlKey: string): Promise<void>;
    getLocalPublicKey(): Promise<string>;
    negotiateKey(remotePeerPublicKey: string): Promise<void>;
    encryptChunk(data: ArrayBuffer): Promise<{
        iv: Uint8Array;
        ciphertext: ArrayBuffer;
    }>;
    decryptChunk(iv: Uint8Array, ciphertext: ArrayBuffer): Promise<ArrayBuffer>;
    private bufferToBase64Url;
    private base64UrlToBuffer;
}

/** Hard ceiling on the declared chunk count, to bound receiver allocation. */
declare const MAX_CHUNKS = 1000000;
declare class FileAssembler {
    private chunks;
    private receivedChunks;
    private receivedBytes;
    private metadata;
    private cryptoEngine;
    constructor(metadata: FileMetadata, cryptoEngine: CryptoEngine);
    /**
     * Decrypt and store one chunk. Resolves true once every distinct chunk index
     * in [0, metadata.chunks) has been received.
     *
     * Duplicate and out-of-range indices are rejected rather than counted. Counting
     * arrivals instead of distinct indices previously allowed a duplicate chunk to
     * mask a missing one, which produced a silently corrupt file.
     */
    addChunk(index: number, iv: Uint8Array, ciphertext: ArrayBuffer): Promise<boolean>;
    isComplete(): boolean;
    /** Distinct chunks accepted so far, plus decrypted byte total. */
    get progress(): {
        received: number;
        total: number;
        bytes: number;
    };
    assemble(): ReceivedFile;
}

interface SignalingEvents {
    open: void;
    message: SignalingMessage;
    close: void;
    error: Event;
}
declare class SignalingClient extends EventEmitter<SignalingEvents> {
    private ws;
    private url;
    private connectPromise;
    constructor(url: string);
    /**
     * Opens the WebSocket. Idempotent: repeat calls return the in-flight or
     * already-resolved promise instead of replacing this.ws and orphaning the
     * previous socket.
     */
    connect(): Promise<void>;
    /** True when the socket is open and send() will actually transmit. */
    get isOpen(): boolean;
    /**
     * Sends a signaling message. Returns false if the socket is not open, so callers
     * can detect a dropped message instead of silently losing it.
     */
    send(message: SignalingMessage): boolean;
    close(): void;
}

interface PeerEvents {
    datachannel_open: RTCDataChannel;
    error: Error;
}
interface PeerConnectionOptions {
    /**
     * ICE servers for the underlying RTCPeerConnection. Defaults to three public
     * STUN servers and NO TURN server, which means symmetric and carrier-grade NAT
     * cannot be traversed. Supply a TURN server here for reliable connectivity.
     */
    iceServers?: RTCIceServer[];
}
declare const DEFAULT_ICE_SERVERS: RTCIceServer[];
declare class PeerConnection extends EventEmitter<PeerEvents> {
    private pc;
    private dc;
    private signaling;
    private isSender;
    private iceFailureReported;
    constructor(signaling: SignalingClient, isSender: boolean, options?: PeerConnectionOptions);
    private checkIceState;
    /** Current ICE/connection state, useful for diagnostics. */
    get state(): {
        ice: RTCIceConnectionState;
        connection: RTCPeerConnectionState;
    };
    private setupDataChannel;
    private handleSignalingMessage;
    initiateConnection(): Promise<void>;
    close(): void;
}

export { CHUNK_SIZE, type CryptoCapabilities, CryptoEngine, type CryptoEngineOptions, DEFAULT_ICE_SERVERS, EventEmitter, FileAssembler, FileChunker, type FileMetadata, MAX_CHUNKS, PQCrypto, PeerConnection, type PeerConnectionOptions, PeerVaultReceiver, PeerVaultSender, type ReceivedFile, type ReceiverOptions, type SenderOptions, SignalingClient, type SignalingMessage, type TransferProgress };
