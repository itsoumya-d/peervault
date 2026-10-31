interface FileMetadata {
    name: string;
    size: number;
    mime: string;
    chunks: number;
}
interface ReceivedFile extends FileMetadata {
    /** Present for in-memory assembly. Absent when the file was streamed to disk. */
    blob?: Blob;
    /** Present for in-memory assembly. Absent when the file was streamed to disk. */
    url?: string;
    /** True when the receiver wrote chunks directly to a user-selected file. */
    streamed?: boolean;
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
    /**
     * Run the ML-KEM-768 + P-256 hybrid handshake before sending metadata and
     * chunks. Default true. Set false only for interoperability with older peers.
     */
    hybridHandshake?: boolean;
    /** Milliseconds to wait for the receiver's hybrid hello/ready. Default 15s. */
    handshakeTimeoutMs?: number;
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
    private hybridHandshakeEnabled;
    private handshakeTimeoutMs;
    private handshake;
    private handshakeInit;
    private handshakePromise;
    private handshakeResolve;
    private handshakeReject;
    private handshakeTimer;
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
    private beginHybridHandshake;
    private handleControlMessage;
    private handleHybridHello;
    private handleHybridReady;
    private resolveHandshake;
    private failHandshake;
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

/**
 * PeerVault ships a FIPS 203 ML-KEM-768 implementation compiled from Rust to
 * WebAssembly (`src/mlkem.ts`). The protocol runs a hybrid handshake that mixes
 * ML-KEM-768, P-256 ECDH and HKDF-SHA256; see `hybrid-handshake.ts`.
 *
 * The helpers below cover the classical and HKDF primitives used by that
 * handshake. `probeMLKEM()` remains available for callers that want to know
 * whether the host platform's WebCrypto exposes its own ML-KEM implementation.
 */
interface CryptoCapabilities {
    /** Whether PeerVault's bundled ML-KEM-768 wasm implementation can run here. */
    supportsMLKEM: boolean;
    supportsECDH: boolean;
    supportsAESGCM: boolean;
    /** True only after a hybrid ML-KEM-768 + P-256 handshake has completed. */
    usesPostQuantumKeyExchange: boolean;
}
declare class PQCrypto {
    /**
     * Reports whether PeerVault's bundled ML-KEM-768 wasm core can execute here.
     * This is about the implementation PeerVault actually uses, not a claim about
     * the host platform's WebCrypto surface. Use {@link probeMLKEM} for that.
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
     * pair when WebCrypto exposes one.
     *
     * PeerVault's default handshake does not use this platform key pair; it uses
     * the bundled wasm ML-KEM implementation in `hybrid-handshake.ts`. This helper
     * is retained for callers building their own constructions.
     */
    static generateHybridKeyPair(): Promise<{
        ecdh: CryptoKeyPair;
        mlkem?: CryptoKeyPair;
    }>;
    /**
     * Derives the hybrid session secret.
     *
     * With no `mlkemSharedSecret`, this is the legacy plain P-256 ECDH behaviour.
     * With an ML-KEM shared secret, it concatenates the ECDH and KEM secrets and
     * runs HKDF-SHA256 with the supplied transcript hash as salt.
     */
    static hybridKeyExchange(localPrivate: CryptoKey, remotePublic: CryptoKey, mlkemSharedSecret?: ArrayBuffer, transcriptHash?: ArrayBuffer): Promise<ArrayBuffer>;
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
     * @deprecated Hybrid key exchange is configured on PeerVaultSender and
     * PeerVaultReceiver (`hybridHandshake`, default true). This flag is retained
     * for API compatibility and has no effect.
     */
    useHybridKeyExchange?: boolean;
}
declare class CryptoEngine {
    private key;
    private localKeyPair;
    private rawKey;
    private hybridEstablished;
    /**
     * @deprecated Always false. Hybrid handshakes are configured on the sender and
     * receiver (default true); check `getCapabilities().usesPostQuantumKeyExchange`
     * after connecting to see whether one actually completed.
     */
    readonly useHybridKeyExchange: boolean;
    constructor(_options?: CryptoEngineOptions);
    /** Reports the primitives this engine can run and whether a hybrid session is live. */
    getCapabilities(): CryptoCapabilities;
    generateKey(): Promise<string>;
    importKey(base64UrlKey: string): Promise<void>;
    /** The share-link key bytes. Used as the pre-shared authentication secret. */
    getRawKey(): Uint8Array;
    /**
     * Derives and installs the transfer key:
     * HKDF-SHA256(share_link_key || hybrid_session, salt = transcript_hash,
     *             info = "peervault/file-key/v1")
     */
    deriveHybridTransferKey(sessionKey: Uint8Array, transcriptHash: Uint8Array): Promise<void>;
    getLocalPublicKey(): Promise<string>;
    negotiateKey(remotePeerPublicKey: string): Promise<void>;
    encryptChunk(data: ArrayBuffer, additionalData?: Uint8Array, providedIv?: Uint8Array): Promise<{
        iv: Uint8Array;
        ciphertext: ArrayBuffer;
    }>;
    /**
     * Encrypt an application control message (for example a datamesh sync
     * payload). The 12-byte IV is prepended and bound as AES-GCM AAD.
     */
    encryptMessage(message: string): Promise<ArrayBuffer>;
    /** Decrypt a control message produced by encryptMessage(). */
    decryptMessage(buffer: ArrayBuffer): Promise<string>;
    decryptChunk(iv: Uint8Array, ciphertext: ArrayBuffer, additionalData?: Uint8Array): Promise<ArrayBuffer>;
    private bufferToBase64Url;
    private base64UrlToBuffer;
}

/** Hard ceiling on the declared chunk count, to bound receiver allocation. */
declare const MAX_CHUNKS = 1000000;
/** Minimal sink implemented by FileSystemWritableFileStream or OPFS adapters. */
interface WritableFileSink {
    writeChunk(index: number, data: ArrayBuffer): Promise<void>;
    close(): Promise<void>;
}
/**
 * Open a user-selected file and stream decrypted chunks into it at their byte
 * offsets. Must be called from a user gesture (the File System Access API
 * requirement). Returns null where the API is unavailable (Firefox/Safari).
 */
declare function createFileSystemSink(suggestedName: string, chunkSize?: number): Promise<WritableFileSink | null>;
declare class FileAssembler {
    private chunks;
    private receivedIndices;
    private receivedChunks;
    private receivedBytes;
    private metadata;
    private cryptoEngine;
    private sink?;
    constructor(metadata: FileMetadata, cryptoEngine: CryptoEngine, sink?: WritableFileSink);
    /**
     * Decrypt and store one chunk. Resolves true once every distinct chunk index
     * in [0, metadata.chunks) has been received.
     *
     * `additionalData` must be the full 21-byte frame header (type, fileIndex,
     * chunkIndex, IV). Binding it to AES-GCM prevents a valid ciphertext from
     * being replayed under a different file, chunk index, or IV.
     *
     * Duplicate and out-of-range indices are rejected rather than counted. When a
     * sink is attached, plaintext is written straight to disk and never retained
     * in memory.
     */
    addChunk(index: number, iv: Uint8Array, ciphertext: ArrayBuffer, additionalData?: Uint8Array): Promise<boolean>;
    isComplete(): boolean;
    /** True when chunks are being written directly to a file sink. */
    get streaming(): boolean;
    /** Distinct chunks accepted so far, plus decrypted byte total. */
    get progress(): {
        received: number;
        total: number;
        bytes: number;
    };
    assemble(): ReceivedFile;
    /**
     * Close the disk sink and return metadata for the completed file. No Blob or
     * object URL is created, so peak memory stays at one chunk.
     */
    finishStreaming(): Promise<ReceivedFile>;
    /** Close an open sink without publishing the file (cancellation path). */
    abort(): Promise<void>;
    private assertByteLength;
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
declare class PeerVaultReceiver extends EventEmitter<ReceiverEvents> {
    private signaling;
    private peerConnection;
    private cryptoEngine;
    private roomId;
    private keyBase64Url;
    private dc;
    private connectTimeoutMs;
    private iceServers?;
    private sinkFactory?;
    private hybridHandshakeEnabled;
    private handshakeTimeoutMs;
    private handshake;
    private handshakeTimer;
    private metadataList;
    private assemblers;
    private isDownloading;
    private isCancelled;
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
    private beginHybridHandshake;
    private handleHybridFinish;
    private handleControlMessage;
    private setupFiles;
    private enqueueChunk;
    private handleChunk;
    private tryFinishFile;
    cancel(): void;
    private throwIfCancelled;
}

declare const MLKEM768_PUBLIC_KEY_BYTES = 1184;
declare const MLKEM768_SECRET_KEY_BYTES = 2400;
declare const MLKEM768_CIPHERTEXT_BYTES = 1088;
declare const MLKEM768_SHARED_SECRET_BYTES = 32;
declare const MLKEM768_SEED_BYTES = 64;
interface MlKem768KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
interface MlKem768Encapsulation {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}
interface MlKem768Decapsulation {
    sharedSecret: Uint8Array;
    /** False when decapsulation hit the FIPS 203 implicit-rejection path. */
    valid: boolean;
}
declare const textEncoder: TextEncoder;
declare class MlKem768 {
    private readonly exports;
    private readonly workspaceOffset;
    private readonly seedOffset;
    private readonly publicKeyOffset;
    private readonly secretKeyOffset;
    private readonly messageOffset;
    private readonly ciphertextOffset;
    private readonly sharedSecretOffset;
    private constructor();
    static load(): Promise<MlKem768>;
    private static instantiate;
    private view;
    generateKeyPair(seed?: Uint8Array): MlKem768KeyPair;
    encapsulate(publicKey: Uint8Array, message?: Uint8Array): MlKem768Encapsulation;
    decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): MlKem768Decapsulation;
}

type HybridRole = 'sender' | 'receiver';
interface HybridHandshakeJSON {
    type: string;
    v: number;
    [key: string]: unknown;
}
declare function bytesToBase64Url(bytes: Uint8Array): string;
declare function base64UrlToBytes(value: string): Uint8Array;
declare class HybridHandshake {
    private readonly role;
    private readonly shareLinkKey;
    private readonly kem;
    private ecdhKeyPair;
    private ecdhPublic;
    private mlkemKeyPair;
    private mlkemPublic;
    private nonce;
    private helloCanonical;
    private sessionKeyBytes;
    private transcriptHashBytes;
    private confirmB64;
    private ready;
    private constructor();
    static create(role: HybridRole, shareLinkKey: Uint8Array): Promise<HybridHandshake>;
    get isReady(): boolean;
    get session(): Uint8Array;
    get transcript(): Uint8Array;
    /** Receiver -> sender. */
    createHello(): Promise<string>;
    /** Sender receives the hello and returns the finish message. */
    acceptHello(raw: string): Promise<string>;
    /** Receiver accepts the finish message and returns the ready message. */
    acceptFinish(raw: string): Promise<string>;
    /** Sender accepts the receiver's key-confirmation message. */
    acceptReady(raw: string): Promise<void>;
    private establish;
}

interface MeshVector {
    id: string;
    embedding: Float32Array;
    metadata?: Record<string, unknown>;
    version: number;
    origin: string;
}
interface MeshMemory {
    id: string;
    text: string;
    weight: number;
    version: number;
    origin: string;
}
interface MeshState {
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
interface MeshMessage {
    type: "datamesh-hello" | "datamesh-state";
    state: MeshState;
}
interface MeshTransport {
    send(data: string): void;
}
declare function encodeFloat32(vector: Float32Array): string;
declare function decodeFloat32(value: string): Float32Array;
declare class MeshNode {
    readonly nodeId: string;
    private clock;
    private vectors;
    private memories;
    constructor(nodeId: string);
    upsertVector(id: string, embedding: Float32Array, metadata?: Record<string, unknown>): MeshVector;
    upsertMemory(id: string, text: string, weight: number): MeshMemory;
    getVector(id: string): MeshVector | undefined;
    getMemory(id: string): MeshMemory | undefined;
    get stats(): {
        vectors: number;
        memories: number;
        clock: number;
    };
    serialize(): MeshState;
    apply(state: MeshState): void;
    /** Send our full state; the peer replies with its state on hello. */
    startSync(transport: MeshTransport): void;
    /** Wire this to the DataChannel onmessage handler. */
    handleMessage(raw: string, transport: MeshTransport): void;
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

export { CHUNK_SIZE, type CryptoCapabilities, CryptoEngine, type CryptoEngineOptions, DEFAULT_ICE_SERVERS, EventEmitter, FileAssembler, FileChunker, type FileMetadata, HybridHandshake, type HybridHandshakeJSON, type HybridRole, MAX_CHUNKS, MLKEM768_CIPHERTEXT_BYTES, MLKEM768_PUBLIC_KEY_BYTES, MLKEM768_SECRET_KEY_BYTES, MLKEM768_SEED_BYTES, MLKEM768_SHARED_SECRET_BYTES, type MeshMemory, type MeshMessage, MeshNode, type MeshState, type MeshTransport, type MeshVector, MlKem768, type MlKem768Decapsulation, type MlKem768Encapsulation, type MlKem768KeyPair, PQCrypto, PeerConnection, type PeerConnectionOptions, PeerVaultReceiver, PeerVaultSender, type ReceivedFile, type ReceiverOptions, type SenderOptions, SignalingClient, type SignalingMessage, type TransferProgress, type WritableFileSink, base64UrlToBytes, bytesToBase64Url, createFileSystemSink, decodeFloat32, encodeFloat32, textEncoder };
