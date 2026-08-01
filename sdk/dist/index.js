"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  CHUNK_SIZE: () => CHUNK_SIZE,
  CryptoEngine: () => CryptoEngine,
  DEFAULT_ICE_SERVERS: () => DEFAULT_ICE_SERVERS,
  EventEmitter: () => EventEmitter,
  FileAssembler: () => FileAssembler,
  FileChunker: () => FileChunker,
  MAX_CHUNKS: () => MAX_CHUNKS,
  PQCrypto: () => PQCrypto,
  PeerConnection: () => PeerConnection,
  PeerVaultReceiver: () => PeerVaultReceiver,
  PeerVaultSender: () => PeerVaultSender,
  SignalingClient: () => SignalingClient
});
module.exports = __toCommonJS(index_exports);

// src/events.ts
var EventEmitter = class {
  listeners = {};
  on(event, callback) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(callback);
  }
  off(event, callback) {
    if (!this.listeners[event]) return;
    this.listeners[event] = this.listeners[event].filter((cb) => cb !== callback);
  }
  emit(event, data) {
    if (!this.listeners[event]) return;
    this.listeners[event].forEach((callback) => callback(data));
  }
};

// src/signaling-client.ts
var SignalingClient = class extends EventEmitter {
  ws = null;
  url;
  connectPromise = null;
  constructor(url) {
    super();
    this.url = url;
  }
  /**
   * Opens the WebSocket. Idempotent: repeat calls return the in-flight or
   * already-resolved promise instead of replacing this.ws and orphaning the
   * previous socket.
   */
  connect() {
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = new Promise((resolve, reject) => {
      let settled = false;
      this.ws = new WebSocket(this.url);
      this.ws.onopen = () => {
        settled = true;
        this.emit("open", void 0);
        resolve();
      };
      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.emit("message", message);
        } catch (err) {
          console.error("Error parsing signaling message:", err);
        }
      };
      this.ws.onclose = () => {
        this.emit("close", void 0);
        if (!settled) {
          settled = true;
          reject(new Error(`PeerVault: signaling connection to ${this.url} closed before opening`));
        }
      };
      this.ws.onerror = (error) => {
        this.emit("error", error);
        if (!settled) {
          settled = true;
          reject(new Error(`PeerVault: could not connect to the signaling relay at ${this.url}`));
        }
      };
    });
    this.connectPromise.catch(() => {
      this.connectPromise = null;
    });
    return this.connectPromise;
  }
  /** True when the socket is open and send() will actually transmit. */
  get isOpen() {
    return !!this.ws && this.ws.readyState === WebSocket.OPEN;
  }
  /**
   * Sends a signaling message. Returns false if the socket is not open, so callers
   * can detect a dropped message instead of silently losing it.
   */
  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
      return true;
    }
    return false;
  }
  close() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connectPromise = null;
  }
};

// src/peer-connection.ts
var DEFAULT_ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
  { urls: "stun:stun.cloudflare.com:3478" }
];
var PeerConnection = class extends EventEmitter {
  pc;
  dc = null;
  signaling;
  isSender;
  iceFailureReported = false;
  constructor(signaling, isSender, options) {
    super();
    this.signaling = signaling;
    this.isSender = isSender;
    this.pc = new RTCPeerConnection({
      iceServers: options?.iceServers ?? DEFAULT_ICE_SERVERS
    });
    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.signaling.send({
          type: "signal",
          payload: { candidate: event.candidate }
        });
      }
    };
    this.pc.oniceconnectionstatechange = () => this.checkIceState();
    this.pc.onconnectionstatechange = () => this.checkIceState();
    if (this.isSender) {
      this.dc = this.pc.createDataChannel("peervault_transfer", {
        ordered: true
      });
      this.setupDataChannel(this.dc);
    } else {
      this.pc.ondatachannel = (event) => {
        this.dc = event.channel;
        this.setupDataChannel(this.dc);
      };
    }
    this.signaling.on("message", this.handleSignalingMessage.bind(this));
  }
  checkIceState() {
    const ice = this.pc.iceConnectionState;
    const conn = this.pc.connectionState;
    if (this.iceFailureReported) return;
    if (ice === "failed" || conn === "failed") {
      this.iceFailureReported = true;
      this.emit(
        "error",
        new Error(
          `PeerVault: ICE negotiation failed (iceConnectionState=${ice}, connectionState=${conn}). No TURN server is configured, so peers behind symmetric or carrier-grade NAT cannot establish a direct connection. Pass iceServers with a TURN entry to fix this.`
        )
      );
    }
  }
  /** Current ICE/connection state, useful for diagnostics. */
  get state() {
    return { ice: this.pc.iceConnectionState, connection: this.pc.connectionState };
  }
  setupDataChannel(dc) {
    dc.binaryType = "arraybuffer";
    dc.onopen = () => {
      this.emit("datachannel_open", dc);
    };
    dc.onerror = (event) => {
      const err = event.error;
      this.emit("error", err instanceof Error ? err : new Error("DataChannel error"));
    };
  }
  async handleSignalingMessage(msg) {
    if (msg.type !== "signal") return;
    try {
      const payload = msg.payload;
      if (!payload || typeof payload !== "object") return;
      if (payload.sdp) {
        await this.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
        if (payload.sdp.type === "offer") {
          const answer = await this.pc.createAnswer();
          await this.pc.setLocalDescription(answer);
          this.signaling.send({
            type: "signal",
            payload: { sdp: this.pc.localDescription }
          });
        }
      } else if (payload.candidate) {
        await this.pc.addIceCandidate(new RTCIceCandidate(payload.candidate));
      }
    } catch (err) {
      this.emit("error", err instanceof Error ? err : new Error("PeerVault: signaling error"));
    }
  }
  async initiateConnection() {
    if (!this.isSender) return;
    try {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      this.signaling.send({
        type: "signal",
        payload: { sdp: this.pc.localDescription }
      });
    } catch (err) {
      this.emit("error", err instanceof Error ? err : new Error("PeerVault: failed to create offer"));
    }
  }
  close() {
    if (this.dc) this.dc.close();
    this.pc.close();
  }
};

// src/pq-crypto.ts
var PQCrypto = class {
  /**
   * @deprecated Misleading and never accurate. This used to return true for any
   * environment that merely exposed `crypto.subtle.generateKey`, which made every
   * modern browser report post-quantum support that does not exist. It now returns
   * false unconditionally because PeerVault performs no ML-KEM operations.
   * Use {@link probeMLKEM} if you want to know what the platform supports.
   */
  static isMLKEMSupported() {
    return false;
  }
  /**
   * Genuine runtime feature probe for platform ML-KEM support. Resolves true only
   * if a real ML-KEM-768 key pair can be generated with KEM key usages.
   *
   * ML-KEM is a key-encapsulation mechanism, so its usages are the
   * `encapsulate`/`decapsulate` family — not `deriveBits`, which is a
   * Diffie-Hellman operation and is rejected even by platforms that fully
   * implement ML-KEM.
   */
  static async probeMLKEM() {
    try {
      if (typeof crypto === "undefined" || !crypto.subtle) return false;
      await crypto.subtle.generateKey({ name: "ML-KEM-768" }, true, [
        "encapsulateBits",
        "decapsulateBits"
      ]);
      return true;
    } catch {
      return false;
    }
  }
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
  static async generateHybridKeyPair() {
    const ecdh = await this.generateECDHKeyPair();
    let mlkem;
    try {
      mlkem = await crypto.subtle.generateKey(
        { name: "ML-KEM-768" },
        true,
        ["encapsulateBits", "decapsulateBits"]
      );
    } catch {
      mlkem = void 0;
    }
    return { ecdh, mlkem };
  }
  /**
   * Plain P-256 ECDH derivation. Kept under its original name for compatibility.
   * Despite the name this is NOT hybrid and NOT post-quantum.
   * @see ecdhKeyExchange
   */
  static async hybridKeyExchange(localPrivate, remotePublic) {
    return this.ecdhKeyExchange(localPrivate, remotePublic);
  }
  /** P-256 ECDH shared secret (256 bits). Accurately named replacement. */
  static async ecdhKeyExchange(localPrivate, remotePublic) {
    return crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: remotePublic
      },
      localPrivate,
      256
    );
  }
  static async deriveSharedKey(sharedSecret, salt, contextInfo) {
    const hkdfSalt = salt || new Uint8Array(32).buffer;
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      { name: "HKDF" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: hkdfSalt,
        info: new TextEncoder().encode(contextInfo || "PeerVault-ECDH-v1").buffer
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }
  static async generateECDHKeyPair() {
    return crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      ["deriveBits"]
    );
  }
  static async exportPublicKey(key) {
    const rawKey = await crypto.subtle.exportKey("raw", key);
    return this.bufferToBase64Url(rawKey);
  }
  static async importPublicKey(base64url) {
    const rawKey = this.base64UrlToBuffer(base64url);
    return crypto.subtle.importKey(
      "raw",
      rawKey,
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      []
    );
  }
  static bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  static base64UrlToBuffer(base64Url) {
    let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
};

// src/crypto-engine.ts
var CryptoEngine = class {
  key = null;
  localKeyPair = null;
  /**
   * @deprecated Always false. Previously defaulted to `PQCrypto.isMLKEMSupported()`,
   * which returned true in every modern browser and told applications that a hybrid
   * post-quantum exchange was in use when none was implemented.
   */
  useHybridKeyExchange = false;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_options) {
  }
  /**
   * Reports what this engine actually does. `supportsMLKEM` describes the platform,
   * not PeerVault: `usesPostQuantumKeyExchange` is always false.
   */
  getCapabilities() {
    const hasSubtle = typeof crypto !== "undefined" && !!crypto.subtle;
    return {
      supportsMLKEM: PQCrypto.isMLKEMSupported(),
      supportsECDH: hasSubtle,
      supportsAESGCM: hasSubtle,
      usesPostQuantumKeyExchange: false
    };
  }
  async generateKey() {
    this.key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const rawKey = await crypto.subtle.exportKey("raw", this.key);
    return this.bufferToBase64Url(rawKey);
  }
  async importKey(base64UrlKey) {
    const rawKey = this.base64UrlToBuffer(base64UrlKey);
    this.key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async getLocalPublicKey() {
    if (!this.localKeyPair) {
      this.localKeyPair = await PQCrypto.generateECDHKeyPair();
    }
    return PQCrypto.exportPublicKey(this.localKeyPair.publicKey);
  }
  async negotiateKey(remotePeerPublicKey) {
    if (!this.localKeyPair) {
      this.localKeyPair = await PQCrypto.generateECDHKeyPair();
    }
    const remotePublic = await PQCrypto.importPublicKey(remotePeerPublicKey);
    const sharedSecret = await PQCrypto.hybridKeyExchange(this.localKeyPair.privateKey, remotePublic);
    this.key = await PQCrypto.deriveSharedKey(sharedSecret);
  }
  async encryptChunk(data) {
    if (!this.key) throw new Error("Key not initialized");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this.key,
      data
    );
    return { iv, ciphertext };
  }
  async decryptChunk(iv, ciphertext) {
    if (!this.key) throw new Error("Key not initialized");
    const ivBytes = new Uint8Array(iv.byteLength);
    ivBytes.set(iv);
    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      this.key,
      ciphertext
    );
  }
  bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  base64UrlToBuffer(base64Url) {
    let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
};

// src/file-chunker.ts
var CHUNK_SIZE = 64 * 1024;
var FileChunker = class {
  file;
  offset = 0;
  sentEmptyFile = false;
  constructor(file) {
    this.file = file;
  }
  get totalChunks() {
    return this.file.size === 0 ? 1 : Math.ceil(this.file.size / CHUNK_SIZE);
  }
  async getNextChunk() {
    if (this.file.size === 0) {
      if (this.sentEmptyFile) return null;
      this.sentEmptyFile = true;
      return new ArrayBuffer(0);
    }
    if (this.offset >= this.file.size) {
      return null;
    }
    const slice = this.file.slice(this.offset, this.offset + CHUNK_SIZE);
    this.offset += CHUNK_SIZE;
    return await slice.arrayBuffer();
  }
  async hashChunk(chunk) {
    return await crypto.subtle.digest("SHA-256", chunk);
  }
};

// src/sender.ts
var MAX_BUFFERED_BYTES = 1024 * 1024 * 16;
var PeerVaultSender = class extends EventEmitter {
  signaling;
  peerConnection = null;
  cryptoEngine;
  files = [];
  roomId = null;
  dc = null;
  isCancelled = false;
  shareLink = null;
  shareLinkPromise = null;
  createRoomTimeoutMs;
  stallTimeoutMs;
  iceServers;
  constructor(signalingUrl, options) {
    super();
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
    this.iceServers = options?.iceServers;
    this.createRoomTimeoutMs = options?.createRoomTimeoutMs ?? 3e4;
    this.stallTimeoutMs = options?.stallTimeoutMs ?? 12e4;
    this.signaling.on("message", (msg) => {
      if (msg.type === "room_created" && msg.roomId) {
        this.roomId = msg.roomId;
      } else if (msg.type === "peer_joined") {
        this.emit("recipient_connected", void 0);
        if (this.peerConnection) {
          this.peerConnection.initiateConnection();
        }
      } else if (msg.type === "error") {
        const detail = msg.payload && typeof msg.payload === "object" && "message" in msg.payload ? String(msg.payload.message) : "unknown relay error";
        this.emit("error", new Error(`PeerVault relay reported an error: ${detail}`));
      }
    });
    this.signaling.on(
      "error",
      (err) => this.emit("error", toError(err, "PeerVault: signaling connection error"))
    );
  }
  addFiles(files) {
    if (!Array.isArray(files)) throw new TypeError("addFiles expects an array of File objects");
    this.files.push(...files);
  }
  /**
   * Creates the room and returns `roomId#keyBase64Url`.
   *
   * Idempotent: calling it twice previously generated a second AES key and
   * silently invalidated any link that had already been shared, so repeat calls
   * now resolve with the same link.
   */
  async createShareLink() {
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
  async doCreateShareLink() {
    await this.signaling.connect();
    return new Promise((resolve, reject) => {
      let timer = null;
      const done = (fn) => {
        if (timer) clearTimeout(timer);
        this.signaling.off("message", handleRoomCreated);
        fn();
      };
      const handleRoomCreated = async (msg) => {
        if (msg.type === "error") {
          const detail = msg.payload && typeof msg.payload === "object" && "message" in msg.payload ? String(msg.payload.message) : "unknown relay error";
          done(() => reject(new Error(`PeerVault relay rejected create_room: ${detail}`)));
          return;
        }
        if (msg.type !== "room_created") return;
        try {
          const keyBase64Url = await this.cryptoEngine.generateKey();
          this.setupPeerConnection();
          const roomId = msg.roomId ?? this.roomId;
          done(() => resolve(`${roomId}#${keyBase64Url}`));
        } catch (err) {
          done(() => reject(toError(err, "PeerVault: failed to create share link")));
        }
      };
      if (this.createRoomTimeoutMs > 0) {
        timer = setTimeout(() => {
          done(
            () => reject(
              new Error(
                `PeerVault: relay did not acknowledge create_room within ${this.createRoomTimeoutMs}ms`
              )
            )
          );
        }, this.createRoomTimeoutMs);
      }
      this.signaling.on("message", handleRoomCreated);
      this.signaling.send({ type: "create_room" });
    });
  }
  setupPeerConnection() {
    this.peerConnection = new PeerConnection(this.signaling, true, { iceServers: this.iceServers });
    this.peerConnection.on("datachannel_open", (dc) => {
      this.dc = dc;
      this.startTransfer();
    });
    this.peerConnection.on("error", (err) => {
      this.emit("error", err);
    });
  }
  async startTransfer() {
    if (!this.dc) return;
    try {
      const chunkers = this.files.map((f) => new FileChunker(f));
      const metadataList = this.files.map((f, i) => ({
        name: f.name,
        size: f.size,
        mime: f.type,
        chunks: chunkers[i].totalChunks
      }));
      this.dc.send(
        JSON.stringify({
          type: "metadata",
          files: metadataList
        })
      );
      for (let i = 0; i < this.files.length; i++) {
        if (this.isCancelled) break;
        await this.transferFile(i, chunkers[i], this.files[i].size, metadataList[i].chunks);
      }
      if (!this.isCancelled) {
        this.emit("complete", void 0);
      }
    } catch (err) {
      this.emit("error", toError(err, "PeerVault: transfer failed"));
    }
  }
  async transferFile(fileIndex, chunker, totalBytes, totalChunks) {
    let chunkIndex = 0;
    let bytesTransferred = 0;
    while (!this.isCancelled) {
      const chunkData = await chunker.getNextChunk();
      if (chunkData === null) break;
      const { iv, ciphertext } = await this.cryptoEngine.encryptChunk(chunkData);
      const buffer = new ArrayBuffer(1 + 4 + 4 + 12 + ciphertext.byteLength);
      const view = new DataView(buffer);
      const u8 = new Uint8Array(buffer);
      view.setUint8(0, 1);
      view.setUint32(1, fileIndex, true);
      view.setUint32(5, chunkIndex, true);
      u8.set(iv, 9);
      u8.set(new Uint8Array(ciphertext), 21);
      await this.waitForDrain();
      if (this.isCancelled) return;
      if (!this.dc || this.dc.readyState !== "open") throw new Error("DataChannel closed");
      this.dc.send(buffer);
      bytesTransferred += chunkData.byteLength;
      this.emit("progress", {
        fileIndex,
        chunkIndex,
        totalChunks,
        bytesTransferred,
        totalBytes
      });
      chunkIndex++;
    }
    if (!this.isCancelled && this.dc && this.dc.readyState === "open") {
      this.dc.send(
        JSON.stringify({
          type: "complete",
          fileIndex
        })
      );
    }
  }
  /**
   * Waits for the data channel send buffer to drain. Bounded by stallTimeoutMs and
   * aborted by cancel() or a closing channel, so a stalled peer surfaces an error
   * instead of halting the transfer silently and forever.
   */
  async waitForDrain() {
    const start = Date.now();
    while (this.dc && this.dc.bufferedAmount > MAX_BUFFERED_BYTES) {
      if (this.isCancelled) return;
      if (this.dc.readyState !== "open") throw new Error("DataChannel closed while draining");
      if (this.stallTimeoutMs > 0 && Date.now() - start > this.stallTimeoutMs) {
        throw new Error(
          `PeerVault: peer stalled \u2014 ${this.dc.bufferedAmount} bytes still buffered after ${this.stallTimeoutMs}ms`
        );
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  cancel() {
    this.isCancelled = true;
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
};
function toError(e, fallback) {
  if (e instanceof Error) return e;
  if (typeof e === "string") return new Error(e);
  if (e && typeof e === "object" && "type" in e) {
    return new Error(`${fallback} (${String(e.type)})`);
  }
  return new Error(fallback);
}

// src/file-assembler.ts
var MAX_CHUNKS = 1e6;
var FileAssembler = class {
  chunks = [];
  receivedChunks = 0;
  receivedBytes = 0;
  metadata;
  cryptoEngine;
  constructor(metadata, cryptoEngine) {
    const declared = metadata?.chunks;
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_CHUNKS) {
      throw new Error(
        `Invalid file metadata: chunks must be an integer in [0, ${MAX_CHUNKS}], received ${String(declared)}`
      );
    }
    if (!Number.isSafeInteger(metadata.size) || metadata.size < 0) {
      throw new Error(
        `Invalid file metadata: size must be a non-negative integer, received ${String(metadata.size)}`
      );
    }
    this.metadata = metadata;
    this.cryptoEngine = cryptoEngine;
    this.chunks = new Array(declared);
  }
  /**
   * Decrypt and store one chunk. Resolves true once every distinct chunk index
   * in [0, metadata.chunks) has been received.
   *
   * Duplicate and out-of-range indices are rejected rather than counted. Counting
   * arrivals instead of distinct indices previously allowed a duplicate chunk to
   * mask a missing one, which produced a silently corrupt file.
   */
  async addChunk(index, iv, ciphertext) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.metadata.chunks) {
      throw new Error(`Chunk index ${String(index)} out of range [0, ${this.metadata.chunks})`);
    }
    const plaintext = await this.cryptoEngine.decryptChunk(iv, ciphertext);
    if (this.chunks[index] !== void 0) {
      return this.isComplete();
    }
    this.chunks[index] = plaintext;
    this.receivedChunks++;
    this.receivedBytes += plaintext.byteLength;
    return this.isComplete();
  }
  isComplete() {
    return this.receivedChunks === this.metadata.chunks;
  }
  /** Distinct chunks accepted so far, plus decrypted byte total. */
  get progress() {
    return { received: this.receivedChunks, total: this.metadata.chunks, bytes: this.receivedBytes };
  }
  assemble() {
    if (!this.isComplete()) {
      throw new Error(
        `File incomplete: ${this.receivedChunks} of ${this.metadata.chunks} chunks received`
      );
    }
    for (let i = 0; i < this.metadata.chunks; i++) {
      if (this.chunks[i] === void 0) {
        throw new Error(`File incomplete: chunk ${i} is missing`);
      }
    }
    if (this.receivedBytes !== this.metadata.size) {
      throw new Error(
        `File corrupt: assembled ${this.receivedBytes} bytes but metadata declared ${this.metadata.size}`
      );
    }
    const blob = new Blob(this.chunks, { type: this.metadata.mime });
    const url = URL.createObjectURL(blob);
    return {
      ...this.metadata,
      blob,
      url
    };
  }
};

// src/receiver.ts
var CHUNK_HEADER_BYTES = 21;
var PeerVaultReceiver = class extends EventEmitter {
  signaling;
  peerConnection = null;
  cryptoEngine;
  roomId;
  keyBase64Url;
  dc = null;
  connectTimeoutMs;
  iceServers;
  metadataList = [];
  assemblers = /* @__PURE__ */ new Map();
  isDownloading = false;
  resolveConnect = null;
  rejectConnect = null;
  connectTimer = null;
  /** Chunks that arrived before download() was called, replayed once it is. */
  pendingChunks = [];
  /** Serialises chunk handling so completion is never evaluated against a stale count. */
  queue = Promise.resolve();
  /** fileIndex values for which the sender has already sent its 'complete' marker. */
  completeSignalled = /* @__PURE__ */ new Set();
  emittedFiles = /* @__PURE__ */ new Set();
  allCompleteEmitted = false;
  constructor(signalingUrl, shareLinkData, options) {
    super();
    if (typeof shareLinkData !== "string") throw new Error("Invalid share link data");
    const [roomId, key] = shareLinkData.split("#");
    if (!roomId || !key) throw new Error("Invalid share link data");
    this.roomId = roomId;
    this.keyBase64Url = key;
    this.iceServers = options?.iceServers;
    this.connectTimeoutMs = options?.connectTimeoutMs ?? 6e4;
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
  }
  async connect() {
    await this.cryptoEngine.importKey(this.keyBase64Url);
    await this.signaling.connect();
    return new Promise((resolve, reject) => {
      this.resolveConnect = resolve;
      this.rejectConnect = reject;
      if (this.connectTimeoutMs > 0) {
        this.connectTimer = setTimeout(() => {
          this.failConnect(
            new Error(
              `PeerVault: timed out after ${this.connectTimeoutMs}ms waiting for the sender. The share link may be stale, the sender may be offline, or the direct peer connection may have been blocked (no TURN server is configured, so symmetric and carrier-grade NAT cannot be traversed).`
            )
          );
        }, this.connectTimeoutMs);
      }
      this.signaling.on("message", (msg) => {
        if (msg && msg.type === "error") {
          const detail = msg.payload && typeof msg.payload === "object" && "message" in msg.payload ? String(msg.payload.message) : "unknown relay error";
          this.failConnect(new Error(`PeerVault relay rejected the request: ${detail}`));
        }
      });
      this.signaling.on("close", () => {
        this.failConnect(
          new Error("PeerVault: signaling connection closed before the transfer started")
        );
      });
      this.signaling.on("error", (e) => {
        this.failConnect(toError2(e, "PeerVault: signaling connection error"));
      });
      this.peerConnection = new PeerConnection(this.signaling, false, { iceServers: this.iceServers });
      this.peerConnection.on("datachannel_open", (dc) => {
        this.dc = dc;
        this.setupDataChannel(dc);
      });
      this.peerConnection.on("error", (err) => {
        this.emit("error", err);
        this.failConnect(err);
      });
      this.signaling.send({
        type: "join_room",
        roomId: this.roomId
      });
    });
  }
  failConnect(err) {
    this.clearConnectTimer();
    const reject = this.rejectConnect;
    this.rejectConnect = null;
    this.resolveConnect = null;
    if (reject) reject(err);
  }
  clearConnectTimer() {
    if (this.connectTimer) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
  }
  async download() {
    if (!this.metadataList.length) throw new Error("No metadata available to download");
    this.isDownloading = true;
    const buffered = this.pendingChunks;
    this.pendingChunks = [];
    for (const buf of buffered) this.enqueueChunk(buf);
  }
  setupDataChannel(dc) {
    dc.onmessage = (event) => {
      try {
        if (typeof event.data === "string") {
          this.handleControlMessage(event.data);
        } else if (event.data instanceof ArrayBuffer) {
          if (this.isDownloading) this.enqueueChunk(event.data);
          else this.pendingChunks.push(event.data);
        }
      } catch (err) {
        this.emit("error", toError2(err, "PeerVault: malformed message from peer"));
      }
    };
    dc.onclose = () => {
      this.failConnect(new Error("PeerVault: data channel closed before the transfer started"));
    };
  }
  handleControlMessage(raw) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      throw new Error("PeerVault: peer sent a control message that is not valid JSON");
    }
    if (!msg || typeof msg !== "object") {
      throw new Error("PeerVault: peer sent a non-object control message");
    }
    const m = msg;
    if (m.type === "metadata") {
      if (!Array.isArray(m.files)) {
        throw new Error("PeerVault: metadata message has no files array");
      }
      const files = m.files;
      this.assemblers.clear();
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
    } else if (m.type === "complete") {
      const fileIndex = Number(m.fileIndex);
      if (!Number.isSafeInteger(fileIndex)) {
        throw new Error(
          `PeerVault: complete message has an invalid fileIndex ${String(m.fileIndex)}`
        );
      }
      this.completeSignalled.add(fileIndex);
      this.queue = this.queue.then(() => this.tryFinishFile(fileIndex)).catch((err) => {
        this.emit("error", toError2(err, "PeerVault: failed to finalise file"));
      });
    }
  }
  enqueueChunk(buffer) {
    this.queue = this.queue.then(() => this.handleChunk(buffer)).catch((err) => {
      this.emit("error", toError2(err, "PeerVault: failed to process chunk"));
    });
  }
  async handleChunk(buffer) {
    if (buffer.byteLength < CHUNK_HEADER_BYTES) {
      throw new Error(
        `PeerVault: chunk frame too short (${buffer.byteLength} bytes, need at least ${CHUNK_HEADER_BYTES})`
      );
    }
    const view = new DataView(buffer);
    const type = view.getUint8(0);
    if (type !== 1) return;
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
    this.emit("progress", {
      fileIndex,
      chunkIndex,
      totalChunks: meta.chunks,
      bytesTransferred: bytes,
      totalBytes: meta.size
    });
    if (received === meta.chunks) await this.tryFinishFile(fileIndex);
  }
  async tryFinishFile(fileIndex) {
    if (this.emittedFiles.has(fileIndex)) return;
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler || !assembler.isComplete()) return;
    if (!this.completeSignalled.has(fileIndex)) return;
    const receivedFile = assembler.assemble();
    this.emittedFiles.add(fileIndex);
    this.emit("file_complete", receivedFile);
    if (!this.allCompleteEmitted && this.metadataList.length > 0 && this.metadataList.every((_, i) => this.emittedFiles.has(i))) {
      this.allCompleteEmitted = true;
      this.emit("complete", void 0);
    }
  }
  cancel() {
    this.clearConnectTimer();
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
};
function toError2(e, fallback) {
  if (e instanceof Error) return e;
  if (typeof e === "string") return new Error(e);
  if (e && typeof e === "object" && "type" in e) {
    return new Error(`${fallback} (${String(e.type)})`);
  }
  return new Error(fallback);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CHUNK_SIZE,
  CryptoEngine,
  DEFAULT_ICE_SERVERS,
  EventEmitter,
  FileAssembler,
  FileChunker,
  MAX_CHUNKS,
  PQCrypto,
  PeerConnection,
  PeerVaultReceiver,
  PeerVaultSender,
  SignalingClient
});
//# sourceMappingURL=index.js.map