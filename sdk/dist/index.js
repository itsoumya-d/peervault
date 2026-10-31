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
  ChunkBitmap: () => ChunkBitmap,
  CryptoEngine: () => CryptoEngine,
  DEFAULT_ICE_SERVERS: () => DEFAULT_ICE_SERVERS,
  EventEmitter: () => EventEmitter,
  FileAssembler: () => FileAssembler,
  FileChunker: () => FileChunker,
  HybridHandshake: () => HybridHandshake,
  MAX_BITMAP_CHUNKS: () => MAX_BITMAP_CHUNKS,
  MAX_CHUNKS: () => MAX_CHUNKS,
  MLKEM768_CIPHERTEXT_BYTES: () => MLKEM768_CIPHERTEXT_BYTES,
  MLKEM768_PUBLIC_KEY_BYTES: () => MLKEM768_PUBLIC_KEY_BYTES,
  MLKEM768_SECRET_KEY_BYTES: () => MLKEM768_SECRET_KEY_BYTES,
  MLKEM768_SEED_BYTES: () => MLKEM768_SEED_BYTES,
  MLKEM768_SHARED_SECRET_BYTES: () => MLKEM768_SHARED_SECRET_BYTES,
  MeshNode: () => MeshNode,
  MlKem768: () => MlKem768,
  PQCrypto: () => PQCrypto,
  PeerConnection: () => PeerConnection,
  PeerVaultReceiver: () => PeerVaultReceiver,
  PeerVaultSender: () => PeerVaultSender,
  SignalingClient: () => SignalingClient,
  base64UrlToBytes: () => base64UrlToBytes,
  bytesToBase64Url: () => bytesToBase64Url,
  createFileSystemSink: () => createFileSystemSink,
  createOpfsSink: () => createOpfsSink,
  createWritableSink: () => createWritableSink,
  decodeFloat32: () => decodeFloat32,
  encodeFloat32: () => encodeFloat32,
  textEncoder: () => textEncoder
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
   * Reports whether PeerVault's bundled ML-KEM-768 wasm core can execute here.
   * This is about the implementation PeerVault actually uses, not a claim about
   * the host platform's WebCrypto surface. Use {@link probeMLKEM} for that.
   */
  static isMLKEMSupported() {
    return typeof WebAssembly !== "undefined";
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
   * pair when WebCrypto exposes one.
   *
   * PeerVault's default handshake does not use this platform key pair; it uses
   * the bundled wasm ML-KEM implementation in `hybrid-handshake.ts`. This helper
   * is retained for callers building their own constructions.
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
   * Derives the hybrid session secret.
   *
   * With no `mlkemSharedSecret`, this is the legacy plain P-256 ECDH behaviour.
   * With an ML-KEM shared secret, it concatenates the ECDH and KEM secrets and
   * runs HKDF-SHA256 with the supplied transcript hash as salt.
   */
  static async hybridKeyExchange(localPrivate, remotePublic, mlkemSharedSecret, transcriptHash) {
    const ecdh = await this.ecdhKeyExchange(localPrivate, remotePublic);
    if (!mlkemSharedSecret) return ecdh;
    const ecdhBytes = new Uint8Array(ecdh);
    const kemBytes = new Uint8Array(mlkemSharedSecret);
    const ikm = new Uint8Array(ecdhBytes.byteLength + kemBytes.byteLength);
    ikm.set(ecdhBytes, 0);
    ikm.set(kemBytes, ecdhBytes.byteLength);
    const hkdfKey = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, [
      "deriveBits"
    ]);
    return crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: transcriptHash ? new Uint8Array(transcriptHash) : new Uint8Array(32),
        info: new TextEncoder().encode("peervault/hybrid-session/v1")
      },
      hkdfKey,
      256
    );
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
  rawKey = null;
  hybridEstablished = false;
  /**
   * @deprecated Always false. Hybrid handshakes are configured on the sender and
   * receiver (default true); check `getCapabilities().usesPostQuantumKeyExchange`
   * after connecting to see whether one actually completed.
   */
  useHybridKeyExchange = false;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_options) {
  }
  /** Reports the primitives this engine can run and whether a hybrid session is live. */
  getCapabilities() {
    const hasSubtle = typeof crypto !== "undefined" && !!crypto.subtle;
    return {
      supportsMLKEM: PQCrypto.isMLKEMSupported(),
      supportsECDH: hasSubtle,
      supportsAESGCM: hasSubtle,
      usesPostQuantumKeyExchange: this.hybridEstablished
    };
  }
  async generateKey() {
    this.key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const rawKey = await crypto.subtle.exportKey("raw", this.key);
    this.rawKey = new Uint8Array(rawKey.slice(0));
    return this.bufferToBase64Url(rawKey);
  }
  async importKey(base64UrlKey) {
    const rawKey = this.base64UrlToBuffer(base64UrlKey);
    this.rawKey = new Uint8Array(rawKey.slice(0));
    this.key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }
  /** The share-link key bytes. Used as the pre-shared authentication secret. */
  getRawKey() {
    if (!this.rawKey) throw new Error("Key not initialized");
    return this.rawKey.slice();
  }
  /**
   * Derives and installs the transfer key:
   * HKDF-SHA256(share_link_key || hybrid_session, salt = transcript_hash,
   *             info = "peervault/file-key/v1")
   */
  async deriveHybridTransferKey(sessionKey, transcriptHash) {
    if (!this.rawKey) throw new Error("Key not initialized");
    const ikm = new Uint8Array(this.rawKey.byteLength + sessionKey.byteLength);
    ikm.set(this.rawKey, 0);
    ikm.set(sessionKey, this.rawKey.byteLength);
    const hkdfKey = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, [
      "deriveKey"
    ]);
    this.key = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(transcriptHash),
        info: new TextEncoder().encode("peervault/file-key/v1")
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    this.hybridEstablished = true;
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
  async encryptChunk(data, additionalData, providedIv) {
    if (!this.key) throw new Error("Key not initialized");
    const iv = providedIv ? new Uint8Array(providedIv) : crypto.getRandomValues(new Uint8Array(12));
    if (iv.byteLength !== 12) throw new Error("AES-GCM nonce must be 12 bytes");
    const aad = additionalData ? new Uint8Array(additionalData) : void 0;
    const ciphertext = await crypto.subtle.encrypt(
      aad ? { name: "AES-GCM", iv, additionalData: aad } : { name: "AES-GCM", iv },
      this.key,
      data
    );
    return { iv, ciphertext };
  }
  /**
   * Encrypt an application control message (for example a datamesh sync
   * payload). The 12-byte IV is prepended and bound as AES-GCM AAD.
   */
  async encryptMessage(message) {
    if (!this.key) throw new Error("Key not initialized");
    const data = new TextEncoder().encode(message).buffer;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: iv },
      this.key,
      data
    );
    const output = new Uint8Array(12 + ciphertext.byteLength);
    output.set(iv, 0);
    output.set(new Uint8Array(ciphertext), 12);
    return output.buffer;
  }
  /** Decrypt a control message produced by encryptMessage(). */
  async decryptMessage(buffer) {
    if (!this.key) throw new Error("Key not initialized");
    const bytes = new Uint8Array(buffer);
    if (bytes.byteLength < 12 + 16) {
      throw new Error("PeerVault: encrypted message is too short");
    }
    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: iv },
      this.key,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  }
  async decryptChunk(iv, ciphertext, additionalData) {
    if (!this.key) throw new Error("Key not initialized");
    const ivBytes = new Uint8Array(iv.byteLength);
    ivBytes.set(iv);
    const aad = additionalData ? new Uint8Array(additionalData) : void 0;
    return crypto.subtle.decrypt(
      aad ? { name: "AES-GCM", iv: ivBytes, additionalData: aad } : { name: "AES-GCM", iv: ivBytes },
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

// src/mlkem-wasm.generated.ts
var MLKEM768_WASM_BASE64 = "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f4WDhSIWNwN4IAApA7ABIRsgACkDuAEhEiAAIAApA8ABIhUgACkDqAEiGCAAKQOgASIaQn+Fg4UiBzcDwAEgACASIBogFUJ/hYOFIgs3A7gBIAAgGyAVIBJCf4WDhSIPNwOwASAAIBggEiAbQn+Fg4UiEjcDqAEgACAaIBsgGEJ/hYOFIhU3A6ABIAAgACkDACAZQQN0KQO4iMCAAIUiGDcDACAZQQFqIhlBGEcNAAsLpAIBAX8jgICAgABBgAhrIgIkgICAgAAgAiABQQBBABCCgICAACAAIAJBgAj8CgAAIAIgAUEBQQAQgoCAgAAgAEGACGogAkGACPwKAAAgAiABQQJBABCCgICAACAAQYAQaiACQYAI/AoAACACIAFBAEEBEIKAgIAAIABBgBhqIAJBgAj8CgAAIAIgAUEBQQEQgoCAgAAgAEGAIGogAkGACPwKAAAgAiABQQJBARCCgICAACAAQYAoaiACQYAI/AoAACACIAFBAEECEIKAgIAAIABBgDBqIAJBgAj8CgAAIAIgAUEBQQIQgoCAgAAgAEGAOGogAkGACPwKAAAgAiABQQJBAhCCgICAACAAQYDAAGogAkGACPwKAAAgAkGACGokgICAgAALzAcEA38CfgF/AX4jgICAgABBgAJrIgQkgICAgAAgBCADOgAhIAQgAjoAICAEIAEpABg3AxggBCABKQAQNwMQIAQgASkACDcDCCAEIAEpAAA3AwBBACEBIARBKGpBAEHIAfwLACAEQR86APgBIARCqAE3A/ABQQAhA0EAIQIDQCAEQShqIAJBA3RqIgIgBCADajEAACABQQN0rYYgAikDAIU3AwAgBCAEKAL0AUEBaiICNgL0AQJAAkACQAJAAkAgAiAEKALwAUYNACADQSFGDQEgAiEBDAQLIARBKGoQgICAgABBACEBIARBADYC9AFBACECIANBIUcNAwwBCyACQQN2IQEgAkHHAUsNAQsgBEEoaiABQQN0aiIBIAQxAPgBIAJBA3SthiABKQMAhTcDACAEKALwAUF/aiIBQQN2IQMCQCABQcgBTw0AIARBKGogA0EDdGoiASABKQMAQoCAgICAgICAgH+FNwMAIAQgBCgC8AEiATYC9AFBACEFIABBAEGACPwLAANAAkACQAJAAkACQAJAAkAgASAEKALwASIGRw0AIARBKGoQgICAgABBACEDIARBADYC9AEgBCgC8AEhBkEAIQEMAQsgAUEDdiEDIAFByAFPDQELIARBKGogA0EDdGopAwAhByAEIAFBAWoiAzYC9AECQAJAIAMgBkcNACAEQShqEICAgIAAQQAhAiAEQQA2AvQBIAQoAvABIQZBACEDDAELIANBA3YhAiABQccBTw0CCyAEQShqIAJBA3RqKQMAIQggBCADQQFqIgI2AvQBAkACQCACIAZHDQAgBEEoahCAgICAAEEAIQYgBEEANgL0AUEAIQIMAQsgAkEDdiEGIANBxwFPDQMLIAFBA3QhCSAEQShqIAZBA3RqKQMAIQogBCACQQFqIgE2AvQBIAogAkEDdK2Ip0EEdCAIIANBA3StiKciAkHwAXFBBHZyQf8fcSEDIAJBD3FBCHQgByAJrYinQf8BcXIiAkGBGkkNAwwECyADQRlBxIPAgAAQ0ICAgAAACyACQRlBxIPAgAAQ0ICAgAAACyAGQRlBxIPAgAAQ0ICAgAAACyAAIAVBAnRqIAI2AgAgBUEBaiEFCwJAIANBgBpLDQAgBUGAAk8NACAAIAVBAnRqIAM2AgAgBUEBaiEFCyAFQYACSQ0ACyAEQYACaiSAgICAAA8LIANBGUH0g8CAABDQgICAAAALIAFBGUHkg8CAABDQgICAAAALIANBAWohAyABQQN2IQIgAUHIAUkNAAsgAkEZQdSDwIAAENCAgIAAAAvCAwEFfyOAgICAAEHAEmsiAySAgICAACADIAFBgAkgABCHgICAACADIAMpABg3AzggAyADKQAQNwMwIAMgAykACDcDKCADIAMpAAA3AyAgAyABKQCgEjcDQCADIAEpAKgSNwNIIAMgASkAsBI3A1AgAyABKQC4EjcDWCADQaAJaiADQSBqQcAAEIWAgIAAIANB4ABqIAFBgAlqIAMgA0HACWoQhoCAgABBACEEQcB3IQUDQCADQeAAaiAFaiIGQcMIai0AACAAIAVqIgdBwwhqLQAAcyAGQcIIai0AACAHQcIIai0AAHMgBkHBCGotAAAgB0HBCGotAABzIAZBwAhqLQAAIAdBwAhqLQAAcyAEcnJyciEEIAVBBGoiBQ0ACwJAAkAgBEH/AXENACACIAMpALgJNwAYIAIgAykAsAk3ABAgAiADKQCoCTcACCACIAMpAKAJNwAADAELIAMgASkA2BI3A/gJIAMgASkA0BI3A/AJIAMgASkAyBI3A+gJIAMgASkAwBI3A+AJIANB4AlqQSBqIABBwAj8CgAAIANB4AlqQeAIIAJBIBCIgICAAAsgA0HAEmokgICAgAAgBEH/AXFFC+YEAQN/I4CAgIAAQYACayIDJICAgIAAQQAhBCADQQhqQQBByAH8CwAgA0EGOgDYASADQogBNwPQAUEAIQUCQAJAAkACQAJAIAJFDQBBACEFA0AgBUEDdiEEIAVBxwFLDQIgA0EIaiAEQQN0aiIEIAExAAAgBUEDdK2GIAQpAwCFNwMAIAMgAygC1AFBAWoiBTYC1AECQCAFIAMoAtABRw0AIANBCGoQgICAgABBACEFIANBADYC1AELIAFBAWohASACQX9qIgINAAsgBUEDdiEEIAVBxwFLDQILIANBCGogBEEDdGoiASADMQDYASAFQQN0rYYgASkDAIU3AwAgAygC0AFBf2oiBUEDdiEBIAVByAFPDQIgA0EIaiABQQN0aiIFIAUpAwBCgICAgICAgICAf4U3AwAgAyADKALQASIFNgLUASADQgA3A/gBIANCADcD8AEgA0IANwPoASADQgA3A+ABQQAhAQNAAkACQCAFIAMoAtABRw0AIANBCGoQgICAgABBACECIANBADYC1AFBACEFDAELIAVBA3YhAiAFQcgBTw0FCyADQeABaiABaiADQQhqIAJBA3RqKQMAIAVBA3StiDwAACADIAVBAWoiBTYC1AEgAUEBaiICIQEgAkEgRw0ACyAAIAMpA/gBNwAYIAAgAykD8AE3ABAgACADKQPoATcACCAAIAMpA+ABNwAAIANBgAJqJICAgIAADwsgBEEZQdSDwIAAENCAgIAAAAsgBEEZQeSDwIAAENCAgIAAAAsgAUEZQfSDwIAAENCAgIAAAAsgAkEZQcSDwIAAENCAgIAAAAuzBQEDfyOAgICAAEGgAmsiAySAgICAAEEAIQQgA0EIakEAQcgB/AsAIANBBjoA2AEgA0LIADcD0AFBACEFAkACQAJAAkACQCACRQ0AQQAhBQNAIAVBA3YhBCAFQccBSw0CIANBCGogBEEDdGoiBCABMQAAIAVBA3SthiAEKQMAhTcDACADIAMoAtQBQQFqIgU2AtQBAkAgBSADKALQAUcNACADQQhqEICAgIAAQQAhBSADQQA2AtQBCyAB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AWokgICAgAAPCyAFQRlB1IPAgAAQ0ICAgAAACyAFQRlB5IPAgAAQ0ICAgAAACyAAQRlB9IPAgAAQ0ICAgAAACyAAQRlBxIPAgAAQ0ICAgAAAC7kZBQR/AX4BfwF+AX9BACEBA0AgACABaiICQYAEaiIDIAIoAgAiBCADNAIAIgVCgICAgICAgIX7AH5CMIdC/+X/////P34gBUKK+v////8/fnxCEIinIgNrNgIAIAIgBCADajYCACABQQRqIgFBgARHDQALQQAhAQNAIAAgAWoiAkGAAmoiAyACKAIAIgQgAzQCACIFQoCAgICAgMDMOX5CMIdC/+X/////P34gBUKZ/f////8/fnxCEIinIgNrNgIAIAIgBCADajYCACABQQRqIgFBgAJHDQALQQAhAQNAIAAgAWoiAkGABmoiAyACQYAEaiICKAIAIgQgAzQCACIFQoCAgICAgMCJA35CMIdC/+X/////P34gBUKT9P////8/fnxCEIinIgNrNgIAIAIgBCADajYCACABQQRqIgFBgAJHDQALQQAhAQNAIAAgAWoiAkGAAWoiAyACKAIAIgQgAzQCACIFQoCAgICAgMDqNH5CMIdC/+X/////P34gBULVC358QhCIpyIDazYCACACIAQgA2o2AgAgAUEEaiIBQYABRw0AC0EAIQEDQCAAIAFqIgJBgANqIgMgAkGAAmoiAigCACIEIAM0AgAiBUKAgICAgICAx09+QjCHQv/l/////z9+IAVCjgt+fEIQiKciA2s2AgAgAiAEIANqNgIAIAFBBGoiAUGAAUcNAAtBACEBA0AgACABaiICQYAFaiIDIAJBgARqIgIoAgAiBCADNAIAIgVCgICAgICAwI/uAH5CMIdC/+X/////P34gBUKfAn58QhCIpyIDazYCACACIAQgA2o2AgAgAUEEaiIBQYABRw0AC0EAIQEDQCAAIAFqIgJBgAdqIgMgAkGABmoiAigCACIEIAM0AgAiBUKAgICAgICA5b5/fkIwh0L/5f////8/fiAFQsoBfnxCEIinIgNrNgIAIAIgBCADajYCACABQQRqIgFBgAFHDQALQdSEwIAAIQJBYCEDIAAhAQNAIAFBwABqIgQgASgCACIGIAQ0AgAgAjQCACIFfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAEgBiAEajYCACABQcQAaiIEIAFBBGoiBigCACIIIAUgBDQCAH4iB0KAgICAgIDAgHN+QjCHQv/l/////z9+IAd8QhCIpyIEazYCACAGIAggBGo2AgAgAUHIAGoiBCABQQhqIgYoAgAiCCAFIAQ0AgB+IgdCgICAgICAwIBzfkIwh0L/5f////8/fiAHfEIQiKciBGs2AgAgBiAIIARqNgIAIAFBzABqIgQgAUEMaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQdAAaiIEIAFBEGoiBigCACIIIAUgBDQCAH4iB0KAgICAgIDAgHN+QjCHQv/l/////z9+IAd8QhCIpyIEazYCACAGIAggBGo2AgAgAUHUAGoiBCABQRRqIgYoAgAiCCAFIAQ0AgB+IgdCgICAgICAwIBzfkIwh0L/5f////8/fiAHfEIQiKciBGs2AgAgBiAIIARqNgIAIAFB2ABqIgQgAUEYaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQdwAaiIEIAFBHGoiBigCACIIIAUgBDQCAH4iB0KAgICAgIDAgHN+QjCHQv/l/////z9+IAd8QhCIpyIEazYCACAGIAggBGo2AgAgAUHgAGoiBCABQSBqIgYoAgAiCCAFIAQ0AgB+IgdCgICAgICAwIBzfkIwh0L/5f////8/fiAHfEIQiKciBGs2AgAgBiAIIARqNgIAIAFB5ABqIgQgAUEkaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQegAaiIEIAFBKGoiBigCACIIIAUgBDQCAH4iB0KAgICAgIDAgHN+QjCHQv/l/////z9+IAd8QhCIpyIEazYCACAGIAggBGo2AgAgAUHsAGoiBCABQSxqIgYoAgAiCCAFIAQ0AgB+IgdCgICAgICAwIBzfkIwh0L/5f////8/fiAHfEIQiKciBGs2AgAgBiAIIARqNgIAIAFB8ABqIgQgAUEwaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQfQAaiIEIAFBNGoiBigCACIIIAUgBDQCAH4iB0KAgICAgIDAgHN+QjCHQv/l/////z9+IAd8QhCIpyIEazYCACAGIAggBGo2AgAgAUH4AGoiBCABQThqIgYoAgAiCCAFIAQ0AgB+IgdCgICAgICAwIBzfkIwh0L/5f////8/fiAHfEIQiKciBGs2AgAgBiAIIARqNgIAIAFB/ABqIgQgAUE8aiIGKAIAIgggBSAENAIAfiIFQoCAgICAgMCAc35CMIdC/+X/////P34gBXxCEIinIgRrNgIAIAYgCCAEajYCACACQQRqIQIgAUGAAWohASADQSBqIgNB4AFJDQALQXAhAyAAIQEDQCABQSBqIgQgASgCACIGIAQ0AgAgAjQCACIFfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAEgBiAEajYCACABQSRqIgQgAUEEaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQShqIgQgAUEIaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQSxqIgQgAUEMaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQTBqIgQgAUEQaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQTRqIgQgAUEUaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQThqIgQgAUEYaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQTxqIgQgAUEcaiIGKAIAIgggBSAENAIAfiIFQoCAgICAgMCAc35CMIdC/+X/////P34gBXxCEIinIgRrNgIAIAYgCCAEajYCACACQQRqIQIgAUHAAGohASADQRBqIgNB8AFJDQALQXghAyAAIQEDQCABQRBqIgQgASgCACIGIAQ0AgAgAjQCACIFfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAEgBiAEajYCACABQRRqIgQgAUEEaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQRhqIgQgAUEIaiIGKAIAIgggBSAENAIAfiIHQoCAgICAgMCAc35CMIdC/+X/////P34gB3xCEIinIgRrNgIAIAYgCCAEajYCACABQRxqIgQgAUEMaiIGKAIAIgggBSAENAIAfiIFQoCAgICAgMCAc35CMIdC/+X/////P34gBXxCEIinIgRrNgIAIAYgCCAEajYCACACQQRqIQIgAUEgaiEBIANBCGoiA0H4AUkNAAtBfCEDIAAhAQNAIAFBCGoiBCABKAIAIgYgBDQCACACNAIAIgV+IgdCgICAgICAwIBzfkIwh0L/5f////8/fiAHfEIQiKciBGs2AgAgASAGIARqNgIAIAFBDGoiBCABQQRqIgYoAgAiCCAFIAQ0AgB+IgVCgICAgICAwIBzfkIwh0L/5f////8/fiAFfEIQiKciBGs2AgAgBiAIIARqNgIAIAFBEGohASACQQRqIQIgA0EEaiIDQfwBSQ0AC0EAIQEDQCAAIAFqIgIgAigCACIDQb+dAWxBgICAEGpBGnVB/2VsIANqNgIAIAJBBGoiAiACKAIAIgJBv50BbEGAgIAQakEadUH/ZWwgAmo2AgAgAUEIaiIBQYAIRw0ACwu1BAYEfwF+AX8EfgF/BH5BtIbAgAAhA0EAIQQDQCAAIARqIgVBBGoiBiAGKAIAIAIgBGoiBkEEajQCACIHIAEgBGoiCDQCACIJfiIKQoCAgICAgMCAc35CMIdC/+X/////P34gCnxCEIinaiAGNAIAIgogCEEEajQCACILfiIMQoCAgICAgMCAc35CMIdC/+X/////P34gDHxCEIinajYCACAFQQxqIg0gDSgCACAGQQxqNAIAIgwgCEEIajQCACIOfiIPQoCAgICAgMCAc35CMIdC/+X/////P34gD3xCEIinaiAGQQhqNAIAIg8gCEEMajQCACIQfiIRQoCAgICAgMCA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IgNBgARqIgQgA0GABmoiAygCACIFIAQoAgAiBGoiBkG/nQFsQYCAgBBqQRp1Qf9lbCAGajYCACADIAUgBGusIAx+IgtCgICAgICAwIBzfkIwh0L/5f////8/fiALfEIQiD4CACACQQRqIgJBgAJHDQALIAFBxAFqNAIAIQxBACECA0AgACACaiIBIAFBgARqIgMoAgAiBCABKAIAIgFqIgVBv50BbEGAgIAQakEadUH/ZWwgBWo2AgAgAyAEIAFrrCAMfiILQoCAgICAgMCAc35CMIdC/+X/////P34gC3xCEIg+AgAgAkEEaiICQYAERw0AC0EAIQIDQCAAIAJqIgEgATQCACILQoCAgICAgMDQWH5CMIdC/+X/////P34gC0KhC358QhCIPgIAIAFBBGoiASABNAIAIgtCgICAgICAwNBYfkIwh0L/5f////8/fiALQqELfnxCEIg+AgAgAkEIaiICQYAIRw0ACwvNBwEEfyOAgICAAEHgAmsiAySAgICAAEEAIQQgA0EIakEAQcgB/AsAIANBHzoA2AEgA0KIATcD0AFBACEFQQAhBgNAIANBCGogBkEDdGoiBiABIAVqMQAAIARBA3SthiAGKQMAhTcDACADIAMoAtQBQQFqIgY2AtQBAkACQAJAAkACQAJAAkACQCAGIAMoAtABRg0AIAVBH0YNASAGIQQMBwsgA0EIahCAgICAAEEAIQQgA0EANgLUAUEAIQYgBUEfRw0GDAELIAZBA3YhBCAGQccBSw0BCyADQQhqIARBA3RqIgQgAq1C/wGDIAZBA3SthiAEKQMAhTcDACADIAMoAtQBQQFqIgQ2AtQBAkACQCAEIAMoAtABRw0AIANBCGoQgICAgABBACEFIANBADYC1AFBACEEDAELIARBA3YhBSAEQccBSw0CCyADQQhqIAVBA3RqIgUgAzEA2AEgBEEDdK2GIAUpAwCFNwMAIAMoAtABQX9qIgRBA3YhBSAEQcgBTw0CIANBCGogBUEDdGoiBCAEKQMAQoCAgICAgICAgH+FNwMAIAMgAygC0AEiBDYC1AFBACEFIANB4AFqQQBBgAH8CwADQAJAAkAgBCADKALQAUcNACADQQhqEICAgIAAQQAhBiADQQA2AtQBQQAhBAwBCyAEQQN2IQYgBEHIAU8NBQsgA0HgAWogBWogA0EIaiAGQQN0aikDACAEQQN0rYg8AAAgAyAEQQFqIgQ2AtQBIAVBAWoiBiEFIAZBgAFHDQALQQAhBiAAQQBBgAj8CwAgA0HgAWohAQNAIAAgBmoiBUEcaiABKAAAIgRBAXZB1arVqgVxIARB1arVqgVxaiIEQRx2QQNxIARBHnZrNgIAIAVBGGogBEEYdkEDcSAEQRp2QQNxazYCACAFQRRqIARBFHZBA3EgBEEWdkEDcWs2AgAgBUEQaiAEQRB2QQNxIARBEnZBA3FrNgIAIAVBDGogBEEMdkEDcSAEQQ52QQNxazYCACAFQQhqIARBCHZBA3EgBEEKdkEDcWs2AgAgBUEEaiAEQQR2QQNxIARBBnZBA3FrNgIAIAUgBEEDcSAEQQJ2QQNxazYCACABQQRqIQEgBkEgaiIGQYAIRw0ACyADQeACaiSAgICAAA8LIARBGUHUg8CAABDQgICAAAALIAVBGUHkg8CAABDQgICAAAALIAVBGUH0g8CAABDQgICAAAALIAZBGUHEg8CAABDQgICAAAALIAVBAWohBSAEQQN2IQYgBEHIAUkNAAsgBkEZQdSDwIAAENCAgIAAAAv0FwYOfwF+AX8EfgF/BH4jgICAgABBkMkBayIEJICAgIAAIARBAzoAKCAEIAApABg3AyAgBCAAKQAQNwMYIAQgACkACDcDECAEIAApAAA3AwggBEEwaiAEQQhqQSEQhYCAgAAgBEHw4ABqIARB0ABqIgBBABCMgICAACAEQfAAaiAEQfDgAGpBgAj8CgAAIARB8OAAaiAAQQEQjICAgAAgBEHwAGpBgAhqIARB8OAAakGACPwKAAAgBEHw4ABqIABBAhCMgICAACAEQfAAakGAEGogBEHw4ABqQYAI/AoAACAEQfDgAGogAEEDEIyAgIAAIARB8BhqIARB8OAAakGACPwKAAAgBEHw4ABqIABBBBCMgICAACAEQfAYakGACGogBEHw4ABqQYAI/AoAACAEQfDgAGogAEEFEIyAgIAAIARB8BhqQYAQaiAEQfDgAGpBgAj8CgAAIARB8DBqIARB8ABqQYAY/AoAACAEQfDIAGogBEHwGGpBgBj8CgAAIARB8DBqEImAgIAAIARB8DBqQYAIaiIFEImAgIAAIARB8DBqQYAQaiIGEImAgIAAIARB8MgAahCJgICAACAEQfDIAGpBgAhqEImAgIAAIARB8MgAakGAEGoQiYCAgAAgBEHw4ABqIARBMGoQgYCAgAAgBEHwqAFqQQBBgBj8CwAgBEHwqAFqQYAQaiEHIARB8KgBakGACGohCCAEQfDgAGohCSAEQfDIAGohCkEAIQsDQCAEQfDAAWpBAEGACPwLACAEQfAwaiEMIAkhDUEAIQ4DQEGAeCEAQbSGwIAAIQ8DQCAEQfDAAWogAGoiEEGECGoiESARKAIAIAwgAGoiEUGECGo0AgAiEiANIABqIhNBgAhqNAIAIhR+IhVCgICAgICAwIBzfkIwh0L/5f////8/fiAVfEIQiKdqIBFBgAhqNAIAIhUgE0GECGo0AgAiFn4iF0KAgICAgIDAgHN+QjCHQv/l/////z9+IBd8QhCIp2o2AgAgEEGMCGoiGCAYKAIAIBFBjAhqNAIAIhcgE0GICGo0AgAiGX4iGkKAgICAgIDAgHN+QjCHQv/l/////z9+IBp8QhCIp2ogEUGICGo0AgAiGiATQYwIajQCACIbfiIcQoCAgICAgMCAc35CMIdC/+X/////P34gHHxCEIinajYCACAQQYAIaiIRIBEoAgAgFSAUfiIUQoCAgICAgMCAc35CMIdC/+X/////P34gFHxCEIinaiASIBZ+IhJCgICAgICAwIBzfkIwh0L/5f////8/fiASfEIQhkIghyAPKAIAIhGsfiISQoCAgICAgMCAc35CMIdC/+X/////P34gEnxCEIinajYCACAQQYgIaiIQIBAoAgAgGiAZfiISQoCAgICAgMCAc35CMIdC/+X/////P34gEnxCEIinaiAXIBt+IhJCgICAgICAwIBzfkIwh0L/5f////8/fiASfEIQhkIgh0EAIBFrrH4iEkKAgICAgIDAgHN+QjCHQv/l/////z9+IBJ8QhCIp2o2AgAgD0EEaiEPIABBEGoiAA0ACyANQYAIaiENIAxBgAhqIQwgDkEBaiIOQQNHDQALQQAhAANAIARB8MABaiAAaiIQIBA0AgAiEkKAgICAgIDApNAAfkIwh0L/5f////8/fiASQskKfnxCEIg+AgAgEEEEaiIQIBA0AgAiEkKAgICAgIDApNAAfkIwh0L/5f////8/fiASQskKfnxCEIg+AgAgAEEIaiIAQYAIRw0AC0GAeCEAA0AgBEHwwAFqIABqIhBBgAhqIhEgESgCACAKIABq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wIAANgLskcCAAEEAQfSRwIAANgKAksCAAEEAQeyRwIAANgL0kcCAAEEAQfyRwIAANgKIksCAAEEAQfSRwIAANgL8kcCAAEEAQYSSwIAANgKQksCAAEEAQfyRwIAANgKEksCAAEEAQYySwIAANgKYksCAAEEAQYSSwIAANgKMksCAAEEAQQAoAoyUwIAAIgBBfyAAGzYChJTAgABBAEGUksCAADYCoJLAgABBAEGMksCAADYClJLAgABBAEGUksCAADYCnJLAgABBAEGcksCAADYCqJLAgABBAEGcksCAADYCpJLAgABBAEGkksCAADYCsJLAgABBAEGkksCAADYCrJLAgABBAEGsksCAADYCuJLAgABBAEGsksCAADYCtJLAgABBAEG0ksCAADYCwJLAgABBAEG0ksCAADYCvJLAgABBAEG8ksCAADYCyJLAgABBAEG8ksCAADYCxJLAgABBAEHEksCAADYC0JLAgABBAEHMksCAADYC2JLAgABBAEHEksCAADYCzJLAgABBAEHMksCAADYC1JLAgABBAEHUksCAADYC4JLAgABBAEHcksCAADYC6JLAgABBAEHUksCAADYC3JLAgABBAEHcksCAADYC5JLAgABBAEHkksCAADYC8JLAgABBAEHkksCAADYC7JLAgABBAEHsksCAADYC+JLAgABBAEHsksCAADYC9JLAgABBAEH0ksCAADYCgJPAgABBAEH0ksCAADYC/JLAgABBAEH8ksCAADYCiJPAgABBAEH8ksCAADYChJPAgABBAEGEk8CAADYCkJPAgABBAEGEk8CAADYCjJPAgABBAEGMk8CAADYCmJPAgABBAEGMk8CAADYClJPAgABBAEGUk8CAADYCoJPAgABBAEGUk8CAADYCnJPAgABBAEGck8CAADYCqJPAgABBAEGkk8CAADYCsJPAgABBAEGck8CAADYCpJPAgABBAEGsk8CAADYCuJPAgABBAEGkk8CAADYCrJPAgABBAEG0k8CAADYCwJPAgABBAEGsk8CAADYCtJPAgABBAEG8k8CAADYCyJPAgABBAEG0k8CAADYCvJPAgABBAEHEk8CAADYC0JPAgABBAEG8k8CAADYCxJPAgABBAEHMk8CAADYC2JPAgABBAEHEk8CAADYCzJPAgABBACAGQQ9qQXhxIgBBeGoiAjYC8JPAgABB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fv///1f9///5AwAA3AIAAGACAAD6+f//mwEAADP////d+f//xwQAAIwCAADY/f//9wMAAPP6///TBQAA5v7///j5//8EAgAA+P///8D+//9m/f//rvn//3b7//9+AAAAvQUAAKv8//+m////8f7//z4DAABrAAAAc/r//wn///9J/P//cv7//8EDAAAc+v//K/3//8ABAADX+///pQIAAAX7//+x+///rgEAACsCAABLAwAAHfv//2cDAAAOBgAAaQAAAKYBAABLAgAAsQAAABX////d/v//NP7//yYGAAB1BgAACv///woDAACHBAAAbf////f8///LBQAApv3//18EAADK+f//hAIAAJj8//9dAQAAogEAAEkBAABk////tf///zEDAABJBAAAWwIAAGICAAAqBQAA+/r//0f6//+AAQAAQfv//3j////CBAAAyfr//5b8///cAAAAXfv//4X5//9f+///Bvr//wL7//8aAwAAGvr//6r8//+a/P//3gEAAJT////M/v//5AMAAN8DAAC+AwAATPr///IFAABcBgAAAAAAAAEAAAAAAAAAgoAAAAAAAACKgAAAAAAAgACAAIAAAACAi4AAAAAAAAABAACAAAAAAIGAAIAAAACACYAAAAAAAICKAAAAAAAAAIgAAAAAAAAACYAAgAAAAAAKAACAAAAAAIuAAIAAAAAAiwAAAAAAAICJgAAAAAAAgAOAAAAAAACAAoAAAAAAAICAAAAAAAAAgAqAAAAAAAAACgAAgAAAAICBgACAAAAAgICAAAAAAACAAQAAgAAAAAAIgACAAAAAgAoAAAAHAAAACwAAABEAAAASAAAAAwAAAAUAAAAQAAAACAAAABUAAAAYAAAABAAAAA8AAAAXAAAAEwAAAA0AAAAMAAAAAgAAABQAAAAOAAAAFgAAAAkAAAAGAAAAAQAAAAEAAAADAAAABgAAAAoAAAAPAAAAFQAAABwAAAAkAAAALQAAADcAAAACAAAADgAAABsAAAApAAAAOAAAAAgAAAAZAAAAKwAAAD4AAAASAAAAJwAAAD0AAAAUAAAALAAAAAIAAAAMAAAABAAAAAMAAAAEAAAABQAAAAAAAAAIAAAABAAAAAYAAAAHAAAACAAAAAkAAAAKAAAAEAAAAAQAAAALAAAADAAAAA0AAAAOAAAAXPbpX9wC9rnxwXBs8mHBJDs3TUqCEEUJw6Vh0T8gOo9hc3NlcnRpb24gZmFpbGVkOiBwc2l6ZSA+PSBzaXplICsgbWluX292ZXJoZWFkAACXARAAKgAAAOkEAAAJAAAAYXNzZXJ0aW9uIGZhaWxlZDogcHNpemUgPD0gc2l6ZSArIG1heF9vdmVyaGVhZAAAlwEQACoAAADvBAAADQAAAJcBEAAqAAAATQUAAB4AAAByd2xvY2sgb3ZlcmZsb3dlZCByZWFkIGxvY2tzzwAQAF0AAAAYAAAALAAAAAAAAAAIAAAABAAAAA8AAAACAAAADAAAAAQAAAAQAAAAcndsb2NrIGhhcyBub3QgYmVlbiBsb2NrZWQgZm9yIHJlYWRpbmcAAM8AEABdAAAAQQAAAAkAAABjYXBhY2l0eSBvdmVyZmxvdwAAAEYBEABQAAAAHAAAAAUAAAAwMDAxMDIwMzA0MDUwNjA3MDgwOTEwMTExMjEzMTQxNTE2MTcxODE5MjAyMTIyMjMyNDI1MjYyNzI4MjkzMDMxMzIzMzM0MzUzNjM3MzgzOTQwNDE0MjQzNDQ0NTQ2NDc0ODQ5NTA1MTUyNTM1NDU1NTY1NzU4NTk2MDYxNjI2MzY0NjU2NjY3Njg2OTcwNzE3MjczNzQ3NTc2Nzc3ODc5ODA4MTgyODM4NDg1ODY4Nzg4ODk5MDkxOTI5Mzk0OTU5Njk3OTg5OWF0dGVtcHQgdG8gZGl2aWRlIGJ5IHplcm8AQcSQwAALzAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQD/DwAAAP8tBG5hbWUAGBdwZWVydmF1bHRfbWxrZW03Njgud2FzbQG2LVkANl9STnZOdENzNnFrUE80VlhhdF8xOHBlZXJ2YXVsdF9tbGtlbTc2ODZrZWNjYWs3a2VjY2FrZgE3X1JOdk50Q3M2cWtQTzRWWGF0XzE4cGVlcnZhdWx0X21sa2VtNzY4M2tlbTEwZ2VuX21hdHJpeAI4X1JOdk50Q3M2cWtQTzRWWGF0XzE4cGVlcnZhdWx0X21sa2VtNzY4NHBvbHkxMHNhbXBsZV9udHQDQF9STnZOdENzNnFrUE80VlhhdF8xOHBlZXJ2YXVsdF9tbGtlbTc2ODNrZW0xOWRlY2Fwc3VsYXRlX2NoZWNrZWQEN19STnZOdENzNnFrUE80VlhhdF8xOHBlZXJ2YXVsdF9tbGtlbTc2ODZrZWNjYWs4c2hhM18yNTYFN19STnZOdENzNnFrUE80VlhhdF8xOHBlZXJ2YXVsdF9tbGtlbTc2ODZrZWNjYWs4c2hhM181MTIGM19STnZOdENzNnFrUE80VlhhdF8xOHBlZXJ2YXVsdF9tbGtlbTc2ODNrZW03ZW5jcnlwdAczX1JOdk50Q3M2cWtQTzRWWGF0XzE4cGVlcnZhdWx0X21sa2VtNzY4M2tlbTdkZWNyeXB0CDdfUk52TnRDczZxa1BPNFZYYXRfMThwZWVydmF1bHRfbWxrZW03Njg2a2VjY2FrOHNoYWtlMjU2CTBfUk52TnRDczZxa1BPNFZYYXRfMThwZWVydmF1bHRfbWxrZW03Njg0cG9seTNudHQKOV9STnZOdENzNnFrUE80VlhhdF8xOHBlZXJ2YXVsdF9tbGtlbTc2ODRwb2x5MTFiYXNlbXVsX2FjYwszX1JOdk50Q3M2cWtQTzRWWGF0XzE4cGVlcnZhdWx0X21sa2VtNzY4NHBvbHk2aW52bnR0DDFfUk52TnRDczZxa1BPNFZYYXRfMThwZWVydmF1bHRfbWxrZW03Njg0cG9seTRjYmQyDTNfUk52TnRDczZxa1BPNFZYYXRfMThwZWVydmF1bHRfbWxrZW03Njgza2VtN2tleXBhaXIOFHB2X21sa2VtNzY4X2N0X2J5dGVzDxVwdl9tbGtlbTc2OF9jdF9vZmZzZXQQF3B2X21sa2VtNzY4X2RlY2Fwc3VsYXRlERdwdl9tbGtlbTc2OF9lbmNhcHN1bGF0ZRITcHZfbWxrZW03Njhfa2V5cGFpchMUcHZfbWxrZW03NjhfbV9vZmZzZXQUFHB2X21sa2VtNzY4X3BrX2J5dGVzFRVwdl9tbGtlbTc2OF9wa19vZmZzZXQWF3B2X21sa2VtNzY4X3NlZWRfb2Zmc2V0FxRwdl9tbGtlbTc2OF9za19ieXRlcxgVcHZfbWxrZW03Njhfc2tfb2Zmc2V0GRRwdl9tbGtlbTc2OF9zc19ieXRlcxoVcHZfbWxrZW03Njhfc3Nfb2Zmc2V0GxVwdl9tbGtlbTc2OF93b3Jrc3BhY2UcKl9STnZDczVmR0hqeldYUmF2XzdfX19ydXN0YzEyX19fcnVzdF9hbGxvYx0sX1JOdkNzNWZHSGp6V1hSYXZfN19fX3J1c3RjMTRfX19ydXN0X2RlYWxsb2MeLF9STnZDczVmR0hqeldYUmF2XzdfX19ydXN0YzE0X19fcnVzdF9yZWFsbG9jH0FfUk52Q3M1ZkdIanpXWFJhdl83X19fcnVzdGMzNV9fX3J1c3Rfbm9fYWxsb2Nfc2hpbV9pc191bnN0YWJsZV92MiAwX1JOdkNzNWZHSGp6V1hSYXZfN19fX3J1c3RjMThfX19ydXN0X3N0YXJ0X3BhbmljIWFfUklOdk50Q3M0TklleHdWMUZHWF80Y29yZTNwdHI5ZHJvcF9nbHVlTnROdENzNUpIZmVXZVFLMHhfNWFsbG9jNnN0cmluZzZTdHJpbmdFQ3NpdVN3bW9RcjA4Y18zc3RkInJfUklOdk50Q3M0TklleHdWMUZHWF80Y29yZTNwdHI5ZHJvcF9nbHVlTnROdk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzEzcGFuaWNfaGFuZGxlcjE5Rm9ybWF0U3RyaW5nUGF5bG9hZEVCSF8jhAFfUklOdk52TXMyX050Q3M1SkhmZVdlUUsweF81YWxsb2M3cmF3X3ZlY0lOdEI4XzExUmF3VmVjSW5uZXJwRTdyZXNlcnZlMjFkb19yZXNlcnZlX2FuZF9oYW5kbGVOdE50QmFfNWFsbG9jNkdsb2JhbEVDc2l1U3dtb1FyMDhjXzNzdGQkZF9SSU52TnROdENzaXVTd21vUXIwOGNfM3N0ZDNzeXM5YmFja3RyYWNlMjZfX19ydXN0X2VuZF9zaG9ydF9iYWNrdHJhY2VOQ052TnRCNl81YWxsb2M4cnVzdF9vb20wekVCNl8lLV9STkNOdk50Q3NpdVN3bW9RcjA4Y18zc3RkNWFsbG9jOHJ1c3Rfb29tMEI1XyZuX1JJTnZOdE50Q3NpdVN3bW9RcjA4Y18zc3RkM3N5czliYWNrdHJhY2UyNl9fX3J1c3RfZW5kX3Nob3J0X2JhY2t0cmFjZU5DTnZOdEI2XzlwYW5pY2tpbmcxM3BhbmljX2hhbmRsZXIwekVCNl8nN19STkNOdk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzEzcGFuaWNfaGFuZGxlcjBCNV8oV19STnZNczVfTnRDczVKSGZlV2VRSzB4XzVhbGxvYzdyYXdfdmVjTnRCNV8xMVJhd1ZlY0lubmVyMTFmaW5pc2hfZ3Jvd0NzaXVTd21vUXIwOGNfM3N0ZCkzX1JOdk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzE1cGFuaWNfd2l0aF9ob29rKjhfUk52TnRDc2l1U3dtb1FyMDhjXzNzdGQ1YWxsb2MyNGRlZmF1bHRfYWxsb2NfZXJyb3JfaG9vaysnX1JOdkNzNWZHSGp6V1hSYXZfN19fX3J1c3RjMTBydXN0X3BhbmljLClfUk52Q3M1ZkdIanpXWFJhdl83X19fcnVzdGMxMV9fX3JkbF9hbGxvYy1nX1JOdk1zMF9OdENzYnc2NEl3N1c5SG5fOGRsbWFsbG9jOGRsbWFsbG9jSU50QjVfOERsbWFsbG9jTnROdEI3XzNzeXM2U3lzdGVtRThtZW1hbGlnbkNzaXVTd21vUXIwOGNfM3N0ZC5lX1JOdk1zMF9OdENzYnc2NEl3N1c5SG5fOGRsbWFsbG9jOGRsbWFsbG9jSU50QjVfOERsbWFsbG9jTnROdEI3XzNzeXM2U3lzdGVtRTZtYWxsb2NDc2l1U3dtb1FyMDhjXzNzdGQvKl9STnZDczVmR0hqeldYUmF2XzdfX19ydXN0YzEyX19fcnVzdF9hYm9ydDArX1JOdkNzNWZHSGp6V1hSYXZfN19fX3J1c3RjMTNfX19yZGxfZGVhbGxvYzFjX1JOdk1zMF9OdENzYnc2NEl3N1c5SG5fOGRsbWFsbG9jOGRsbWFsbG9jSU50QjVfOERsbWFsbG9jTnROdEI3XzNzeXM2U3lzdGVtRTRmcmVlQ3NpdVN3bW9RcjA4Y18zc3RkMitfUk52Q3M1ZkdIanpXWFJhdl83X19fcnVzdGMxM19fX3JkbF9yZWFsbG9jM2xfUk52TXMwX050Q3NidzY0SXc3VzlIbl84ZGxtYWxsb2M4ZGxtYWxsb2NJTnRCNV84RGxtYWxsb2NOdE50QjdfM3N5czZTeXN0ZW1FMTJ1bmxpbmtfY2h1bmtDc2l1U3dtb1FyMDhjXzNzdGQ0bV9STnZNczBfTnRDc2J3NjRJdzdXOUhuXzhkbG1hbGxvYzhkbG1hbGxvY0lOdEI1XzhEbG1hbGxvY050TnRCN18zc3lzNlN5c3RlbUUxM2Rpc3Bvc2VfY2h1bmtDc2l1U3dtb1FyMDhjXzNzdGQ1Ll9STnZDczVmR0hqeldYUmF2XzdfX19ydXN0YzE3cnVzdF9iZWdpbl91bndpbmQ2OF9STnZDczVmR0hqeldYUmF2XzdfX19ydXN0YzI2X19fcnVzdF9hbGxvY19lcnJvcl9oYW5kbGVyNydfUk52TnRDc2l1U3dtb1FyMDhjXzNzdGQ1YWxsb2M4cnVzdF9vb204cl9STnZNczBfTnRDc2J3NjRJdzdXOUhuXzhkbG1hbGxvYzhkbG1hbGxvY0lOdEI1XzhEbG1hbGxvY050TnRCN18zc3lzNlN5c3RlbUUxOGluc2VydF9sYXJnZV9jaHVua0NzaXVTd21vUXIwOGNfM3N0ZDk6X1JOdk50TnRDc2l1U3dtb1FyMDhjXzNzdGQ5cGFuaWNraW5nMTFwYW5pY19jb3VudDhpbmNyZWFzZTpnX1JOdlhOdENzNE5JZXh3VjFGR1hfNGNvcmUzYW55TnROdENzNUpIZmVXZVFLMHhfNWFsbG9jNnN0cmluZzZTdHJpbmdOdEIyXzNBbnk3dHlwZV9pZENzaXVTd21vUXIwOGNfM3N0ZDtDX1JOdlhOdENzNE5JZXh3VjFGR1hfNGNvcmUzYW55UmVOdEIyXzNBbnk3dHlwZV9pZENzaXVTd21vUXIwOGNfM3N0ZDx4X1JOdlhzMF9Odk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzEzcGFuaWNfaGFuZGxlck50QjVfMTlGb3JtYXRTdHJpbmdQYXlsb2FkTnROdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10N0Rpc3BsYXkzZm10PX1fUk52WHMxX052TnRDc2l1U3dtb1FyMDhjXzNzdGQ5cGFuaWNraW5nMTNwYW5pY19oYW5kbGVyTnRCNV8xNlN0YXRpY1N0clBheWxvYWROdE50Q3M0TklleHdWMUZHWF80Y29yZTVwYW5pYzEyUGFuaWNQYXlsb2FkM2dldD6AAV9STnZYczFfTnZOdENzaXVTd21vUXIwOGNfM3N0ZDlwYW5pY2tpbmcxM3BhbmljX2hhbmRsZXJOdEI1XzE2U3RhdGljU3RyUGF5bG9hZE50TnRDczROSWV4d1YxRkdYXzRjb3JlNXBhbmljMTJQYW5pY1BheWxvYWQ2YXNfc3RyP4IBX1JOdlhzMV9Odk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzEzcGFuaWNfaGFuZGxlck50QjVfMTZTdGF0aWNTdHJQYXlsb2FkTnROdENzNE5JZXh3VjFGR1hfNGNvcmU1cGFuaWMxMlBhbmljUGF5bG9hZDh0YWtlX2JveEB1X1JOdlhzMl9Odk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzEzcGFuaWNfaGFuZGxlck50QjVfMTZTdGF0aWNTdHJQYXlsb2FkTnROdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10N0Rpc3BsYXkzZm10QV5fUk52WHNaX050Q3M1SkhmZVdlUUsweF81YWxsb2M2c3RyaW5nTnRCNV82U3RyaW5nTnROdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10NVdyaXRlMTB3cml0ZV9jaGFyQlxfUk52WHNaX050Q3M1SkhmZVdlUUsweF81YWxsb2M2c3RyaW5nTnRCNV82U3RyaW5nTnROdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10NVdyaXRlOXdyaXRlX3N0ckN/X1JOdlhzX052TnRDc2l1U3dtb1FyMDhjXzNzdGQ5cGFuaWNraW5nMTNwYW5pY19oYW5kbGVyTnRCNF8xOUZvcm1hdFN0cmluZ1BheWxvYWROdE50Q3M0TklleHdWMUZHWF80Y29yZTVwYW5pYzEyUGFuaWNQYXlsb2FkM2dldESEAV9STnZYc19Odk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzEzcGFuaWNfaGFuZGxlck50QjRfMTlGb3JtYXRTdHJpbmdQYXlsb2FkTnROdENzNE5JZXh3VjFGR1hfNGNvcmU1cGFuaWMxMlBhbmljUGF5bG9hZDh0YWtlX2JveEV1X1JOdllJTnROdk50Q3NpdVN3bW9RcjA4Y18zc3RkOXBhbmlja2luZzExYmVnaW5fcGFuaWM3UGF5bG9hZFJlRU50TnRDczROSWV4d1YxRkdYXzRjb3JlNXBhbmljMTJQYW5pY1BheWxvYWQ2YXNfc3RyQjlfRmhfUk52WU50TnRDczVKSGZlV2VRSzB4XzVhbGxvYzZzdHJpbmc2U3RyaW5nTnROdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10NVdyaXRlOXdyaXRlX2ZtdENzaXVTd21vUXIwOGNfM3N0ZEdFX1JOdlhzX050Q3NidzY0SXc3VzlIbl84ZGxtYWxsb2Mzc3lzTnRCNF82U3lzdGVtTnRCNl85QWxsb2NhdG9yNWFsbG9jSDBfUk52TnRDczVKSGZlV2VRSzB4XzVhbGxvYzdyYXdfdmVjMTJoYW5kbGVfZXJyb3JJNF9STnZOdENzNUpIZmVXZVFLMHhfNWFsbG9jNWFsbG9jMThoYW5kbGVfYWxsb2NfZXJyb3JKNV9STnZOdENzNUpIZmVXZVFLMHhfNWFsbG9jN3Jhd192ZWMxN2NhcGFjaXR5X292ZXJmbG93SylfUk52TnRDczROSWV4d1YxRkdYXzRjb3JlOXBhbmlja2luZzVwYW5pY0w4X1JOdlhzMWlfTnRDczROSWV4d1YxRkdYXzRjb3JlM2ZtdFJlTnRCNl83RGlzcGxheTNmbXRCOF9NI19STnZOdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10NXdyaXRlTi1fUk52TnRDczROSWV4d1YxRkdYXzRjb3JlOXBhbmlja2luZzlwYW5pY19mbXRPOV9STnZOdE50Q3M0TklleHdWMUZHWF80Y29yZTVzbGljZTVpbmRleDE2c2xpY2VfaW5kZXhfZmFpbFA3X1JOdk50Q3M0TklleHdWMUZHWF80Y29yZTlwYW5pY2tpbmcxOHBhbmljX2JvdW5kc19jaGVja1E+X1JOdk1zYV9OdENzNE5JZXh3VjFGR1hfNGNvcmUzZm10TnRCNV85Rm9ybWF0dGVyMTJwYWRfaW50ZWdyYWxSNV9STnZOdE50Q3M0TklleHdWMUZHWF80Y29yZTNzdHI1Y291bnQxNGRvX2NvdW50X2NoYXJzU05fUk52TnZNc2FfTnRDczROSWV4d1YxRkdYXzRjb3JlM2ZtdE50QjdfOUZvcm1hdHRlcjEycGFkX2ludGVncmFsMTJ3cml0ZV9wcmVmaXhUNF9STnZNc2FfTnRDczROSWV4d1YxRkdYXzRjb3JlM2ZtdE50QjVfOUZvcm1hdHRlcjNwYWRVOl9STnZNc2FfTnRDczROSWV4d1YxRkdYXzRjb3JlM2ZtdE50QjVfOUZvcm1hdHRlcjl3cml0ZV9zdHJWP19STnZYczhfTnROdE50Q3M0TklleHdWMUZHWF80Y29yZTNmbXQzbnVtM2ltcG1OdEI5XzdEaXNwbGF5M2ZtdFcvX1JOdk50Q3M0TklleHdWMUZHWF80Y29yZTZvcHRpb24xM2V4cGVjdF9mYWlsZWRYS19STnZOdE50Q3M0TklleHdWMUZHWF80Y29yZTlwYW5pY2tpbmcxMXBhbmljX2NvbnN0MjNwYW5pY19jb25zdF9kaXZfYnlfemVybwcSAQAPX19zdGFja19wb2ludGVyCRECAAcucm9kYXRhAQUuZGF0YQBNCXByb2R1Y2VycwIIbGFuZ3VhZ2UBBFJ1c3QADHByb2Nlc3NlZC1ieQEFcnVzdGMdMS45OS4xICg1OGNmOGY5YzMgMjAyNi0xMC0xMykAlAEPdGFyZ2V0X2ZlYXR1cmVzCCsLYnVsay1tZW1vcnkrD2J1bGstbWVtb3J5LW9wdCsWY2FsbC1pbmRpcmVjdC1vdmVybG9uZysKbXVsdGl2YWx1ZSsPbXV0YWJsZS1nbG9iYWxzKxNub250cmFwcGluZy1mcHRvaW50Kw9yZWZlcmVuY2UtdHlwZXMrCHNpZ24tZXh0";

// src/mlkem.ts
var MLKEM768_PUBLIC_KEY_BYTES = 1184;
var MLKEM768_SECRET_KEY_BYTES = 2400;
var MLKEM768_CIPHERTEXT_BYTES = 1088;
var MLKEM768_SHARED_SECRET_BYTES = 32;
var MLKEM768_SEED_BYTES = 64;
var textEncoder = new TextEncoder();
function base64ToBytes(value) {
  if (typeof atob === "function") {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  const nodeBuffer = globalThis.Buffer;
  if (nodeBuffer) return new Uint8Array(nodeBuffer.from(value, "base64"));
  throw new Error("PeerVault: no base64 decoder is available for the ML-KEM module");
}
function toArrayBuffer(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
function randomBytes(length) {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== "function") {
    throw new Error("PeerVault: secure random numbers are unavailable");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}
var instancePromise = null;
var MlKem768 = class _MlKem768 {
  constructor(exports2, workspaceOffset, seedOffset, publicKeyOffset, secretKeyOffset, messageOffset, ciphertextOffset, sharedSecretOffset) {
    this.exports = exports2;
    this.workspaceOffset = workspaceOffset;
    this.seedOffset = seedOffset;
    this.publicKeyOffset = publicKeyOffset;
    this.secretKeyOffset = secretKeyOffset;
    this.messageOffset = messageOffset;
    this.ciphertextOffset = ciphertextOffset;
    this.sharedSecretOffset = sharedSecretOffset;
  }
  exports;
  workspaceOffset;
  seedOffset;
  publicKeyOffset;
  secretKeyOffset;
  messageOffset;
  ciphertextOffset;
  sharedSecretOffset;
  static load() {
    if (!instancePromise) {
      instancePromise = _MlKem768.instantiate().catch((error) => {
        instancePromise = null;
        throw error;
      });
    }
    return instancePromise;
  }
  static async instantiate() {
    if (typeof WebAssembly === "undefined") {
      throw new Error("PeerVault: WebAssembly is required for ML-KEM-768");
    }
    const bytes = base64ToBytes(MLKEM768_WASM_BASE64);
    const { instance } = await WebAssembly.instantiate(toArrayBuffer(bytes), {});
    const exports2 = instance.exports;
    if (exports2.pv_mlkem768_pk_bytes() !== MLKEM768_PUBLIC_KEY_BYTES || exports2.pv_mlkem768_sk_bytes() !== MLKEM768_SECRET_KEY_BYTES || exports2.pv_mlkem768_ct_bytes() !== MLKEM768_CIPHERTEXT_BYTES) {
      throw new Error("PeerVault: ML-KEM wasm module reports unexpected sizes");
    }
    const workspace = exports2.pv_mlkem768_workspace();
    return new _MlKem768(
      exports2,
      workspace,
      workspace + exports2.pv_mlkem768_seed_offset(),
      workspace + exports2.pv_mlkem768_pk_offset(),
      workspace + exports2.pv_mlkem768_sk_offset(),
      workspace + exports2.pv_mlkem768_m_offset(),
      workspace + exports2.pv_mlkem768_ct_offset(),
      workspace + exports2.pv_mlkem768_ss_offset()
    );
  }
  view() {
    return new Uint8Array(this.exports.memory.buffer);
  }
  generateKeyPair(seed) {
    const seedBytes = seed ?? randomBytes(MLKEM768_SEED_BYTES);
    if (seedBytes.byteLength !== MLKEM768_SEED_BYTES) {
      throw new Error(`ML-KEM-768 key generation needs ${MLKEM768_SEED_BYTES} seed bytes`);
    }
    const memory = this.view();
    memory.set(seedBytes, this.seedOffset);
    if (this.exports.pv_mlkem768_keypair() !== 0) {
      throw new Error("ML-KEM-768 key generation failed");
    }
    return {
      publicKey: memory.slice(this.publicKeyOffset, this.publicKeyOffset + MLKEM768_PUBLIC_KEY_BYTES),
      secretKey: memory.slice(this.secretKeyOffset, this.secretKeyOffset + MLKEM768_SECRET_KEY_BYTES)
    };
  }
  encapsulate(publicKey, message) {
    if (publicKey.byteLength !== MLKEM768_PUBLIC_KEY_BYTES) {
      throw new Error(`ML-KEM-768 public key must be ${MLKEM768_PUBLIC_KEY_BYTES} bytes`);
    }
    const m = message ?? randomBytes(32);
    if (m.byteLength !== 32) throw new Error("ML-KEM-768 encapsulation message must be 32 bytes");
    const memory = this.view();
    memory.set(publicKey, this.publicKeyOffset);
    memory.set(m, this.messageOffset);
    if (this.exports.pv_mlkem768_encapsulate() !== 0) {
      throw new Error("ML-KEM-768 encapsulation failed");
    }
    return {
      ciphertext: memory.slice(this.ciphertextOffset, this.ciphertextOffset + MLKEM768_CIPHERTEXT_BYTES),
      sharedSecret: memory.slice(
        this.sharedSecretOffset,
        this.sharedSecretOffset + MLKEM768_SHARED_SECRET_BYTES
      )
    };
  }
  decapsulate(ciphertext, secretKey) {
    if (ciphertext.byteLength !== MLKEM768_CIPHERTEXT_BYTES) {
      throw new Error(`ML-KEM-768 ciphertext must be ${MLKEM768_CIPHERTEXT_BYTES} bytes`);
    }
    if (secretKey.byteLength !== MLKEM768_SECRET_KEY_BYTES) {
      throw new Error(`ML-KEM-768 secret key must be ${MLKEM768_SECRET_KEY_BYTES} bytes`);
    }
    const memory = this.view();
    memory.set(ciphertext, this.ciphertextOffset);
    memory.set(secretKey, this.secretKeyOffset);
    const valid = this.exports.pv_mlkem768_decapsulate() === 0;
    return {
      sharedSecret: memory.slice(
        this.sharedSecretOffset,
        this.sharedSecretOffset + MLKEM768_SHARED_SECRET_BYTES
      ),
      valid
    };
  }
};

// src/hybrid-handshake.ts
var PROTOCOL_VERSION = 1;
var encoder = new TextEncoder();
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function base64UrlToBytes(value) {
  let base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function toArrayBuffer2(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
async function hmacSha256(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer2(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  return new Uint8Array(signature);
}
async function sha256(message) {
  const bytes = encoder.encode(message);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer2(bytes)));
}
function helloCanonical(ecdh, mlkem, nonce) {
  return `pv-hybrid-hello|${PROTOCOL_VERSION}|${ecdh}|${mlkem}|${nonce}`;
}
function finishCanonical(ecdh, mlkemCt, confirm) {
  return `pv-hybrid-finish|${PROTOCOL_VERSION}|${ecdh}|${mlkemCt}|${confirm}`;
}
function readyCanonical(confirm) {
  return `pv-hybrid-ready|${PROTOCOL_VERSION}|${confirm}`;
}
function transcriptCanonical(hello, ecdh, mlkemCt) {
  return `pv-hybrid-transcript|${PROTOCOL_VERSION}|${hello}|${ecdh}|${mlkemCt}`;
}
function parseMessage(raw, expectedType) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("PeerVault: hybrid handshake message is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("PeerVault: hybrid handshake message is not an object");
  }
  const message = parsed;
  if (message.type !== expectedType) {
    throw new Error(`PeerVault: expected ${expectedType}, received ${String(message.type)}`);
  }
  if (message.v !== PROTOCOL_VERSION) {
    throw new Error(`PeerVault: unsupported hybrid handshake version ${String(message.v)}`);
  }
  return message;
}
function requiredString(message, field) {
  const value = message[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`PeerVault: hybrid handshake field "${field}" is missing`);
  }
  return value;
}
var HybridHandshake = class _HybridHandshake {
  constructor(role, shareLinkKey, kem) {
    this.role = role;
    this.shareLinkKey = shareLinkKey;
    this.kem = kem;
  }
  role;
  shareLinkKey;
  kem;
  ecdhKeyPair = null;
  ecdhPublic = "";
  mlkemKeyPair = null;
  mlkemPublic = "";
  nonce = null;
  helloCanonical = "";
  sessionKeyBytes = null;
  transcriptHashBytes = null;
  confirmB64 = "";
  ready = false;
  static async create(role, shareLinkKey) {
    if (shareLinkKey.byteLength !== 32) {
      throw new Error("PeerVault: the share-link key must be 32 bytes");
    }
    const kem = await MlKem768.load();
    const handshake = new _HybridHandshake(role, shareLinkKey.slice(), kem);
    handshake.ecdhKeyPair = await PQCrypto.generateECDHKeyPair();
    handshake.ecdhPublic = await PQCrypto.exportPublicKey(handshake.ecdhKeyPair.publicKey);
    if (role === "receiver") {
      handshake.mlkemKeyPair = kem.generateKeyPair();
      handshake.mlkemPublic = bytesToBase64Url(handshake.mlkemKeyPair.publicKey);
      handshake.nonce = crypto.getRandomValues(new Uint8Array(16));
      handshake.helloCanonical = helloCanonical(
        handshake.ecdhPublic,
        handshake.mlkemPublic,
        bytesToBase64Url(handshake.nonce)
      );
    }
    return handshake;
  }
  get isReady() {
    return this.ready;
  }
  get session() {
    if (!this.sessionKeyBytes) throw new Error("PeerVault: hybrid session is not established");
    return this.sessionKeyBytes.slice();
  }
  get transcript() {
    if (!this.transcriptHashBytes) throw new Error("PeerVault: hybrid transcript is not established");
    return this.transcriptHashBytes.slice();
  }
  /** Receiver -> sender. */
  async createHello() {
    if (this.role !== "receiver" || !this.nonce) {
      throw new Error("PeerVault: only the receiver creates a hybrid hello");
    }
    const mac = await hmacSha256(this.shareLinkKey, this.helloCanonical);
    return JSON.stringify({
      type: "pv-hybrid-hello",
      v: PROTOCOL_VERSION,
      ecdh: this.ecdhPublic,
      mlkem: this.mlkemPublic,
      nonce: bytesToBase64Url(this.nonce),
      mac: bytesToBase64Url(mac)
    });
  }
  /** Sender receives the hello and returns the finish message. */
  async acceptHello(raw) {
    if (this.role !== "sender") throw new Error("PeerVault: only the sender accepts a hello");
    if (!this.ecdhKeyPair) throw new Error("PeerVault: sender key pair is missing");
    const message = parseMessage(raw, "pv-hybrid-hello");
    const remoteEcdh = requiredString(message, "ecdh");
    const remoteMlkem = requiredString(message, "mlkem");
    const nonce = requiredString(message, "nonce");
    const mac = requiredString(message, "mac");
    const canonical = helloCanonical(remoteEcdh, remoteMlkem, nonce);
    const expectedMac = await hmacSha256(this.shareLinkKey, canonical);
    if (!timingSafeEqual(expectedMac, base64UrlToBytes(mac))) {
      throw new Error("PeerVault: hybrid hello failed authentication");
    }
    const encapsulation = this.kem.encapsulate(base64UrlToBytes(remoteMlkem));
    const mlkemCt = bytesToBase64Url(encapsulation.ciphertext);
    this.helloCanonical = canonical;
    await this.establish(
      remoteEcdh,
      encapsulation.sharedSecret,
      transcriptCanonical(canonical, this.ecdhPublic, mlkemCt)
    );
    this.confirmB64 = bytesToBase64Url(
      await hmacSha256(this.session, `pv-hybrid-confirm|${PROTOCOL_VERSION}|${bytesToBase64Url(this.transcript)}`)
    );
    const finish = finishCanonical(this.ecdhPublic, mlkemCt, this.confirmB64);
    const finishMac = await hmacSha256(this.shareLinkKey, finish);
    return JSON.stringify({
      type: "pv-hybrid-finish",
      v: PROTOCOL_VERSION,
      ecdh: this.ecdhPublic,
      mlkemCt,
      confirm: this.confirmB64,
      mac: bytesToBase64Url(finishMac)
    });
  }
  /** Receiver accepts the finish message and returns the ready message. */
  async acceptFinish(raw) {
    if (this.role !== "receiver") throw new Error("PeerVault: only the receiver accepts a finish");
    if (!this.mlkemKeyPair) throw new Error("PeerVault: receiver ML-KEM key pair is missing");
    const message = parseMessage(raw, "pv-hybrid-finish");
    const remoteEcdh = requiredString(message, "ecdh");
    const mlkemCt = requiredString(message, "mlkemCt");
    const confirm = requiredString(message, "confirm");
    const mac = requiredString(message, "mac");
    const finish = finishCanonical(remoteEcdh, mlkemCt, confirm);
    const expectedMac = await hmacSha256(this.shareLinkKey, finish);
    if (!timingSafeEqual(expectedMac, base64UrlToBytes(mac))) {
      throw new Error("PeerVault: hybrid finish failed authentication");
    }
    const decapsulation = this.kem.decapsulate(
      base64UrlToBytes(mlkemCt),
      this.mlkemKeyPair.secretKey
    );
    if (!decapsulation.valid) {
      throw new Error("PeerVault: ML-KEM-768 ciphertext failed re-encryption validation");
    }
    await this.establish(
      remoteEcdh,
      decapsulation.sharedSecret,
      transcriptCanonical(this.helloCanonical, remoteEcdh, mlkemCt)
    );
    const expectedConfirm = bytesToBase64Url(
      await hmacSha256(this.session, `pv-hybrid-confirm|${PROTOCOL_VERSION}|${bytesToBase64Url(this.transcript)}`)
    );
    if (!timingSafeEqual(base64UrlToBytes(expectedConfirm), base64UrlToBytes(confirm))) {
      throw new Error("PeerVault: hybrid key confirmation failed");
    }
    this.confirmB64 = confirm;
    this.ready = true;
    const ready = readyCanonical(this.confirmB64);
    const readyMac = await hmacSha256(this.shareLinkKey, ready);
    return JSON.stringify({
      type: "pv-hybrid-ready",
      v: PROTOCOL_VERSION,
      confirm: this.confirmB64,
      mac: bytesToBase64Url(readyMac)
    });
  }
  /** Sender accepts the receiver's key-confirmation message. */
  async acceptReady(raw) {
    if (this.role !== "sender") throw new Error("PeerVault: only the sender accepts ready");
    if (!this.confirmB64) throw new Error("PeerVault: hybrid session is not established");
    const message = parseMessage(raw, "pv-hybrid-ready");
    const confirm = requiredString(message, "confirm");
    const mac = requiredString(message, "mac");
    const canonical = readyCanonical(confirm);
    const expectedMac = await hmacSha256(this.shareLinkKey, canonical);
    if (!timingSafeEqual(expectedMac, base64UrlToBytes(mac))) {
      throw new Error("PeerVault: hybrid ready message failed authentication");
    }
    if (!timingSafeEqual(base64UrlToBytes(confirm), base64UrlToBytes(this.confirmB64))) {
      throw new Error("PeerVault: hybrid ready key confirmation does not match");
    }
    this.ready = true;
  }
  async establish(remoteEcdh, kemSecret, transcriptInput) {
    if (!this.ecdhKeyPair) throw new Error("PeerVault: ECDH key pair is missing");
    const remotePublic = await PQCrypto.importPublicKey(remoteEcdh);
    const transcriptHash = await sha256(transcriptInput);
    const session = await PQCrypto.hybridKeyExchange(
      this.ecdhKeyPair.privateKey,
      remotePublic,
      kemSecret.slice().buffer,
      transcriptHash.slice().buffer
    );
    this.sessionKeyBytes = new Uint8Array(session);
    this.transcriptHashBytes = transcriptHash;
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
  hybridHandshakeEnabled;
  handshakeTimeoutMs;
  handshake = null;
  handshakeInit = null;
  handshakePromise = Promise.resolve();
  handshakeResolve = null;
  handshakeReject = null;
  handshakeTimer = null;
  /** Serialises receiver-requested chunk retransmissions. */
  resendQueue = Promise.resolve();
  constructor(signalingUrl, options) {
    super();
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
    this.iceServers = options?.iceServers;
    this.createRoomTimeoutMs = options?.createRoomTimeoutMs ?? 3e4;
    this.stallTimeoutMs = options?.stallTimeoutMs ?? 12e4;
    this.hybridHandshakeEnabled = options?.hybridHandshake ?? true;
    this.handshakeTimeoutMs = options?.handshakeTimeoutMs ?? 15e3;
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
      dc.onmessage = (event) => {
        if (typeof event.data === "string") this.handleControlMessage(event.data);
      };
      this.handshakePromise = this.beginHybridHandshake();
      void this.startTransfer();
    });
    this.peerConnection.on("error", (err) => {
      this.emit("error", err);
    });
  }
  async beginHybridHandshake() {
    if (!this.hybridHandshakeEnabled) return;
    this.handshakeInit = HybridHandshake.create("sender", this.cryptoEngine.getRawKey());
    const handshake = await this.handshakeInit;
    this.handshake = handshake;
    await new Promise((resolve, reject) => {
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
  handleControlMessage(raw) {
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      this.emit("error", new Error("PeerVault: peer sent an invalid JSON control message"));
      return;
    }
    if (message.type === "pv-hybrid-hello") {
      void this.handleHybridHello(raw);
    } else if (message.type === "pv-hybrid-ready") {
      void this.handleHybridReady(raw);
    } else if (message.type === "pv-request-chunks") {
      const request = message;
      void this.handleChunkRequest(request);
    }
  }
  async handleHybridHello(raw) {
    try {
      const handshake = this.handshake ?? (this.handshakeInit ? await this.handshakeInit : null);
      if (!handshake) throw new Error("PeerVault: received a hybrid hello before setup");
      const finish = await handshake.acceptHello(raw);
      await this.cryptoEngine.deriveHybridTransferKey(handshake.session, handshake.transcript);
      if (!this.dc || this.dc.readyState !== "open") {
        throw new Error("DataChannel closed during the hybrid handshake");
      }
      this.dc.send(finish);
    } catch (error) {
      this.failHandshake(toError(error, "PeerVault: hybrid handshake failed"));
    }
  }
  async handleHybridReady(raw) {
    try {
      const handshake = this.handshake ?? (this.handshakeInit ? await this.handshakeInit : null);
      if (!handshake) throw new Error("PeerVault: received hybrid ready before setup");
      await handshake.acceptReady(raw);
      this.resolveHandshake();
    } catch (error) {
      this.failHandshake(toError(error, "PeerVault: hybrid key confirmation failed"));
    }
  }
  resolveHandshake() {
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    const resolve = this.handshakeResolve;
    this.handshakeResolve = null;
    this.handshakeReject = null;
    if (resolve) resolve();
  }
  failHandshake(error) {
    if (this.handshakeTimer) {
      clearTimeout(this.handshakeTimer);
      this.handshakeTimer = null;
    }
    const reject = this.handshakeReject;
    this.handshakeResolve = null;
    this.handshakeReject = null;
    if (reject) reject(error);
    else this.emit("error", error);
  }
  async startTransfer() {
    if (!this.dc) return;
    try {
      await this.handshakePromise;
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
        await this.transferFile(i, this.files[i].size, metadataList[i].chunks);
      }
      if (!this.isCancelled) {
        this.emit("complete", void 0);
      }
    } catch (err) {
      this.emit("error", toError(err, "PeerVault: transfer failed"));
    }
  }
  async transferFile(fileIndex, totalBytes, totalChunks) {
    let bytesTransferred = 0;
    const file = this.files[fileIndex];
    for (let chunkIndex = 0; chunkIndex < totalChunks && !this.isCancelled; chunkIndex++) {
      await this.sendChunk(file, fileIndex, chunkIndex);
      if (chunkIndex % 256 === 255) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      const start = chunkIndex * CHUNK_SIZE;
      bytesTransferred += Math.min(CHUNK_SIZE, Math.max(0, file.size - start));
      this.emit("progress", {
        fileIndex,
        chunkIndex,
        totalChunks,
        bytesTransferred,
        totalBytes
      });
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
   * Resend specific chunk indices. The receiver calls this through the
   * `pv-request-chunks` control message after persisting a bitmap and
   * reconnecting; each chunk is read from the original File, never buffered.
   */
  async resendChunks(fileIndex, indices) {
    if (!Number.isSafeInteger(fileIndex) || fileIndex < 0 || fileIndex >= this.files.length) {
      throw new RangeError(`fileIndex ${String(fileIndex)} is out of range`);
    }
    if (!Array.isArray(indices) || indices.length === 0) {
      throw new TypeError("indices must be a non-empty array");
    }
    if (indices.length > 4096) {
      throw new RangeError("at most 4096 chunks can be requested at once");
    }
    const file = this.files[fileIndex];
    const totalChunks = this.totalChunks(file);
    const unique = [...new Set(indices)].sort((a, b) => a - b);
    for (const index of unique) {
      if (!Number.isSafeInteger(index) || index < 0 || index >= totalChunks) {
        throw new RangeError(`chunk index ${String(index)} is out of range [0, ${totalChunks})`);
      }
    }
    const run = this.resendQueue.then(async () => {
      for (let offset = 0; offset < unique.length; offset++) {
        await this.sendChunk(file, fileIndex, unique[offset]);
        if (offset % 256 === 255) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }
      return unique.length;
    });
    this.resendQueue = run.then(() => void 0, () => void 0);
    return run;
  }
  totalChunks(file) {
    return file.size === 0 ? 1 : Math.ceil(file.size / CHUNK_SIZE);
  }
  async handleChunkRequest(request) {
    try {
      const fileIndex = Number(request.fileIndex);
      if (!Number.isSafeInteger(fileIndex)) {
        throw new TypeError("pv-request-chunks fileIndex must be an integer");
      }
      if (!Array.isArray(request.indices)) {
        throw new TypeError("pv-request-chunks indices must be an array");
      }
      await this.resendChunks(fileIndex, request.indices.map(Number));
    } catch (error) {
      this.emit("error", toError(error, "PeerVault: chunk resend failed"));
    }
  }
  async sendChunk(file, fileIndex, chunkIndex) {
    const start = chunkIndex * CHUNK_SIZE;
    const end = Math.min(file.size, start + CHUNK_SIZE);
    const chunkData = await file.slice(start, end).arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const header = new Uint8Array(21);
    const headerView = new DataView(header.buffer);
    headerView.setUint8(0, 1);
    headerView.setUint32(1, fileIndex, true);
    headerView.setUint32(5, chunkIndex, true);
    header.set(iv, 9);
    const { ciphertext } = await this.cryptoEngine.encryptChunk(chunkData, header, iv);
    const buffer = new ArrayBuffer(21 + ciphertext.byteLength);
    const u8 = new Uint8Array(buffer);
    u8.set(header, 0);
    u8.set(new Uint8Array(ciphertext), 21);
    await this.waitForDrain();
    if (this.isCancelled) return;
    if (!this.dc || this.dc.readyState !== "open") throw new Error("DataChannel closed");
    this.dc.send(buffer);
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

// src/chunk-bitmap.ts
var MAX_BITMAP_CHUNKS = 1e7;
function assertIndex(index, size) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) {
    throw new RangeError(`chunk index ${String(index)} out of range [0, ${size})`);
  }
}
function bytesToBase64(bytes) {
  let binary = "";
  const window = 32768;
  for (let offset = 0; offset < bytes.length; offset += window) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + window));
  }
  return btoa(binary);
}
function base64ToBytes2(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
var ChunkBitmap = class _ChunkBitmap {
  size;
  bytes;
  constructor(size, bytes) {
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_BITMAP_CHUNKS) {
      throw new RangeError(
        `bitmap size must be an integer in [0, ${MAX_BITMAP_CHUNKS}], received ${String(size)}`
      );
    }
    this.size = size;
    const expected = Math.ceil(size / 8);
    if (bytes === void 0) {
      this.bytes = new Uint8Array(expected);
    } else {
      if (!(bytes instanceof Uint8Array) || bytes.length !== expected) {
        throw new TypeError(`bitmap bytes must be a Uint8Array of length ${expected}`);
      }
      this.bytes = new Uint8Array(bytes);
    }
  }
  mark(index) {
    assertIndex(index, this.size);
    this.bytes[index >> 3] |= 1 << (index & 7);
    return this;
  }
  clear(index) {
    assertIndex(index, this.size);
    this.bytes[index >> 3] &= ~(1 << (index & 7));
    return this;
  }
  has(index) {
    assertIndex(index, this.size);
    return (this.bytes[index >> 3] & 1 << (index & 7)) !== 0;
  }
  get count() {
    let total = 0;
    for (let i = 0; i < this.bytes.length; i++) {
      let value = this.bytes[i];
      value = value - (value >> 1 & 85);
      value = (value & 51) + (value >> 2 & 51);
      total += value + (value >> 4) & 15;
    }
    return total;
  }
  get complete() {
    return this.count === this.size;
  }
  missing(limit = Number.POSITIVE_INFINITY) {
    if (limit !== Number.POSITIVE_INFINITY && (!Number.isSafeInteger(limit) || limit < 0)) {
      throw new RangeError("limit must be a non-negative integer or Infinity");
    }
    const out = [];
    if (limit === 0) return out;
    for (let index = 0; index < this.size; index++) {
      if (!this.has(index)) {
        out.push(index);
        if (out.length >= limit) break;
      }
    }
    return out;
  }
  *missingIterator() {
    for (let index = 0; index < this.size; index++) {
      if (!this.has(index)) yield index;
    }
  }
  toBytes() {
    return new Uint8Array(this.bytes);
  }
  toBase64() {
    return bytesToBase64(this.bytes);
  }
  toJSON() {
    return { size: this.size, base64: this.toBase64() };
  }
  clone() {
    return new _ChunkBitmap(this.size, this.bytes);
  }
  static fromBase64(value, size) {
    if (typeof value !== "string") {
      throw new TypeError("bitmap base64 value must be a string");
    }
    return new _ChunkBitmap(size, base64ToBytes2(value));
  }
  static fromJSON(value) {
    if (!value || typeof value !== "object") {
      throw new TypeError("bitmap JSON must be an object");
    }
    const record = value;
    if (typeof record.base64 !== "string") {
      throw new TypeError("bitmap JSON.base64 must be a string");
    }
    return _ChunkBitmap.fromBase64(record.base64, Number(record.size));
  }
};

// src/file-assembler.ts
var MAX_CHUNKS = 1e6;
function createWritableSink(writable, chunkSize = CHUNK_SIZE) {
  if (!writable || typeof writable.write !== "function" || typeof writable.close !== "function") {
    throw new TypeError("writable must implement write() and close()");
  }
  return {
    async writeChunk(index, data) {
      await writable.write({ type: "write", position: index * chunkSize, data });
    },
    async close() {
      await writable.close();
    }
  };
}
async function createFileSystemSink(suggestedName, chunkSize = CHUNK_SIZE) {
  const picker = globalThis.showSaveFilePicker;
  if (typeof picker !== "function") return null;
  const handle = await picker({ suggestedName });
  const writable = await handle.createWritable();
  return createWritableSink(writable, chunkSize);
}
async function createOpfsSink(fileName, chunkSize = CHUNK_SIZE) {
  if (typeof fileName !== "string" || fileName.length === 0) {
    throw new TypeError("fileName must be a non-empty string");
  }
  const storage = globalThis.navigator?.storage;
  if (!storage || typeof storage.getDirectory !== "function") return null;
  const root = await storage.getDirectory();
  const handle = await root.getFileHandle(fileName, { create: true });
  const writable = await handle.createWritable();
  return createWritableSink(writable, chunkSize);
}
var FileAssembler = class {
  chunks = [];
  bitmap;
  receivedChunks = 0;
  receivedBytes = 0;
  metadata;
  cryptoEngine;
  sink;
  constructor(metadata, cryptoEngine, sink) {
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
    this.bitmap = new ChunkBitmap(declared);
    this.sink = sink;
  }
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
  async addChunk(index, iv, ciphertext, additionalData) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.metadata.chunks) {
      throw new Error(`Chunk index ${String(index)} out of range [0, ${this.metadata.chunks})`);
    }
    if (this.bitmap.has(index)) {
      return this.isComplete();
    }
    const plaintext = await this.cryptoEngine.decryptChunk(iv, ciphertext, additionalData);
    if (this.bitmap.has(index)) return this.isComplete();
    if (this.sink) {
      await this.sink.writeChunk(index, plaintext);
    } else {
      this.chunks[index] = plaintext;
    }
    this.bitmap.mark(index);
    this.receivedChunks++;
    this.receivedBytes += plaintext.byteLength;
    return this.isComplete();
  }
  isComplete() {
    return this.receivedChunks === this.metadata.chunks;
  }
  /** True when chunks are being written directly to a file sink. */
  get streaming() {
    return this.sink !== void 0;
  }
  /** Distinct chunks accepted so far, plus decrypted byte total. */
  get progress() {
    return { received: this.receivedChunks, total: this.metadata.chunks, bytes: this.receivedBytes };
  }
  /** Clone of the received-chunk bitmap, safe for persistence. */
  receivedBitmap() {
    return this.bitmap.clone();
  }
  /**
   * Missing chunk indices, in ascending order. `limit` bounds the returned
   * array; pass Infinity to enumerate everything.
   */
  missingChunks(limit = 1e3) {
    return this.bitmap.missing(limit);
  }
  assemble() {
    if (this.sink) {
      throw new Error("FileAssembler: disk sink active; call finishStreaming() instead");
    }
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
    this.assertByteLength();
    const blob = new Blob(this.chunks, { type: this.metadata.mime });
    const url = URL.createObjectURL(blob);
    return {
      ...this.metadata,
      blob,
      url
    };
  }
  /**
   * Close the disk sink and return metadata for the completed file. No Blob or
   * object URL is created, so peak memory stays at one chunk.
   */
  async finishStreaming() {
    if (!this.sink) {
      throw new Error("FileAssembler: finishStreaming() requires a disk sink");
    }
    if (!this.isComplete()) {
      throw new Error(
        `File incomplete: ${this.receivedChunks} of ${this.metadata.chunks} chunks received`
      );
    }
    this.assertByteLength();
    const sink = this.sink;
    this.sink = void 0;
    await sink.close();
    return {
      ...this.metadata,
      streamed: true
    };
  }
  /** Close an open sink without publishing the file (cancellation path). */
  async abort() {
    const sink = this.sink;
    this.sink = void 0;
    if (sink) {
      try {
        await sink.close();
      } catch {
      }
    }
  }
  assertByteLength() {
    if (this.receivedBytes !== this.metadata.size) {
      throw new Error(
        `File corrupt: assembled ${this.receivedBytes} bytes but metadata declared ${this.metadata.size}`
      );
    }
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
  sinkFactory;
  hybridHandshakeEnabled;
  handshakeTimeoutMs;
  handshake = null;
  handshakeTimer = null;
  metadataList = [];
  assemblers = /* @__PURE__ */ new Map();
  isDownloading = false;
  isCancelled = false;
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
    this.sinkFactory = options?.sinkFactory;
    this.hybridHandshakeEnabled = options?.hybridHandshake ?? true;
    this.handshakeTimeoutMs = options?.handshakeTimeoutMs ?? 15e3;
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
  }
  async connect() {
    this.throwIfCancelled();
    await this.cryptoEngine.importKey(this.keyBase64Url);
    this.throwIfCancelled();
    await this.signaling.connect();
    this.throwIfCancelled();
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
        if (this.isCancelled) {
          dc.close();
          return;
        }
        this.dc = dc;
        this.setupDataChannel(dc);
        void this.beginHybridHandshake(dc);
      });
      this.peerConnection.on("error", (err) => {
        if (this.isCancelled) return;
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
    this.throwIfCancelled();
    if (!this.metadataList.length) throw new Error("No metadata available to download");
    this.isDownloading = true;
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
  requestMissingChunks(fileIndex, limit = 1e3) {
    if (!Number.isSafeInteger(fileIndex) || fileIndex < 0) {
      throw new RangeError(`fileIndex ${String(fileIndex)} is invalid`);
    }
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler) throw new Error(`No assembler for fileIndex ${fileIndex}`);
    if (!this.dc || this.dc.readyState !== "open") {
      throw new Error("PeerVault: data channel is not open");
    }
    const missing = assembler.missingChunks(limit);
    if (missing.length === 0) return 0;
    this.dc.send(
      JSON.stringify({
        type: "pv-request-chunks",
        fileIndex,
        indices: missing
      })
    );
    return missing.length;
  }
  setupDataChannel(dc) {
    dc.onmessage = (event) => {
      if (this.isCancelled) return;
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
  async beginHybridHandshake(dc) {
    if (!this.hybridHandshakeEnabled) return;
    try {
      const handshake = await HybridHandshake.create(
        "receiver",
        this.cryptoEngine.getRawKey()
      );
      if (this.isCancelled) return;
      this.handshake = handshake;
      const hello = await handshake.createHello();
      if (this.isCancelled || dc.readyState !== "open") return;
      dc.send(hello);
      if (this.handshakeTimeoutMs > 0) {
        this.handshakeTimer = setTimeout(() => {
          const error = new Error(
            `PeerVault: hybrid handshake timed out after ${this.handshakeTimeoutMs}ms`
          );
          this.emit("error", error);
          this.failConnect(error);
        }, this.handshakeTimeoutMs);
      }
    } catch (error) {
      const failure = toError2(error, "PeerVault: failed to start the hybrid handshake");
      this.emit("error", failure);
      this.failConnect(failure);
    }
  }
  async handleHybridFinish(raw) {
    try {
      if (!this.handshake) throw new Error("PeerVault: received a hybrid finish before setup");
      const ready = await this.handshake.acceptFinish(raw);
      await this.cryptoEngine.deriveHybridTransferKey(
        this.handshake.session,
        this.handshake.transcript
      );
      if (this.dc && this.dc.readyState === "open") this.dc.send(ready);
      if (this.handshakeTimer) {
        clearTimeout(this.handshakeTimer);
        this.handshakeTimer = null;
      }
    } catch (error) {
      const failure = toError2(error, "PeerVault: hybrid handshake failed");
      this.emit("error", failure);
      this.failConnect(failure);
    }
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
    if (m.type === "pv-hybrid-finish") {
      this.queue = this.queue.then(() => this.handleHybridFinish(raw)).catch((err) => {
        if (this.isCancelled) return;
        this.emit("error", toError2(err, "PeerVault: hybrid handshake failed"));
      });
      return;
    }
    if (m.type === "metadata") {
      if (!Array.isArray(m.files)) {
        throw new Error("PeerVault: metadata message has no files array");
      }
      const files = m.files;
      this.queue = this.queue.then(() => this.setupFiles(files)).catch((err) => {
        if (this.isCancelled) return;
        const error = toError2(err, "PeerVault: failed to prepare files");
        this.emit("error", error);
        this.failConnect(error);
      });
    } else if (m.type === "complete") {
      const fileIndex = Number(m.fileIndex);
      if (!Number.isSafeInteger(fileIndex)) {
        throw new Error(
          `PeerVault: complete message has an invalid fileIndex ${String(m.fileIndex)}`
        );
      }
      this.completeSignalled.add(fileIndex);
      this.queue = this.queue.then(() => this.tryFinishFile(fileIndex)).catch((err) => {
        if (this.isCancelled) return;
        this.emit("error", toError2(err, "PeerVault: failed to finalise file"));
      });
    }
  }
  async setupFiles(files) {
    const assemblers = /* @__PURE__ */ new Map();
    for (let i = 0; i < files.length; i++) {
      let sink;
      if (this.sinkFactory) {
        try {
          sink = await this.sinkFactory(files[i], i) ?? void 0;
        } catch (err) {
          this.emit("error", toError2(err, "PeerVault: failed to open disk sink"));
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
  enqueueChunk(buffer) {
    this.queue = this.queue.then(() => this.handleChunk(buffer)).catch((err) => {
      if (this.isCancelled) return;
      this.emit("error", toError2(err, "PeerVault: failed to process chunk"));
    });
  }
  async handleChunk(buffer) {
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
    const additionalData = new Uint8Array(buffer.slice(0, CHUNK_HEADER_BYTES));
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler) {
      throw new Error(`PeerVault: chunk for unknown fileIndex ${fileIndex}`);
    }
    await assembler.addChunk(chunkIndex, iv, ciphertext, additionalData);
    if (this.isCancelled) return;
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
    if (this.isCancelled) return;
    if (this.emittedFiles.has(fileIndex)) return;
    const assembler = this.assemblers.get(fileIndex);
    if (!assembler || !assembler.isComplete()) return;
    if (!this.completeSignalled.has(fileIndex)) return;
    const receivedFile = assembler.streaming ? await assembler.finishStreaming() : assembler.assemble();
    this.emittedFiles.add(fileIndex);
    this.emit("file_complete", receivedFile);
    if (this.isCancelled) return;
    if (!this.allCompleteEmitted && this.metadataList.length > 0 && this.metadataList.every((_, i) => this.emittedFiles.has(i))) {
      this.allCompleteEmitted = true;
      this.emit("complete", void 0);
    }
  }
  cancel() {
    if (this.isCancelled) return;
    this.isCancelled = true;
    this.isDownloading = false;
    this.pendingChunks = [];
    for (const assembler of this.assemblers.values()) void assembler.abort();
    this.assemblers.clear();
    this.metadataList = [];
    this.completeSignalled.clear();
    this.failConnect(new Error("PeerVault: transfer cancelled"));
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
  throwIfCancelled() {
    if (this.isCancelled) throw new Error("PeerVault: transfer cancelled");
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

// src/datamesh.ts
function bytesToBase642(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToBytes3(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function encodeFloat32(vector) {
  return bytesToBase642(new Uint8Array(vector.buffer, vector.byteOffset, vector.byteLength));
}
function decodeFloat32(value) {
  const bytes = base64ToBytes3(value);
  return new Float32Array(bytes.buffer, bytes.byteOffset, bytes.byteLength / 4);
}
function wins(remote, local) {
  if (remote.version !== local.version) return remote.version > local.version;
  return remote.origin > local.origin;
}
var MeshNode = class {
  nodeId;
  clock = 0;
  vectors = /* @__PURE__ */ new Map();
  memories = /* @__PURE__ */ new Map();
  constructor(nodeId) {
    if (!nodeId) throw new Error("MeshNode requires a nodeId");
    this.nodeId = nodeId;
  }
  upsertVector(id, embedding, metadata) {
    if (embedding.length === 0) throw new Error("embedding must not be empty");
    const entry = {
      id,
      embedding: embedding.slice(),
      metadata,
      version: ++this.clock,
      origin: this.nodeId
    };
    const existing = this.vectors.get(id);
    if (!existing || wins(entry, existing)) this.vectors.set(id, entry);
    return entry;
  }
  upsertMemory(id, text, weight) {
    if (!text.trim()) throw new Error("memory text must not be empty");
    const entry = {
      id,
      text,
      weight,
      version: ++this.clock,
      origin: this.nodeId
    };
    const existing = this.memories.get(id);
    if (!existing || wins(entry, existing)) this.memories.set(id, entry);
    return entry;
  }
  getVector(id) {
    return this.vectors.get(id);
  }
  getMemory(id) {
    return this.memories.get(id);
  }
  get stats() {
    return {
      vectors: this.vectors.size,
      memories: this.memories.size,
      clock: this.clock
    };
  }
  serialize() {
    return {
      nodeId: this.nodeId,
      vectors: [...this.vectors.values()].map((vector) => ({
        id: vector.id,
        embedding: encodeFloat32(vector.embedding),
        metadata: vector.metadata,
        version: vector.version,
        origin: vector.origin
      })),
      memories: [...this.memories.values()].map((memory) => ({ ...memory }))
    };
  }
  apply(state) {
    for (const vector of state.vectors) {
      const entry = {
        id: vector.id,
        embedding: decodeFloat32(vector.embedding),
        metadata: vector.metadata,
        version: vector.version,
        origin: vector.origin
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
  startSync(transport) {
    transport.send(
      JSON.stringify({ type: "datamesh-hello", state: this.serialize() })
    );
  }
  /** Wire this to the DataChannel onmessage handler. */
  handleMessage(raw, transport) {
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      throw new Error("PeerVault datamesh: message is not valid JSON");
    }
    if (!message || message.type !== "datamesh-hello" && message.type !== "datamesh-state") {
      throw new Error("PeerVault datamesh: unknown message type");
    }
    if (!message.state || typeof message.state.nodeId !== "string") {
      throw new Error("PeerVault datamesh: malformed state");
    }
    this.apply(message.state);
    if (message.type === "datamesh-hello") {
      transport.send(
        JSON.stringify({ type: "datamesh-state", state: this.serialize() })
      );
    }
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CHUNK_SIZE,
  ChunkBitmap,
  CryptoEngine,
  DEFAULT_ICE_SERVERS,
  EventEmitter,
  FileAssembler,
  FileChunker,
  HybridHandshake,
  MAX_BITMAP_CHUNKS,
  MAX_CHUNKS,
  MLKEM768_CIPHERTEXT_BYTES,
  MLKEM768_PUBLIC_KEY_BYTES,
  MLKEM768_SECRET_KEY_BYTES,
  MLKEM768_SEED_BYTES,
  MLKEM768_SHARED_SECRET_BYTES,
  MeshNode,
  MlKem768,
  PQCrypto,
  PeerConnection,
  PeerVaultReceiver,
  PeerVaultSender,
  SignalingClient,
  base64UrlToBytes,
  bytesToBase64Url,
  createFileSystemSink,
  createOpfsSink,
  createWritableSink,
  decodeFloat32,
  encodeFloat32,
  textEncoder
});
//# sourceMappingURL=index.js.map