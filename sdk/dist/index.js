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
  PQCrypto: () => PQCrypto,
  PeerVaultReceiver: () => PeerVaultReceiver,
  PeerVaultSender: () => PeerVaultSender
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
  constructor(url) {
    super();
    this.url = url;
  }
  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.onopen = () => {
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
      };
      this.ws.onerror = (error) => {
        this.emit("error", error);
        reject(error);
      };
    });
  }
  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }
  close() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
};

// src/peer-connection.ts
var PeerConnection = class extends EventEmitter {
  pc;
  dc = null;
  signaling;
  isSender;
  constructor(signaling, isSender) {
    super();
    this.signaling = signaling;
    this.isSender = isSender;
    this.pc = new RTCPeerConnection({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
        { urls: "stun:stun.cloudflare.com:3478" }
      ]
    });
    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.signaling.send({
          type: "signal",
          payload: { candidate: event.candidate }
        });
      }
    };
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
  setupDataChannel(dc) {
    dc.binaryType = "arraybuffer";
    dc.onopen = () => {
      this.emit("datachannel_open", dc);
    };
    dc.onerror = (error) => {
      this.emit("error", new Error("DataChannel error: " + error));
    };
  }
  async handleSignalingMessage(msg) {
    if (msg.type !== "signal") return;
    try {
      const payload = msg.payload;
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
      this.emit("error", err);
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
      this.emit("error", err);
    }
  }
  close() {
    if (this.dc) this.dc.close();
    this.pc.close();
  }
};

// src/pq-crypto.ts
var PQCrypto = class {
  static isMLKEMSupported() {
    try {
      return typeof crypto !== "undefined" && typeof crypto.subtle !== "undefined" && "generateKey" in crypto.subtle;
    } catch {
      return false;
    }
  }
  static async generateHybridKeyPair() {
    const ecdh = await this.generateECDHKeyPair();
    let mlkem;
    if (this.isMLKEMSupported()) {
      try {
        mlkem = await crypto.subtle.generateKey(
          { name: "ML-KEM-768" },
          true,
          ["deriveBits"]
        );
      } catch (e) {
        console.warn("ML-KEM generation failed", e);
      }
    }
    return { ecdh, mlkem };
  }
  static async hybridKeyExchange(localPrivate, remotePublic) {
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
  useHybridKeyExchange;
  constructor(options) {
    this.useHybridKeyExchange = options?.useHybridKeyExchange ?? PQCrypto.isMLKEMSupported();
  }
  getCapabilities() {
    return {
      supportsMLKEM: PQCrypto.isMLKEMSupported(),
      supportsECDH: typeof crypto !== "undefined" && !!crypto.subtle,
      supportsAESGCM: typeof crypto !== "undefined" && !!crypto.subtle
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
    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
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
var PeerVaultSender = class extends EventEmitter {
  signaling;
  peerConnection = null;
  cryptoEngine;
  files = [];
  roomId = null;
  dc = null;
  isCancelled = false;
  constructor(signalingUrl) {
    super();
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
    this.signaling.on("message", (msg) => {
      if (msg.type === "room_created" && msg.roomId) {
        this.roomId = msg.roomId;
      } else if (msg.type === "peer_joined") {
        this.emit("recipient_connected", void 0);
        if (this.peerConnection) {
          this.peerConnection.initiateConnection();
        }
      }
    });
    this.signaling.on("error", (err) => this.emit("error", err));
  }
  addFiles(files) {
    this.files.push(...files);
  }
  async createShareLink() {
    await this.signaling.connect();
    return new Promise((resolve, reject) => {
      const handleRoomCreated = async (msg) => {
        if (msg.type === "room_created") {
          this.signaling.off("message", handleRoomCreated);
          try {
            const keyBase64Url = await this.cryptoEngine.generateKey();
            this.setupPeerConnection();
            resolve(`${this.roomId}#${keyBase64Url}`);
          } catch (err) {
            reject(err);
          }
        }
      };
      this.signaling.on("message", handleRoomCreated);
      this.signaling.send({ type: "create_room" });
    });
  }
  setupPeerConnection() {
    this.peerConnection = new PeerConnection(this.signaling, true);
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
      const metadataList = this.files.map((f) => ({
        name: f.name,
        size: f.size,
        mime: f.type,
        chunks: Math.ceil(f.size / (64 * 1024))
      }));
      this.dc.send(JSON.stringify({
        type: "metadata",
        files: metadataList
      }));
      for (let i = 0; i < this.files.length; i++) {
        if (this.isCancelled) break;
        await this.transferFile(i, this.files[i], metadataList[i].chunks);
      }
      if (!this.isCancelled) {
        this.emit("complete", void 0);
      }
    } catch (err) {
      this.emit("error", err);
    }
  }
  async transferFile(fileIndex, file, totalChunks) {
    const chunker = new FileChunker(file);
    let chunkIndex = 0;
    let totalBytes = file.size;
    let bytesTransferred = 0;
    while (!this.isCancelled) {
      const chunkData = await chunker.getNextChunk();
      if (!chunkData) break;
      const { iv, ciphertext } = await this.cryptoEngine.encryptChunk(chunkData);
      const buffer = new ArrayBuffer(1 + 4 + 4 + 12 + ciphertext.byteLength);
      const view = new DataView(buffer);
      const u8 = new Uint8Array(buffer);
      view.setUint8(0, 1);
      view.setUint32(1, fileIndex, true);
      view.setUint32(5, chunkIndex, true);
      u8.set(iv, 9);
      u8.set(new Uint8Array(ciphertext), 21);
      while (this.dc && this.dc.bufferedAmount > 1024 * 1024 * 16) {
        await new Promise((r) => setTimeout(r, 50));
      }
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
    if (!this.isCancelled && this.dc) {
      this.dc.send(JSON.stringify({
        type: "complete",
        fileIndex
      }));
    }
  }
  cancel() {
    this.isCancelled = true;
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
};

// src/file-assembler.ts
var FileAssembler = class {
  chunks = [];
  receivedChunks = 0;
  metadata;
  cryptoEngine;
  constructor(metadata, cryptoEngine) {
    this.metadata = metadata;
    this.cryptoEngine = cryptoEngine;
    this.chunks = new Array(metadata.chunks);
  }
  async addChunk(index, iv, ciphertext) {
    try {
      const plaintext = await this.cryptoEngine.decryptChunk(iv, ciphertext);
      this.chunks[index] = plaintext;
      this.receivedChunks++;
      return this.isComplete();
    } catch (error) {
      console.error(`Failed to decrypt chunk ${index}:`, error);
      throw error;
    }
  }
  isComplete() {
    return this.receivedChunks === this.metadata.chunks;
  }
  assemble() {
    if (!this.isComplete()) {
      throw new Error("File incomplete");
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
var PeerVaultReceiver = class extends EventEmitter {
  signaling;
  peerConnection = null;
  cryptoEngine;
  roomId;
  keyBase64Url;
  dc = null;
  metadataList = [];
  assemblers = /* @__PURE__ */ new Map();
  isDownloading = false;
  resolveConnect = null;
  constructor(signalingUrl, shareLinkData) {
    super();
    const [roomId, key] = shareLinkData.split("#");
    if (!roomId || !key) throw new Error("Invalid share link data");
    this.roomId = roomId;
    this.keyBase64Url = key;
    this.signaling = new SignalingClient(signalingUrl);
    this.cryptoEngine = new CryptoEngine();
  }
  async connect() {
    await this.cryptoEngine.importKey(this.keyBase64Url);
    await this.signaling.connect();
    return new Promise((resolve, reject) => {
      this.resolveConnect = resolve;
      this.peerConnection = new PeerConnection(this.signaling, false);
      this.peerConnection.on("datachannel_open", (dc) => {
        this.dc = dc;
        this.setupDataChannel(dc);
      });
      this.peerConnection.on("error", (err) => {
        this.emit("error", err);
        reject(err);
      });
      this.signaling.send({
        type: "join_room",
        roomId: this.roomId
      });
    });
  }
  async download() {
    if (!this.metadataList.length) throw new Error("No metadata available to download");
    this.isDownloading = true;
  }
  setupDataChannel(dc) {
    dc.onmessage = async (event) => {
      if (typeof event.data === "string") {
        const msg = JSON.parse(event.data);
        if (msg.type === "metadata") {
          this.metadataList = msg.files;
          msg.files.forEach((meta, i) => {
            this.assemblers.set(i, new FileAssembler(meta, this.cryptoEngine));
          });
          if (this.resolveConnect) {
            this.resolveConnect(this.metadataList);
            this.resolveConnect = null;
          }
        } else if (msg.type === "complete") {
          const assembler = this.assemblers.get(msg.fileIndex);
          if (assembler && assembler.isComplete()) {
            const receivedFile = assembler.assemble();
            this.emit("file_complete", receivedFile);
          }
          let allComplete = true;
          for (let i = 0; i < this.metadataList.length; i++) {
            if (!this.assemblers.get(i)?.isComplete()) {
              allComplete = false;
              break;
            }
          }
          if (allComplete) {
            this.emit("complete", void 0);
          }
        }
      } else if (event.data instanceof ArrayBuffer && this.isDownloading) {
        await this.handleChunk(event.data);
      }
    };
  }
  async handleChunk(buffer) {
    const view = new DataView(buffer);
    const u8 = new Uint8Array(buffer);
    const type = view.getUint8(0);
    if (type !== 1) return;
    const fileIndex = view.getUint32(1, true);
    const chunkIndex = view.getUint32(5, true);
    const iv = new Uint8Array(buffer, 9, 12);
    const ciphertext = buffer.slice(21);
    const assembler = this.assemblers.get(fileIndex);
    if (assembler) {
      await assembler.addChunk(chunkIndex, iv, ciphertext);
      const meta = this.metadataList[fileIndex];
      this.emit("progress", {
        fileIndex,
        chunkIndex,
        totalChunks: meta.chunks,
        bytesTransferred: Math.min((chunkIndex + 1) * 64 * 1024, meta.size),
        totalBytes: meta.size
      });
    }
  }
  cancel() {
    if (this.peerConnection) this.peerConnection.close();
    this.signaling.close();
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  PQCrypto,
  PeerVaultReceiver,
  PeerVaultSender
});
//# sourceMappingURL=index.js.map