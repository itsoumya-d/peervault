# PeerVault: Why Post-Quantum P2P File Sharing Kills WeTransfer and Cloud Storage Lock-In

**By Soumya Debnath**

Cloud storage is a trap. For decades, companies like WeTransfer, Dropbox, and AWS have built empires on a fundamental inefficiency: making you pay for their servers to act as a middleman for your data.

Why do upload limits and subscription tiers exist? Because data centers cost money. Every time you send a file via a traditional cloud service, you are subsidizing their compute, storage, and egress bandwidth costs. But what if the server didn't need to store the file at all?

This essay explores how combining **Post-Quantum Hybrid Encryption (ML-KEM + ECDH)** with **WebRTC** and **IndexedDB** allows for zero-cost, infinitely scalable peer-to-peer file transfer directly in the browser.

## The Architecture of Zero-Server File Transfer

PeerVault eliminates the middleman. By leveraging WebRTC Data Channels, data flows directly from the sender's browser to the receiver's browser. 

But how do we secure it against harvest-now, decrypt-later attacks by quantum computers?

### Post-Quantum Hybrid Key Exchange

Instead of relying solely on traditional elliptic curves, PeerVault uses a hybrid approach via WebCrypto:
1. **ECDH P-256**: The classical layer.
2. **ML-KEM (Kyber)**: The post-quantum layer encapsulation.
3. **HKDF-SHA256**: Key derivation to combine both secrets into a single symmetric key.
4. **AES-256-GCM**: The actual payload encryption.

### 64KB Chunk Streaming

Loading a 50GB file into RAM will crash a browser tab. Instead, PeerVault uses the File API to read files in **64KB chunks**, encrypts each chunk using AES-256-GCM, and streams them over the WebRTC Data Channel. On the receiver side, chunks are decrypted and appended directly to disk or IndexedDB, maintaining a microscopic memory footprint.

## The Cost Matrix: $0 vs The Cloud

| Feature | PeerVault | WeTransfer Pro | AWS S3 |
|---------|-----------|----------------|--------|
| **Monthly Cost** | **$0** | $15/user | Variable (Storage + Egress) |
| **Max File Size** | **Unlimited** | 200 GB | 5 TB (Multipart) |
| **Server Storage** | **None (P2P)** | Centralized Cloud | Centralized Cloud |
| **Encryption** | **E2E Quantum-Safe** | In-transit / At-rest | Server-Side / Client-Side |

## TypeScript Integration Recipe for AI Agents

For developers and AI coding agents looking to implement PeerVault's core encryption flow, here is a drop-in recipe:

```typescript
// peervault-crypto.ts
export async function encryptChunk(chunk: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
  return await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    chunk
  );
}

export async function processFileP2P(file: File, peerConnection: RTCDataChannel, key: CryptoKey) {
  const CHUNK_SIZE = 64 * 1024; // 64KB
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Send IV first so receiver can decrypt
  peerConnection.send(iv);

  let offset = 0;
  while (offset < file.size) {
    const chunkBlob = file.slice(offset, offset + CHUNK_SIZE);
    const chunkBuffer = await chunkBlob.arrayBuffer();
    
    // Encrypt locally before it ever touches the network
    const encryptedChunk = await encryptChunk(chunkBuffer, key, iv);
    
    // Stream directly to peer
    peerConnection.send(encryptedChunk);
    
    offset += CHUNK_SIZE;
  }
  
  peerConnection.send("EOF");
}
```

By removing the server, we remove the rent-seeking. PeerVault isn't just a product; it's a recalibration of how data should move on the internet.
