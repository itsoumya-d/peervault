# PeerVault: Zero-Server P2P File Transfer and the Cost of Cloud Storage Lock-In

**By Soumya Debnath**

Cloud storage is a trap. For decades, companies like WeTransfer, Dropbox, and AWS have built empires on a fundamental inefficiency: making you pay for their servers to act as a middleman for your data.

Why do upload limits and subscription tiers exist? Because data centers cost money. Every time you send a file via a traditional cloud service, you are subsidizing their compute, storage, and egress bandwidth costs. But what if the server didn't need to store the file at all?

This essay explores how combining **WebCrypto AES-256-GCM** with **WebRTC DataChannels** allows for zero-server peer-to-peer file transfer directly in the browser.

> **Correction.** An earlier version of this article claimed PeerVault implemented "Post-Quantum Hybrid Encryption (ML-KEM + ECDH)" and streamed chunks to IndexedDB. Neither is true. There is no ML-KEM / Kyber implementation anywhere in the codebase, and the receiver assembles files in memory. The sections below describe what the code actually does.

## The Architecture of Zero-Server File Transfer

PeerVault eliminates the middleman. By leveraging WebRTC Data Channels, data flows directly from the sender's browser to the receiver's browser.

So how is the payload secured, and what is the honest limit of that protection?

### Key Handling (What the Code Actually Does)

PeerVault uses only classical, standardised WebCrypto primitives:

1. **AES-256-GCM** — the payload encryption. The sender generates a random 256-bit key and places it in the share link's URL fragment, which browsers never transmit to a server. The signaling relay therefore never sees the key.
2. **A fresh 96-bit IV per chunk** — generated with `crypto.getRandomValues` inside the encryption call. Reusing a single IV across chunks under one AES-GCM key would leak the XOR of the plaintexts and destroy integrity.
3. **The GCM authentication tag** — detects tampering with any chunk payload.
4. **P-256 ECDH + HKDF-SHA-256** — available in the SDK as `PQCrypto`, but not used by the default share-link transfer path.
5. **No ML-KEM / Kyber** — there is no lattice implementation in this codebase. The transfer is not post-quantum secure and does not address harvest-now-decrypt-later.

### 64KB Chunk Streaming

Loading a very large file into RAM will crash a browser tab. On the *send* side PeerVault avoids this: it uses the File API to read files in **64KB chunks**, encrypts each chunk with its own IV, and streams them over the WebRTC Data Channel, so the sender never holds the whole file.

The *receive* side is the current limitation. Chunks are decrypted and held in memory, then assembled into a `Blob`. Measured peak memory is roughly 1.5x the file size, so multi-gigabyte transfers are bounded by device RAM. Streaming to disk (File System Access API or IndexedDB) is not implemented.

Two other honest limitations are worth stating plainly:

- **No TURN relay.** The ICE configuration ships three public STUN servers and no TURN server, so peers behind symmetric or carrier-grade NAT cannot establish a direct connection. You can pass your own `iceServers` (including TURN) to `PeerVaultSender` and `PeerVaultReceiver`.
- **Transfers are not resumable.** If either tab closes, the transfer must be restarted from the beginning.

## The Cost Matrix: $0 vs The Cloud

| Feature | PeerVault | WeTransfer Pro | AWS S3 |
|---------|-----------|----------------|--------|
| **Monthly Cost** | **$0** | $15/user | Variable (Storage + Egress) |
| **Max File Size** | **Bounded by receiver RAM** | 200 GB | 5 TB (Multipart) |
| **Server Storage** | **None (P2P)** | Centralized Cloud | Centralized Cloud |
| **Encryption** | **E2E AES-256-GCM (classical)** | In-transit / At-rest | Server-Side / Client-Side |

## TypeScript Integration Recipe for AI Agents

For developers and AI coding agents looking to implement PeerVault's core encryption flow, here is a drop-in recipe. Note the IV: it is generated **inside** the loop, once per chunk.

```typescript
// peervault-crypto.ts
// A fresh IV MUST be generated for every chunk. Reusing one IV across chunks
// under the same AES-GCM key leaks the XOR of the plaintexts and destroys
// integrity, so the IV is generated inside the loop and sent with each chunk.
export async function encryptChunk(chunk: ArrayBuffer, key: CryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, chunk);
  return { iv, ciphertext };
}

export async function processFileP2P(file: File, channel: RTCDataChannel, key: CryptoKey) {
  const CHUNK_SIZE = 64 * 1024; // 64KB
  const totalChunks = file.size === 0 ? 1 : Math.ceil(file.size / CHUNK_SIZE);

  channel.send(JSON.stringify({ type: "metadata", size: file.size, chunks: totalChunks }));

  let offset = 0;
  let chunkIndex = 0;
  do {
    const chunkBuffer = await file.slice(offset, offset + CHUNK_SIZE).arrayBuffer();

    // Encrypt locally before it ever touches the network.
    const { iv, ciphertext } = await encryptChunk(chunkBuffer, key);

    // Frame every chunk: [4B chunkIndex][12B IV][ciphertext]. Without an explicit
    // index the receiver cannot detect a dropped or duplicated chunk.
    const framed = new Uint8Array(4 + 12 + ciphertext.byteLength);
    new DataView(framed.buffer).setUint32(0, chunkIndex, true);
    framed.set(iv, 4);
    framed.set(new Uint8Array(ciphertext), 16);
    channel.send(framed);

    offset += CHUNK_SIZE;
    chunkIndex++;
  } while (offset < file.size);

  channel.send(JSON.stringify({ type: "complete", chunks: totalChunks }));
}
```

The receiver must reject an out-of-range `chunkIndex`, ignore duplicates rather than counting them, and verify that the total assembled byte length matches the declared size before handing the file to the user. Counting arrivals instead of distinct indices lets a duplicate chunk mask a missing one and produces a silently corrupt file.

## Links

- [GitHub repository](https://github.com/itsoumya-d/peervault)
- [Homepage](https://itsoumya-d.github.io/peervault/)
- [llms.txt](https://itsoumya-d.github.io/peervault/llms.txt)

By removing the server, we remove the rent-seeking. PeerVault isn't just a product; it's a recalibration of how data should move on the internet.
