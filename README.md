# PeerVault

PeerVault is a zero-server, end-to-end encrypted, browser-to-browser file transfer system. It acts as an SDK for dropping in real-time, peer-to-peer file transfers into your applications. It costs nothing to host for file transfers, as all data transfers happen directly between browsers over WebRTC.

## Architecture & Security Model

PeerVault consists of two parts:
1. **TypeScript SDK**: A browser-native library handling file chunking (64KB), streaming, AES-256-GCM encryption, and WebRTC data channels.
2. **Go Signaling Relay**: A lightweight WebSocket server used *only* to exchange WebRTC connection information (SDP offers/answers and ICE candidates).

**Security**: 
- Files are encrypted using the Web Crypto API (`crypto.subtle`) with AES-256-GCM.
- Encryption keys are generated locally and embedded in the share link as a URL fragment (`#key`). URL fragments are never sent to the server.
- The file data *never* touches the Go signaling server. It travels directly between the sender and receiver.

## Usage

### Setup Signaling Server (Go)

```bash
cd relay
go run .
```

### SDK Example

**Sender:**
```typescript
import { PeerVaultSender } from 'peervault';

const sender = new PeerVaultSender('ws://localhost:4002/ws');

// Assuming you have an HTML input type="file"
const fileInput = document.getElementById('file-input') as HTMLInputElement;
sender.addFiles(Array.from(fileInput.files));

const shareLinkData = await sender.createShareLink();
console.log('Send this to the receiver:', shareLinkData);

sender.on('recipient_connected', () => console.log('Recipient joined, starting transfer...'));
sender.on('progress', (p) => console.log(p.bytesTransferred / p.totalBytes));
sender.on('complete', () => console.log('Transfer complete'));
```

**Receiver:**
```typescript
import { PeerVaultReceiver } from 'peervault';

const shareLinkData = 'room_id#key_base64_url'; // Received from sender
const receiver = new PeerVaultReceiver('ws://localhost:4002/ws', shareLinkData);

const metadata = await receiver.connect();
console.log('Incoming files:', metadata);

receiver.on('progress', (p) => console.log(p.bytesTransferred / p.totalBytes));
receiver.on('file_complete', (file) => {
  console.log('Downloaded file:', file.name);
  
  // Trigger download
  const a = document.createElement('a');
  a.href = file.url;
  a.download = file.name;
  a.click();
});

// Start receiving chunks
await receiver.download();
```

## License
AGPL-3.0 - See [LICENSE](LICENSE)

For commercial usage, see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)
