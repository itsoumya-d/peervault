# Deploying the PeerVault TURN relay

The Go relay only carries signaling. A TURN server is required when either peer
is behind symmetric NAT or carrier-grade NAT. PeerVault does not bundle TURN
credentials; the caller supplies `iceServers`.

## OCI Always Free runbook

1. Provision the Ampere A1 instance and reserve a public IP.
2. Open ingress in the OCI security list / NSG:
   - TCP 3478, 5349
   - UDP 3478, 5349
   - UDP 49152–65535
3. Install Docker and run coturn with host networking:

```bash
cd relay/coturn
cp turnserver.conf.example turnserver.conf
# Set TURN_USER, TURN_PASSWORD, TURN_PUBLIC_IP in turnserver.conf (never commit it)
docker compose up -d
```

4. Verify from a machine outside the VPC:

```bash
turnutils_uclient -u "$TURN_USER" -w "$TURN_PASSWORD" -p 3478 "$TURN_PUBLIC_IP"
```

5. Pass the TURN entry to both peers:

```ts
const iceServers = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'turn:turn.example.com:3478', username: user, credential: password },
];
new PeerVaultSender(url, { iceServers });
new PeerVaultReceiver(url, shareLink, { iceServers });
```

## Security notes

- Do not commit `turnserver.conf` or static credentials. Prefer the TURN REST API
  with short-lived credentials for production.
- `no-multicast-peers`, `no-loopback-peers`, and `stale-nonce` are enabled in the
  example config.
- The TURN server sees peer IP addresses and relayed packet sizes, but PeerVault
  payloads remain AES-256-GCM encrypted end-to-end.

## Status

This runbook is configuration only. It was **not deployed** in this environment:
there is no authenticated OCI session. No live TURN traversal result is claimed.
