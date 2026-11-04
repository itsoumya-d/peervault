# PeerVault PQC Validation Results

FIPS 203 ML-KEM-768 core: Rust (`pqc/`), compiled to `wasm32-unknown-unknown`,
embedded in the SDK as base64. No imports, no allocator.

## Implementation coverage

| Component | Location | Notes |
|---|---|---|
| Polynomial ring `Z_q[X]/(X^256+1)`, `q=3329` | `pqc/src/poly.rs` | i32 coefficients, Montgomery arithmetic |
| NTT / inverse NTT | `pqc/src/poly.rs` | 7 layers, reference twiddle table |
| CBD sampling (`eta=2`) | `pqc/src/poly.rs` | SHAKE256 PRF |
| Uniform rejection sampling | `pqc/src/poly.rs` | SHAKE128 XOF |
| FIPS 203 encode/decode (1/4/10/12-bit) | `pqc/src/kem.rs` | generic little-endian bit packing |
| Compress / decompress | `pqc/src/poly.rs` | `d = 1, 4, 10, 12` |
| Key generation, encapsulation, decapsulation | `pqc/src/kem.rs` | implicit rejection `J(z || c)` |
| SHA3-256/512, SHAKE128/256 | `pqc/src/keccak.rs` | Keccak-f[1600] |

## Known-answer tests

`pqc/tests/vectors/mlkem768_kat_sample.txt` contains all 100 vectors from the
`itzmeanjan/ml-kem` NIST KAT set (same structure as the NIST ACVP vectors).

```
cd pqc
cargo test --release
```

Result: **100/100** vectors match for:

- deterministic key generation from `(d, z)` — `pk` and `sk` byte-exact,
- deterministic encapsulation from `m` — `ct` and `ss` byte-exact,
- decapsulation — `ss` byte-exact,
- implicit rejection of a tampered ciphertext — `J(z || c)`.

## Interoperability

`sdk/tests/hybrid.test.mjs`:

- imports a PeerVault-generated public key into Node/OpenSSL's ML-KEM-768,
- encapsulates with the independent implementation,
- decapsulates with the bundled wasm core,
- asserts the shared secrets match and the re-encryption check passes.

Result: **pass** on Node 26.3.0 / OpenSSL 4.1.0.

## Protocol tests

- **Hybrid handshake:** ML-KEM-768 + P-256 ECDH + HKDF-SHA256; both peers agree
  on session key and transcript; wrong share-link key is rejected; tampered KEM
  ciphertext, confirmation, and ready message are rejected.
- **Full-header AAD:** flipping any one of the 21 header bytes rejects; 200
  randomized header mutations reject; a valid frame still decrypts.
- **End-to-end:** 200 KB transfer over in-memory WebRTC fakes using the default
  hybrid handshake completes byte-exactly.

```
cd sdk
npm run build
npm test
```

Result: **75/75 tests pass** (Node 26.3.0), including mesh convergence, LWW conflict resolution, encrypted control messages, and full-header fuzz rejection.

## Datamesh and chunk throughput

`npm run bench:throughput` (local AES-GCM, 300 × 64 KiB chunks):

| Operation | Throughput |
|---|---:|
| Encrypt | 1395 MB/s |
| Decrypt | 1043 MB/s |
| Mesh state serialize (1,000 × 768 dims) | 64.8 ms |
| Mesh state apply | 16.4 ms |

The mesh state is 4.16 MB of base64 JSON. These are local measurements; no live
WebRTC/DataChannel network throughput is claimed.

## Microbenchmarks

Apple Silicon laptop, Node 26.3.0, wasm core 49,446 bytes. `npm run bench:pqc`:

| Operation | Mean | Throughput |
|---|---:|---:|
| ML-KEM-768 keygen | 0.057 ms | 17,597 ops/s |
| ML-KEM-768 encapsulate | 0.057 ms | 17,542 ops/s |
| ML-KEM-768 decapsulate | 0.054 ms | 18,484 ops/s |
| Full hybrid handshake (ECDH + KEM + HKDF + confirmations) | 0.87 ms | 1,149 ops/s |

Handshake latency: p50 **0.836 ms**, p95 **1.082 ms**.

These are single-threaded JavaScript/wasm numbers and will vary by device.
They are well below the per-transfer cost of the 64 KB AES-GCM chunk loop.

### Windows 11 (RTX 2060 host) local runs — 2026-11-04

Re-ran against the same wasm core (49,446 bytes, restored from the bundled
base64 since `cargo` was not installed on this host; the artifact was
byte-identical to the checked-in `mlkem-wasm.generated.ts` payload).

`npm run bench:pqc` (250 KEM iterations, 50 handshakes):

| Operation | Mean | Throughput |
|---|---:|---:|
| ML-KEM-768 keygen | 0.085 ms | 11,710 ops/s |
| ML-KEM-768 encapsulate | 0.086 ms | 11,612 ops/s |
| ML-KEM-768 decapsulate | 0.083 ms | 12,025 ops/s |
| Full hybrid handshake | 2.252 ms | 444 ops/s |

Handshake latency: p50 **2.221 ms**, p95 **2.668 ms**. Raw JSON:
[`sdk/bench-pqc.local.json`](../sdk/bench-pqc.local.json).

`npm run bench:memory` (sparse-file/discarding-sink, 1 GB, 16,384 chunks,
no real WebRTC):

| Phase | Baseline RSS | Peak RSS | Delta |
|---|---:|---:|---:|
| Sender | 28.22 MB | 67.67 MB | **39.45 MB** |
| Receiver | 53.36 MB | 69.45 MB | **16.09 MB** |

Raw JSON: [`sdk/bench-memory.local.json`](../sdk/bench-memory.local.json).
The receiver path remains below the 32 MB target only in the Apple Silicon
run (3.02 MB); on Windows 11 it measures 16.09 MB and the sender 39.45 MB.
These are not WebRTC transfer benchmarks.

## Reproduce

```bash
# Rust KATs + wasm build
cd pqc
cargo test --release
cargo build --release --target wasm32-unknown-unknown

# Re-embed the wasm and run the SDK suite
cd ../sdk
npm run build:mlkem
npm run build
npm test
npm run bench:pqc
```

## Scope and limitations

- Not independently audited.
- The Rust core uses branch-free implicit rejection, but wasm/JS side channels
  are not formally analysed.
- The share link is the root of trust. Possession of the link permits joining
  the room; the handshake authenticates ephemeral keys but does not add identity
  verification beyond the link secret.
- `hybridHandshake: false` disables post-quantum protection for interoperability
  with pre-PQC peers.
