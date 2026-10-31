// SPDX-License-Identifier: AGPL-3.0-or-later
// PeerVault ML-KEM-768 core.
//
// The wasm module exposes a single 8 KiB workspace. JavaScript writes seeds,
// public keys, messages and ciphertexts at fixed offsets, calls one function,
// and reads the outputs. This avoids an allocator entirely, so the module is
// deterministic and cheap to instantiate.

pub mod keccak;
pub mod kem;
pub mod poly;

pub use kem::{CT_BYTES, PK_BYTES, SEED_BYTES, SK_BYTES, SS_BYTES};

const SEED_OFFSET: usize = 0;
const PK_OFFSET: usize = 64;
const SK_OFFSET: usize = PK_OFFSET + PK_BYTES;
const MESSAGE_OFFSET: usize = SK_OFFSET + SK_BYTES;
const CT_OFFSET: usize = MESSAGE_OFFSET + 32;
const SS_OFFSET: usize = CT_OFFSET + CT_BYTES;
const WORKSPACE_BYTES: usize = SS_OFFSET + SS_BYTES + 256;

static mut WORKSPACE: [u8; WORKSPACE_BYTES] = [0u8; WORKSPACE_BYTES];

fn workspace_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(WORKSPACE) as *mut u8
}

unsafe fn read_array<const L: usize>(base: *const u8, offset: usize) -> [u8; L] {
    let mut out = [0u8; L];
    core::ptr::copy_nonoverlapping(base.add(offset), out.as_mut_ptr(), L);
    out
}

unsafe fn write_array<const L: usize>(base: *mut u8, offset: usize, value: &[u8; L]) {
    core::ptr::copy_nonoverlapping(value.as_ptr(), base.add(offset), L);
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_workspace() -> *mut u8 {
    workspace_ptr()
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_seed_offset() -> usize {
    SEED_OFFSET
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_pk_offset() -> usize {
    PK_OFFSET
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_sk_offset() -> usize {
    SK_OFFSET
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_m_offset() -> usize {
    MESSAGE_OFFSET
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_ct_offset() -> usize {
    CT_OFFSET
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_ss_offset() -> usize {
    SS_OFFSET
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_pk_bytes() -> usize {
    PK_BYTES
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_sk_bytes() -> usize {
    SK_BYTES
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_ct_bytes() -> usize {
    CT_BYTES
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_ss_bytes() -> usize {
    SS_BYTES
}

#[no_mangle]
pub extern "C" fn pv_mlkem768_seed_bytes() -> usize {
    SEED_BYTES
}

/// Deterministic key generation from 64 seed bytes (d || z).
#[no_mangle]
pub extern "C" fn pv_mlkem768_keypair() -> i32 {
    unsafe {
        let base = workspace_ptr();
        let seed = read_array::<64>(base, SEED_OFFSET);
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);

        let mut pk = [0u8; PK_BYTES];
        let mut sk = [0u8; SK_BYTES];
        kem::keypair(&d, &z, &mut pk, &mut sk);
        write_array(base, PK_OFFSET, &pk);
        write_array(base, SK_OFFSET, &sk);
    }
    0
}

/// Deterministic encapsulation from a 32-byte message `m` at MESSAGE_OFFSET.
#[no_mangle]
pub extern "C" fn pv_mlkem768_encapsulate() -> i32 {
    unsafe {
        let base = workspace_ptr();
        let pk = read_array::<PK_BYTES>(base, PK_OFFSET);
        let m = read_array::<32>(base, MESSAGE_OFFSET);
        let mut ct = [0u8; CT_BYTES];
        let mut ss = [0u8; SS_BYTES];
        kem::encapsulate(&pk, &m, &mut ss, &mut ct);
        write_array(base, CT_OFFSET, &ct);
        write_array(base, SS_OFFSET, &ss);
    }
    0
}

/// Decapsulation. Returns 0 when the ciphertext re-encrypts correctly and 1
/// when implicit rejection produced the fallback secret.
#[no_mangle]
pub extern "C" fn pv_mlkem768_decapsulate() -> i32 {
    unsafe {
        let base = workspace_ptr();
        let ct = read_array::<CT_BYTES>(base, CT_OFFSET);
        let sk = read_array::<SK_BYTES>(base, SK_OFFSET);
        let mut ss = [0u8; SS_BYTES];
        let valid = kem::decapsulate_checked(&ct, &sk, &mut ss);
        write_array(base, SS_OFFSET, &ss);
        if valid {
            0
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::kem;
    use super::keccak::shake256;

    struct Vector {
        d: [u8; 32],
        z: [u8; 32],
        pk: Vec<u8>,
        sk: Vec<u8>,
        m: [u8; 32],
        ct: Vec<u8>,
        ss: Vec<u8>,
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn parse_vectors() -> Vec<Vector> {
        let raw = include_str!("../tests/vectors/mlkem768_kat_sample.txt");
        let mut vectors = Vec::new();
        let mut fields: Vec<(String, Vec<u8>)> = Vec::new();

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(parts.len(), 3, "malformed KAT line");
            fields.push((parts[0].to_string(), hex_decode(parts[2])));

            if fields.len() == 7 {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                let mut m = [0u8; 32];
                let mut pk = Vec::new();
                let mut sk = Vec::new();
                let mut ct = Vec::new();
                let mut ss = Vec::new();
                for (name, bytes) in fields.drain(..) {
                    match name.as_str() {
                        "d" => d.copy_from_slice(&bytes),
                        "z" => z.copy_from_slice(&bytes),
                        "m" => m.copy_from_slice(&bytes),
                        "pk" => pk = bytes,
                        "sk" => sk = bytes,
                        "ct" => ct = bytes,
                        "ss" => ss = bytes,
                        other => panic!("unexpected KAT field {other}"),
                    }
                }
                vectors.push(Vector { d, z, pk, sk, m, ct, ss });
            }
        }
        assert_eq!(fields.len(), 0, "trailing KAT fields");
        vectors
    }

    #[test]
    fn keygen_encaps_and_decaps_match_nist_kat_vectors() {
        let vectors = parse_vectors();
        assert!(vectors.len() >= 10, "expected at least 10 KAT vectors");
        for (index, vector) in vectors.iter().enumerate() {
            let mut pk = [0u8; kem::PK_BYTES];
            let mut sk = [0u8; kem::SK_BYTES];
            kem::keypair(&vector.d, &vector.z, &mut pk, &mut sk);
            assert_eq!(pk.as_slice(), vector.pk.as_slice(), "pk mismatch at {index}");
            assert_eq!(sk.as_slice(), vector.sk.as_slice(), "sk mismatch at {index}");

            let mut ct = [0u8; kem::CT_BYTES];
            let mut ss = [0u8; kem::SS_BYTES];
            kem::encapsulate(&pk, &vector.m, &mut ss, &mut ct);
            assert_eq!(ct.as_slice(), vector.ct.as_slice(), "ct mismatch at {index}");
            assert_eq!(ss.as_slice(), vector.ss.as_slice(), "ss mismatch at {index}");

            let mut ct_vec = [0u8; kem::CT_BYTES];
            ct_vec.copy_from_slice(&vector.ct);
            let mut decapsulated = [0u8; kem::SS_BYTES];
            kem::decapsulate(&ct_vec, &sk, &mut decapsulated);
            assert_eq!(
                decapsulated.as_slice(),
                vector.ss.as_slice(),
                "decaps ss mismatch at {index}"
            );
        }
    }

    #[test]
    fn encapsulate_decapsulate_roundtrip() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..32 {
            let mut seed = [0u8; 64];
            for chunk in seed.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            d.copy_from_slice(&seed[..32]);
            z.copy_from_slice(&seed[32..]);

            let mut pk = [0u8; kem::PK_BYTES];
            let mut sk = [0u8; kem::SK_BYTES];
            kem::keypair(&d, &z, &mut pk, &mut sk);

            let mut m = [0u8; 32];
            for chunk in m.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let mut ct = [0u8; kem::CT_BYTES];
            let mut sender_secret = [0u8; kem::SS_BYTES];
            kem::encapsulate(&pk, &m, &mut sender_secret, &mut ct);

            let mut receiver_secret = [0u8; kem::SS_BYTES];
            kem::decapsulate(&ct, &sk, &mut receiver_secret);
            assert_eq!(sender_secret, receiver_secret);

            ct[0] ^= 1;
            let mut rejected = [0u8; kem::SS_BYTES];
            kem::decapsulate(&ct, &sk, &mut rejected);
            assert_ne!(rejected, sender_secret);

            let mut expected = [0u8; 32 + kem::CT_BYTES];
            expected[..32].copy_from_slice(&z);
            expected[32..].copy_from_slice(&ct);
            let mut fallback = [0u8; kem::SS_BYTES];
            shake256(&expected, &mut fallback);
            assert_eq!(rejected, fallback, "implicit rejection must use J(z || c)");
        }
    }
}

