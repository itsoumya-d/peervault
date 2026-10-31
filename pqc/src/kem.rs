// SPDX-License-Identifier: AGPL-3.0-or-later
// FIPS 203 ML-KEM-768 (k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4).

use crate::keccak::{sha3_256, sha3_512, shake256};
use crate::poly::{
    basemul_acc, canonical, cbd2, compress, decompress, invntt, ntt, reduce_all, sample_ntt,
    tomont, N,
};

pub const K: usize = 3;
pub const ETA1: u8 = 2;
pub const ETA2: u8 = 2;
pub const DU: u32 = 10;
pub const DV: u32 = 4;

pub const PK_BYTES: usize = 1184;
pub const SK_BYTES: usize = 2400;
pub const CT_BYTES: usize = 1088;
pub const SS_BYTES: usize = 32;
pub const SEED_BYTES: usize = 64;

pub const PKE_SK_BYTES: usize = 384 * K;
pub const PKE_PK_BYTES: usize = PK_BYTES;

fn byte_encode(coeffs: &[i32], d: u32, out: &mut [u8]) {
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut at = 0usize;
    for &coeff in coeffs {
        acc |= ((canonical(coeff) as u32) & mask) << bits;
        bits += d;
        while bits >= 8 {
            out[at] = acc as u8;
            at += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

fn byte_decode(bytes: &[u8], d: u32, out: &mut [i32]) {
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut at = 0usize;
    for coeff in out.iter_mut() {
        while bits < d {
            acc |= (bytes[at] as u32) << bits;
            at += 1;
            bits += 8;
        }
        *coeff = (acc & mask) as i32;
        acc >>= d;
        bits -= d;
    }
}

fn gen_matrix(rho: &[u8; 32]) -> [[[i32; N]; K]; K] {
    let mut matrix = [[[0i32; N]; K]; K];
    for i in 0..K {
        for j in 0..K {
            matrix[i][j] = sample_ntt(rho, j as u8, i as u8);
        }
    }
    matrix
}

pub fn keypair(
    d: &[u8; 32],
    z: &[u8; 32],
    pk: &mut [u8; PK_BYTES],
    sk: &mut [u8; SK_BYTES],
) {
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = K as u8;

    let g = sha3_512(&g_input);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    let mut s = [[0i32; N]; K];
    let mut e = [[0i32; N]; K];
    let mut nonce = 0u8;
    for item in s.iter_mut() {
        *item = cbd2(&sigma, nonce);
        nonce += 1;
    }
    for item in e.iter_mut() {
        *item = cbd2(&sigma, nonce);
        nonce += 1;
    }

    let mut s_hat = s;
    let mut e_hat = e;
    for item in s_hat.iter_mut() {
        ntt(item);
    }
    for item in e_hat.iter_mut() {
        ntt(item);
    }

    let a = gen_matrix(&rho);
    let mut t_hat = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..K {
            basemul_acc(&mut acc, &a[i][j], &s_hat[j]);
        }
        tomont(&mut acc);
        for x in 0..N {
            acc[x] += e_hat[i][x];
        }
        reduce_all(&mut acc);
        t_hat[i] = acc;
    }

    for i in 0..K {
        byte_encode(&t_hat[i], 12, &mut pk[i * 384..(i + 1) * 384]);
    }
    pk[PKE_SK_BYTES..PK_BYTES].copy_from_slice(&rho);

    for i in 0..K {
        byte_encode(&s_hat[i], 12, &mut sk[i * 384..(i + 1) * 384]);
    }
    sk[PKE_SK_BYTES..PKE_SK_BYTES + PK_BYTES].copy_from_slice(pk);

    let h = sha3_256(pk);
    sk[2336..2368].copy_from_slice(&h);
    sk[2368..2400].copy_from_slice(z);
}

pub fn encrypt(pk: &[u8; PK_BYTES], m: &[u8; 32], coins: &[u8; 32]) -> [u8; CT_BYTES] {
    let mut t_hat = [[0i32; N]; K];
    for i in 0..K {
        byte_decode(&pk[i * 384..(i + 1) * 384], 12, &mut t_hat[i]);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[PKE_SK_BYTES..PK_BYTES]);

    let mut r = [[0i32; N]; K];
    let mut e1 = [[0i32; N]; K];
    let mut nonce = 0u8;
    for item in r.iter_mut() {
        *item = cbd2(coins, nonce);
        nonce += 1;
    }
    for item in e1.iter_mut() {
        *item = cbd2(coins, nonce);
        nonce += 1;
    }
    let e2 = cbd2(coins, nonce);

    let mut r_hat = r;
    for item in r_hat.iter_mut() {
        ntt(item);
    }

    let a = gen_matrix(&rho);
    let mut u = [[0i32; N]; K];
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..K {
            // A^T[i][j] = A[j][i] = SampleNTT(rho || i || j).
            basemul_acc(&mut acc, &a[j][i], &r_hat[j]);
        }
        invntt(&mut acc);
        for x in 0..N {
            acc[x] = canonical(acc[x] + e1[i][x]);
        }
        u[i] = acc;
    }

    let mut v = [0i32; N];
    for j in 0..K {
        basemul_acc(&mut v, &t_hat[j], &r_hat[j]);
    }
    invntt(&mut v);
    for x in 0..N {
        v[x] = canonical(v[x] + e2[x]);
    }

    for i in 0..32 {
        for bit in 0..8 {
            let message_bit = ((m[i] >> bit) & 1) as i32;
            v[8 * i + bit] = canonical(v[8 * i + bit] + decompress(message_bit, 1));
        }
    }

    let mut ct = [0u8; CT_BYTES];
    for i in 0..K {
        let mut compressed = [0i32; N];
        for x in 0..N {
            compressed[x] = compress(u[i][x], DU);
        }
        byte_encode(&compressed, DU, &mut ct[i * 320..(i + 1) * 320]);
    }
    let mut compressed_v = [0i32; N];
    for x in 0..N {
        compressed_v[x] = compress(v[x], DV);
    }
    byte_encode(&compressed_v, DV, &mut ct[960..1088]);

    ct
}

pub fn decrypt(pke_sk: &[u8], ct: &[u8; CT_BYTES]) -> [u8; 32] {
    let mut s_hat = [[0i32; N]; K];
    for i in 0..K {
        byte_decode(&pke_sk[i * 384..(i + 1) * 384], 12, &mut s_hat[i]);
    }

    let mut u = [[0i32; N]; K];
    for i in 0..K {
        let mut poly = [0i32; N];
        byte_decode(&ct[i * 320..(i + 1) * 320], DU, &mut poly);
        for x in 0..N {
            poly[x] = decompress(poly[x], DU);
        }
        u[i] = poly;
    }

    let mut v = [0i32; N];
    {
        let mut poly = [0i32; N];
        byte_decode(&ct[960..1088], DV, &mut poly);
        for x in 0..N {
            v[x] = decompress(poly[x], DV);
        }
    }

    let mut acc = [0i32; N];
    for i in 0..K {
        let mut u_hat = u[i];
        ntt(&mut u_hat);
        basemul_acc(&mut acc, &s_hat[i], &u_hat);
    }
    invntt(&mut acc);

    let mut m = [0u8; 32];
    for i in 0..32 {
        let mut byte = 0u8;
        for bit in 0..8 {
            let value = canonical(v[8 * i + bit] - acc[8 * i + bit]);
            byte |= ((compress(value, 1) as u8) & 1) << bit;
        }
        m[i] = byte;
    }
    m
}

pub fn encapsulate(
    pk: &[u8; PK_BYTES],
    m: &[u8; 32],
    shared_secret: &mut [u8; SS_BYTES],
    ct: &mut [u8; CT_BYTES],
) {
    let h = sha3_256(pk);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h);

    let g = sha3_512(&g_input);
    shared_secret.copy_from_slice(&g[..32]);
    let mut coins = [0u8; 32];
    coins.copy_from_slice(&g[32..]);

    *ct = encrypt(pk, m, &coins);
}

pub fn decapsulate_checked(
    ct: &[u8; CT_BYTES],
    sk: &[u8; SK_BYTES],
    shared_secret: &mut [u8; SS_BYTES],
) -> bool {
    let m = decrypt(&sk[..PKE_SK_BYTES], ct);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m);
    g_input[32..].copy_from_slice(&sk[2336..2368]);

    let g = sha3_512(&g_input);
    let mut candidate = [0u8; 32];
    candidate.copy_from_slice(&g[..32]);
    let mut coins = [0u8; 32];
    coins.copy_from_slice(&g[32..]);

    let mut ek = [0u8; PK_BYTES];
    ek.copy_from_slice(&sk[PKE_SK_BYTES..PKE_SK_BYTES + PK_BYTES]);
    let reencrypted = encrypt(&ek, &m, &coins);

    let mut diff = 0u8;
    for i in 0..CT_BYTES {
        diff |= ct[i] ^ reencrypted[i];
    }

    if diff == 0 {
        *shared_secret = candidate;
        true
    } else {
        let mut rejection_input = [0u8; 32 + CT_BYTES];
        rejection_input[..32].copy_from_slice(&sk[2368..2400]);
        rejection_input[32..].copy_from_slice(ct);
        shake256(&rejection_input, shared_secret);
        false
    }
}

pub fn decapsulate(ct: &[u8; CT_BYTES], sk: &[u8; SK_BYTES], shared_secret: &mut [u8; SS_BYTES]) {
    let _ = decapsulate_checked(ct, sk, shared_secret);
}
