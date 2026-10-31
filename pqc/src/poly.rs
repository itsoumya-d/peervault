// SPDX-License-Identifier: AGPL-3.0-or-later
// Polynomial arithmetic in R_q = Z_q[X]/(X^256 + 1), q = 3329.
//
// The NTT and Montgomery routines follow the FIPS 203 reference algorithm:
// a 7-layer Cooley-Tukey transform with Montgomery-domain twiddle factors.

use crate::keccak::Sponge;

pub const N: usize = 256;
pub const Q: i32 = 3329;
const QINV: i32 = 62209;

pub const ZETAS: [i32; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187,
    -1659, -1185, -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460,
    1522, 1628,
];

#[inline]
fn montgomery_reduce(a: i64) -> i32 {
    // `t = (int16_t)a * QINV` in the reference implementation: only the low
    // 16 bits of the product matter, then the result is sign-extended.
    let u = (a as i32 as u32).wrapping_mul(QINV as u32) & 0xffff;
    let t = (u as i16) as i64;
    ((a - t * Q as i64) >> 16) as i32
}

#[inline]
pub fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a as i64 * b as i64)
}

#[inline]
fn barrett_reduce(a: i32) -> i32 {
    let v = ((1i32 << 26) + Q / 2) / Q;
    let t = (v.wrapping_mul(a) + (1 << 25)) >> 26;
    a - t * Q
}

#[inline]
pub fn canonical(a: i32) -> i32 {
    let mut r = barrett_reduce(a);
    if r < 0 {
        r += Q;
    }
    r
}

pub fn ntt(r: &mut [i32; N]) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    for value in r.iter_mut() {
        *value = barrett_reduce(*value);
    }
}

pub fn invntt(r: &mut [i32; N]) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] -= t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for value in r.iter_mut() {
        *value = fqmul(*value, 1441);
    }
}

/// Multiplies two NTT-domain polynomials and accumulates into `acc`.
pub fn basemul_acc(acc: &mut [i32; N], a: &[i32; N], b: &[i32; N]) {
    for i in 0..N / 4 {
        let zeta = ZETAS[64 + i];
        let a0 = a[4 * i];
        let a1 = a[4 * i + 1];
        let b0 = b[4 * i];
        let b1 = b[4 * i + 1];
        acc[4 * i] += fqmul(fqmul(a1, b1), zeta) + fqmul(a0, b0);
        acc[4 * i + 1] += fqmul(a0, b1) + fqmul(a1, b0);

        let a2 = a[4 * i + 2];
        let a3 = a[4 * i + 3];
        let b2 = b[4 * i + 2];
        let b3 = b[4 * i + 3];
        acc[4 * i + 2] += fqmul(fqmul(a3, b3), -zeta) + fqmul(a2, b2);
        acc[4 * i + 3] += fqmul(a2, b3) + fqmul(a3, b2);
    }
}

/// Converts a normal-domain polynomial into the Montgomery domain (multiply by R).
pub fn tomont(r: &mut [i32; N]) {
    for value in r.iter_mut() {
        *value = fqmul(*value, 1353);
    }
}

pub fn reduce_all(r: &mut [i32; N]) {
    for value in r.iter_mut() {
        *value = canonical(*value);
    }
}

/// Centered Binomial Distribution with eta = 2 over SHAKE256(seed || nonce).
pub fn cbd2(seed: &[u8; 32], nonce: u8) -> [i32; N] {
    let mut sponge = Sponge::new(136, 0x1f);
    sponge.absorb(seed);
    sponge.absorb(&[nonce]);
    sponge.finalize();

    let mut buf = [0u8; 128];
    for byte in buf.iter_mut() {
        *byte = sponge.squeeze_byte();
    }

    let mut r = [0i32; N];
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i32;
            let b = ((d >> (4 * j + 2)) & 0x3) as i32;
            r[8 * i + j] = a - b;
        }
    }
    r
}

/// Uniform rejection sampling of a polynomial from SHAKE128(rho || j || i).
pub fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> [i32; N] {
    let mut input = [0u8; 34];
    input[..32].copy_from_slice(rho);
    input[32] = j;
    input[33] = i;
    let mut sponge = Sponge::new(168, 0x1f);
    sponge.absorb(&input);
    sponge.finalize();
    let mut r = [0i32; N];
    let mut c = 0usize;
    while c < N {
        let b0 = sponge.squeeze_byte();
        let b1 = sponge.squeeze_byte();
        let b2 = sponge.squeeze_byte();
        let d1 = (b0 as u16) | (((b1 & 0x0f) as u16) << 8);
        let d2 = ((b1 >> 4) as u16) | ((b2 as u16) << 4);
        if d1 < Q as u16 {
            r[c] = d1 as i32;
            c += 1;
        }
        if d2 < Q as u16 && c < N {
            r[c] = d2 as i32;
            c += 1;
        }
    }
    r
}

#[inline]
pub fn compress(x: i32, d: u32) -> i32 {
    let x = canonical(x) as u32;
    ((((x << d) + (Q as u32 / 2)) / Q as u32) & ((1u32 << d) - 1)) as i32
}

#[inline]
pub fn decompress(y: i32, d: u32) -> i32 {
    let y = y as u32 & ((1u32 << d) - 1);
    (((y * Q as u32) + (1u32 << (d - 1))) >> d) as i32
}
