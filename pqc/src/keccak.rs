// SPDX-License-Identifier: AGPL-3.0-or-later
// Keccak-f[1600] sponge used by SHA3-256, SHA3-512, SHAKE128 and SHAKE256.

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccakf(st: &mut [u64; 25]) {
    for round in 0..24 {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            let mut j = i;
            while j < 25 {
                st[j] ^= t;
                j += 5;
            }
        }

        let mut t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let next = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = next;
        }

        for j in (0..25).step_by(5) {
            let mut row = [0u64; 5];
            row.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
            }
        }

        st[0] ^= RC[round];
    }
}

pub struct Sponge {
    state: [u64; 25],
    rate: usize,
    pos: usize,
    domain: u8,
}

impl Sponge {
    pub fn new(rate: usize, domain: u8) -> Self {
        debug_assert!(rate % 8 == 0 && rate < 200);
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
            domain,
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.state[self.pos / 8] ^= (byte as u64) << (8 * (self.pos % 8));
            self.pos += 1;
            if self.pos == self.rate {
                keccakf(&mut self.state);
                self.pos = 0;
            }
        }
    }

    pub fn finalize(&mut self) {
        self.state[self.pos / 8] ^= (self.domain as u64) << (8 * (self.pos % 8));
        self.state[(self.rate - 1) / 8] ^= 0x80u64 << 56;
        self.pos = self.rate;
    }

    pub fn squeeze_byte(&mut self) -> u8 {
        if self.pos == self.rate {
            keccakf(&mut self.state);
            self.pos = 0;
        }
        let byte = (self.state[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
        self.pos += 1;
        byte
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sponge = Sponge::new(136, 0x06);
    sponge.absorb(data);
    sponge.finalize();
    let mut out = [0u8; 32];
    for byte in out.iter_mut() {
        *byte = sponge.squeeze_byte();
    }
    out
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut sponge = Sponge::new(72, 0x06);
    sponge.absorb(data);
    sponge.finalize();
    let mut out = [0u8; 64];
    for byte in out.iter_mut() {
        *byte = sponge.squeeze_byte();
    }
    out
}

pub fn shake128_absorb(data: &[u8]) -> Sponge {
    let mut sponge = Sponge::new(168, 0x1f);
    sponge.absorb(data);
    sponge.finalize();
    sponge
}

pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut sponge = Sponge::new(136, 0x1f);
    sponge.absorb(data);
    sponge.finalize();
    for byte in out.iter_mut() {
        *byte = sponge.squeeze_byte();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha3_known_answers() {
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_512(b"")),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        let mut out = [0u8; 32];
        shake256(b"", &mut out);
        assert_eq!(hex(&out), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    }
}
