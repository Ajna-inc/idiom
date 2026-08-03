//! BLAKE-1-512 — the original BLAKE hash (SHA-3 finalist, 2008), NOT BLAKE2.
//!
//! Byte-identical Rust port of the reference Python
//! `did_kanon/v1_0/zk/_blake1.py`, which in turn matches the npm `blake-hash`
//! package (`createBlakeHash('blake512')`) that circomlibjs's
//! `eddsa.signPoseidon` uses for its two internal derivations:
//!
//!   1. `prv2pub` clamps `BLAKE-512(prv)[0:32]` to derive the secret scalar.
//!   2. `signPoseidon` builds the nonce `r` from
//!      `BLAKE-512(BLAKE-512(prv)[32:64] || M)` reduced mod the subgroup order.
//!
//! The algorithm is not in any standard Rust hash crate (they only ship
//! BLAKE2/BLAKE3), so we vendor it here. Correctness is gated by the KATs at
//! the bottom of this file, extracted from the Python reference across padding
//! boundary lengths (0, 111, 112, 128, 129, …).

/// BLAKE-512 initial values (same as SHA-512 IV).
const IV_512: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

/// 16 round constants (pi digits).
const C_512: [u64; 16] = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
    0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7,
    0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99,
    0x24A19947B3916CF7,
    0x0801F2E2858EFC16,
    0x636920D871574E69,
];

/// Message permutation table. The compression runs 16 rounds indexing
/// `SIGMA[r % 10]`; we mirror the Python module which lists 10 rows.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline]
fn rotr64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

/// One round of the BLAKE-512 mixing function (operates in place on `v`).
#[inline]
#[allow(clippy::too_many_arguments)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, m: &[u64; 16], e: usize, f: usize) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[e] ^ C_512[f]);
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = rotr64(v[b] ^ v[c], 25);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[f] ^ C_512[e]);
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = rotr64(v[b] ^ v[c], 11);
}

/// One BLAKE-512 compression step. Updates `h` in place. `t` is the 128-bit
/// bit-length counter (`t` low 64 bits and high 64 bits from a `u128`).
fn compress(h: &mut [u64; 8], block: &[u8], salt: &[u64; 4], t: u128) {
    debug_assert_eq!(block.len(), 128);
    // Parse the 128-byte block into 16 big-endian 64-bit message words.
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *word = u64::from_be_bytes(buf);
    }

    let t_lo = (t & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    let t_hi = ((t >> 64) & 0xFFFF_FFFF_FFFF_FFFF) as u64;

    let mut v = [0u64; 16];
    v[0..8].copy_from_slice(h);
    v[8] = salt[0] ^ C_512[0];
    v[9] = salt[1] ^ C_512[1];
    v[10] = salt[2] ^ C_512[2];
    v[11] = salt[3] ^ C_512[3];
    v[12] = t_lo ^ C_512[4];
    v[13] = t_lo ^ C_512[5];
    v[14] = t_hi ^ C_512[6];
    v[15] = t_hi ^ C_512[7];

    // 16 rounds; each applies 8 G-mixings under a SIGMA[r % 10] permutation.
    for r in 0..16 {
        let s = &SIGMA[r % 10];
        // Column mixings.
        g(&mut v, 0, 4, 8, 12, &m, s[0], s[1]);
        g(&mut v, 1, 5, 9, 13, &m, s[2], s[3]);
        g(&mut v, 2, 6, 10, 14, &m, s[4], s[5]);
        g(&mut v, 3, 7, 11, 15, &m, s[6], s[7]);
        // Diagonal mixings.
        g(&mut v, 0, 5, 10, 15, &m, s[8], s[9]);
        g(&mut v, 1, 6, 11, 12, &m, s[10], s[11]);
        g(&mut v, 2, 7, 8, 13, &m, s[12], s[13]);
        g(&mut v, 3, 4, 9, 14, &m, s[14], s[15]);
    }

    // Finalise: h_i ^= v_i ^ v_{i+8} ^ salt_{i%4}.
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8] ^ salt[i % 4];
    }
}

/// Return the 64-byte BLAKE-512 digest of `data`.
///
/// Byte-identical to npm `blake-hash`'s `createBlakeHash('blake512')` and to
/// the Python `_blake1.blake512`. See the KATs at the bottom of this file.
pub fn blake512(data: &[u8]) -> [u8; 64] {
    let mut h = IV_512;
    let salt = [0u64; 4];
    let mut t_counter: u128 = 0; // bit-length counter

    let n = data.len();
    let mut offset = 0usize;
    // Process full 128-byte blocks.
    while n - offset >= 128 {
        t_counter += 1024;
        compress(&mut h, &data[offset..offset + 128], &salt, t_counter);
        offset += 128;
    }

    // Final block(s) with padding — mirrors the Python `blake512` exactly.
    let rem = &data[offset..];
    let rem_bits = (rem.len() * 8) as u128;

    let mut pad: Vec<u8> = rem.to_vec();
    pad.push(0x80);
    // Zero-pad so that `len(pad) % 128 == 111`.
    while pad.len() % 128 != 111 {
        pad.push(0x00);
    }
    pad.push(0x01);
    // 16-byte big-endian message bit-length: high 64 = 0, low 64 = total bits.
    let total_bits = rem_bits + (offset as u128) * 8;
    pad.extend_from_slice(&0u64.to_be_bytes());
    pad.extend_from_slice(&(total_bits as u64).to_be_bytes());

    if pad.len() == 128 {
        // Single padded block.
        if rem_bits == 0 {
            compress(&mut h, &pad, &salt, 0);
        } else {
            t_counter += rem_bits;
            compress(&mut h, &pad, &salt, t_counter);
        }
    } else {
        // Two padded blocks: the first carries the real data bits, the second
        // is pad-only with counter=0 (spec).
        let first = &pad[..128];
        let second = &pad[128..];
        if rem_bits == 0 {
            compress(&mut h, first, &salt, 0);
        } else {
            t_counter += rem_bits;
            compress(&mut h, first, &salt, t_counter);
        }
        compress(&mut h, second, &salt, 0);
    }

    // Serialise: 8 big-endian 64-bit words.
    let mut out = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// KAT from the reference docstring / `blake-hash` npm cross-check.
    #[test]
    fn blake512_docstring_vector() {
        assert_eq!(
            hex::encode(blake512(&[1, 2, 3, 4])),
            "c181d3707ba41c176481e9f56d88be376153e8be6d6718f9bdb605601bd1ee63\
             4c9d7130553d6853585d48cb43da3e2cd54939c97f64eccd4a3774efa5e924d2"
        );
    }

    /// KATs generated from the Python reference `_blake1.blake512` across the
    /// padding-boundary lengths (data[i] = (i*7+1) & 0xff). These pin every
    /// branch of the padding logic (single-block, two-block, empty).
    #[test]
    fn blake512_boundary_vectors() {
        let cases: &[(usize, &str)] = &[
            (0, "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8"),
            (1, "df390c157b7a2146b863aba0320d64b5efe0387883f3536b176ad0871a63ade2300614a0ce07aa5ef2a5b7095fad88e02584aaf92c6ad3a7ff84945af89c8f4f"),
            (4, "40a6dafb18a2f34f9c3069d36622a14aa03c60c32219a932282b4f5cbdbb33825b1b5fc72579311c2fc94f418f0aa9d53fadc607792681800c85c1cdf7fd19f9"),
            (32, "aa90fa804efaca9348fe756c2f51587b7ccfc6428cedad391dcfc621e49b19e1a26501831690ddf75f3aad3ce813c87901ca95559f826be74b7e274c93a94d55"),
            (55, "5d25ef7cbcaa34c53330069d8b8d5ab6d0f7b22021bfedc7c86076bbb976221047c5f027fc193c78f97b5b322170a175577155452212a4872a8c8d174b44f9f3"),
            (63, "0b69b8127eee0dfb9c955d87d02636a07b3876f850d898181e61195bd9e9943f4070c1c759596f5a4c6f96523c5700537ce914123b5d51e94f2f0187139b0d8d"),
            (64, "8e2c2fd1d51ec1d59d86103118209a1d9492be51315b8a1709fe0e8935342c056e70eab28a3455e1321500a535d99155f553de9bf602f81e22f587dde153c943"),
            (110, "9fae0459020145b858b23e8681cb217459b2e79e992f4d275b41b61c939a1cd85bf7eb97bddcb36401bb65049ff5d4cea2ed151670a50f050d1b4a48d6baf73b"),
            (111, "c927c8644e7795174f131cddf34a82e2ac0d9f72daba3a86f3f3dd26a5ce375cdf060d35ef4987cf524f4e3bf3b157bf9bcbd71d7663a7f64a2778414e3679b1"),
            (112, "d71eb06c7be30ee72d4b8c8a665be67426b61d8d0c423edcdbd18f2325cdbe6655cba66c50db710199fb435e6f50ae0c70067ab1cc7d8c6da131296fc131e1f8"),
            (127, "549f7ed7446034588fd7f80ada44544845ed0725e7f2d1b9c0af7f3404514be0faf0239cdcbf9435f0df1c93ca81a8d6df97efb640ff2b719c237b658b8f27dc"),
            (128, "bd88c1a902f3a6b393849e567e3607c62a509aa9328a606b9155452eec0d5d430a971e520c65d70376a90f3227371ed49973c60754764d39559ac3cdfa9dc1b5"),
            (129, "df9590b401269b1ceffd12e37a5d266236fc992d5e3dfa6894bf274b76e10cde474fd20957e36c10c9ac011d34fcaeb17ce163fe6b631d85ca07d42e0746ab4a"),
            (200, "9e8f880597de193667aa524a797795089de97e484a3c73cb2e50107185a786ad006e8ae4a8d8a8d7641961b8a108bd56d11157f4c461873b678ca86d7ec0a547"),
        ];
        for (n, expected) in cases {
            let data: Vec<u8> = (0..*n).map(|i| ((i * 7 + 1) & 0xff) as u8).collect();
            assert_eq!(
                blake512(&data).to_vec(),
                hx(expected),
                "BLAKE-512 mismatch at len {n}"
            );
        }
    }
}
