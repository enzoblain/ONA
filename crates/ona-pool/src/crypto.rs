//! BLS12-381 checks on NEAR host functions (same code as `ona-mint`), the hashes, and the refusal of
//! ed25519 keys of small order.

use near_sdk::{env, require};

pub const G1_LEN: usize = 48;
pub const G2_LEN: usize = 96;

/// Base field modulus of BLS12-381, most significant limb first. Same as `ona-mint`.
const P: [u64; 6] = [
    0x1a0111ea397fe69a,
    0x4b1ba7b6434bacd7,
    0x64774b84f38512bf,
    0x6730d2a0f6b0f624,
    0x1eabfffeb153ffff,
    0xb9feffffffffaaab,
];

const G1_GEN: [u8; 96] = hex96(
    b"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);
const NEG_G1: [u8; 96] = hex96(
    b"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca",
);
const NEG_G2: [u8; 192] = hex192(
    b"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed0d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa",
);

/// Encodings of the ed25519 points of small order, and their non-canonical forms (`y + p`). With such a
/// key, a signature can be made for any message without a secret. Tests check each against
/// `ed25519-dalek`'s `is_weak`.
pub const WEAK_KEYS: [[u8; 32]; 12] = [
    hex32(b"0100000000000000000000000000000000000000000000000000000000000000"),
    hex32(b"0100000000000000000000000000000000000000000000000000000000000080"),
    hex32(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32(b"0000000000000000000000000000000000000000000000000000000000000000"),
    hex32(b"0000000000000000000000000000000000000000000000000000000000000080"),
    hex32(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex32(b"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    hex32(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hex32(b"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hex32(b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex32(b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
];

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

const fn hex32(s: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex96(s: &[u8; 192]) -> [u8; 96] {
    let mut out = [0u8; 96];
    let mut i = 0;
    while i < 96 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex192(s: &[u8; 384]) -> [u8; 192] {
    let mut out = [0u8; 192];
    let mut i = 0;
    while i < 192 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    env::sha256(data).try_into().unwrap_or_else(|_| env::panic_str("sha256 length"))
}

/// RFC 9380 `expand_message_xmd` with SHA-256, for 128 output bytes. Same as `ona-mint`.
fn expand_message_xmd(msg: &[u8], dst: &[u8]) -> [u8; 128] {
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let mut input = vec![0u8; 64];
    input.extend_from_slice(msg);
    input.extend_from_slice(&[0, 128, 0]);
    input.extend_from_slice(&dst_prime);
    let b0 = sha256(&input);

    let mut out = [0u8; 128];
    let mut prev = [0u8; 32];
    for i in 0..4u8 {
        let mut block = Vec::with_capacity(33 + dst_prime.len());
        for j in 0..32 {
            block.push(b0[j] ^ prev[j]);
        }
        block.push(i + 1);
        block.extend_from_slice(&dst_prime);
        prev = sha256(&block);
        out[usize::from(i) * 32..usize::from(i + 1) * 32].copy_from_slice(&prev);
    }
    out
}

fn reduce_mod_p(bytes: &[u8]) -> [u8; 48] {
    let mut r = [0u64; 6];
    for byte in bytes {
        for bit in (0..8).rev() {
            let mut carry = u64::from(byte >> bit & 1);
            for limb in r.iter_mut().rev() {
                let next = *limb >> 63;
                *limb = *limb << 1 | carry;
                carry = next;
            }
            if r >= P {
                let mut borrow = false;
                for i in (0..6).rev() {
                    let (a, b1) = r[i].overflowing_sub(P[i]);
                    let (a, b2) = a.overflowing_sub(u64::from(borrow));
                    r[i] = a;
                    borrow = b1 || b2;
                }
            }
        }
    }
    let mut out = [0u8; 48];
    for (i, limb) in r.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn hash_to_g1_raw(msg: &[u8], dst: &[u8]) -> Vec<u8> {
    let uniform = expand_message_xmd(msg, dst);
    let mut fps = Vec::with_capacity(96);
    fps.extend_from_slice(&reduce_mod_p(&uniform[..64]));
    fps.extend_from_slice(&reduce_mod_p(&uniform[64..]));
    let mapped = env::bls12381_map_fp_to_g1(&fps)
        .filter(|m| m.len() == 192)
        .unwrap_or_else(|| env::panic_str("map_fp_to_g1 failed"));
    let mut sum_input = Vec::with_capacity(194);
    sum_input.push(0);
    sum_input.extend_from_slice(&mapped[..96]);
    sum_input.push(0);
    sum_input.extend_from_slice(&mapped[96..192]);
    env::bls12381_p1_sum(&sum_input).unwrap_or_else(|| env::panic_str("p1_sum failed"))
}

fn decompress_g1(p: &[u8; G1_LEN]) -> Option<Vec<u8>> {
    if p[0] & 0x80 == 0 || p[0] & 0x40 != 0 {
        return None;
    }
    env::bls12381_p1_decompress(p).filter(|raw| raw.len() == 96)
}

fn pairing_ok(sig_raw: &[u8], point_raw: &[u8], pk_raw: &[u8]) -> bool {
    let mut input = Vec::with_capacity(576);
    input.extend_from_slice(sig_raw);
    input.extend_from_slice(&NEG_G2);
    input.extend_from_slice(point_raw);
    input.extend_from_slice(pk_raw);
    env::bls12381_pairing_check(&input).unwrap_or(false)
}

/// The BLS signature `sig` on `message`, hashed with `dst`, verifies under the uncompressed key `pk_raw`.
pub fn bls_valid(sig: &[u8; G1_LEN], message: &[u8], dst: &[u8], pk_raw: &[u8]) -> bool {
    decompress_g1(sig).is_some_and(|sig_raw| pairing_ok(&sig_raw, &hash_to_g1_raw(message, dst), pk_raw))
}

/// Checks a compressed G2 key and returns it uncompressed, as `ona-mint::new` does.
pub fn checked_key(pk: &[u8]) -> Vec<u8> {
    let pk: [u8; G2_LEN] = pk.try_into().unwrap_or_else(|_| env::panic_str("bad key length"));
    require!(pk[0] & 0x80 != 0 && pk[0] & 0x40 == 0, "bad key flags");
    let pk_raw = env::bls12381_p2_decompress(pk)
        .filter(|raw| raw.len() == 192)
        .unwrap_or_else(|| env::panic_str("bad key"));
    let mut check = Vec::with_capacity(576);
    check.extend_from_slice(&G1_GEN);
    check.extend_from_slice(&pk_raw);
    check.extend_from_slice(&NEG_G1);
    check.extend_from_slice(&pk_raw);
    require!(env::bls12381_pairing_check(&check).unwrap_or(false), "key outside the subgroup");
    pk_raw
}

/// The note owner's ed25519 signature on `digest`, refusing keys of small order.
pub fn owner_signed(pk: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    !WEAK_KEYS.contains(pk) && env::ed25519_verify(sig, digest, pk)
}
