//! ONA token crypto: blind BLS signatures on BLS12-381 (message and signature in G1, key in G2).
//!
//! Status: draft, not reviewed by a cryptographer. Format described in `../SPEC.md`.
//!
//! Every function that receives a curve point takes its compressed bytes and validates them
//! (on curve, not infinity, in the prime-order subgroup) before use, so an unvalidated point
//! cannot reach a scalar multiplication or a pairing.

use blst::*;
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub const G1_LEN: usize = 48;
pub const G2_LEN: usize = 96;
pub const G1_RAW_LEN: usize = 96;
pub const G2_RAW_LEN: usize = 192;
pub const TOKEN_LEN: usize = 113;
pub const MESSAGE_LEN: usize = 65;
pub const MAX_DENOM_ID: u8 = 7;
/// RFC 9380 section 3.1 limits a domain separation tag to 255 bytes.
pub const MAX_DST_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not a canonical encoding of a point on the curve.
    BadPoint,
    /// The point at infinity, which would make any signature trivial.
    Infinity,
    /// On the curve but outside the prime-order subgroup.
    NotInSubgroup,
    BadLength,
    BadDenom,
    BadSecretKey,
    DstTooLong,
    /// The signer's answer does not verify under the published key.
    BadSignature,
}

impl core::fmt::Display for TokenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TokenError {}

fn zero_scalar(s: &mut blst_scalar) {
    for byte in s.b.iter_mut() {
        // SAFETY: `byte` is a valid exclusive reference. Volatile so the wipe is not optimized out.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

/// Mint signing key for one denomination.
pub struct SecretKey(blst_scalar);

impl Drop for SecretKey {
    fn drop(&mut self) {
        zero_scalar(&mut self.0);
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: `out` holds the 32 bytes written; `self.0` is initialized.
        unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), &self.0) };
        out
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, TokenError> {
        let mut s = blst_scalar::default();
        // SAFETY: `bytes` holds the 32 bytes read; `s` is a valid output.
        unsafe { blst_scalar_from_bendian(&mut s, bytes.as_ptr()) };
        // SAFETY: `s` is initialized. `blst_sk_check` rejects zero and values >= r.
        if !unsafe { blst_sk_check(&s) } {
            return Err(TokenError::BadSecretKey);
        }
        Ok(Self(s))
    }

    pub fn public_key(&self) -> [u8; G2_LEN] {
        let mut p = blst_p2::default();
        let mut a = blst_p2_affine::default();
        let mut out = [0u8; G2_LEN];
        // SAFETY: all pointers refer to live, correctly sized values.
        unsafe {
            blst_sk_to_pk_in_g2(&mut p, &self.0);
            blst_p2_to_affine(&mut a, &p);
            blst_p2_affine_compress(out.as_mut_ptr(), &a);
        }
        out
    }
}

/// The wallet's blinding scalar. Must stay secret and must never be derived from a seed.
pub struct BlindingFactor(blst_scalar);

impl Drop for BlindingFactor {
    fn drop(&mut self) {
        zero_scalar(&mut self.0);
    }
}

fn decode_g1(bytes: &[u8; G1_LEN]) -> Result<blst_p1_affine, TokenError> {
    let mut a = blst_p1_affine::default();
    // SAFETY: `bytes` holds the 48 bytes read; `a` is a valid output.
    if unsafe { blst_p1_uncompress(&mut a, bytes.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
        return Err(TokenError::BadPoint);
    }
    // SAFETY: `a` was initialized above.
    if unsafe { blst_p1_affine_is_inf(&a) } {
        return Err(TokenError::Infinity);
    }
    // SAFETY: `a` was initialized above.
    if !unsafe { blst_p1_affine_in_g1(&a) } {
        return Err(TokenError::NotInSubgroup);
    }
    Ok(a)
}

fn decode_g2(bytes: &[u8; G2_LEN]) -> Result<blst_p2_affine, TokenError> {
    let mut a = blst_p2_affine::default();
    // SAFETY: `bytes` holds the 96 bytes read; `a` is a valid output.
    if unsafe { blst_p2_uncompress(&mut a, bytes.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
        return Err(TokenError::BadPoint);
    }
    // SAFETY: `a` was initialized above.
    if unsafe { blst_p2_affine_is_inf(&a) } {
        return Err(TokenError::Infinity);
    }
    // SAFETY: `a` was initialized above.
    if !unsafe { blst_p2_affine_in_g2(&a) } {
        return Err(TokenError::NotInSubgroup);
    }
    Ok(a)
}

fn compress_g1(p: &blst_p1) -> [u8; G1_LEN] {
    let mut a = blst_p1_affine::default();
    let mut out = [0u8; G1_LEN];
    // SAFETY: all pointers refer to live, correctly sized values.
    unsafe {
        blst_p1_to_affine(&mut a, p);
        blst_p1_affine_compress(out.as_mut_ptr(), &a);
    }
    out
}

fn to_jacobian(a: &blst_p1_affine) -> blst_p1 {
    let mut p = blst_p1::default();
    // SAFETY: both pointers refer to live values.
    unsafe { blst_p1_from_affine(&mut p, a) };
    p
}

fn hash_jacobian(m: &[u8], dst: &[u8]) -> blst_p1 {
    let mut h = blst_p1::default();
    // SAFETY: pointers and lengths come from valid slices; the augmentation is empty.
    unsafe {
        blst_hash_to_g1(
            &mut h,
            m.as_ptr(),
            m.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        )
    };
    h
}

fn hash_affine(m: &[u8], dst: &[u8]) -> blst_p1_affine {
    let h = hash_jacobian(m, dst);
    let mut a = blst_p1_affine::default();
    // SAFETY: both pointers refer to live values.
    unsafe { blst_p1_to_affine(&mut a, &h) };
    a
}

/// `e(sig, G2) == e(msg_point, pk)`. All inputs must already be validated.
fn pairing_eq(sig: &blst_p1_affine, msg_point: &blst_p1_affine, pk: &blst_p2_affine) -> bool {
    let mut left = blst_fp12::default();
    let mut right = blst_fp12::default();
    // SAFETY: all pointers refer to live values; the generator pointer is a static in blst.
    unsafe {
        blst_miller_loop(&mut left, blst_p2_affine_generator(), sig);
        blst_miller_loop(&mut right, pk, msg_point);
        blst_fp12_finalverify(&left, &right)
    }
}

/// Generates a mint key from 32 bytes of the given CSPRNG.
pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let mut s = blst_scalar::default();
    // SAFETY: `ikm` is 32 bytes as declared; the empty `info` is null with length 0.
    unsafe { blst_keygen(&mut s, ikm.as_ptr(), ikm.len(), core::ptr::null(), 0) };
    ikm.iter_mut().for_each(|b| *b = 0);
    SecretKey(s)
}

/// Domain separation tag for hashing a token message.
///
/// This separates honest wallets only. The signer is blind, so it cannot see which tag a blinded
/// point was hashed with: a key shared by two deployments could be used to mint on one for the
/// other. Every deployment must have its own keys.
pub fn token_dst(network: &str, contract: &str) -> Result<Vec<u8>, TokenError> {
    let dst = format!("ONA-MINT-V1:{network}:{contract}:BLS12381G1_XMD:SHA-256_SSWU_RO_");
    if dst.len() > MAX_DST_LEN {
        return Err(TokenError::DstTooLong);
    }
    Ok(dst.into_bytes())
}

/// RFC 9380 `hash_to_curve`, returned compressed.
pub fn hash_to_g1(m: &[u8], dst: &[u8]) -> [u8; G1_LEN] {
    compress_g1(&hash_jacobian(m, dst))
}

/// Blinds a message: returns the secret factor `r` and `B = r * H(m)`.
pub fn blind<R: RngCore + CryptoRng>(
    m: &[u8],
    dst: &[u8],
    rng: &mut R,
) -> (BlindingFactor, [u8; G1_LEN]) {
    let mut wide = [0u8; 64];
    let mut r = blst_scalar::default();
    loop {
        rng.fill_bytes(&mut wide);
        // SAFETY: `wide` is 64 bytes as declared. Reduces mod the group order, false when zero.
        if unsafe { blst_scalar_from_be_bytes(&mut r, wide.as_ptr(), wide.len()) } {
            break;
        }
    }
    wide.iter_mut().for_each(|b| *b = 0);
    let h = hash_jacobian(m, dst);
    let mut b = blst_p1::default();
    // SAFETY: the scalar buffer holds 255 bits in little-endian form.
    unsafe { blst_p1_mult(&mut b, &h, r.b.as_ptr(), 255) };
    (BlindingFactor(r), compress_g1(&b))
}

/// Signer side: `S' = sk * B`. Refuses anything but a valid subgroup point.
pub fn sign_blinded(sk: &SecretKey, blinded: &[u8; G1_LEN]) -> Result<[u8; G1_LEN], TokenError> {
    let b = to_jacobian(&decode_g1(blinded)?);
    let mut s = blst_p1::default();
    // SAFETY: `b` is a validated subgroup point and `sk.0` an initialized scalar.
    unsafe { blst_sign_pk_in_g2(&mut s, &b, &sk.0) };
    Ok(compress_g1(&s))
}

/// Wallet side: `S = r^-1 * S'`. The caller must then `verify` against the published key.
pub fn unblind(
    blind_sig: &[u8; G1_LEN],
    r: &BlindingFactor,
) -> Result<[u8; G1_LEN], TokenError> {
    let s_prime = to_jacobian(&decode_g1(blind_sig)?);
    let mut inv = blst_scalar::default();
    let mut s = blst_p1::default();
    // SAFETY: `r.0` is a non-zero scalar; the inverse buffer holds 255 bits little-endian.
    unsafe {
        blst_sk_inverse(&mut inv, &r.0);
        blst_p1_mult(&mut s, &s_prime, inv.b.as_ptr(), 255);
    }
    zero_scalar(&mut inv);
    Ok(compress_g1(&s))
}

/// Checks one signature on one message. Any invalid input gives `false`.
pub fn verify(pk: &[u8; G2_LEN], m: &[u8], dst: &[u8], sig: &[u8; G1_LEN]) -> bool {
    let (Ok(pk), Ok(sig)) = (decode_g2(pk), decode_g1(sig)) else {
        return false;
    };
    pairing_eq(&sig, &hash_affine(m, dst), &pk)
}

/// Checks that `S'` is `sk * B` without knowing the message: `e(S', G2) == e(B, pk)`.
pub fn verify_blind_issue(
    pk: &[u8; G2_LEN],
    blinded: &[u8; G1_LEN],
    blind_sig: &[u8; G1_LEN],
) -> bool {
    let (Ok(pk), Ok(b), Ok(s)) = (decode_g2(pk), decode_g1(blinded), decode_g1(blind_sig)) else {
        return false;
    };
    pairing_eq(&s, &b, &pk)
}

/// Uncompressed encoding (`x || y`) expected by NEAR host functions, after full validation.
pub fn g1_to_raw(point: &[u8; G1_LEN]) -> Result<[u8; G1_RAW_LEN], TokenError> {
    let a = decode_g1(point)?;
    let mut out = [0u8; G1_RAW_LEN];
    // SAFETY: `out` holds the 96 bytes written.
    unsafe { blst_p1_affine_serialize(out.as_mut_ptr(), &a) };
    Ok(out)
}

/// Uncompressed encoding expected by NEAR host functions, after full validation.
pub fn g2_to_raw(point: &[u8; G2_LEN]) -> Result<[u8; G2_RAW_LEN], TokenError> {
    let a = decode_g2(point)?;
    let mut out = [0u8; G2_RAW_LEN];
    // SAFETY: `out` holds the 192 bytes written.
    unsafe { blst_p2_affine_serialize(out.as_mut_ptr(), &a) };
    Ok(out)
}

/// Compresses a key read from a contract, after checking that it is a valid subgroup point.
pub fn g2_from_raw(raw: &[u8; G2_RAW_LEN]) -> Result<[u8; G2_LEN], TokenError> {
    let mut a = blst_p2_affine::default();
    // SAFETY: `raw` holds the 192 bytes read; `a` is a valid output.
    if unsafe { blst_p2_deserialize(&mut a, raw.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
        return Err(TokenError::BadPoint);
    }
    // SAFETY: `a` was initialized above.
    if unsafe { blst_p2_affine_is_inf(&a) } {
        return Err(TokenError::Infinity);
    }
    // SAFETY: `a` was initialized above.
    if !unsafe { blst_p2_affine_in_g2(&a) } {
        return Err(TokenError::NotInSubgroup);
    }
    let mut out = [0u8; G2_LEN];
    // SAFETY: `out` holds the 96 bytes written.
    unsafe { blst_p2_affine_compress(out.as_mut_ptr(), &a) };
    Ok(out)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// Includes the tier: otherwise a blinded copy of a token's message signed on a cheap tier could
/// burn the nullifier of an expensive token.
pub fn nullifier(denom_id: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"ONA-NF-V1", &[denom_id], pk, nonce])
}

/// A spendable token. Value and verification key are selected by `denom_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub denom_id: u8,
    pub pk: [u8; 32],
    pub nonce: [u8; 32],
    pub sig: [u8; G1_LEN],
}

impl Token {
    pub fn to_bytes(&self) -> [u8; TOKEN_LEN] {
        let mut out = [0u8; TOKEN_LEN];
        out[0] = self.denom_id;
        out[1..33].copy_from_slice(&self.pk);
        out[33..65].copy_from_slice(&self.nonce);
        out[65..].copy_from_slice(&self.sig);
        out
    }

    /// Checks length and tier only; the signature is checked by `verify_token`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        let bytes: &[u8; TOKEN_LEN] = bytes.try_into().map_err(|_| TokenError::BadLength)?;
        if bytes[0] > MAX_DENOM_ID {
            return Err(TokenError::BadDenom);
        }
        let mut token = Self {
            denom_id: bytes[0],
            pk: [0; 32],
            nonce: [0; 32],
            sig: [0; G1_LEN],
        };
        token.pk.copy_from_slice(&bytes[1..33]);
        token.nonce.copy_from_slice(&bytes[33..65]);
        token.sig.copy_from_slice(&bytes[65..]);
        Ok(token)
    }

    pub fn message(&self) -> [u8; MESSAGE_LEN] {
        message(self.denom_id, &self.pk, &self.nonce)
    }

    pub fn nullifier(&self) -> [u8; 32] {
        nullifier(self.denom_id, &self.pk, &self.nonce)
    }
}

fn message(denom_id: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[0] = denom_id;
    m[1..33].copy_from_slice(pk);
    m[33..].copy_from_slice(nonce);
    m
}

pub fn verify_token(denom_pk: &[u8; G2_LEN], token: &Token, dst: &[u8]) -> bool {
    verify(denom_pk, &token.message(), dst, &token.sig)
}

/// One blinded change token requested in a `spend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeOut {
    pub denom_id: u8,
    pub blinded: [u8; G1_LEN],
}

/// What the token owner signs to authorize a `spend`. Every variable-length field is hashed or
/// counted, so two different requests cannot share an encoding. The submitter is bound so that
/// nobody can replay the arguments from another account and take the fee.
#[allow(clippy::too_many_arguments)]
pub fn spend_digest(
    contract: &str,
    submitter: &str,
    denom_id: u8,
    nf: &[u8; 32],
    to: &str,
    amount: u128,
    fee: u128,
    change: &[ChangeOut],
) -> [u8; 32] {
    let contract_hash = sha256(&[contract.as_bytes()]);
    let submitter_hash = sha256(&[submitter.as_bytes()]);
    let to_hash = sha256(&[to.as_bytes()]);
    let mut h = Sha256::new();
    h.update(b"ONA-SPEND-V2");
    h.update(contract_hash);
    h.update(submitter_hash);
    h.update([denom_id]);
    h.update(nf);
    h.update(to_hash);
    h.update(amount.to_le_bytes());
    h.update(fee.to_le_bytes());
    h.update((change.len() as u32).to_le_bytes());
    for out in change {
        h.update([out.denom_id]);
        h.update(out.blinded);
    }
    h.finalize().into()
}

/// What the token owner signs to redeem. Without it, anyone who sees a token could force its exit
/// and collect the fee, cancelling a payment in flight.
pub fn redeem_digest(contract: &str, submitter: &str, nf: &[u8; 32]) -> [u8; 32] {
    sha256(&[
        b"ONA-REDEEM-V1",
        &sha256(&[contract.as_bytes()]),
        &sha256(&[submitter.as_bytes()]),
        nf,
    ])
}

/// What the token owner signs to let the named relay collect the token.
pub fn claim_digest(mint: &str, relay: &str, nf: &[u8; 32]) -> [u8; 32] {
    sha256(&[
        b"ONA-CLAIM-V1",
        &sha256(&[mint.as_bytes()]),
        &sha256(&[relay.as_bytes()]),
        nf,
    ])
}

pub fn sign_digest(owner: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
    owner.sign(digest).to_bytes()
}

pub fn verify_digest(pk: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    key.verify(digest, &EdSignature::from_bytes(sig)).is_ok()
}

/// A token waiting for the signer's blinded answer. Holds the owner key and the blinding factor.
pub struct PendingToken {
    pub denom_id: u8,
    pub blinded: [u8; G1_LEN],
    owner: SigningKey,
    nonce: [u8; 32],
    r: BlindingFactor,
    dst: Vec<u8>,
}

impl PendingToken {
    /// Everything needed to finish this token after a restart. Secret: holds the owner key and
    /// the blinding factor. It must be written, encrypted, before the deposit is sent.
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(98 + self.dst.len());
        out.push(self.denom_id);
        out.extend_from_slice(&self.owner.to_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.r.0.b);
        out.push(self.dst.len() as u8);
        out.extend_from_slice(&self.dst);
        out
    }

    /// Rebuilds the token and recomputes its blinded point from the stored secrets.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.len() < 98 || bytes.len() != 98 + usize::from(bytes[97]) {
            return Err(TokenError::BadLength);
        }
        if bytes[0] > MAX_DENOM_ID {
            return Err(TokenError::BadDenom);
        }
        let seed: [u8; 32] = bytes[1..33].try_into().map_err(|_| TokenError::BadLength)?;
        let nonce: [u8; 32] = bytes[33..65].try_into().map_err(|_| TokenError::BadLength)?;
        let mut r = blst_scalar::default();
        r.b.copy_from_slice(&bytes[65..97]);
        // SAFETY: `r` is initialized. Rejects zero and values >= the group order.
        if !unsafe { blst_sk_check(&r) } {
            return Err(TokenError::BadSecretKey);
        }
        let r = BlindingFactor(r);
        let owner = SigningKey::from_bytes(&seed);
        let dst = bytes[98..].to_vec();
        let m = message(bytes[0], owner.verifying_key().as_bytes(), &nonce);
        let h = hash_jacobian(&m, &dst);
        let mut b = blst_p1::default();
        // SAFETY: the scalar buffer holds 255 bits in little-endian form.
        unsafe { blst_p1_mult(&mut b, &h, r.0.b.as_ptr(), 255) };
        Ok(Self { denom_id: bytes[0], blinded: compress_g1(&b), owner, nonce, r, dst })
    }

    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        denom_id: u8,
        dst: &[u8],
    ) -> Result<Self, TokenError> {
        if denom_id > MAX_DENOM_ID {
            return Err(TokenError::BadDenom);
        }
        let owner = SigningKey::generate(rng);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let m = message(denom_id, owner.verifying_key().as_bytes(), &nonce);
        let (r, blinded) = blind(&m, dst, rng);
        Ok(Self {
            denom_id,
            blinded,
            owner,
            nonce,
            r,
            dst: dst.to_vec(),
        })
    }

    /// Unblinds and verifies under the key read from the contract. A signer using another key
    /// (which would let it tag this user) is detected here.
    pub fn finish(
        self,
        blind_sig: &[u8; G1_LEN],
        denom_pk: &[u8; G2_LEN],
    ) -> Result<(Token, SigningKey), TokenError> {
        let sig = unblind(blind_sig, &self.r)?;
        let token = Token {
            denom_id: self.denom_id,
            pk: self.owner.verifying_key().to_bytes(),
            nonce: self.nonce,
            sig,
        };
        if !verify_token(denom_pk, &token, &self.dst) {
            return Err(TokenError::BadSignature);
        }
        Ok((token, self.owner))
    }
}
