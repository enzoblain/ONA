use blst::*;
use ona_token::*;
use rand::rngs::OsRng;
use rand::RngCore;

const DST: &[u8] = b"ONA-MINT-V1:testnet:mint.test:BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn issue(sk: &SecretKey, m: &[u8]) -> [u8; G1_LEN] {
    let (r, b) = blind(m, DST, &mut OsRng);
    let sp = sign_blinded(sk, &b).unwrap();
    unblind(&sp, &r).unwrap()
}

/// A point on E(Fp) outside the prime-order subgroup, found by scanning small x coordinates.
fn non_subgroup_g1() -> [u8; G1_LEN] {
    for x in 1u32.. {
        let mut c = [0u8; G1_LEN];
        c[44..].copy_from_slice(&x.to_be_bytes());
        c[0] = 0x80;
        let mut a = blst_p1_affine::default();
        let ok = unsafe { blst_p1_uncompress(&mut a, c.as_ptr()) } == BLST_ERROR::BLST_SUCCESS;
        if ok && !unsafe { blst_p1_affine_in_g1(&a) } {
            return c;
        }
    }
    unreachable!()
}

fn non_subgroup_g2() -> [u8; G2_LEN] {
    for x in 1u32.. {
        let mut c = [0u8; G2_LEN];
        c[47] = 1;
        c[92..].copy_from_slice(&x.to_be_bytes());
        c[0] = 0x80;
        let mut a = blst_p2_affine::default();
        let ok = unsafe { blst_p2_uncompress(&mut a, c.as_ptr()) } == BLST_ERROR::BLST_SUCCESS;
        if ok && !unsafe { blst_p2_affine_in_g2(&a) } {
            return c;
        }
    }
    unreachable!()
}

fn infinity_g1() -> [u8; G1_LEN] {
    let mut c = [0u8; G1_LEN];
    c[0] = 0xc0;
    c
}

fn infinity_g2() -> [u8; G2_LEN] {
    let mut c = [0u8; G2_LEN];
    c[0] = 0xc0;
    c
}

fn g1_add(a: &[u8; G1_LEN], b: &[u8; G1_LEN]) -> [u8; G1_LEN] {
    let mut pa = blst_p1_affine::default();
    let mut pb = blst_p1_affine::default();
    let mut sum = blst_p1::default();
    let mut af = blst_p1_affine::default();
    let mut out = [0u8; G1_LEN];
    unsafe {
        assert_eq!(blst_p1_uncompress(&mut pa, a.as_ptr()), BLST_ERROR::BLST_SUCCESS);
        assert_eq!(blst_p1_uncompress(&mut pb, b.as_ptr()), BLST_ERROR::BLST_SUCCESS);
        let mut ja = blst_p1::default();
        blst_p1_from_affine(&mut ja, &pa);
        blst_p1_add_or_double_affine(&mut sum, &ja, &pb);
        blst_p1_to_affine(&mut af, &sum);
        blst_p1_affine_compress(out.as_mut_ptr(), &af);
    }
    out
}

fn g1_neg(a: &[u8; G1_LEN]) -> [u8; G1_LEN] {
    let mut out = *a;
    out[0] ^= 0x20;
    out
}

/// Aggregate check over two messages: e(S1 + S2, G2) == e(H1, pk) * e(H2, pk).
fn aggregate_verifies(pk: &[u8; G2_LEN], m1: &[u8], m2: &[u8], agg: &[u8; G1_LEN]) -> bool {
    let h_sum = g1_add(&hash_to_g1(m1, DST), &hash_to_g1(m2, DST));
    verify_blind_issue(pk, &h_sum, agg)
}

#[test]
fn round_trip_blind_signature() {
    let sk = keygen(&mut OsRng);
    let pk = sk.public_key();
    let m = [7u8; 64];
    let s = issue(&sk, &m);
    assert!(verify(&pk, &m, DST, &s));
}

#[test]
fn unblinded_signature_equals_direct_signature() {
    let sk = keygen(&mut OsRng);
    let m = [9u8; 64];
    let direct = sign_blinded(&sk, &hash_to_g1(&m, DST)).unwrap();
    assert_eq!(issue(&sk, &m), direct, "signatures are unique, whatever the blinding");
}

#[test]
fn unlinkability_shape() {
    let sk = keygen(&mut OsRng);
    let m = [1u8; 64];
    let h = hash_to_g1(&m, DST);
    let (r1, b1) = blind(&m, DST, &mut OsRng);
    let (_r2, b2) = blind(&m, DST, &mut OsRng);
    assert_ne!(b1, h);
    assert_ne!(b1, b2, "two blindings of one message must differ");
    let sp = sign_blinded(&sk, &b1).unwrap();
    assert_ne!(sp, unblind(&sp, &r1).unwrap());
}

#[test]
fn wrong_key_message_or_dst_rejected() {
    let sk = keygen(&mut OsRng);
    let other = keygen(&mut OsRng);
    let m = [3u8; 64];
    let s = issue(&sk, &m);
    let pk = sk.public_key();
    assert!(!verify(&other.public_key(), &m, DST, &s));
    assert!(!verify(&pk, &[4u8; 64], DST, &s));
    let other_dst = token_dst("mainnet", "mint.test").unwrap();
    assert!(!verify(&pk, &m, &other_dst, &s));
}

#[test]
fn tampered_token_byte_rejected() {
    let sk = keygen(&mut OsRng);
    let pk = sk.public_key();
    let p = PendingToken::new(&mut OsRng, 2, DST).unwrap();
    let sp = sign_blinded(&sk, &p.blinded).unwrap();
    let (token, _owner) = p.finish(&sp, &pk).unwrap();
    assert!(verify_token(&pk, &token, DST));

    let bytes = token.to_bytes();
    for i in 0..TOKEN_LEN {
        let mut bad = bytes;
        bad[i] ^= 1;
        let t = Token::from_bytes(&bad).unwrap();
        assert!(!verify_token(&pk, &t, DST), "byte {i} changed but token still verifies");
    }
}

#[test]
fn split_attack_is_refused() {
    let sk = keygen(&mut OsRng);
    let pk = sk.public_key();
    let (m1, m2) = ([1u8; 64], [2u8; 64]);
    let (s1, s2) = (issue(&sk, &m1), issue(&sk, &m2));
    let agg = g1_add(&s1, &s2);
    assert!(aggregate_verifies(&pk, &m1, &m2, &agg), "the honest aggregate must verify");

    let noise = hash_to_g1(b"attacker chosen point", DST);
    let (part1, part2) = (g1_add(&s1, &noise), g1_add(&s2, &g1_neg(&noise)));
    assert_eq!(g1_add(&part1, &part2), agg, "the split keeps the same aggregate");
    assert!(aggregate_verifies(&pk, &m1, &m2, &g1_add(&part1, &part2)), "an aggregate check is fooled");
    assert!(!verify(&pk, &m1, DST, &part1), "per-token check must refuse part 1");
    assert!(!verify(&pk, &m2, DST, &part2), "per-token check must refuse part 2");
}

#[test]
fn invalid_points_rejected_everywhere() {
    let sk = keygen(&mut OsRng);
    let pk = sk.public_key();
    let m = [5u8; 64];
    let s = issue(&sk, &m);
    let good_b = hash_to_g1(&m, DST);
    let good_sp = sign_blinded(&sk, &good_b).unwrap();

    let bad_g1 = non_subgroup_g1();
    assert_eq!(sign_blinded(&sk, &bad_g1), Err(TokenError::NotInSubgroup));
    assert_eq!(sign_blinded(&sk, &infinity_g1()), Err(TokenError::Infinity));
    assert_eq!(sign_blinded(&sk, &[0u8; G1_LEN]), Err(TokenError::BadPoint));

    for bad in [bad_g1, infinity_g1(), [0u8; G1_LEN]] {
        assert!(!verify(&pk, &m, DST, &bad));
        assert!(!verify_blind_issue(&pk, &bad, &good_sp));
        assert!(!verify_blind_issue(&pk, &good_b, &bad));
    }
    for bad in [non_subgroup_g2(), infinity_g2(), [0u8; G2_LEN]] {
        assert!(!verify(&bad, &m, DST, &s));
        assert!(!verify_blind_issue(&bad, &good_b, &good_sp));
    }
}

#[test]
fn infinity_cannot_forge_with_zero_like_inputs() {
    let sk = keygen(&mut OsRng);
    let pk = sk.public_key();
    assert!(!verify_blind_issue(&pk, &infinity_g1(), &infinity_g1()));
    assert!(!verify(&infinity_g2(), b"m", DST, &infinity_g1()));
}

#[test]
fn verify_blind_issue_catches_wrong_signer_key() {
    let (sk, other) = (keygen(&mut OsRng), keygen(&mut OsRng));
    let (_r, b) = blind(&[6u8; 64], DST, &mut OsRng);
    let sp = sign_blinded(&sk, &b).unwrap();
    assert!(verify_blind_issue(&sk.public_key(), &b, &sp));
    assert!(!verify_blind_issue(&other.public_key(), &b, &sp));
}

#[test]
fn wallet_detects_signer_using_another_key() {
    let (published, tagging) = (keygen(&mut OsRng), keygen(&mut OsRng));
    let p = PendingToken::new(&mut OsRng, 0, DST).unwrap();
    let sp = sign_blinded(&tagging, &p.blinded).unwrap();
    assert!(matches!(
        p.finish(&sp, &published.public_key()),
        Err(TokenError::BadSignature)
    ));
}

#[test]
fn pending_token_survives_a_restart() {
    let sk = keygen(&mut OsRng);
    let p = PendingToken::new(&mut OsRng, 3, DST).unwrap();
    let saved = p.to_secret_bytes();
    let blinded = p.blinded;
    drop(p);

    let restored = PendingToken::from_secret_bytes(&saved).unwrap();
    assert_eq!(restored.blinded, blinded, "the same blinded point comes back");
    let sp = sign_blinded(&sk, &restored.blinded).unwrap();
    let (token, _owner) = restored.finish(&sp, &sk.public_key()).unwrap();
    assert!(verify_token(&sk.public_key(), &token, DST));
}

#[test]
fn bad_saved_tokens_are_refused() {
    let p = PendingToken::new(&mut OsRng, 3, DST).unwrap();
    let saved = p.to_secret_bytes();
    assert!(PendingToken::from_secret_bytes(&saved[..50]).is_err());
    let mut extra = saved.clone();
    extra.push(0);
    assert!(PendingToken::from_secret_bytes(&extra).is_err());
    let mut tier = saved.clone();
    tier[0] = 8;
    assert!(PendingToken::from_secret_bytes(&tier).is_err());
    let mut zero_r = saved;
    zero_r[65..97].fill(0);
    assert!(PendingToken::from_secret_bytes(&zero_r).is_err());
}

#[test]
fn token_encoding() {
    let t = Token { denom_id: 3, pk: [1; 32], nonce: [2; 32], sig: [3; G1_LEN] };
    assert_eq!(Token::from_bytes(&t.to_bytes()).unwrap(), t);
    assert_eq!(t.to_bytes().len(), 113);
    for len in [0, 1, 112, 114, 500] {
        assert_eq!(Token::from_bytes(&vec![0u8; len]), Err(TokenError::BadLength));
    }
    let mut bad = t.to_bytes();
    bad[0] = 8;
    assert_eq!(Token::from_bytes(&bad), Err(TokenError::BadDenom));
    assert!(PendingToken::new(&mut OsRng, 8, DST).is_err());
}

#[test]
fn nullifier_depends_on_owner_and_nonce() {
    let base = nullifier(0, &[1; 32], &[2; 32]);
    assert_ne!(base, nullifier(0, &[9; 32], &[2; 32]));
    assert_ne!(base, nullifier(0, &[1; 32], &[9; 32]));
    assert_ne!(base, nullifier(7, &[1; 32], &[2; 32]), "the tier is part of the nullifier");
    assert_eq!(base, nullifier(0, &[1; 32], &[2; 32]));
}

#[test]
fn the_tier_is_part_of_the_signed_message() {
    let sk = keygen(&mut OsRng);
    let pk = sk.public_key();
    let p = PendingToken::new(&mut OsRng, 2, DST).unwrap();
    let sp = sign_blinded(&sk, &p.blinded).unwrap();
    let (token, _owner) = p.finish(&sp, &pk).unwrap();
    let mut other_tier = token.clone();
    other_tier.denom_id = 3;
    assert_ne!(token.message(), other_tier.message());
    assert!(!verify_token(&pk, &other_tier, DST), "same key, other tier");
}

/// Applies a scalar to a point without any validation, as a malicious signer or depositor could.
fn raw_mult(point: &[u8; G1_LEN], sk: &SecretKey) -> [u8; G1_LEN] {
    let scalar = sk.to_bytes();
    let mut le = scalar;
    le.reverse();
    let mut a = blst_p1_affine::default();
    let (mut j, mut out, mut af) = (blst_p1::default(), blst_p1::default(), blst_p1_affine::default());
    let mut c = [0u8; G1_LEN];
    unsafe {
        assert_eq!(blst_p1_uncompress(&mut a, point.as_ptr()), BLST_ERROR::BLST_SUCCESS);
        blst_p1_from_affine(&mut j, &a);
        blst_p1_mult(&mut out, &j, le.as_ptr(), 255);
        blst_p1_to_affine(&mut af, &out);
        blst_p1_affine_compress(c.as_mut_ptr(), &af);
    }
    c
}

#[test]
fn a_correct_signature_on_a_non_subgroup_point_is_refused() {
    let sk = keygen(&mut OsRng);
    let bad = non_subgroup_g1();
    let sig = raw_mult(&bad, &sk);
    assert!(!verify_blind_issue(&sk.public_key(), &bad, &sig), "sk*B with B outside the subgroup");
}

#[test]
fn secret_key_round_trip_and_bad_keys() {
    let sk = keygen(&mut OsRng);
    let again = SecretKey::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(sk.public_key(), again.public_key());
    assert!(SecretKey::from_bytes(&[0u8; 32]).is_err());
    assert!(SecretKey::from_bytes(&[0xffu8; 32]).is_err());
}

#[test]
fn dst_length_limit() {
    assert!(token_dst("testnet", &"a".repeat(64)).is_ok());
    assert_eq!(token_dst("testnet", &"a".repeat(300)).err(), Some(TokenError::DstTooLong));
}

#[test]
fn spend_digest_binds_every_field() {
    let nf = [4u8; 32];
    let change = [ChangeOut { denom_id: 1, blinded: [5u8; G1_LEN] }];
    let base = spend_digest("m", "r", 2, &nf, "bob", 10, 1, &change);
    assert_eq!(base, spend_digest("m", "r", 2, &nf, "bob", 10, 1, &change));
    assert_ne!(base, spend_digest("x", "r", 2, &nf, "bob", 10, 1, &change));
    assert_ne!(base, spend_digest("m", "other", 2, &nf, "bob", 10, 1, &change));
    assert_ne!(base, spend_digest("m", "r", 3, &nf, "bob", 10, 1, &change));
    assert_ne!(base, spend_digest("m", "r", 2, &[6u8; 32], "bob", 10, 1, &change));
    assert_ne!(base, spend_digest("m", "r", 2, &nf, "eve", 10, 1, &change));
    assert_ne!(base, spend_digest("m", "r", 2, &nf, "bob", 11, 1, &change));
    assert_ne!(base, spend_digest("m", "r", 2, &nf, "bob", 10, 2, &change));
    assert_ne!(base, spend_digest("m", "r", 2, &nf, "bob", 10, 1, &[]));
    let other = [ChangeOut { denom_id: 1, blinded: [6u8; G1_LEN] }];
    assert_ne!(base, spend_digest("m", "r", 2, &nf, "bob", 10, 1, &other));
    let other = [ChangeOut { denom_id: 2, blinded: [5u8; G1_LEN] }];
    assert_ne!(base, spend_digest("m", "r", 2, &nf, "bob", 10, 1, &other));
}

#[test]
fn redeem_digest_binds_submitter() {
    let nf = [4u8; 32];
    let base = redeem_digest("m", "r", &nf);
    assert_ne!(base, redeem_digest("m", "other", &nf));
    assert_ne!(base, redeem_digest("x", "r", &nf));
    assert_ne!(base, redeem_digest("m", "r", &[5u8; 32]));
}

#[test]
fn owner_signature_round_trip() {
    let owner = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pk = owner.verifying_key().to_bytes();
    let nf = [1u8; 32];
    let d = claim_digest("mint", "relay", &nf);
    let sig = sign_digest(&owner, &d);
    assert!(verify_digest(&pk, &d, &sig));
    assert!(!verify_digest(&pk, &claim_digest("mint", "evil", &nf), &sig));
    let other = ed25519_dalek::SigningKey::generate(&mut OsRng);
    assert!(!verify_digest(&other.verifying_key().to_bytes(), &d, &sig));
}

#[test]
fn raw_encodings_are_uncompressed_and_validated() {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let h = hash_to_g1(&buf, DST);
    let raw = g1_to_raw(&h).unwrap();
    assert_eq!(&raw[1..48], &h[1..48], "x coordinate unchanged apart from the flags");
    assert_eq!(g1_to_raw(&non_subgroup_g1()), Err(TokenError::NotInSubgroup));
    let pk = keygen(&mut OsRng).public_key();
    assert_eq!(g2_to_raw(&pk).unwrap().len(), G2_RAW_LEN);
    assert_eq!(g2_to_raw(&non_subgroup_g2()), Err(TokenError::NotInSubgroup));
}

/// RFC 9380 appendix J.9.1 vectors. The RFC site is blocked in this sandbox, so they were
/// transcribed from memory: agreement with blst below is what validates both.
#[test]
fn rfc9380_hash_to_g1_vectors() {
    const QUUX: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let vectors: [(&[u8], &str); 2] = [
        (b"", "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"),
        (b"abc", "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903"),
    ];
    for (msg, x_hex) in vectors {
        let c = hash_to_g1(msg, QUUX);
        let mut x = c;
        x[0] &= 0x1f;
        let got: String = x.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, x_hex);
    }
}
