use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ona_token::{keygen, sign_blinded, verify_token, PendingToken};
use ona_wallet::Wallet;
use rand::rngs::OsRng;

const DST: &[u8] = b"ONA-MINT-V1:sandbox:mint.test:BLS12381G1_XMD:SHA-256_SSWU_RO_";
const KEY: [u8; 32] = [7u8; 32];

fn fresh(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ona-wallet-{}-{name}", std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

#[test]
fn a_crash_after_the_deposit_does_not_lose_the_token() {
    let path = fresh("crash");
    let sk = keygen(&mut OsRng);
    let p = PendingToken::new(&mut OsRng, 1, DST).unwrap();
    let blinded = p.blinded;
    {
        let mut w = Wallet::open(&path, &KEY).unwrap();
        w.save_pending(&p).unwrap();
    }
    drop(p);

    let mut w = Wallet::open(&path, &KEY).unwrap();
    assert_eq!(w.pending().unwrap().len(), 1);
    let sig = sign_blinded(&sk, &blinded).unwrap();
    let token = w.finish(&blinded, &sig, &sk.public_key()).unwrap();
    assert!(verify_token(&sk.public_key(), &token, DST));
    assert!(w.pending().unwrap().is_empty());

    let w = Wallet::open(&path, &KEY).unwrap();
    assert!(w.pending().unwrap().is_empty(), "still finished after a restart");
    let available = w.available();
    assert_eq!(available.len(), 1);
    assert_eq!(available[0].0, token);
    assert_eq!(available[0].1.verifying_key().to_bytes(), token.pk, "the owner key comes back");
    fs::remove_file(&path).unwrap();
}

#[test]
fn a_token_being_spent_is_not_offered_again_after_a_restart() {
    let path = fresh("spend");
    let sk = keygen(&mut OsRng);
    let p = PendingToken::new(&mut OsRng, 0, DST).unwrap();
    let blinded = p.blinded;
    let mut w = Wallet::open(&path, &KEY).unwrap();
    w.save_pending(&p).unwrap();
    let token = w.finish(&blinded, &sign_blinded(&sk, &blinded).unwrap(), &sk.public_key()).unwrap();
    let nf = token.nullifier();
    w.mark_spending(&nf).unwrap();
    assert!(w.available().is_empty());
    drop(w);

    let mut w = Wallet::open(&path, &KEY).unwrap();
    assert!(w.available().is_empty());
    w.release(&nf).unwrap();
    assert_eq!(w.available().len(), 1);
    drop(w);
    assert_eq!(Wallet::open(&path, &KEY).unwrap().available().len(), 1);
    fs::remove_file(&path).unwrap();
}

#[test]
fn a_wrong_signer_key_leaves_the_token_pending() {
    let path = fresh("wrongkey");
    let (published, tagging) = (keygen(&mut OsRng), keygen(&mut OsRng));
    let p = PendingToken::new(&mut OsRng, 0, DST).unwrap();
    let blinded = p.blinded;
    let mut w = Wallet::open(&path, &KEY).unwrap();
    w.save_pending(&p).unwrap();
    let sig = sign_blinded(&tagging, &blinded).unwrap();
    assert!(w.finish(&blinded, &sig, &published.public_key()).is_err());
    assert_eq!(w.pending().unwrap().len(), 1);
    assert!(w.available().is_empty());
    assert!(w.finish(&[0u8; 48], &sig, &published.public_key()).is_err(), "unknown blinded point");
    fs::remove_file(&path).unwrap();
}

fn two_line_wallet(name: &str) -> PathBuf {
    let path = fresh(name);
    let mut w = Wallet::open(&path, &KEY).unwrap();
    for _ in 0..2 {
        w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    }
    path
}

#[test]
fn the_file_is_private_and_holds_no_clear_secrets() {
    let path = fresh("private");
    let p = PendingToken::new(&mut OsRng, 0, DST).unwrap();
    let mut w = Wallet::open(&path, &KEY).unwrap();
    w.save_pending(&p).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let text = fs::read_to_string(&path).unwrap();
    let secret: String = p.to_secret_bytes()[1..33].iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&secret), "the owner key must not appear in clear");
    assert!(!text.contains("ONA-MINT"), "nor the domain");
    fs::remove_file(&path).unwrap();
}

#[test]
fn wrong_key_tampering_and_reordering_are_refused() {
    let path = two_line_wallet("tamper");
    assert!(Wallet::open(&path, &[8u8; 32]).is_err(), "wrong key");

    let text = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.swap(0, 1);
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    assert!(Wallet::open(&path, &KEY).is_err(), "lines swapped");

    let mut bytes = text.clone().into_bytes();
    bytes[60] = if bytes[60] == b'0' { b'1' } else { b'0' };
    fs::write(&path, &bytes).unwrap();
    assert!(Wallet::open(&path, &KEY).is_err(), "one character changed");

    fs::write(&path, "not hex\n").unwrap();
    assert!(Wallet::open(&path, &KEY).is_err());
    fs::remove_file(&path).unwrap();
}
