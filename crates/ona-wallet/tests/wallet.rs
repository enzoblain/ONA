use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ona_token::{keygen, sign_blinded, verify_token, PendingToken};
use ona_wallet::Wallet;
use rand::rngs::OsRng;

const DST: &[u8] = b"ONA-MINT-V1:sandbox:mint.test:BLS12381G1_XMD:SHA-256_SSWU_RO_";
const KEY: [u8; 32] = [7u8; 32];

fn seal_of(path: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.seal", path.display()))
}

fn fresh(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ona-wallet-{}-{name}", std::process::id()));
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(seal_of(&path));
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
    drop(w);

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

// ---------- crashes, concurrent opens, rollbacks ----------

#[test]
fn a_torn_last_line_is_dropped_and_reported() {
    let path = fresh("torn");
    {
        let mut w = Wallet::open(&path, &KEY).unwrap();
        w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
        assert!(!w.dropped_torn_line());
    }
    // A crash in the middle of the next append: half a line, no newline.
    let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all(b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
    drop(f);
    let mut w = Wallet::open(&path, &KEY).expect("the intact token stays reachable");
    assert!(w.dropped_torn_line());
    assert_eq!(w.pending().unwrap().len(), 1);
    w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    drop(w);
    let w = Wallet::open(&path, &KEY).unwrap();
    assert!(!w.dropped_torn_line());
    assert_eq!(w.pending().unwrap().len(), 2, "the file is clean after the repair");
}

#[test]
fn a_complete_last_line_that_fails_is_still_refused() {
    let path = two_line_wallet("tailtamper");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str(&"ab".repeat(80));
    text.push('\n');
    fs::write(&path, text).unwrap();
    assert!(Wallet::open(&path, &KEY).is_err());
}

#[test]
fn a_second_open_of_the_same_wallet_is_refused() {
    let path = fresh("two");
    let mut a = Wallet::open(&path, &KEY).unwrap();
    assert_eq!(Wallet::open(&path, &KEY).err().unwrap(), "the wallet is already open in another process");
    a.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    drop(a);
    let w = Wallet::open(&path, &KEY).unwrap();
    assert_eq!(w.pending().unwrap().len(), 1);
}

#[test]
fn an_older_copy_is_refused_instead_of_offering_a_spent_token_again() {
    let path = fresh("rollback");
    let sk = keygen(&mut OsRng);
    let p = PendingToken::new(&mut OsRng, 0, DST).unwrap();
    let blinded = p.blinded;
    let mut w = Wallet::open(&path, &KEY).unwrap();
    w.save_pending(&p).unwrap();
    let token = w.finish(&blinded, &sign_blinded(&sk, &blinded).unwrap(), &sk.public_key()).unwrap();
    let backup = fs::read(&path).unwrap();
    w.mark_spending(&token.nullifier()).unwrap();
    drop(w);
    fs::write(&path, &backup).unwrap();
    assert!(Wallet::open(&path, &KEY).err().unwrap().contains("rolled back"));
}

#[test]
fn lines_removed_from_the_end_are_detected() {
    let path = two_line_wallet("cut");
    let text = fs::read_to_string(&path).unwrap();
    let first = text.lines().next().unwrap();
    fs::write(&path, format!("{first}\n")).unwrap();
    assert!(Wallet::open(&path, &KEY).err().unwrap().contains("rolled back"));
}

#[test]
fn a_deleted_wallet_is_not_silently_recreated_empty() {
    let path = two_line_wallet("deleted");
    fs::remove_file(&path).unwrap();
    assert!(Wallet::open(&path, &KEY).err().unwrap().contains("missing"));
    assert!(!path.exists(), "nothing was created in its place");
}

#[test]
fn a_state_kept_elsewhere_catches_a_restore_of_wallet_and_seal_together() {
    let path = fresh("both");
    let mut w = Wallet::open(&path, &KEY).unwrap();
    w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    let (old_wallet, old_seal) = (fs::read(&path).unwrap(), fs::read(seal_of(&path)).unwrap());
    w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    let kept = w.state();
    drop(w);
    fs::write(&path, old_wallet).unwrap();
    fs::write(seal_of(&path), old_seal).unwrap();
    assert!(Wallet::open(&path, &KEY).is_ok(), "the seal alone cannot see this");
    assert!(Wallet::open_expecting(&path, &KEY, kept).is_err());
}

#[test]
fn spend_marks_need_a_known_token_and_a_release_needs_a_mark() {
    let path = fresh("guards");
    let mut w = Wallet::open(&path, &KEY).unwrap();
    assert!(w.mark_spending(&[9u8; 32]).is_err(), "not a token of this wallet");
    assert!(w.release(&[9u8; 32]).is_err(), "nothing being spent");
    let sk = keygen(&mut OsRng);
    let p = PendingToken::new(&mut OsRng, 0, DST).unwrap();
    let blinded = p.blinded;
    w.save_pending(&p).unwrap();
    let token = w.finish(&blinded, &sign_blinded(&sk, &blinded).unwrap(), &sk.public_key()).unwrap();
    w.mark_spending(&token.nullifier()).unwrap();
    assert!(w.mark_spending(&token.nullifier()).is_err(), "already being spent");
}

#[test]
fn an_existing_wallet_readable_by_others_is_refused() {
    let path = two_line_wallet("perms");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Wallet::open(&path, &KEY).err().unwrap().contains("owner only"));
}

#[test]
fn a_wrong_key_on_a_lone_torn_line_without_seal_touches_nothing() {
    let path = fresh("wrongtorn");
    {
        let mut w = Wallet::open(&path, &KEY).unwrap();
        w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    }
    // One line without its newline, and no seal: nothing proves which key is right.
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.trim_end()).unwrap();
    fs::remove_file(seal_of(&path)).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(Wallet::open(&path, &[8u8; 32]).is_err());
    assert_eq!(fs::read(&path).unwrap(), before, "the file is untouched");
    assert!(!seal_of(&path).exists(), "no seal was written");
}

#[test]
fn a_rolled_back_wallet_with_a_torn_line_is_refused_untouched() {
    let path = two_line_wallet("rolltorn");
    let text = fs::read_to_string(&path).unwrap();
    let first = text.lines().next().unwrap();
    fs::write(&path, format!("{first}\n0011aabb")).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(Wallet::open(&path, &KEY).err().unwrap().contains("rolled back"));
    assert_eq!(fs::read(&path).unwrap(), before, "no repair before the rollback check");
}

#[test]
fn an_expected_state_refuses_a_missing_wallet_without_creating_it() {
    let path = fresh("expectmissing");
    let mut w = Wallet::open(&path, &KEY).unwrap();
    w.save_pending(&PendingToken::new(&mut OsRng, 0, DST).unwrap()).unwrap();
    let kept = w.state();
    drop(w);
    fs::remove_file(&path).unwrap();
    fs::remove_file(seal_of(&path)).unwrap();
    assert!(Wallet::open_expecting(&path, &KEY, kept).err().unwrap().contains("rolled back"));
    assert!(!path.exists(), "no empty wallet was created");
    assert!(!seal_of(&path).exists());
}

#[test]
fn a_wallet_without_seal_is_refused_unless_adopted_explicitly() {
    let path = two_line_wallet("adopt");
    fs::remove_file(seal_of(&path)).unwrap();
    assert!(Wallet::open(&path, &KEY).err().unwrap().contains("seal is missing"));
    assert!(Wallet::open_adopting_unsealed(&path, &[8u8; 32]).is_err(), "every line must still decrypt");
    let w = Wallet::open_adopting_unsealed(&path, &KEY).unwrap();
    assert_eq!(w.pending().unwrap().len(), 2);
    drop(w);
    assert!(Wallet::open(&path, &KEY).is_ok(), "sealed from now on");
    assert!(Wallet::open_adopting_unsealed(&path, &KEY).is_err(), "only for a wallet without seal");
}
