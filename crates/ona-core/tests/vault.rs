use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ona_core::vault::{Vault, MAX_TTL_SECS};
use ona_core::Core;
use serde_json::Value;

const T0: u64 = 1_000_000;
const SECRET: &str = "le dossier confidentiel de M. Martin";

fn dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("ona-vault-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    path
}

fn chat_file(d: &PathBuf, id: &str) -> PathBuf {
    d.join(format!("{id}.chat"))
}

#[test]
fn a_chat_is_readable_until_24_hours_and_not_after() {
    let d = dir("ttl");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("c1", SECRET, T0).unwrap();
    assert_eq!(v.get("c1", T0 + MAX_TTL_SECS - 1).unwrap().as_deref(), Some(SECRET));
    assert_eq!(v.get("c1", T0 + MAX_TTL_SECS).unwrap(), None);
    assert!(!chat_file(&d, "c1").exists(), "the file is gone");
    let keys = fs::read_to_string(d.join("keys")).unwrap();
    assert!(!keys.contains("c1"), "and so is its key");
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn nothing_readable_is_left_on_disk() {
    let d = dir("clear");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("c1", SECRET, T0).unwrap();
    let raw = fs::read(chat_file(&d, "c1")).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"dossier"), "the text is encrypted");
    for name in ["keys", "c1.chat"] {
        assert_eq!(fs::metadata(d.join(name)).unwrap().permissions().mode() & 0o777, 0o600, "{name}");
    }
    assert_eq!(fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn an_old_chat_is_destroyed_when_the_app_starts() {
    let d = dir("restart");
    {
        let mut v = Vault::open(&d, T0).unwrap();
        v.put("old", SECRET, T0).unwrap();
        v.put("new", "recent", T0 + 80_000).unwrap();
    }
    let mut v = Vault::open(&d, T0 + MAX_TTL_SECS).unwrap();
    assert!(!chat_file(&d, "old").exists(), "gone without any read");
    assert_eq!(v.get("new", T0 + MAX_TTL_SECS).unwrap().as_deref(), Some("recent"));
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn saving_again_does_not_extend_the_life_of_a_chat() {
    let d = dir("extend");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("c1", "first", T0).unwrap();
    v.put("c1", "second", T0 + 86_000).unwrap();
    assert_eq!(v.get("c1", T0 + 86_000).unwrap().as_deref(), Some("second"));
    assert_eq!(v.get("c1", T0 + MAX_TTL_SECS).unwrap(), None);
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_shorter_life_is_allowed_a_longer_one_is_not() {
    let d = dir("limits");
    assert!(Vault::with_ttl(&d, T0, MAX_TTL_SECS + 1).is_err());
    assert!(Vault::with_ttl(&d, T0, 0).is_err());
    let mut v = Vault::with_ttl(&d, T0, 60).unwrap();
    v.put("c1", "x", T0).unwrap();
    assert_eq!(v.get("c1", T0 + 60).unwrap(), None);
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn ids_cannot_escape_the_vault_directory() {
    let d = dir("ids");
    let mut v = Vault::open(&d, T0).unwrap();
    for bad in ["../evil", "a/b", "", ".", "..", "a b", &"x".repeat(65)] {
        assert!(v.put(bad, "x", T0).is_err(), "{bad}");
        assert!(v.get(bad, T0).is_err(), "{bad}");
    }
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn editing_the_key_file_cannot_extend_a_chat() {
    let d = dir("edit");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("c1", SECRET, T0).unwrap();
    drop(v);
    let keys = fs::read_to_string(d.join("keys")).unwrap();
    let later = T0 + MAX_TTL_SECS + 999;
    let edited = keys.replace(&(T0 + MAX_TTL_SECS).to_string(), &later.to_string());
    assert_ne!(keys, edited);
    fs::write(d.join("keys"), edited).unwrap();
    let mut v = Vault::open(&d, T0).unwrap();
    assert!(v.get("c1", T0 + MAX_TTL_SECS + 1).is_err(), "the expiry is authenticated");
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn an_altered_file_is_refused() {
    let d = dir("tamper");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("c1", SECRET, T0).unwrap();
    let mut raw = fs::read(chat_file(&d, "c1")).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    fs::write(chat_file(&d, "c1"), raw).unwrap();
    assert!(v.get("c1", T0).is_err());
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_crash_between_key_and_file_deletion_leaves_nothing_behind() {
    let d = dir("orphan");
    {
        let mut v = Vault::open(&d, T0).unwrap();
        v.put("c1", SECRET, T0).unwrap();
    }
    fs::write(d.join("keys"), "").unwrap(); // the key was destroyed, the crash came before the file
    assert!(chat_file(&d, "c1").exists());
    Vault::open(&d, T0).unwrap();
    assert!(!chat_file(&d, "c1").exists());
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_chat_is_only_kept_past_24_hours_if_the_user_chose_it() {
    let d = dir("keep");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("kept", SECRET, T0).unwrap();
    v.put("default", "x", T0).unwrap();
    v.keep("kept", T0 + 10).unwrap();
    drop(v);

    let later = T0 + 10 * MAX_TTL_SECS;
    let mut v = Vault::open(&d, later).unwrap();
    assert_eq!(v.get("kept", later).unwrap().as_deref(), Some(SECRET), "survives past 24 hours and a restart");
    assert_eq!(v.get("default", later).unwrap(), None, "the other chat expired as usual");
    let raw = fs::read(d.join("kept.kept")).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"dossier"), "a kept chat stays encrypted");
    assert!(!chat_file(&d, "kept").exists(), "no second copy under the old name");

    v.put("kept", "updated", later).unwrap();
    assert_eq!(v.get("kept", later + 5 * MAX_TTL_SECS).unwrap().as_deref(), Some("updated"));
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn only_an_existing_live_chat_can_be_kept() {
    let d = dir("keep-limits");
    let mut v = Vault::open(&d, T0).unwrap();
    assert!(v.keep("absent", T0).is_err());
    v.put("c1", "x", T0).unwrap();
    assert!(v.keep("c1", T0 + MAX_TTL_SECS).is_err(), "too late: it has already expired");
    assert!(v.keep("../evil", T0).is_err());
    v.put("c2", "y", T0).unwrap();
    v.keep("c2", T0).unwrap();
    v.keep("c2", T0).unwrap();
    assert_eq!(v.get("c2", T0).unwrap().as_deref(), Some("y"), "keeping twice changes nothing");
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn the_user_can_delete_any_chat_at_once() {
    let d = dir("forget");
    let mut v = Vault::open(&d, T0).unwrap();
    v.put("a", "x", T0).unwrap();
    v.put("b", "y", T0).unwrap();
    v.keep("b", T0).unwrap();
    assert!(v.forget("a").unwrap());
    assert!(v.forget("b").unwrap());
    assert!(!v.forget("a").unwrap(), "already gone");
    assert_eq!(v.get("b", T0).unwrap(), None);
    assert!(!chat_file(&d, "a").exists());
    assert!(!d.join("b.kept").exists());
    assert!(!fs::read_to_string(d.join("keys")).unwrap().contains("b "), "its key is destroyed");
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_crash_during_keep_leaves_exactly_one_readable_copy() {
    let d = dir("keep-crash");
    {
        let mut v = Vault::open(&d, T0).unwrap();
        v.put("before", SECRET, T0).unwrap();
        v.put("after", SECRET, T0).unwrap();
        v.keep("after", T0).unwrap();
    }
    // Crash before the key update: a stray kept file next to the normal chat.
    fs::write(d.join("before.kept"), b"partial").unwrap();
    // Crash after the key update: the old chat file was not removed yet.
    fs::write(chat_file(&d, "after"), b"stale").unwrap();

    let mut v = Vault::open(&d, T0).unwrap();
    assert_eq!(v.get("before", T0).unwrap().as_deref(), Some(SECRET));
    assert_eq!(v.get("after", T0).unwrap().as_deref(), Some(SECRET));
    assert!(!d.join("before.kept").exists());
    assert!(!chat_file(&d, "after").exists());
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn both_front_ends_reach_the_vault_through_dispatch() {
    let d = dir("dispatch");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut core = Core::with_vault(Vault::open(&d, now).unwrap());
    let ask = |core: &mut Core, r: &str| -> Value { serde_json::from_str(&core.dispatch(r)).unwrap() };
    let saved = ask(&mut core, r#"{"cmd":"chat_save","id":"c1","text":"bonjour"}"#);
    assert_eq!(saved["ok"], true, "{saved}");
    assert_eq!(saved["expires_in_secs"], 86400);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_read","id":"c1"}"#)["text"], "bonjour");
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_read","id":"absent"}"#)["text"], Value::Null);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_keep","id":"c1"}"#)["kept"], true);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_forget","id":"c1"}"#)["forgotten"], true);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_read","id":"c1"}"#)["text"], Value::Null);
    fs::remove_dir_all(&d).unwrap();

    let mut without = Core::new();
    assert_eq!(ask(&mut without, r#"{"cmd":"chat_read","id":"c1"}"#)["ok"], false);
}
