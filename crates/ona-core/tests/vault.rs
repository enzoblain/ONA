use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ona_core::vault::{Expiry, FileKeyStore, KeyStore, Vault, CLOCK_TOLERANCE_SECS, MAX_TTL_SECS};
use ona_core::Core;
use serde_json::Value;

const T0: u64 = 1_000_000;
const SECRET: &str = "le dossier confidentiel de M. Martin";

/// A test folder holding the vault directory and, apart from it, the key file.
struct Place {
    root: PathBuf,
}

impl Place {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ona-vault-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("keys-dir")).unwrap();
        Self { root }
    }

    fn dir(&self) -> PathBuf {
        self.root.join("vault")
    }

    fn keys_file(&self) -> PathBuf {
        self.root.join("keys-dir").join("keys")
    }

    fn keys(&self) -> Box<dyn KeyStore> {
        Box::new(FileKeyStore::new(&self.keys_file()))
    }

    fn open(&self, now: u64) -> Vault {
        Vault::open(&self.dir(), self.keys(), now).unwrap()
    }

    fn chat(&self, id: &str) -> PathBuf {
        self.dir().join(format!("{id}.chat"))
    }

    fn key_text(&self) -> String {
        fs::read_to_string(self.keys_file()).unwrap_or_default()
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_chat_is_readable_until_24_hours_and_not_after() {
    let p = Place::new("ttl");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    assert_eq!(v.get("c1", T0 + MAX_TTL_SECS - 1).unwrap().as_deref(), Some(SECRET));
    assert_eq!(v.get("c1", T0 + MAX_TTL_SECS).unwrap(), None);
    assert!(!p.chat("c1").exists(), "the file is gone");
    assert!(!p.key_text().contains("c1"), "and so is its key");
}

#[test]
fn nothing_readable_is_left_on_disk() {
    let p = Place::new("clear");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    let raw = fs::read(p.chat("c1")).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"dossier"), "the text is encrypted");
    // The modes exist on Unix only (`private_fs`).
    #[cfg(unix)]
    {
        for path in [p.keys_file(), p.chat("c1")] {
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{path:?}");
        }
        assert_eq!(fs::metadata(p.dir()).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

/// The key is not next to the file. The vault refuses a key file in its directory.
#[test]
fn keys_are_kept_apart_from_the_chats() {
    let p = Place::new("apart");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    let key_line = p.key_text().lines().find(|l| l.starts_with("c1 ")).unwrap().to_string();
    let key_hex = key_line.split(' ').nth(1).unwrap().to_string();
    let names: Vec<String> = fs::read_dir(p.dir()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    for name in &names {
        let text = String::from_utf8_lossy(&fs::read(p.dir().join(name)).unwrap()).to_string();
        assert!(!text.contains(&key_hex), "the key is in {name}");
    }
    assert!(!names.iter().any(|n| n == "keys"), "{names:?}");
    drop(v);
    let inside = Box::new(FileKeyStore::new(&p.dir().join("keys")));
    let err = Vault::open(&p.dir(), inside, T0).err().unwrap();
    assert!(err.contains("inside the vault directory"), "{err}");
}

/// Once the vault has seen a later time, setting the clock back destroys every expiring chat.
#[test]
fn setting_the_clock_back_destroys_expiring_chats() {
    let p = Place::new("clock");
    {
        let mut v = p.open(T0);
        v.put("c1", SECRET, T0).unwrap();
        v.put("kept", SECRET, T0).unwrap();
        v.keep("kept", T0).unwrap();
        // The application runs again ten hours later: that time is recorded.
        v.get("c1", T0 + 36_000).unwrap();
    }
    let back = T0 + 3600;
    let mut v = p.open(back);
    assert_eq!(v.get("c1", back).unwrap(), None, "read one hour after saving, long after");
    assert!(!p.chat("c1").exists());
    assert_eq!(v.get("kept", back).unwrap().as_deref(), Some(SECRET), "a kept chat is the user's choice");
}

/// The recorded time cannot be removed on its own: it lives with the keys. Removing whatever holds it, then
/// setting the clock back, leaves no chat to read.
#[test]
fn the_recorded_time_cannot_be_removed_alone() {
    let p = Place::new("floor");
    {
        let mut v = p.open(T0);
        v.put("c1", SECRET, T0).unwrap();
        v.get("c1", T0 + 36_000).unwrap();
    }
    assert!(p.key_text().starts_with(&format!("floor {}\n", T0 + 36_000)), "{}", p.key_text());
    let _ = fs::remove_file(p.dir().join("clock"));
    let back = T0 + 3600;
    let mut v = p.open(back);
    assert_eq!(v.get("c1", back).unwrap(), None);
    drop(v);
    fs::remove_file(p.keys_file()).unwrap();
    let mut v = p.open(back);
    assert_eq!(v.get("c1", back).unwrap(), None, "no key, no chat");
}

/// Files an earlier version left in the vault directory are removed when it opens.
#[test]
fn files_of_an_earlier_version_are_removed() {
    let p = Place::new("legacy");
    fs::create_dir_all(p.dir()).unwrap();
    fs::write(p.dir().join("keys"), "c1 00 1\n").unwrap();
    fs::write(p.dir().join("clock"), "5").unwrap();
    let witness = p.root.join("legacy-keys");
    fs::hard_link(p.dir().join("keys"), &witness).unwrap();
    p.open(T0);
    assert!(!p.dir().join("keys").exists());
    assert!(!p.dir().join("clock").exists());
    let left = fs::read(&witness).unwrap();
    assert_eq!(left.len(), 8);
    assert!(left.iter().all(|b| *b == 0), "the old key file is overwritten, not only removed");
}

/// A clock far ahead when saving, then corrected, does not make a chat live for ever.
#[test]
fn a_clock_corrected_after_running_ahead_ends_the_chats_saved_meanwhile() {
    let p = Place::new("ahead");
    let ahead = T0 + 1_000 * MAX_TTL_SECS;
    let mut v = p.open(ahead);
    v.put("c1", SECRET, ahead).unwrap();
    assert_eq!(v.get("c1", T0).unwrap(), None, "the clock came back: everything expiring is destroyed");
}

#[test]
fn a_small_clock_correction_destroys_nothing() {
    let p = Place::new("small");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0 + 600).unwrap();
    let back = T0 + 600 - CLOCK_TOLERANCE_SECS;
    assert_eq!(v.get("c1", back).unwrap().as_deref(), Some(SECRET));
    assert_eq!(v.expiry("c1"), Some(Expiry::At(T0 + 600 + MAX_TTL_SECS)), "the expiry did not move");
}

/// A second process cannot open the same vault and write a forgotten key back.
#[test]
fn a_second_process_cannot_open_the_vault() {
    let p = Place::new("two");
    let mut a = p.open(T0);
    a.put("c1", SECRET, T0).unwrap();
    let err = Vault::open(&p.dir(), p.keys(), T0).err().unwrap();
    assert!(err.contains("already open"), "{err}");
    assert!(a.forget("c1").unwrap());
    drop(a);
    let mut b = p.open(T0 + 1);
    b.put("c2", "x", T0 + 1).unwrap();
    assert!(!p.key_text().contains("c1 "), "c1's key stays destroyed");
}

/// Temporary files left by a crash are cleared at start.
#[test]
fn leftovers_of_a_crash_are_cleared() {
    let p = Place::new("tmp");
    {
        let mut v = p.open(T0);
        v.put("c1", SECRET, T0).unwrap();
        fs::copy(p.chat("c1"), p.dir().join("c1.tmp")).unwrap();
    }
    fs::copy(p.keys_file(), p.keys_file().with_extension("tmp")).unwrap();
    let mut v = p.open(T0 + 1);
    assert!(!p.dir().join("c1.tmp").exists(), "ciphertext copy removed");
    v.put("c2", "x", T0 + 1).unwrap();
    assert!(!p.keys_file().with_extension("tmp").exists(), "old key copy removed at the next key write");
}

/// A `put` interrupted after its key was saved and before its file was written: no chat, not an error, and
/// the key goes at the next start.
#[test]
fn a_key_without_its_file_is_dropped() {
    let p = Place::new("nofile");
    {
        let mut v = p.open(T0);
        v.put("c1", SECRET, T0).unwrap();
    }
    fs::remove_file(p.chat("c1")).unwrap();
    let mut v = p.open(T0 + 1);
    assert_eq!(v.get("c1", T0 + 1).unwrap(), None);
    assert!(!p.key_text().contains("c1"));
}

/// A deleted chat file is overwritten before it is removed. Checked through a hard link, which keeps
/// the same file alive: its contents must be zeros afterwards. On an SSD or a copy-on-write file system,
/// that still says nothing about the old blocks.
#[test]
fn a_deleted_chat_is_overwritten_first() {
    let p = Place::new("shred");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    let witness = p.root.join("witness");
    fs::hard_link(p.chat("c1"), &witness).unwrap();
    let before = fs::read(&witness).unwrap();
    assert!(before.iter().any(|b| *b != 0));
    assert!(v.forget("c1").unwrap());
    let after = fs::read(&witness).unwrap();
    assert_eq!(after.len(), before.len());
    assert!(after.iter().all(|b| *b == 0), "the ciphertext was released without being overwritten");
}

/// A replaced key file is overwritten too, so an old copy of every key is not simply released.
#[test]
fn the_old_key_file_is_overwritten_when_replaced() {
    let p = Place::new("old-keys");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    let witness = p.root.join("old-keys");
    fs::hard_link(p.keys_file(), &witness).unwrap();
    assert!(fs::read_to_string(&witness).unwrap().contains("c1 "));
    v.forget("c1").unwrap();
    assert!(fs::read(&witness).unwrap().iter().all(|b| *b == 0));
}

#[test]
fn an_old_chat_is_destroyed_when_the_app_starts() {
    let p = Place::new("restart");
    {
        let mut v = p.open(T0);
        v.put("old", SECRET, T0).unwrap();
        v.put("new", "recent", T0 + 80_000).unwrap();
    }
    let mut v = p.open(T0 + MAX_TTL_SECS);
    assert!(!p.chat("old").exists(), "gone without any read");
    assert_eq!(v.get("new", T0 + MAX_TTL_SECS).unwrap().as_deref(), Some("recent"));
}

#[test]
fn saving_again_does_not_extend_the_life_of_a_chat() {
    let p = Place::new("extend");
    let mut v = p.open(T0);
    v.put("c1", "first", T0).unwrap();
    v.put("c1", "second", T0 + 86_000).unwrap();
    assert_eq!(v.get("c1", T0 + 86_000).unwrap().as_deref(), Some("second"));
    assert_eq!(v.get("c1", T0 + MAX_TTL_SECS).unwrap(), None);
}

#[test]
fn a_shorter_life_is_allowed_a_longer_one_is_not() {
    let p = Place::new("limits");
    assert!(Vault::with_ttl(&p.dir(), p.keys(), T0, MAX_TTL_SECS + 1).is_err());
    assert!(Vault::with_ttl(&p.dir(), p.keys(), T0, 0).is_err());
    let mut v = Vault::with_ttl(&p.dir(), p.keys(), T0, 60).unwrap();
    v.put("c1", "x", T0).unwrap();
    assert_eq!(v.get("c1", T0 + 60).unwrap(), None);
}

#[test]
fn ids_cannot_escape_the_vault_directory() {
    let p = Place::new("ids");
    let mut v = p.open(T0);
    for bad in ["../evil", "a/b", "", ".", "..", "a b", &"x".repeat(65)] {
        assert!(v.put(bad, "x", T0).is_err(), "{bad}");
        assert!(v.get(bad, T0).is_err(), "{bad}");
    }
}

#[test]
fn editing_the_key_file_cannot_extend_a_chat() {
    let p = Place::new("edit");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    drop(v);
    let keys = p.key_text();
    let later = T0 + MAX_TTL_SECS + 999;
    let edited = keys.replace(&(T0 + MAX_TTL_SECS).to_string(), &later.to_string());
    assert_ne!(keys, edited);
    fs::write(p.keys_file(), edited).unwrap();
    let mut v = p.open(T0);
    assert!(v.get("c1", T0 + MAX_TTL_SECS + 1).is_err(), "the expiry is authenticated");
}

#[test]
fn an_altered_file_is_refused() {
    let p = Place::new("tamper");
    let mut v = p.open(T0);
    v.put("c1", SECRET, T0).unwrap();
    let mut raw = fs::read(p.chat("c1")).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    fs::write(p.chat("c1"), raw).unwrap();
    assert!(v.get("c1", T0).is_err());
}

#[test]
fn a_crash_between_key_and_file_deletion_leaves_nothing_behind() {
    let p = Place::new("orphan");
    {
        let mut v = p.open(T0);
        v.put("c1", SECRET, T0).unwrap();
    }
    fs::write(p.keys_file(), "").unwrap(); // the key was destroyed, the crash came before the file
    assert!(p.chat("c1").exists());
    p.open(T0);
    assert!(!p.chat("c1").exists());
}

#[test]
fn a_chat_is_only_kept_past_24_hours_if_the_user_chose_it() {
    let p = Place::new("keep");
    let mut v = p.open(T0);
    v.put("kept", SECRET, T0).unwrap();
    v.put("default", "x", T0).unwrap();
    v.keep("kept", T0 + 10).unwrap();
    assert_eq!(v.expiry("kept"), Some(Expiry::Kept));
    drop(v);

    let later = T0 + 10 * MAX_TTL_SECS;
    let mut v = p.open(later);
    assert_eq!(v.get("kept", later).unwrap().as_deref(), Some(SECRET), "survives past 24 hours and a restart");
    assert_eq!(v.get("default", later).unwrap(), None, "the other chat expired as usual");
    let raw = fs::read(p.dir().join("kept.kept")).unwrap();
    assert!(!raw.windows(7).any(|w| w == b"dossier"), "a kept chat stays encrypted");
    assert!(!p.chat("kept").exists(), "no second copy under the old name");

    v.put("kept", "updated", later).unwrap();
    assert_eq!(v.get("kept", later + 5 * MAX_TTL_SECS).unwrap().as_deref(), Some("updated"));
}

#[test]
fn only_an_existing_live_chat_can_be_kept() {
    let p = Place::new("keep-limits");
    let mut v = p.open(T0);
    assert!(v.keep("absent", T0).is_err());
    v.put("c1", "x", T0).unwrap();
    assert!(v.keep("c1", T0 + MAX_TTL_SECS).is_err(), "too late: it has already expired");
    assert!(v.keep("../evil", T0).is_err());
    v.put("c2", "y", T0 + MAX_TTL_SECS).unwrap();
    v.keep("c2", T0 + MAX_TTL_SECS).unwrap();
    v.keep("c2", T0 + MAX_TTL_SECS).unwrap();
    assert_eq!(v.get("c2", T0 + MAX_TTL_SECS).unwrap().as_deref(), Some("y"), "keeping twice changes nothing");
}

#[test]
fn the_user_can_delete_any_chat_at_once() {
    let p = Place::new("forget");
    let mut v = p.open(T0);
    v.put("a", "x", T0).unwrap();
    v.put("b", "y", T0).unwrap();
    v.keep("b", T0).unwrap();
    assert!(v.forget("a").unwrap());
    assert!(v.forget("b").unwrap());
    assert!(!v.forget("a").unwrap(), "already gone");
    assert_eq!(v.get("b", T0).unwrap(), None);
    assert!(!p.chat("a").exists());
    assert!(!p.dir().join("b.kept").exists());
    assert!(!p.key_text().contains("b "), "its key is destroyed");
}

#[test]
fn a_crash_during_keep_leaves_exactly_one_readable_copy() {
    let p = Place::new("keep-crash");
    {
        let mut v = p.open(T0);
        v.put("before", SECRET, T0).unwrap();
        v.put("after", SECRET, T0).unwrap();
        v.keep("after", T0).unwrap();
    }
    // Crash before the key update: a stray kept file next to the normal chat.
    fs::write(p.dir().join("before.kept"), b"partial").unwrap();
    // Crash after the key update: the old chat file was not removed yet.
    fs::write(p.chat("after"), b"stale").unwrap();

    let mut v = p.open(T0);
    assert_eq!(v.get("before", T0).unwrap().as_deref(), Some(SECRET));
    assert_eq!(v.get("after", T0).unwrap().as_deref(), Some(SECRET));
    assert!(!p.dir().join("before.kept").exists());
    assert!(!p.chat("after").exists());
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn both_front_ends_reach_the_vault_through_dispatch() {
    let p = Place::new("dispatch");
    let mut core = Core::with_vault(p.open(now()));
    let ask = |core: &mut Core, r: &str| -> Value { serde_json::from_str(&core.dispatch(r)).unwrap() };
    let saved = ask(&mut core, r#"{"cmd":"chat_save","id":"c1","text":"bonjour"}"#);
    assert_eq!(saved["ok"], true, "{saved}");
    assert_eq!(saved["expires_in_secs"], 86400);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_read","id":"c1"}"#)["text"], "bonjour");
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_read","id":"absent"}"#)["text"], Value::Null);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_keep","id":"c1"}"#)["kept"], true);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_forget","id":"c1"}"#)["forgotten"], true);
    assert_eq!(ask(&mut core, r#"{"cmd":"chat_read","id":"c1"}"#)["text"], Value::Null);

    let mut without = Core::new();
    assert_eq!(ask(&mut without, r#"{"cmd":"chat_read","id":"c1"}"#)["ok"], false);
}
