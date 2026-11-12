//! The agent's durable state: a key-value log, one JSON line per write, synced before each write returns. The
//! latest line for a key wins; a `null` value removes it. Built like the relay's store:
//!
//! - created once (`ona-agent init-store`), with a first line naming the keys it belongs to, and only opened
//!   afterwards, so a lost file stops the agent instead of starting from nothing;
//! - readable by its owner only, held by one process through an exclusive lock on `<file>.lock`, and stopped if
//!   that lock file is removed or replaced;
//! - a last line without its newline (a write that never returned) is cut at opening; any other damage is an error;
//! - after a failed write nothing more is written until a restart;
//! - rewritten atomically (new file, synced, renamed over the old one) once obsolete lines outnumber live keys, and
//!   whenever the agent purges what it no longer needs (`Store::compact`).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const FORMAT: &str = "ona-agent-store-v1";
const COMPACT_MIN_DEAD_LINES: usize = 256;

/// What the agent's logic needs from its store.
pub trait Store {
    fn get(&self, key: &str) -> Option<Value>;
    /// Durable before it returns. `Value::Null` removes the key.
    fn put(&mut self, key: &str, value: Value) -> Result<(), String>;
    /// Every key starting with `prefix`, in order.
    fn scan(&self, prefix: &str) -> Vec<(String, Value)>;
    /// Drops removed keys and old values from what is kept on disk.
    fn compact(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryStore {
    map: BTreeMap<String, Value>,
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Option<Value> {
        self.map.get(key).cloned()
    }
    fn put(&mut self, key: &str, value: Value) -> Result<(), String> {
        if value.is_null() {
            self.map.remove(key);
        } else {
            self.map.insert(key.to_string(), value);
        }
        Ok(())
    }
    fn scan(&self, prefix: &str) -> Vec<(String, Value)> {
        self.map.range(prefix.to_string()..).take_while(|(k, _)| k.starts_with(prefix)).map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

pub struct FileStore {
    file: File,
    path: PathBuf,
    binding: String,
    memory: MemoryStore,
    dead_lines: usize,
    failed: bool,
    _lock: File,
    lock_path: PathBuf,
    lock_id: (u64, u64),
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn header(binding: &str) -> Value {
    json!({"store": FORMAT, "binding": binding})
}

fn line(value: &Value) -> Vec<u8> {
    let mut bytes = value.to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent).and_then(|d| d.sync_all()).map_err(|e| e.to_string())
}

impl FileStore {
    /// Creates a new, empty store readable by its owner only. Never overwrites one.
    pub fn create(path: &Path, binding: &str) -> Result<Self, String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot create store file: {e}"))?;
        file.write_all(&line(&header(binding))).and_then(|()| file.sync_all()).map_err(|e| e.to_string())?;
        sync_parent(path)?;
        drop(file);
        Self::open(path, binding)
    }

    pub fn open(path: &Path, binding: &str) -> Result<Self, String> {
        let lock_path = with_suffix(path, ".lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| format!("cannot open store lock: {e}"))?;
        lock.try_lock().map_err(|_| "store is in use by another agent process".to_string())?;
        let lock_meta = lock.metadata().map_err(|e| e.to_string())?;
        let meta = fs::metadata(path).map_err(|e| format!("cannot open store file, create it with init-store: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("store file is accessible to other users".into());
        }
        let _ = fs::remove_file(with_suffix(path, ".compact"));
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let mut lines = bytes[..complete].split_inclusive(|b| *b == b'\n');
        let first: Option<Value> = lines.next().and_then(|l| serde_json::from_slice(l).ok());
        if first.as_ref() != Some(&header(binding)) {
            return Err("store file belongs to other keys, or has no header".into());
        }
        let mut memory = MemoryStore::default();
        let mut count = 0;
        for raw in lines {
            let v: Value = serde_json::from_slice(raw).map_err(|_| "corrupt store line".to_string())?;
            let key = v["k"].as_str().ok_or("corrupt store line")?;
            memory.put(key, v["v"].clone())?;
            count += 1;
        }
        if complete < bytes.len() {
            let f = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
            f.set_len(complete as u64).and_then(|()| f.sync_all()).map_err(|e| e.to_string())?;
        }
        let file = OpenOptions::new().append(true).open(path).map_err(|e| e.to_string())?;
        let live = memory.map.len();
        Ok(Self {
            file,
            path: path.to_path_buf(),
            binding: binding.to_string(),
            memory,
            dead_lines: count - live.min(count),
            failed: false,
            _lock: lock,
            lock_path,
            lock_id: (lock_meta.dev(), lock_meta.ino()),
        })
    }

    fn check(&mut self) -> Result<(), String> {
        if self.failed {
            return Err("store stopped after a write error: restart the agent".into());
        }
        let current = fs::metadata(&self.lock_path).map(|m| (m.dev(), m.ino())).ok();
        if current != Some(self.lock_id) {
            self.failed = true;
            return Err("store lock file was removed or replaced: restart the agent".into());
        }
        Ok(())
    }

    /// Rewrites the log with one line per live key, atomically.
    fn rewrite(&mut self) -> Result<(), String> {
        self.check()?;
        let mut bytes = line(&header(&self.binding));
        for (k, v) in &self.memory.map {
            bytes.extend(line(&json!({"k": k, "v": v})));
        }
        let target = with_suffix(&self.path, ".compact");
        let _ = fs::remove_file(&target);
        let mut file =
            OpenOptions::new().create_new(true).append(true).mode(0o600).open(&target).map_err(|e| e.to_string())?;
        if let Err(e) = file.write_all(&bytes).and_then(|()| file.sync_all()).and_then(|()| fs::rename(&target, &self.path)) {
            let _ = fs::remove_file(&target);
            return Err(e.to_string());
        }
        self.file = file;
        self.dead_lines = 0;
        sync_parent(&self.path).inspect_err(|_| self.failed = true)
    }
}

impl Store for FileStore {
    fn get(&self, key: &str) -> Option<Value> {
        self.memory.get(key)
    }

    fn put(&mut self, key: &str, value: Value) -> Result<(), String> {
        self.check()?;
        let written = self.file.write_all(&line(&json!({"k": key, "v": value}))).and_then(|()| self.file.sync_all());
        if let Err(e) = written {
            self.failed = true;
            return Err(e.to_string());
        }
        if self.memory.map.contains_key(key) || value.is_null() {
            self.dead_lines += 1;
        }
        self.memory.put(key, value)?;
        if self.dead_lines >= COMPACT_MIN_DEAD_LINES.max(self.memory.map.len()) {
            // The write is durable already: a failed rewrite loses nothing.
            if let Err(e) = self.rewrite() {
                eprintln!("store compaction failed: {e}");
            }
        }
        Ok(())
    }

    fn scan(&self, prefix: &str) -> Vec<(String, Value)> {
        self.memory.scan(prefix)
    }

    fn compact(&mut self) -> Result<(), String> {
        self.rewrite()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ona-agent-store-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn values_survive_a_restart_and_a_rewrite() {
        let path = temp("restart");
        {
            let mut s = FileStore::create(&path, "b").unwrap();
            s.put("r:1", json!({"s": "sent"})).unwrap();
            s.put("r:1", json!({"s": "done"})).unwrap();
            s.put("r:2", json!(1)).unwrap();
            s.put("r:2", Value::Null).unwrap();
            s.compact().unwrap();
            s.put("r:3", json!(3)).unwrap();
        }
        let s = FileStore::open(&path, "b").unwrap();
        assert_eq!(s.get("r:1"), Some(json!({"s": "done"})));
        assert_eq!(s.get("r:2"), None);
        assert_eq!(s.scan("r:").len(), 2);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_missing_foreign_shared_or_unlocked_store_is_refused() {
        let path = temp("rules");
        assert!(FileStore::open(&path, "b").err().unwrap().contains("init-store"));
        let first = FileStore::create(&path, "b").unwrap();
        assert!(FileStore::open(&path, "b").err().unwrap().contains("in use"));
        drop(first);
        assert!(FileStore::open(&path, "other").err().unwrap().contains("other keys"));
        assert!(FileStore::create(&path, "b").is_err(), "never overwritten");

        let mut s = FileStore::open(&path, "b").unwrap();
        fs::remove_file(with_suffix(&path, ".lock")).unwrap();
        assert!(s.put("k", json!(1)).unwrap_err().contains("lock file"));
        drop(s);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FileStore::open(&path, "b").err().unwrap().contains("other users"));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_torn_last_line_is_cut_and_other_damage_refused() {
        let path = temp("torn");
        drop(FileStore::create(&path, "b").unwrap());
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"{\"k\":\"a\",\"v\":1}\n{\"k\":\"b\"");
        fs::write(&path, &bytes).unwrap();
        let s = FileStore::open(&path, "b").unwrap();
        assert_eq!(s.get("a"), Some(json!(1)));
        assert_eq!(s.get("b"), None);
        drop(s);
        let mut damaged = fs::read(&path).unwrap();
        damaged.extend_from_slice(b"not json\n");
        fs::write(&path, &damaged).unwrap();
        assert!(FileStore::open(&path, "b").is_err());
        fs::remove_file(&path).unwrap();
    }
}
