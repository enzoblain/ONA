//! `ona-signer`: the issuing loop. Has no network input: it reads the chain, signs, writes back.
//!
//! The chain is behind the `Chain` trait; `near::NearChain` is the RPC implementation.
//! Keys live in a local file for now. Sealing them in an enclave is a later step.

pub mod near;

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ona_token::{keygen, sign_blinded, verify_blind_issue, SecretKey, G1_LEN, G2_LEN};
use rand::rngs::OsRng;

/// A pending deposit as read from `ona-mint`.
#[derive(Debug, Clone)]
pub struct PendingRecord {
    pub id: u64,
    pub items: Vec<(u8, [u8; G1_LEN])>,
    pub deadline: u64,
    /// Zero until locked. Must come from a final block, or a signature could leave too early.
    pub locked_until: u64,
}

/// Do not start publishing signatures when the lock is about to expire: a failed `issue` could
/// not be retried in time, and the depositor could combine a refund with the public signature.
/// Once a record has been broadcast, retries continue until the lock really ends.
pub const ISSUE_MARGIN_NS: u64 = 3_600_000_000_000;

/// What must survive a restart: which records have had signatures broadcast, and the scan position.
pub trait Durable {
    fn is_broadcast(&self, id: u64) -> bool;
    /// Must be on disk before this returns, because it precedes the first broadcast.
    fn mark_broadcast(&mut self, id: u64) -> Result<(), String>;
    fn cursor(&self) -> u64;
    fn set_cursor(&mut self, cursor: u64) -> Result<(), String>;
}

#[derive(Default)]
pub struct MemoryDurable {
    broadcast: HashSet<u64>,
    cursor: u64,
}

impl Durable for MemoryDurable {
    fn is_broadcast(&self, id: u64) -> bool {
        self.broadcast.contains(&id)
    }
    fn mark_broadcast(&mut self, id: u64) -> Result<(), String> {
        self.broadcast.insert(id);
        Ok(())
    }
    fn cursor(&self) -> u64 {
        self.cursor
    }
    fn set_cursor(&mut self, cursor: u64) -> Result<(), String> {
        self.cursor = cursor;
        Ok(())
    }
}

/// Append-only text file, synced on every write: `b <id>` and `c <cursor>` lines.
pub struct FileDurable {
    file: fs::File,
    memory: MemoryDurable,
    /// Set by a failed write: the file may end in a partial line, so nothing more may be appended.
    failed: bool,
}

impl FileDurable {
    /// A last line without its newline was being written during a crash: its write never
    /// returned, so nothing relied on it and it is dropped. Any other malformed line is corruption.
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut memory = MemoryDurable::default();
        if path.exists() {
            let bytes = fs::read(path).map_err(|e| e.to_string())?;
            let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            let text = std::str::from_utf8(&bytes[..complete]).map_err(|_| "corrupt state file")?;
            for line in text.lines() {
                let (kind, value) = line.split_once(' ').ok_or("corrupt state file")?;
                let value: u64 = value.parse().map_err(|_| "corrupt state file")?;
                match kind {
                    "b" => {
                        memory.broadcast.insert(value);
                    }
                    "c" => memory.cursor = value,
                    _ => return Err("corrupt state file".into()),
                }
            }
            if complete < bytes.len() {
                let file = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
                file.set_len(complete as u64).map_err(|e| e.to_string())?;
                file.sync_all().map_err(|e| e.to_string())?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        Ok(Self { file, memory, failed: false })
    }

    fn write_line(&mut self, line: String) -> Result<(), String> {
        if self.failed {
            return Err("state file failed earlier, restart required".into());
        }
        let result = self
            .file
            .write_all(format!("{line}\n").as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| e.to_string());
        self.failed = result.is_err();
        result
    }
}

impl Durable for FileDurable {
    fn is_broadcast(&self, id: u64) -> bool {
        self.memory.is_broadcast(id)
    }
    fn mark_broadcast(&mut self, id: u64) -> Result<(), String> {
        self.write_line(format!("b {id}"))?;
        self.memory.mark_broadcast(id)
    }
    fn cursor(&self) -> u64 {
        self.memory.cursor()
    }
    fn set_cursor(&mut self, cursor: u64) -> Result<(), String> {
        if cursor == self.memory.cursor() {
            return Ok(());
        }
        self.write_line(format!("c {cursor}"))?;
        self.memory.set_cursor(cursor)
    }
}

pub trait Chain {
    fn pending(&mut self, from: u64, limit: u16) -> Result<Vec<PendingRecord>, String>;
    fn lock(&mut self, id: u64) -> Result<(), String>;
    /// Public key of a denomination as the contract knows it.
    fn denom_key(&mut self, denom_id: u8) -> Result<[u8; G2_LEN], String>;
    fn now(&mut self) -> Result<u64, String>;
    fn issue(&mut self, id: u64, sigs: Vec<[u8; G1_LEN]>) -> Result<(), String>;
}

pub struct KeyStore {
    keys: Vec<SecretKey>,
}

impl KeyStore {
    pub fn from_keys(keys: Vec<SecretKey>) -> Self {
        Self { keys }
    }

    pub fn generate(count: usize) -> Self {
        Self { keys: (0..count).map(|_| keygen(&mut OsRng)).collect() }
    }

    pub fn public_keys(&self) -> Vec<[u8; G2_LEN]> {
        self.keys.iter().map(|k| k.public_key()).collect()
    }

    /// Writes the keys to a new file readable by this user only. Never overwrites.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot create key file: {e}"))?;
        for key in &self.keys {
            file.write_all(&key.to_bytes()).map_err(|e| e.to_string())?;
        }
        file.sync_all().map_err(|e| e.to_string())
    }

    /// Refuses a key file that other users could read.
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = fs::metadata(path).map_err(|e| format!("cannot read key file: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("key file is accessible to other users".into());
        }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        if bytes.is_empty() || bytes.len() % 32 != 0 {
            return Err("key file has the wrong size".into());
        }
        let keys = bytes
            .chunks_exact(32)
            .map(|chunk| {
                let chunk: &[u8; 32] = chunk.try_into().map_err(|_| "chunk size".to_string())?;
                SecretKey::from_bytes(chunk).map_err(|e| e.to_string())
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { keys })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    pub locked: Vec<u64>,
    pub issued: Vec<u64>,
    /// Records left unsigned on purpose. Their depositors get a refund at the deadline.
    pub skipped: Vec<(u64, String)>,
}

pub struct Signer<D> {
    keys: KeyStore,
    /// Records already answered in this run, so a slow chain does not get them twice.
    done: HashSet<u64>,
    state: D,
    /// Why the durable state can no longer be trusted. Once set, no pass runs again.
    halted: Option<String>,
}

impl<D: Durable> Signer<D> {
    pub fn new(keys: KeyStore, state: D) -> Self {
        Self { keys, done: HashSet::new(), state, halted: None }
    }

    /// Set after a failed write of the durable state: the process must stop and be restarted.
    pub fn halted(&self) -> Option<&str> {
        self.halted.as_deref()
    }

    fn halt(&mut self, reason: String) -> String {
        self.halted = Some(reason.clone());
        reason
    }

    /// Refuses to start if the keys held here are not the ones the contract verifies against.
    pub fn check_keys<C: Chain>(&self, chain: &mut C) -> Result<(), String> {
        for (id, pk) in self.keys.public_keys().iter().enumerate() {
            let on_chain = chain.denom_key(id as u8)?;
            if &on_chain != pk {
                return Err(format!("key {id} does not match the contract"));
            }
        }
        Ok(())
    }

    fn sign_record(&self, record: &PendingRecord) -> Result<Vec<[u8; G1_LEN]>, String> {
        let public = self.keys.public_keys();
        let mut sigs = Vec::with_capacity(record.items.len());
        for (denom_id, blinded) in &record.items {
            let key = self
                .keys
                .keys
                .get(usize::from(*denom_id))
                .ok_or_else(|| format!("unknown denomination {denom_id}"))?;
            let sig = sign_blinded(key, blinded).map_err(|e| format!("invalid blinded point: {e}"))?;
            // A signature that fails here means a fault in this machine. Never publish it.
            if !verify_blind_issue(&public[usize::from(*denom_id)], blinded, &sig) {
                return Err("signature failed its own check".into());
            }
            sigs.push(sig);
        }
        Ok(sigs)
    }

    /// One pass over the pending deposits. A failed record does not block the following ones,
    /// but a failed write to the durable state stops the whole pass.
    pub fn tick<C: Chain>(&mut self, chain: &mut C) -> Result<TickReport, String> {
        if let Some(reason) = &self.halted {
            return Err(reason.clone());
        }
        let now = chain.now()?;
        let records = chain.pending(self.state.cursor(), 64)?;
        let mut report = TickReport::default();
        let last_seen = records.last().map(|r| r.id);
        let ids: Vec<u64> = records.iter().map(|r| r.id).collect();
        for record in records {
            if self.done.contains(&record.id) {
                continue;
            }
            let sigs = match self.sign_record(&record) {
                Ok(sigs) => sigs,
                Err(reason) => {
                    self.done.insert(record.id);
                    report.skipped.push((record.id, reason));
                    continue;
                }
            };
            if record.locked_until == 0 {
                // First pass: only lock. The signatures stay here until the lock is confirmed.
                if now >= record.deadline {
                    report.skipped.push((record.id, "deadline passed, left for refund".into()));
                    self.done.insert(record.id);
                    continue;
                }
                match chain.lock(record.id) {
                    Ok(()) => report.locked.push(record.id),
                    Err(e) => report.skipped.push((record.id, format!("lock failed: {e}"))),
                }
                continue;
            }
            if now >= record.locked_until {
                report.skipped.push((record.id, "lock expired".into()));
                self.done.insert(record.id);
                continue;
            }
            if !self.state.is_broadcast(record.id) {
                if now.saturating_add(ISSUE_MARGIN_NS) >= record.locked_until {
                    report.skipped.push((record.id, "lock too close to expiry, left for refund".into()));
                    self.done.insert(record.id);
                    continue;
                }
                if let Err(e) = self.state.mark_broadcast(record.id) {
                    return Err(self.halt(format!("cannot record broadcast: {e}")));
                }
            }
            match chain.issue(record.id, sigs) {
                Ok(()) => {
                    self.done.insert(record.id);
                    report.issued.push(record.id);
                }
                // Not marked done: the next pass retries a transient chain failure.
                Err(e) => report.skipped.push((record.id, format!("issue failed: {e}"))),
            }
        }
        // Moves past finished records, which may stay on chain until refunded, so that a full
        // page of them cannot hide newer deposits. Stops at the first one still to retry.
        if let Some(last) = last_seen {
            let next = ids.into_iter().find(|id| !self.done.contains(id)).unwrap_or(last + 1);
            if let Err(e) = self.state.set_cursor(next) {
                return Err(self.halt(format!("cannot record cursor: {e}")));
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ona_token::{hash_to_g1, verify_blind_issue};

    const DST: &[u8] = b"test-dst";

    #[derive(Default)]
    struct FakeChain {
        records: Vec<PendingRecord>,
        keys: Vec<[u8; G2_LEN]>,
        now: u64,
        issued: Vec<(u64, Vec<[u8; G1_LEN]>)>,
        fail_issue_once: bool,
    }

    const LOCK: u64 = 100 * ISSUE_MARGIN_NS;

    impl Chain for FakeChain {
        fn pending(&mut self, from: u64, limit: u16) -> Result<Vec<PendingRecord>, String> {
            Ok(self.records.iter().filter(|r| r.id >= from).take(limit as usize).cloned().collect())
        }
        fn lock(&mut self, id: u64) -> Result<(), String> {
            let now = self.now;
            let r = self.records.iter_mut().find(|r| r.id == id).ok_or("unknown")?;
            r.locked_until = now + LOCK;
            Ok(())
        }
        fn denom_key(&mut self, denom_id: u8) -> Result<[u8; G2_LEN], String> {
            self.keys.get(usize::from(denom_id)).copied().ok_or_else(|| "none".to_string())
        }
        fn now(&mut self) -> Result<u64, String> {
            Ok(self.now)
        }
        fn issue(&mut self, id: u64, sigs: Vec<[u8; G1_LEN]>) -> Result<(), String> {
            if self.fail_issue_once {
                self.fail_issue_once = false;
                return Err("rpc down".into());
            }
            self.issued.push((id, sigs));
            self.records.retain(|r| r.id != id);
            Ok(())
        }
    }

    fn point(tag: u8) -> [u8; G1_LEN] {
        hash_to_g1(&[tag; 16], DST)
    }

    fn setup(count: usize) -> (Signer<MemoryDurable>, FakeChain) {
        let keys = KeyStore::generate(count);
        let chain = FakeChain { keys: keys.public_keys(), now: 10, ..Default::default() };
        (Signer::new(keys, MemoryDurable::default()), chain)
    }

    #[test]
    fn a_broadcast_record_is_retried_inside_the_margin() {
        let (mut s, mut c) = setup(1);
        c.records.push(record(1, vec![(0, point(1))]));
        s.tick(&mut c).unwrap();
        c.fail_issue_once = true;
        assert!(s.tick(&mut c).unwrap().issued.is_empty(), "the broadcast failed");

        c.now += LOCK - ISSUE_MARGIN_NS;
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![1], "its signatures are public, so it must not be abandoned");
    }

    #[test]
    fn broadcast_state_and_cursor_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("ona-signer-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        let _ = fs::remove_file(&path);

        let keys = KeyStore::generate(1);
        let key_path = dir.join("k.bin");
        let _ = fs::remove_file(&key_path);
        keys.save(&key_path).unwrap();
        let mut c = FakeChain { keys: keys.public_keys(), now: 10, ..Default::default() };
        c.records.push(record(5, vec![(0, point(1))]));
        {
            let mut s = Signer::new(keys, FileDurable::open(&path).unwrap());
            s.tick(&mut c).unwrap();
            c.fail_issue_once = true;
            s.tick(&mut c).unwrap();
        }

        c.now += LOCK - ISSUE_MARGIN_NS;
        let state = FileDurable::open(&path).unwrap();
        assert!(state.is_broadcast(5));
        assert_eq!(state.cursor(), 5);
        let mut s = Signer::new(KeyStore::load(&key_path).unwrap(), state);
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![5], "still retried after a restart");
        fs::remove_dir_all(&dir).unwrap();
    }

    fn state_file(name: &str, content: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ona-signer-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        fs::write(&path, content).unwrap();
        (dir, path)
    }

    #[test]
    fn only_a_last_line_without_newline_is_dropped() {
        let (dir, path) = state_file("partial", b"b 1\nc 2\nb 3");
        let mut state = FileDurable::open(&path).unwrap();
        assert!(state.is_broadcast(1));
        assert_eq!(state.cursor(), 2);
        assert!(!state.is_broadcast(3), "a line that was never finished does not count");
        assert_eq!(fs::read(&path).unwrap(), b"b 1\nc 2\n");

        state.mark_broadcast(4).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"b 1\nc 2\nb 4\n", "the next write starts on a clean line");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_partial_last_line_may_be_invalid_text() {
        let (dir, path) = state_file("binary", b"b 1\n\xff\xfe");
        assert!(FileDurable::open(&path).unwrap().is_broadcast(1));
        assert_eq!(fs::read(&path).unwrap(), b"b 1\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_complete_line_is_corruption_and_nothing_is_truncated() {
        for content in [&b"b 1\nxx\nb 2\n"[..], &b"b 1\nb x\n"[..], &b"zz 1\nb 2"[..]] {
            let (dir, path) = state_file("corrupt", content);
            assert!(FileDurable::open(&path).err().unwrap().contains("corrupt"));
            assert_eq!(fs::read(&path).unwrap(), content, "the evidence is left in place");
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn nothing_is_appended_after_a_failed_write() {
        let (dir, path) = state_file("failed", b"");
        let read_only = fs::File::open(&path).unwrap();
        let mut state = FileDurable { file: read_only, memory: MemoryDurable::default(), failed: false };
        assert!(state.mark_broadcast(1).is_err());
        assert!(!state.is_broadcast(1));

        state.file = OpenOptions::new().append(true).open(&path).unwrap();
        assert!(state.mark_broadcast(2).is_err(), "even if the file looks writable again");
        assert_eq!(fs::read(&path).unwrap(), b"");
        fs::remove_dir_all(&dir).unwrap();
    }

    struct BrokenDurable;

    impl Durable for BrokenDurable {
        fn is_broadcast(&self, _id: u64) -> bool {
            false
        }
        fn mark_broadcast(&mut self, _id: u64) -> Result<(), String> {
            Err("disk full".into())
        }
        fn cursor(&self) -> u64 {
            0
        }
        fn set_cursor(&mut self, _cursor: u64) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_state_write_stops_the_signer_before_any_signature_leaves() {
        let keys = KeyStore::generate(1);
        let mut c = FakeChain { keys: keys.public_keys(), now: 10, ..Default::default() };
        let mut locked = record(1, vec![(0, point(1))]);
        locked.locked_until = LOCK;
        c.records.push(locked);
        let mut s = Signer::new(keys, BrokenDurable);

        assert!(s.tick(&mut c).unwrap_err().contains("disk full"));
        assert!(c.issued.is_empty());
        assert!(s.halted().unwrap().contains("disk full"));

        c.now = u64::MAX; // would otherwise be read as a new pass over the chain
        assert!(s.tick(&mut c).unwrap_err().contains("disk full"), "no further pass runs");
    }

    fn record(id: u64, items: Vec<(u8, [u8; G1_LEN])>) -> PendingRecord {
        PendingRecord { id, items, deadline: 100, locked_until: 0 }
    }

    #[test]
    fn no_signature_leaves_before_the_lock_is_seen_on_chain() {
        let (mut s, mut c) = setup(1);
        c.records.push(record(1, vec![(0, point(1))]));
        let report = s.tick(&mut c).unwrap();
        assert_eq!(report.locked, vec![1]);
        assert!(c.issued.is_empty(), "the first pass only locks");
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![1]);
    }

    #[test]
    fn nothing_is_published_when_the_lock_is_about_to_expire() {
        let (mut s, mut c) = setup(1);
        c.records.push(record(1, vec![(0, point(1))]));
        s.tick(&mut c).unwrap();
        c.now += LOCK - ISSUE_MARGIN_NS;
        let report = s.tick(&mut c).unwrap();
        assert!(report.issued.is_empty());
        assert!(report.skipped[0].1.contains("expiry"));
        assert!(c.issued.is_empty());
    }

    #[test]
    fn signs_each_item_with_its_denomination_key() {
        let (mut s, mut c) = setup(3);
        c.records.push(record(7, vec![(0, point(1)), (2, point(2))]));
        assert_eq!(s.tick(&mut c).unwrap().locked, vec![7]);
        let report = s.tick(&mut c).unwrap();
        assert_eq!(report.issued, vec![7]);
        let (_, sigs) = &c.issued[0];
        assert!(verify_blind_issue(&c.keys[0], &point(1), &sigs[0]));
        assert!(verify_blind_issue(&c.keys[2], &point(2), &sigs[1]));
        assert!(!verify_blind_issue(&c.keys[1], &point(2), &sigs[1]));
    }

    #[test]
    fn invalid_point_signs_nothing_and_does_not_block_the_next_record() {
        let (mut s, mut c) = setup(1);
        let mut inf = [0u8; G1_LEN];
        inf[0] = 0xc0;
        c.records.push(record(1, vec![(0, point(1)), (0, inf)]));
        c.records.push(record(2, vec![(0, point(2))]));
        let report = s.tick(&mut c).unwrap();
        assert_eq!(report.locked, vec![2]);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, 1);
        assert_eq!(c.records[0].locked_until, 0, "a bad record is never locked, so it can be refunded");
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![2]);
        assert_eq!(c.issued.len(), 1, "no signature leaves for the bad record");
    }

    #[test]
    fn unknown_denomination_is_skipped() {
        let (mut s, mut c) = setup(1);
        c.records.push(record(1, vec![(5, point(1))]));
        let report = s.tick(&mut c).unwrap();
        assert!(report.issued.is_empty());
        assert!(report.skipped[0].1.contains("unknown denomination"));
    }

    #[test]
    fn expired_record_is_left_for_refund() {
        let (mut s, mut c) = setup(1);
        c.now = 100;
        c.records.push(record(1, vec![(0, point(1))]));
        let report = s.tick(&mut c).unwrap();
        assert!(c.issued.is_empty());
        assert!(report.skipped[0].1.contains("refund"));
    }

    #[test]
    fn transient_failure_is_retried_and_success_is_not_repeated() {
        let (mut s, mut c) = setup(1);
        c.fail_issue_once = true;
        c.records.push(record(1, vec![(0, point(1))]));
        s.tick(&mut c).unwrap();
        assert!(s.tick(&mut c).unwrap().issued.is_empty());
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![1]);

        let mut lagging = record(1, vec![(0, point(1))]); // the chain view lags behind
        lagging.locked_until = c.now + LOCK;
        c.records.push(lagging);
        assert!(s.tick(&mut c).unwrap().issued.is_empty());
        assert_eq!(c.issued.len(), 1, "one answer per record");
    }

    #[test]
    fn a_full_page_of_finished_records_does_not_hide_new_deposits() {
        let (mut s, mut c) = setup(1);
        c.now = 100;
        for id in 0..64 {
            c.records.push(PendingRecord { id, items: vec![(0, point(1))], deadline: 50, locked_until: 0 });
        }
        c.records.push(PendingRecord { id: 64, items: vec![(0, point(2))], deadline: 500, locked_until: 0 });
        assert!(s.tick(&mut c).unwrap().locked.is_empty(), "the first page is all expired");
        assert_eq!(s.tick(&mut c).unwrap().locked, vec![64]);
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![64]);
    }

    #[test]
    fn check_keys_detects_a_mismatch() {
        let (s, mut c) = setup(2);
        assert!(s.check_keys(&mut c).is_ok());
        c.keys[1] = KeyStore::generate(1).public_keys()[0];
        assert!(s.check_keys(&mut c).unwrap_err().contains("does not match"));
    }

    #[test]
    fn key_file_round_trip_and_permissions() {
        let dir = std::env::temp_dir().join(format!("ona-signer-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.bin");
        let _ = fs::remove_file(&path);

        let keys = KeyStore::generate(2);
        keys.save(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(KeyStore::load(&path).unwrap().public_keys(), keys.public_keys());
        assert!(keys.save(&path).is_err(), "an existing key file is never overwritten");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(KeyStore::load(&path).err().unwrap().contains("other users"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, [1u8; 33]).unwrap();
        assert!(KeyStore::load(&path).err().unwrap().contains("wrong size"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
