//! `ona-signer`: the issuing loop. Has no network input: it reads the chain, signs, writes back.
//!
//! The chain is behind the `Chain` trait; `near::NearChain` is the RPC implementation.
//! Keys live in a local file for now. Sealing them in an enclave is a later step.
//!
//! A lock on a deposit no longer expires (`ona-mint` `lock`): once the signer has broadcast a record's
//! signatures, the depositor cannot be refunded, and the signer keeps sending `issue` until it lands.
//! A locked record it never broadcast and cannot sign is unlocked, so that it refunds at its deadline.

/// The same two-endpoint reader as the relay's, shared as one source file.
#[path = "../../ona-server/src/crossrpc.rs"]
pub mod crossrpc;
pub mod near;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use ona_token::{keygen, sign_blinded, verify_blind_issue, SecretKey, G1_LEN, G2_LEN};
use rand::rngs::OsRng;
use zeroize::Zeroize;

/// Records read per call of `pending_scan`, the most the contract returns.
pub const PAGE: u16 = 64;
/// Scans per pass. Each reads at most 256 record ids (`ona-mint` `MAX_SCAN`), so a pass sees at most
/// 512 records and 2048 ids from the cursor: what lies beyond waits for the next pass.
pub const MAX_PAGES: usize = 8;
/// A pass stops starting new work after this long. What is left waits for the next pass.
pub const MAX_PASS: Duration = Duration::from_secs(600);
/// The block height floor is written to disk when it has moved by this many blocks (about 10 minutes),
/// and always before a broadcast or an unlock.
pub const HEIGHT_RECORD_STEP: u64 = 600;
/// Scans `refuse_new_state_with_locked_deposits` may make, about a million record ids.
const MAX_STARTUP_SCANS: usize = 4096;
const KEYS_HEADER: &[u8] = b"ONA-SIGNER-KEYS-V1\n";

/// A pending deposit as read from `ona-mint`.
#[derive(Debug, Clone)]
pub struct PendingRecord {
    pub id: u64,
    /// The account that made the deposit. Locks go round the depositors, so one of them cannot push
    /// the others' deposits past their deadline. Several accounts of one person count as several.
    pub depositor: String,
    pub items: Vec<(u8, [u8; G1_LEN])>,
    pub deadline: u64,
    /// Zero until locked. Must come from a final block, or a signature could leave too early.
    pub locked_until: u64,
}

/// The final block a pass reads at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pass {
    pub height: u64,
    /// Nanoseconds.
    pub now: u64,
}

/// What must survive a restart: which records have had signatures broadcast, the scan position, and
/// the highest block height used, so that no later pass acts on an older view of the chain.
pub trait Durable {
    fn is_broadcast(&self, id: u64) -> bool;
    /// Must be on disk before this returns, because it precedes the first broadcast.
    fn mark_broadcast(&mut self, id: u64) -> Result<(), String>;
    fn cursor(&self) -> u64;
    fn set_cursor(&mut self, cursor: u64) -> Result<(), String>;
    fn height_floor(&self) -> u64;
    /// Must be on disk before this returns.
    fn set_height_floor(&mut self, height: u64) -> Result<(), String>;
}

#[derive(Default)]
pub struct MemoryDurable {
    broadcast: HashSet<u64>,
    cursor: u64,
    height: u64,
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
    fn height_floor(&self) -> u64 {
        self.height
    }
    fn set_height_floor(&mut self, height: u64) -> Result<(), String> {
        self.height = self.height.max(height);
        Ok(())
    }
}

/// Append-only text file, synced on every write: `b <id>`, `c <cursor>` and `h <height>` lines, after a
/// first `m <binding>` line naming the contract and keys it belongs to. Readable by its owner only, and
/// held by one process at a time through an exclusive lock on `<file>.lock`.
pub struct FileDurable {
    file: fs::File,
    memory: MemoryDurable,
    /// Set by a failed write: the file may end in a partial line, so nothing more may be appended.
    failed: bool,
    /// Created by this open, so it knows nothing of earlier broadcasts.
    new: bool,
    _lock: Option<fs::File>,
}

/// What a state file belongs to: the mint account and the signer's public keys. A state file reused
/// for another deployment would skip its deposits and its broadcast marks would be wrong.
pub fn state_binding(mint: &str, keys: &KeyStore) -> String {
    use std::fmt::Write as _;
    let mut text = format!("{mint}:");
    for pk in keys.public_keys() {
        for byte in &pk[..8] {
            let _ = write!(text, "{byte:02x}");
        }
    }
    text
}

impl FileDurable {
    /// A last line without its newline was being written during a crash: its write never
    /// returned, so nothing relied on it and it is dropped. Any other malformed line is corruption,
    /// and so is a state file made for another binding. A file with no complete line was created
    /// but never written (its first write is the header), so it counts as new.
    pub fn open(path: &Path, binding: &str) -> Result<Self, String> {
        if binding.is_empty() || binding.contains(char::is_whitespace) {
            return Err("invalid state binding".into());
        }
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_name)
            .map_err(|e| format!("cannot open state lock: {e}"))?;
        lock.try_lock().map_err(|_| "state file is in use by another signer process".to_string())?;

        let mut memory = MemoryDurable::default();
        let mut new = true;
        if path.exists() {
            let meta = fs::metadata(path).map_err(|e| e.to_string())?;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("state file is accessible to other users".into());
            }
            let bytes = fs::read(path).map_err(|e| e.to_string())?;
            let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            if complete > 0 {
                new = false;
                let text = std::str::from_utf8(&bytes[..complete]).map_err(|_| "corrupt state file")?;
                let mut lines = text.lines();
                if lines.next() != Some(format!("m {binding}").as_str()) {
                    return Err("state file belongs to another contract or keys, or has no header".into());
                }
                for line in lines {
                    let (kind, value) = line.split_once(' ').ok_or("corrupt state file")?;
                    let value: u64 = value.parse().map_err(|_| "corrupt state file")?;
                    match kind {
                        "b" => {
                            memory.broadcast.insert(value);
                        }
                        "c" => memory.cursor = value,
                        "h" => memory.height = memory.height.max(value),
                        _ => return Err("corrupt state file".into()),
                    }
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
        let mut state = Self { file, memory, failed: false, new, _lock: Some(lock) };
        if new {
            state.write_line(format!("m {binding}"))?;
        }
        Ok(state)
    }

    /// Whether this file was just created. See `refuse_new_state_with_locked_deposits`.
    pub fn is_new(&self) -> bool {
        self.new
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
    fn height_floor(&self) -> u64 {
        self.memory.height_floor()
    }
    fn set_height_floor(&mut self, height: u64) -> Result<(), String> {
        if height <= self.memory.height_floor() {
            return Ok(());
        }
        self.write_line(format!("h {height}"))?;
        self.memory.set_height_floor(height)
    }
}

pub trait Chain {
    /// Pins the final block every read of this pass is made at, and refuses one below `floor`.
    fn begin_pass(&mut self, floor: u64) -> Result<Pass, String>;
    /// Live records from `from`, and where the next scan starts. The next start can move past ids
    /// even when no record is returned.
    fn pending_scan(&mut self, from: u64, limit: u16) -> Result<(Vec<PendingRecord>, u64), String>;
    fn lock(&mut self, id: u64, tokens: usize) -> Result<(), String>;
    /// Reopens a refund for a locked record. Only for a record never broadcast.
    fn unlock(&mut self, id: u64, tokens: usize) -> Result<(), String>;
    /// Public key of a denomination as the contract knows it.
    fn denom_key(&mut self, denom_id: u8) -> Result<[u8; G2_LEN], String>;
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

    /// Writes the keys to a new file readable by this user only, after a type line. Never overwrites.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot create key file: {e}"))?;
        let mut bytes = KEYS_HEADER.to_vec();
        for key in &self.keys {
            bytes.extend_from_slice(&key.to_bytes());
        }
        let written = file.write_all(&bytes).and_then(|()| file.sync_all());
        bytes.zeroize();
        written.map_err(|e| e.to_string())
    }

    /// Refuses a key file that other users could read, or one made for another use: a relay
    /// request key used as a mint key, or the reverse, would mix two roles.
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = fs::metadata(path).map_err(|e| format!("cannot read key file: {e}"))?;
        if !meta.is_file() {
            return Err("key file is not a regular file".into());
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("key file is accessible to other users".into());
        }
        let mut bytes = fs::read(path).map_err(|e| e.to_string())?;
        let keys = match bytes.strip_prefix(KEYS_HEADER) {
            None => Err("not a signer key file".to_string()),
            Some(rest) if rest.is_empty() || rest.len() % 32 != 0 => Err("key file has the wrong size".to_string()),
            Some(rest) => rest
                .chunks_exact(32)
                .map(|chunk| {
                    let chunk: &[u8; 32] = chunk.try_into().map_err(|_| "chunk size".to_string())?;
                    SecretKey::from_bytes(chunk).map_err(|e| e.to_string())
                })
                .collect::<Result<_, _>>(),
        };
        bytes.zeroize();
        Ok(Self { keys: keys? })
    }
}

/// A new state file knows of no earlier broadcast. If the contract already holds locked deposits,
/// some of them may have had signatures published, and must be retried rather than unlocked. So the
/// signer refuses to start: the old state file must be restored. Every record id is scanned.
pub fn refuse_new_state_with_locked_deposits<C: Chain>(chain: &mut C, is_new: bool) -> Result<(), String> {
    if !is_new {
        return Ok(());
    }
    let mut from = 0;
    for _ in 0..MAX_STARTUP_SCANS {
        let (page, next) = chain.pending_scan(from, PAGE)?;
        if page.iter().any(|r| r.locked_until != 0) {
            return Err("the state file is new but the contract holds locked deposits: restore the state file".into());
        }
        if next <= from {
            return Ok(());
        }
        from = next;
    }
    Err("too many deposits to check with a new state file".into())
}

/// Lock order: oldest first for each depositor, taking one deposit from each depositor in turn.
fn round_robin(records: Vec<PendingRecord>) -> Vec<PendingRecord> {
    let mut by_depositor: BTreeMap<String, VecDeque<PendingRecord>> = BTreeMap::new();
    let mut first_seen: Vec<String> = Vec::new();
    for record in records {
        if !by_depositor.contains_key(&record.depositor) {
            first_seen.push(record.depositor.clone());
        }
        by_depositor.entry(record.depositor.clone()).or_default().push_back(record);
    }
    let mut ordered = Vec::new();
    loop {
        let mut took = false;
        for depositor in &first_seen {
            if let Some(record) = by_depositor.get_mut(depositor).and_then(VecDeque::pop_front) {
                ordered.push(record);
                took = true;
            }
        }
        if !took {
            return ordered;
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    pub locked: Vec<u64>,
    pub issued: Vec<u64>,
    /// Locked records that could not be signed and were never broadcast: unlocked for a refund.
    pub unlocked: Vec<u64>,
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
    /// Highest block height used in this run. The disk copy lags by up to `HEIGHT_RECORD_STEP`
    /// blocks; this one never goes back.
    height_seen: u64,
}

impl<D: Durable> Signer<D> {
    pub fn new(keys: KeyStore, state: D) -> Self {
        let height_seen = state.height_floor();
        Self { keys, done: HashSet::new(), state, halted: None, height_seen }
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

    /// Records the height of the pass's block: on disk when it moved enough, or when `now` is set
    /// because a broadcast or an unlock follows.
    fn record_height(&mut self, height: u64, now: bool) -> Result<(), String> {
        let recorded = self.state.height_floor();
        if height > recorded && (now || height - recorded >= HEIGHT_RECORD_STEP) {
            if let Err(e) = self.state.set_height_floor(height) {
                return Err(self.halt(format!("cannot record block height: {e}")));
            }
        }
        Ok(())
    }

    /// Reads up to `MAX_PAGES` scans from the cursor. Returns the records and where the scan stopped.
    fn read_pending<C: Chain>(&self, chain: &mut C) -> Result<(Vec<PendingRecord>, u64), String> {
        let mut records = Vec::new();
        let mut from = self.state.cursor();
        for _ in 0..MAX_PAGES {
            let (page, next) = chain.pending_scan(from, PAGE)?;
            records.extend(page);
            if next <= from {
                break;
            }
            from = next;
        }
        Ok((records, from))
    }

    /// One pass over the pending deposits, all read at one final block that both RPC endpoints agree
    /// on, never older than the highest block already used. A failed record does not block the
    /// following ones, but a failed write to the durable state stops the whole pass.
    ///
    /// Locks come first, going round the depositors, because a lock is one cheap transaction and an
    /// unlocked deposit expires after an hour: a flood of deposits from one account then delays the
    /// others' locks by one turn each, not by the whole flood. Issues follow.
    pub fn tick<C: Chain>(&mut self, chain: &mut C) -> Result<TickReport, String> {
        if let Some(reason) = &self.halted {
            return Err(reason.clone());
        }
        let started = Instant::now();
        let floor = self.height_seen.max(self.state.height_floor());
        let pass = chain.begin_pass(floor)?;
        if pass.height < floor {
            return Err(format!("the chain offered block {}, below block {floor} already used", pass.height));
        }
        self.height_seen = pass.height;
        self.record_height(pass.height, false)?;
        let (records, scanned_to) = self.read_pending(chain)?;
        let mut report = TickReport::default();
        let ids: Vec<u64> = records.iter().map(|r| r.id).collect();
        let (unlocked, locked): (Vec<_>, Vec<_>) = records.into_iter().partition(|r| r.locked_until == 0);

        for record in round_robin(unlocked) {
            if self.done.contains(&record.id) || started.elapsed() >= MAX_PASS {
                continue;
            }
            // Signed here only to refuse a record that could never be issued, before locking it.
            if let Err(reason) = self.sign_record(&record) {
                self.done.insert(record.id);
                report.skipped.push((record.id, reason));
                continue;
            }
            // A late lock is only refused by the contract and publishes nothing.
            if pass.now >= record.deadline {
                report.skipped.push((record.id, "deadline passed, left for refund".into()));
                self.done.insert(record.id);
                continue;
            }
            match chain.lock(record.id, record.items.len()) {
                Ok(()) => report.locked.push(record.id),
                Err(e) => report.skipped.push((record.id, format!("lock failed: {e}"))),
            }
        }

        for record in locked {
            if self.done.contains(&record.id) || started.elapsed() >= MAX_PASS {
                continue;
            }
            let broadcast = self.state.is_broadcast(record.id);
            let sigs = match self.sign_record(&record) {
                Ok(sigs) => sigs,
                Err(reason) if !broadcast => {
                    self.record_height(pass.height, true)?;
                    match chain.unlock(record.id, record.items.len()) {
                        Ok(()) => {
                            self.done.insert(record.id);
                            report.unlocked.push(record.id);
                        }
                        Err(e) => report.skipped.push((record.id, format!("{reason}; unlock failed: {e}"))),
                    }
                    continue;
                }
                Err(reason) => {
                    // Its signatures are public: never unlocked, and a fault worth stopping for.
                    return Err(self.halt(format!("record {} was broadcast but cannot be signed again: {reason}", record.id)));
                }
            };
            if !broadcast {
                self.record_height(pass.height, true)?;
                if let Err(e) = self.state.mark_broadcast(record.id) {
                    return Err(self.halt(format!("cannot record broadcast: {e}")));
                }
            }
            match chain.issue(record.id, sigs) {
                Ok(()) => {
                    self.done.insert(record.id);
                    report.issued.push(record.id);
                }
                // Not marked done: the next pass retries, for as long as it takes.
                Err(e) => report.skipped.push((record.id, format!("issue failed: {e}"))),
            }
        }

        // Moves past finished records, which may stay on chain until refunded, so that a full
        // page of them cannot hide newer deposits. Stops at the first one still to retry.
        let next = ids.into_iter().find(|id| !self.done.contains(id)).unwrap_or(scanned_to);
        if let Err(e) = self.state.set_cursor(next) {
            return Err(self.halt(format!("cannot record cursor: {e}")));
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ona_token::{hash_to_g1, verify_blind_issue};

    const DST: &[u8] = b"test-dst";
    const LOCKED: u64 = u64::MAX;

    #[derive(Default)]
    struct FakeChain {
        records: Vec<PendingRecord>,
        keys: Vec<[u8; G2_LEN]>,
        now: u64,
        height: u64,
        issued: Vec<(u64, Vec<[u8; G1_LEN]>)>,
        unlocked: Vec<u64>,
        fail_issue_once: bool,
    }

    /// As the contract: at most 256 ids per scan.
    const MAX_SCAN: u64 = 256;

    impl Chain for FakeChain {
        fn begin_pass(&mut self, floor: u64) -> Result<Pass, String> {
            if self.height < floor {
                return Err(format!("block {} is below block {floor} already used", self.height));
            }
            Ok(Pass { height: self.height, now: self.now })
        }
        fn pending_scan(&mut self, from: u64, limit: u16) -> Result<(Vec<PendingRecord>, u64), String> {
            let next_id = self.records.iter().map(|r| r.id + 1).max().unwrap_or(0);
            let end = from.saturating_add(MAX_SCAN).min(next_id).max(from);
            let mut out = Vec::new();
            for id in from..end {
                if out.len() == usize::from(limit) {
                    return Ok((out, id));
                }
                if let Some(r) = self.records.iter().find(|r| r.id == id) {
                    out.push(r.clone());
                }
            }
            Ok((out, end))
        }
        fn lock(&mut self, id: u64, _tokens: usize) -> Result<(), String> {
            let r = self.records.iter_mut().find(|r| r.id == id).ok_or("unknown")?;
            r.locked_until = LOCKED;
            Ok(())
        }
        fn unlock(&mut self, id: u64, _tokens: usize) -> Result<(), String> {
            let r = self.records.iter_mut().find(|r| r.id == id).ok_or("unknown")?;
            r.locked_until = 0;
            self.unlocked.push(id);
            Ok(())
        }
        fn denom_key(&mut self, denom_id: u8) -> Result<[u8; G2_LEN], String> {
            self.keys.get(usize::from(denom_id)).copied().ok_or_else(|| "none".to_string())
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
        let chain = FakeChain { keys: keys.public_keys(), now: 10, height: 1000, ..Default::default() };
        (Signer::new(keys, MemoryDurable::default()), chain)
    }

    fn record(id: u64, items: Vec<(u8, [u8; G1_LEN])>) -> PendingRecord {
        PendingRecord { id, depositor: "user.test".into(), items, deadline: 100, locked_until: 0 }
    }

    fn invalid_point() -> [u8; G1_LEN] {
        let mut inf = [0u8; G1_LEN];
        inf[0] = 0xc0;
        inf
    }

    #[test]
    fn a_broadcast_record_is_retried_without_time_limit() {
        let (mut s, mut c) = setup(1);
        c.records.push(record(1, vec![(0, point(1))]));
        s.tick(&mut c).unwrap();
        c.fail_issue_once = true;
        assert!(s.tick(&mut c).unwrap().issued.is_empty(), "the broadcast failed");

        c.now = u64::MAX - 1;
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![1], "its signatures are public, so it is never abandoned");
    }

    #[test]
    fn broadcast_state_cursor_and_height_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("ona-signer-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        let _ = fs::remove_file(&path);

        let keys = KeyStore::generate(1);
        let key_path = dir.join("k.bin");
        let _ = fs::remove_file(&key_path);
        keys.save(&key_path).unwrap();
        let mut c = FakeChain { keys: keys.public_keys(), now: 10, height: 1000, ..Default::default() };
        c.records.push(record(5, vec![(0, point(1))]));
        {
            let mut s = Signer::new(keys, FileDurable::open(&path, "test").unwrap());
            s.tick(&mut c).unwrap();
            c.fail_issue_once = true;
            s.tick(&mut c).unwrap();
        }

        let state = FileDurable::open(&path, "test").unwrap();
        assert!(!state.is_new());
        assert!(state.is_broadcast(5));
        assert_eq!(state.cursor(), 5);
        assert_eq!(state.height_floor(), 1000, "written before the broadcast");
        let mut s = Signer::new(KeyStore::load(&key_path).unwrap(), state);
        c.height = 999;
        assert!(s.tick(&mut c).unwrap_err().contains("below block 1000"), "an older view is refused after a restart");
        c.height = 1001;
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![5], "still retried after a restart");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_height_floor_is_written_only_when_it_moved_enough() {
        let dir = std::env::temp_dir().join(format!("ona-signer-height-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        let _ = fs::remove_file(&path);
        let (_, mut c) = setup(1);
        let mut s = Signer::new(KeyStore::generate(1), FileDurable::open(&path, "test").unwrap());
        for height in [1000, 1001, 1002, 1000 + HEIGHT_RECORD_STEP] {
            c.height = height;
            s.tick(&mut c).unwrap();
        }
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().filter(|l| l.starts_with("h ")).count(), 2, "{text}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_height_floor_never_goes_back_between_two_writes() {
        let (mut s, mut c) = setup(1);
        c.height = 1000;
        s.tick(&mut c).unwrap();
        c.height = 1001;
        s.tick(&mut c).unwrap();
        c.height = 1000;
        assert!(s.tick(&mut c).unwrap_err().contains("below block 1001"), "even though only 1000 was written");
    }

    fn state_file(name: &str, content: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ona-signer-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        let mut bytes = b"m test\n".to_vec();
        bytes.extend_from_slice(content);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (dir, path)
    }

    #[test]
    fn only_a_last_line_without_newline_is_dropped() {
        let (dir, path) = state_file("partial", b"b 1\nc 2\nh 7\nb 3");
        let mut state = FileDurable::open(&path, "test").unwrap();
        assert!(state.is_broadcast(1));
        assert_eq!(state.cursor(), 2);
        assert_eq!(state.height_floor(), 7);
        assert!(!state.is_broadcast(3), "a line that was never finished does not count");
        assert_eq!(fs::read(&path).unwrap(), b"m test\nb 1\nc 2\nh 7\n");

        state.mark_broadcast(4).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"m test\nb 1\nc 2\nh 7\nb 4\n", "the next write starts on a clean line");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_partial_last_line_may_be_invalid_text() {
        let (dir, path) = state_file("binary", b"b 1\n\xff\xfe");
        assert!(FileDurable::open(&path, "test").unwrap().is_broadcast(1));
        assert_eq!(fs::read(&path).unwrap(), b"m test\nb 1\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_complete_line_is_corruption_and_nothing_is_truncated() {
        for content in [&b"b 1\nxx\nb 2\n"[..], &b"b 1\nb x\n"[..], &b"zz 1\nb 2"[..]] {
            let (dir, path) = state_file("corrupt", content);
            let before = fs::read(&path).unwrap();
            assert!(FileDurable::open(&path, "test").err().unwrap().contains("corrupt"));
            assert_eq!(fs::read(&path).unwrap(), before, "the evidence is left in place");
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_state_file_for_another_deployment_is_refused() {
        let (dir, path) = state_file("binding", b"b 1\nc 9\n");
        assert!(FileDurable::open(&path, "other-mint:00").err().unwrap().contains("another contract"));
        fs::write(&path, b"b 1\nc 9\n").unwrap();
        assert!(FileDurable::open(&path, "test").err().unwrap().contains("no header"), "a file from before the header");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_state_file_readable_by_others_is_refused() {
        let (dir, path) = state_file("mode", b"b 1\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FileDurable::open(&path, "test").err().unwrap().contains("other users"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_state_file_left_empty_by_a_crash_counts_as_new() {
        let dir = std::env::temp_dir().join(format!("ona-signer-empty-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        fs::write(&path, b"m te").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let state = FileDurable::open(&path, "test").unwrap();
        assert!(state.is_new(), "so the check for locked deposits runs");
        drop(state);
        assert_eq!(fs::read(&path).unwrap(), b"m test\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_state_file_is_held_by_one_signer_at_a_time() {
        let dir = std::env::temp_dir().join(format!("ona-signer-lock-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.log");
        let _ = fs::remove_file(&path);
        let first = FileDurable::open(&path, "test").unwrap();
        assert!(first.is_new());
        assert!(FileDurable::open(&path, "test").err().unwrap().contains("in use"));
        drop(first);
        assert!(!FileDurable::open(&path, "test").unwrap().is_new());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_state_file_is_refused_while_deposits_are_locked() {
        let (_, mut c) = setup(1);
        c.records.push(record(1, vec![(0, point(1))]));
        assert!(refuse_new_state_with_locked_deposits(&mut c, true).is_ok(), "nothing locked yet");
        c.records[0].locked_until = LOCKED;
        assert!(refuse_new_state_with_locked_deposits(&mut c, true).unwrap_err().contains("restore"));
        assert!(refuse_new_state_with_locked_deposits(&mut c, false).is_ok());
    }

    #[test]
    fn a_locked_deposit_far_beyond_the_first_scan_is_still_found() {
        let (_, mut c) = setup(1);
        let mut far = record(5_000, vec![(0, point(1))]);
        far.locked_until = LOCKED;
        c.records.push(far);
        assert!(refuse_new_state_with_locked_deposits(&mut c, true).unwrap_err().contains("restore"));
    }

    #[test]
    fn the_binding_names_the_mint_and_the_keys() {
        let keys = KeyStore::generate(2);
        let binding = state_binding("mint.test", &keys);
        assert!(binding.starts_with("mint.test:"));
        assert_ne!(binding, state_binding("mint.test", &KeyStore::generate(2)));
        assert!(!binding.contains(char::is_whitespace));
    }

    #[test]
    fn nothing_is_appended_after_a_failed_write() {
        let (dir, path) = state_file("failed", b"");
        let read_only = fs::File::open(&path).unwrap();
        let mut state =
            FileDurable { file: read_only, memory: MemoryDurable::default(), failed: false, new: false, _lock: None };
        assert!(state.mark_broadcast(1).is_err());
        assert!(!state.is_broadcast(1));

        state.file = OpenOptions::new().append(true).open(&path).unwrap();
        assert!(state.mark_broadcast(2).is_err(), "even if the file looks writable again");
        assert_eq!(fs::read(&path).unwrap(), b"m test\n");
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
        fn height_floor(&self) -> u64 {
            0
        }
        fn set_height_floor(&mut self, _height: u64) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_state_write_stops_the_signer_before_any_signature_leaves() {
        let keys = KeyStore::generate(1);
        let mut c = FakeChain { keys: keys.public_keys(), now: 10, ..Default::default() };
        let mut locked = record(1, vec![(0, point(1))]);
        locked.locked_until = LOCKED;
        c.records.push(locked);
        let mut s = Signer::new(keys, BrokenDurable);

        assert!(s.tick(&mut c).unwrap_err().contains("disk full"));
        assert!(c.issued.is_empty());
        assert!(s.halted().unwrap().contains("disk full"));
        assert!(s.tick(&mut c).unwrap_err().contains("disk full"), "no further pass runs");
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
    fn a_locked_record_that_cannot_be_signed_is_unlocked_if_never_broadcast() {
        let (mut s, mut c) = setup(1);
        let mut bad = record(1, vec![(0, invalid_point())]);
        bad.locked_until = LOCKED;
        c.records.push(bad);
        let report = s.tick(&mut c).unwrap();
        assert_eq!(report.unlocked, vec![1]);
        assert_eq!(c.records[0].locked_until, 0, "it refunds at its deadline");
        assert!(c.issued.is_empty());
    }

    #[test]
    fn a_broadcast_record_is_never_unlocked() {
        let keys = KeyStore::generate(1);
        let mut c = FakeChain { keys: keys.public_keys(), now: 10, height: 1, ..Default::default() };
        let mut bad = record(1, vec![(0, invalid_point())]);
        bad.locked_until = LOCKED;
        c.records.push(bad);
        let mut state = MemoryDurable::default();
        state.mark_broadcast(1).unwrap();
        let mut s = Signer::new(keys, state);
        assert!(s.tick(&mut c).unwrap_err().contains("broadcast"));
        assert!(c.unlocked.is_empty(), "its signatures are public");
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
        c.records.push(record(1, vec![(0, point(1)), (0, invalid_point())]));
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
        lagging.locked_until = LOCKED;
        c.records.push(lagging);
        assert!(s.tick(&mut c).unwrap().issued.is_empty());
        assert_eq!(c.issued.len(), 1, "one answer per record");
    }

    #[test]
    fn a_full_page_of_finished_records_does_not_hide_new_deposits() {
        let (mut s, mut c) = setup(1);
        c.now = 100;
        for id in 0..64 {
            c.records.push(PendingRecord { deadline: 50, ..record(id, vec![(0, point(1))]) });
        }
        c.records.push(PendingRecord { deadline: 500, ..record(64, vec![(0, point(2))]) });
        assert_eq!(s.tick(&mut c).unwrap().locked, vec![64], "the second page is read in the same pass");
        assert_eq!(s.tick(&mut c).unwrap().issued, vec![64]);
        assert_eq!(s.state.cursor(), 65, "the cursor moved past the expired page and the issued record");
    }

    #[test]
    fn the_cursor_moves_past_a_long_run_of_finished_ids() {
        let (mut s, mut c) = setup(1);
        // Ids 0..3000 were all issued or refunded: only id 3000 is still pending.
        c.records.push(PendingRecord { deadline: 500, ..record(3_000, vec![(0, point(2))]) });
        let mut locked = false;
        for _ in 0..3 {
            locked |= s.tick(&mut c).unwrap().locked == vec![3_000];
        }
        assert!(locked, "the scan cursor advances over empty ranges");
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
        let mut odd = KEYS_HEADER.to_vec();
        odd.extend_from_slice(&[1u8; 33]);
        fs::write(&path, odd).unwrap();
        assert!(KeyStore::load(&path).err().unwrap().contains("wrong size"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_flood_from_one_depositor_does_not_delay_the_others_locks() {
        let (mut s, mut c) = setup(1);
        for id in 0..100 {
            let mut r = record(id, vec![(0, point(1))]);
            r.depositor = "flood.test".into();
            c.records.push(r);
        }
        let mut honest = record(100, vec![(0, point(2))]);
        honest.depositor = "honest.test".into();
        c.records.push(honest);
        let report = s.tick(&mut c).unwrap();
        assert!(report.locked.len() > 64, "more than one page is read in a pass");
        assert_eq!(report.locked[1], 100, "the honest deposit is locked second, not after the flood");
    }

    #[test]
    fn round_robin_takes_one_deposit_per_depositor_in_turn() {
        let mk = |id, who: &str| PendingRecord { depositor: who.into(), ..record(id, vec![]) };
        let order: Vec<u64> =
            round_robin(vec![mk(1, "a"), mk(2, "a"), mk(3, "a"), mk(4, "b"), mk(5, "c"), mk(6, "b")]).iter().map(|r| r.id).collect();
        assert_eq!(order, vec![1, 4, 5, 2, 6, 3]);
    }

    #[test]
    fn a_key_file_of_another_kind_is_refused() {
        let dir = std::env::temp_dir().join(format!("ona-signer-kind-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.bin");
        fs::write(&path, KeyStore::generate(1).keys[0].to_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(KeyStore::load(&path).err().unwrap().contains("not a signer key file"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
