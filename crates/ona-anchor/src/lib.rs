//! `ona-anchor`: the aggregator. It collects checkpoint leaves, anchors one padded tree per hour
//! with `anchor(root)` on `ona-registry`, even when no leaf came in, and hands back the inclusion proofs
//! with the anchor's `seq`. Before handing them back it reads the anchor again from a final block: a node
//! that lies about the anchor does not get proofs handed out against a root that was never anchored.
//!
//! A sender gives a checkpoint tag and a commitment (`ona_core::checkpoint`); the aggregator builds the leaf
//! from both, so the tag it checks is inside the anchored leaf. A tag already seen is refused. Tags are kept
//! `TAG_RETENTION_SECS`, in a file if one is given (`with_tag_file`), so a restart does not forget them. An
//! auditor must use a maximum gap between checkpoints shorter than that retention. At most `MAX_SEEN_TAGS` are
//! kept; beyond that new leaves are refused rather than old tags forgotten early. A tag is a keyed hash and
//! links nothing on chain.
//!
//! Each sender is limited to `MAX_LEAVES_PER_CLIENT` leaves per batch. `client` is whatever the network layer
//! uses to tell senders apart; nothing checks it here, so the limit holds only once it comes from something
//! a sender cannot multiply for free (a spent ONA request token is the plan, not built).
//!
//! The aggregator sees who sends a leaf and when: unlinkability holds on chain, not towards it. Someone who
//! sees a leaf in transit can submit it first; the sender is refused and gets no proof.
//!
//! Library only: no program receives leaves over the network yet.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_core::checkpoint::{leaf_hash, AnchorReader, AnchoredProof, Hash, PaddedBatch, CAPACITY};
use serde_json::{json, Value};

pub const ANCHOR_INTERVAL_SECS: u64 = 3600;
pub const MAX_LEAVES_PER_CLIENT: usize = 4;
/// The retention auditors rely on (`ona_core::checkpoint::TAG_RETENTION_NS`).
pub const TAG_RETENTION_SECS: u64 = ona_core::checkpoint::TAG_RETENTION_NS / 1_000_000_000;
/// Full batches every hour for the whole retention.
pub const MAX_SEEN_TAGS: usize = CAPACITY * (TAG_RETENTION_SECS / ANCHOR_INTERVAL_SECS) as usize;
/// Attached to every `anchor` call to pay for its storage; the registry refunds what it does not use. About
/// 105 bytes per anchor were measured on the simulated VM; the price per byte is the network's (not
/// verified here).
pub const ANCHOR_DEPOSIT_YOCTO: u128 = 10_000_000_000_000_000_000_000;

pub trait AnchorChain {
    /// Records the root and returns its sequence number in the registry.
    fn anchor(&mut self, root: &Hash) -> Result<u64, String>;
    /// Root of anchor `seq`, read from a final block.
    fn read_anchor(&mut self, seq: u64) -> Result<Option<Hash>, String>;
    /// The latest anchor, read from a final block.
    fn latest_anchor(&mut self) -> Result<Option<(u64, Hash)>, String>;
}

pub struct AnchoredBatch {
    pub seq: u64,
    pub root: Hash,
    /// One proof per leaf received, to deliver to whoever sent it.
    pub proofs: BTreeMap<Hash, AnchoredProof>,
}

#[derive(Default)]
pub struct Aggregator {
    /// Leaf to tag.
    pending: BTreeMap<Hash, Hash>,
    pending_tags: BTreeSet<Hash>,
    per_client: BTreeMap<Hash, usize>,
    /// Tag to the time it was anchored.
    seen_tags: BTreeMap<Hash, u64>,
    tag_file: Option<PathBuf>,
    /// A lower limit than `MAX_SEEN_TAGS`, if set.
    tag_limit: Option<usize>,
    last_anchor: Option<u64>,
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_tag_line(line: &str) -> Option<(Hash, u64)> {
    let (hex, secs) = line.split_once(' ')?;
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect::<Option<_>>()?;
    Some((bytes.try_into().ok()?, secs.parse().ok()?))
}

impl Aggregator {
    /// Tags kept in memory only: a restart forgets them. For tests and tools.
    pub fn new() -> Self {
        Self::default()
    }

    /// Tags kept in `path` (one `hex seconds` line each, readable by its owner only). Expired tags are dropped
    /// and the file rewritten; a line that cannot be read is a refusal to start.
    pub fn with_tag_file(path: &Path, now_secs: u64) -> Result<Self, String> {
        let mut aggregator = Self { tag_file: Some(path.to_path_buf()), ..Self::default() };
        match fs::read_to_string(path) {
            Ok(text) => {
                for line in text.lines() {
                    let (tag, at) = parse_tag_line(line).ok_or("the tag file is corrupt")?;
                    aggregator.seen_tags.insert(tag, at);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        aggregator.expire(now_secs);
        let mut text = String::new();
        for (tag, at) in &aggregator.seen_tags {
            text.push_str(&format!("{} {at}\n", to_hex(tag)));
        }
        let tmp = path.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        let mut file =
            OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
        file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(aggregator)
    }

    fn expire(&mut self, now_secs: u64) {
        self.seen_tags.retain(|_, at| now_secs < at.saturating_add(TAG_RETENTION_SECS));
    }

    fn record(&mut self, tags: &[Hash], now_secs: u64) -> Result<(), String> {
        for tag in tags {
            self.seen_tags.insert(*tag, now_secs);
        }
        let Some(path) = &self.tag_file else {
            return Ok(());
        };
        let mut text = String::new();
        for tag in tags {
            text.push_str(&format!("{} {now_secs}\n", to_hex(tag)));
        }
        let mut file =
            OpenOptions::new().append(true).create(true).mode(0o600).open(path).map_err(|e| e.to_string())?;
        file.write_all(text.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| e.to_string())
    }

    pub fn seen_tags(&self) -> usize {
        self.seen_tags.len()
    }

    /// Keeps fewer tags than `MAX_SEEN_TAGS` (never more).
    pub fn limit_seen_tags(mut self, limit: usize) -> Self {
        self.tag_limit = Some(limit.min(MAX_SEEN_TAGS));
        self
    }

    /// Takes a checkpoint's tag and commitment and builds its leaf.
    pub fn submit(&mut self, client: Hash, tag: Hash, commitment: Hash) -> Result<Hash, &'static str> {
        let leaf = leaf_hash(&tag, &commitment);
        if self.pending.contains_key(&leaf) {
            return Err("leaf already submitted");
        }
        if self.pending_tags.contains(&tag) || self.seen_tags.contains_key(&tag) {
            return Err("a checkpoint of this rank was already submitted for this mission");
        }
        if self.per_client.get(&client).copied().unwrap_or(0) >= MAX_LEAVES_PER_CLIENT {
            return Err("too many leaves from this sender in this batch");
        }
        if self.pending.len() >= CAPACITY {
            return Err("this hour's batch is full; submit after the next anchor");
        }
        if self.seen_tags.len() + self.pending.len() >= self.tag_limit.unwrap_or(MAX_SEEN_TAGS) {
            return Err("too many tags kept; refusing rather than forgetting them early");
        }
        self.pending.insert(leaf, tag);
        self.pending_tags.insert(tag);
        *self.per_client.entry(client).or_default() += 1;
        Ok(leaf)
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// True once an hour has passed since the last successful anchor, or before the first one. A clock that
    /// went back is treated as due, so anchoring does not stop until it catches up.
    pub fn is_due(&self, now_secs: u64) -> bool {
        self.last_anchor.is_none_or(|last| now_secs < last || now_secs >= last.saturating_add(ANCHOR_INTERVAL_SECS))
    }

    /// Builds a new padded tree and anchors it. The anchor is read back from a final block before the proofs
    /// are handed out. If the chain refused or the reply was lost, the latest anchor is read: if it is this
    /// root, the batch is done; otherwise the leaves stay for the next attempt, which uses new positions and
    /// new filler leaves.
    pub fn flush<C: AnchorChain>(&mut self, chain: &mut C, now_secs: u64) -> Result<AnchoredBatch, String> {
        let leaves: Vec<Hash> = self.pending.keys().copied().collect();
        let batch = PaddedBatch::build(&leaves).map_err(String::from)?;
        let root = batch.root();
        let seq = match chain.anchor(&root) {
            Ok(seq) => {
                if chain.read_anchor(seq)? != Some(root) {
                    return Err(format!("anchor {seq} on chain is not the root sent; proofs withheld"));
                }
                seq
            }
            Err(e) => match chain.latest_anchor() {
                Ok(Some((seq, latest))) if latest == root => seq,
                Ok(_) => return Err(e),
                Err(read) => return Err(format!("{e}; and the latest anchor could not be read: {read}")),
            },
        };
        let tags: Vec<Hash> = std::mem::take(&mut self.pending_tags).into_iter().collect();
        self.pending.clear();
        self.per_client.clear();
        self.last_anchor = Some(now_secs);
        self.expire(now_secs);
        // The batch is anchored: if its tags cannot be saved, the proofs are withheld rather than handed out
        // with a tag store that would accept a second leaf for the same ranks after a restart.
        self.record(&tags, now_secs).map_err(|e| format!("anchored as {seq}, but the tags could not be saved: {e}"))?;
        let proofs = batch.into_proofs().into_iter().map(|(leaf, proof)| (leaf, AnchoredProof { seq, proof })).collect();
        Ok(AnchoredBatch { seq, root, proofs })
    }
}

/// Arguments of the registry's `anchor` method: a `Base64VecU8` root.
pub fn anchor_args(root: &Hash) -> Value {
    json!({"root": B64.encode(root)})
}

/// The registry returns its `U64` sequence number, which NEAR encodes as a JSON string.
pub fn parse_seq(value: &Value) -> Result<u64, String> {
    value
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("anchor returned no sequence number: {value}"))
}

/// Reads an `Anchor` as the registry's views return it: `{seq, root, timestamp}`, or `null`.
pub fn parse_anchor(value: &Value) -> Result<Option<(u64, Hash, u64)>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let number = |field: &str| {
        value[field].as_str().and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| format!("anchor without {field}"))
    };
    let root: Hash = value["root"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or("anchor without a 32-byte root")?;
    Ok(Some((number("seq")?, root, number("timestamp")?)))
}

/// Anchors through `ona-near`, signed by the account the registry names as aggregator.
pub struct NearAnchor {
    pub client: ona_near::Client,
    pub aggregator_account: String,
    pub registry: String,
}

impl NearAnchor {
    fn view(&self, method: &str, args: Value) -> Result<Option<(u64, Hash, u64)>, String> {
        let value = self.client.view_final(&self.registry, method, args).map_err(|e| e.to_string())?;
        parse_anchor(&value)
    }
}

impl AnchorChain for NearAnchor {
    fn anchor(&mut self, root: &Hash) -> Result<u64, String> {
        let outcome = self
            .client
            .call(&self.aggregator_account, &self.registry, "anchor", anchor_args(root), ANCHOR_DEPOSIT_YOCTO)
            .map_err(|e| e.to_string())?;
        if let Some(failure) = outcome.failure {
            return Err(format!("anchor failed: {failure}"));
        }
        parse_seq(&outcome.value)
    }

    fn read_anchor(&mut self, seq: u64) -> Result<Option<Hash>, String> {
        Ok(self.view("get_anchor", json!({"seq": seq.to_string()}))?.map(|(_, root, _)| root))
    }

    fn latest_anchor(&mut self) -> Result<Option<(u64, Hash)>, String> {
        Ok(self.view("latest_anchor", json!({}))?.map(|(seq, root, _)| (seq, root)))
    }
}

/// What an auditor uses to read anchors with `ona_core::checkpoint::verify_checkpoints`.
impl AnchorReader for NearAnchor {
    fn anchored_root(&self, seq: u64) -> Result<Option<(Hash, u64)>, String> {
        let found = self.view("get_anchor", json!({"seq": seq.to_string()}))?;
        match found {
            Some((got, root, timestamp)) if got == seq => Ok(Some((root, timestamp))),
            Some(_) => Err(format!("the registry answered another anchor than {seq}")),
            None => Ok(None),
        }
    }
}
