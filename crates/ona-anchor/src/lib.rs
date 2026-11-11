//! `ona-anchor`: the aggregator. It collects checkpoint leaves, anchors one padded tree per hour
//! with `anchor(root, count)` on `ona-registry`, even when no leaf came in, and hands back the
//! inclusion proofs. Once a batch is anchored it keeps no leaf and no proof.
//!
//! Library only: no program receives leaves over the network yet.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_core::checkpoint::{Hash, InclusionProof, PaddedBatch, CAPACITY};
use serde_json::{json, Value};

pub const ANCHOR_INTERVAL_SECS: u64 = 3600;
/// Sent as `count` in every anchor. The real number of leaves would tell how busy the hour was,
/// which the padded tree exists to hide.
pub const PUBLISHED_COUNT: u32 = CAPACITY as u32;

pub trait AnchorChain {
    /// Records the root and returns its sequence number in the registry.
    fn anchor(&mut self, root: &Hash, count: u32) -> Result<u64, String>;
}

pub struct AnchoredBatch {
    pub seq: u64,
    pub root: Hash,
    /// One proof per leaf received, to deliver to whoever sent it.
    pub proofs: BTreeMap<Hash, InclusionProof>,
}

#[derive(Default)]
pub struct Aggregator {
    pending: BTreeSet<Hash>,
    last_anchor: Option<u64>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit(&mut self, leaf: Hash) -> Result<(), &'static str> {
        if self.pending.contains(&leaf) {
            return Err("leaf already submitted");
        }
        if self.pending.len() >= CAPACITY {
            return Err("this hour's batch is full; submit after the next anchor");
        }
        self.pending.insert(leaf);
        Ok(())
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// True once an hour has passed since the last successful anchor, or before the first one.
    pub fn is_due(&self, now_secs: u64) -> bool {
        self.last_anchor.is_none_or(|last| now_secs >= last.saturating_add(ANCHOR_INTERVAL_SECS))
    }

    /// Builds a new padded tree and anchors it. If the chain refuses, the leaves stay for the next
    /// attempt, which uses new positions and new filler leaves. If the chain accepted but the reply
    /// was lost, the leaves are anchored a second time, which costs gas but breaks no proof.
    pub fn flush<C: AnchorChain>(&mut self, chain: &mut C, now_secs: u64) -> Result<AnchoredBatch, String> {
        let leaves: Vec<Hash> = self.pending.iter().copied().collect();
        let batch = PaddedBatch::build(&leaves).map_err(String::from)?;
        let root = batch.root();
        let seq = chain.anchor(&root, PUBLISHED_COUNT)?;
        self.pending.clear();
        self.last_anchor = Some(now_secs);
        Ok(AnchoredBatch { seq, root, proofs: batch.into_proofs() })
    }
}

/// Arguments of the registry's `anchor` method: `Base64VecU8` root and `u32` count.
pub fn anchor_args(root: &Hash, count: u32) -> Value {
    json!({"root": B64.encode(root), "count": count})
}

/// The registry returns its `U64` sequence number, which NEAR encodes as a JSON string.
pub fn parse_seq(value: &Value) -> Result<u64, String> {
    value
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("anchor returned no sequence number: {value}"))
}

/// Anchors through `ona-near`, signed by the account the registry names as aggregator.
pub struct NearAnchor {
    pub client: ona_near::Client,
    pub aggregator_account: String,
    pub registry: String,
}

impl AnchorChain for NearAnchor {
    fn anchor(&mut self, root: &Hash, count: u32) -> Result<u64, String> {
        let outcome = self
            .client
            .call(&self.aggregator_account, &self.registry, "anchor", anchor_args(root, count), 0)
            .map_err(|e| e.to_string())?;
        if let Some(failure) = outcome.failure {
            return Err(format!("anchor failed: {failure}"));
        }
        parse_seq(&outcome.value)
    }
}
