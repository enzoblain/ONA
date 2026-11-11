//! Journal checkpoints, anchored on chain in a Merkle tree of fixed size.
//!
//! Hashing uses the RFC 9162 prefixes: `0x00` before a leaf, `0x01` before a node, so a node can never pass
//! for a leaf. The tree itself is not an RFC 9162 log: it always has `CAPACITY` leaves, filled with random
//! ones, and real leaves sit at random positions, so a root is 32 bytes and a proof `DEPTH` hashes whatever
//! the size of the batch.
//!
//! **Checkpoint chain.** The checkpoints of one journal form a chain: checkpoint `n` commits to its rank `n`,
//! the journal head and the leaf of checkpoint `n - 1`. Its salt and its tag come from a checkpoint key that
//! only the agent holds (derived from the journal's secret salt), so leaves of one mission cannot be linked on
//! chain. The agent sends the tag of rank `n` and the commitment; the aggregator builds the leaf from both,
//! so the tag is part of what is anchored, and it refuses a tag it has already seen.
//!
//! `verify_checkpoints` checks, for an auditor who received the checkpoint key and the anchored checkpoints:
//! - every rank from 0 to the last, with no gap and no duplicate, each linked to the one before;
//! - every leaf rebuilt with the tag the key gives for its rank, and found in the root the registry holds at
//!   the stated `seq`, read by the auditor itself;
//! - the first anchor inside the opening window the auditor knows from outside the agent;
//! - anchors in increasing order and never further apart than the auditor's maximum gap;
//! - every head is a state of the journal presented, in order, and the last one is its final head.
//!
//! The auditor's windows (opening window, maximum gap) must be shorter than `TAG_RETENTION_NS`, or the check
//! refuses to run. Under these conditions:
//! - the aggregator is honest, has kept its tag file, and stayed the same aggregator for the whole mission
//!   (a new aggregator set by `SetAggregator` starts with no tags);
//! - the auditor's opening window is right;
//!
//! then, for a given checkpoint key, no second chain that passes this check can have been anchored: its rank 0
//! falls in the opening window, while the first chain's tags are still kept, and each later rank falls within
//! the maximum gap of the one before, while that rank's tag is still kept. A leaf sent with any other tag does
//! not pass for that key.
//!
//! What it cannot detect: a parallel chain built with another checkpoint key from rank 0, unless the opening
//! tag (`AuditTrust::opening_tag`) was recorded somewhere other than the agent when the mission started; a
//! second leaf for a rank if any condition above fails. And it proves what the agent wrote in its journal, not
//! that the journal tells the truth.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type Hash = [u8; 32];

pub const DEPTH: usize = 10;
pub const CAPACITY: usize = 1 << DEPTH;
/// Index on two bytes, little-endian, then the siblings from the leaf up.
pub const PROOF_LEN: usize = 2 + DEPTH * 32;
/// The registry's `seq` on eight bytes, little-endian, then the inclusion proof.
pub const ANCHORED_PROOF_LEN: usize = 8 + PROOF_LEN;

const LEAF_DOMAIN: &[u8] = b"ona/leaf/v3";
const COMMIT_DOMAIN: &[u8] = b"ona/cp/commit/v1";

/// HMAC-SHA256 of `label || 0x00 || data` under `key` (the HKDF extract step is exactly that HMAC).
pub fn prf(key: &[u8], label: &[u8], data: &[u8]) -> Hash {
    let mut message = label.to_vec();
    message.push(0);
    message.extend_from_slice(data);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(key), &message);
    prk.into()
}

/// What hides the checkpoint: `SHA-256("ona/cp/commit/v1" || salt || rank (u64 LE) || head || prev)`.
pub fn commitment_hash(salt: &[u8; 32], rank: u64, head: &Hash, prev: &Hash) -> Hash {
    Sha256::new()
        .chain_update(COMMIT_DOMAIN)
        .chain_update(salt)
        .chain_update(rank.to_le_bytes())
        .chain_update(head)
        .chain_update(prev)
        .finalize()
        .into()
}

/// The anchored leaf: `SHA-256(0x00 || "ona/leaf/v3" || tag || commitment)`. The aggregator computes it itself
/// from the tag and the commitment it receives, so the tag it checks for uniqueness is the one inside the leaf.
pub fn leaf_hash(tag: &Hash, commitment: &Hash) -> Hash {
    Sha256::new().chain_update([0x00]).chain_update(LEAF_DOMAIN).chain_update(tag).chain_update(commitment).finalize().into()
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new().chain_update([0x01]).chain_update(left).chain_update(right).finalize().into()
}

/// The tag of rank `rank`, sent to the aggregator with the leaf.
pub fn checkpoint_tag(key: &[u8; 32], rank: u64) -> Hash {
    prf(key, b"ona/cp/tag", &rank.to_le_bytes())
}

fn checkpoint_salt(key: &[u8; 32], rank: u64) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(prf(key, b"ona/cp/salt", &rank.to_le_bytes()))
}

fn random_hash() -> Hash {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// One checkpoint of a journal. Everything in it is rebuilt from the checkpoint key, the rank and the head,
/// so the agent stores nothing extra to prove it later.
#[derive(Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub rank: u64,
    pub head: Hash,
    /// Leaf of the checkpoint before it; zero for rank 0.
    pub prev: Hash,
    commitment: Hash,
    tag: Hash,
}

impl std::fmt::Debug for Checkpoint {
    /// No salt and no key: only what is already public or harmless.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpoint").field("rank", &self.rank).finish_non_exhaustive()
    }
}

impl Checkpoint {
    fn at(key: &[u8; 32], rank: u64, head: Hash, prev: Hash) -> Self {
        let salt = checkpoint_salt(key, rank);
        Self { rank, head, prev, commitment: commitment_hash(&salt, rank, &head, &prev), tag: checkpoint_tag(key, rank) }
    }

    /// The first checkpoint of a journal. Its tag is the mission's opening tag.
    pub fn first(key: &[u8; 32], head: Hash) -> Self {
        Self::at(key, 0, head, [0u8; 32])
    }

    /// The checkpoint that follows this one.
    pub fn next(&self, key: &[u8; 32], head: Hash) -> Self {
        Self::at(key, self.rank + 1, head, self.leaf())
    }

    pub fn leaf(&self) -> Hash {
        leaf_hash(&self.tag, &self.commitment)
    }

    /// Sent to the aggregator with the tag; the leaf is rebuilt from both.
    pub fn commitment(&self) -> Hash {
        self.commitment
    }

    pub fn tag(&self) -> Hash {
        self.tag
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u16,
    pub siblings: [Hash; DEPTH],
}

impl InclusionProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.index.to_le_bytes().to_vec();
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != PROOF_LEN {
            return Err("proof has the wrong length");
        }
        let index = u16::from_le_bytes([bytes[0], bytes[1]]);
        if usize::from(index) >= CAPACITY {
            return Err("proof index is outside the tree");
        }
        let mut siblings = [[0u8; 32]; DEPTH];
        for (i, sibling) in siblings.iter_mut().enumerate() {
            sibling.copy_from_slice(&bytes[2 + i * 32..2 + (i + 1) * 32]);
        }
        Ok(Self { index, siblings })
    }
}

/// An inclusion proof and the registry anchor it refers to, so nobody has to search every anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredProof {
    pub seq: u64,
    pub proof: InclusionProof,
}

impl AnchoredProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.seq.to_le_bytes().to_vec();
        out.extend_from_slice(&self.proof.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != ANCHORED_PROOF_LEN {
            return Err("anchored proof has the wrong length");
        }
        let seq = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| "bad seq")?);
        Ok(Self { seq, proof: InclusionProof::from_bytes(&bytes[8..])? })
    }
}

/// Checks that `leaf` is in the tree whose root is `root`. Low level: an auditor uses `verify_checkpoints`,
/// which recomputes the leaf and reads the root on chain itself.
pub fn verify_inclusion(leaf: &Hash, proof: &InclusionProof, root: &Hash) -> bool {
    let mut index = usize::from(proof.index);
    if index >= CAPACITY {
        return false;
    }
    let mut hash = *leaf;
    for sibling in &proof.siblings {
        hash = if index & 1 == 0 { node_hash(&hash, sibling) } else { node_hash(sibling, &hash) };
        index >>= 1;
    }
    &hash == root
}

/// Reads anchors from the registry. An implementation must read a final block from a source the auditor
/// trusts, never take the agent's word for a root.
pub trait AnchorReader {
    /// The root and the block timestamp (nanoseconds) of anchor `seq`, or `None` if there is none.
    fn anchored_root(&self, seq: u64) -> Result<Option<(Hash, u64)>, String>;
}

/// A checkpoint as the agent presents it to the auditor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCheckpoint {
    pub rank: u64,
    pub head: Hash,
    pub proof: AnchoredProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointAudit {
    pub checkpoints: usize,
    pub first_anchor_ns: u64,
    pub last_anchor_ns: u64,
}

/// What the auditor brings from outside the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrust {
    /// The mission's opening tag, if it was recorded elsewhere when the mission started.
    pub opening_tag: Option<Hash>,
    /// When the mission was opened, as known from outside the agent: the first checkpoint must be anchored
    /// in `[not_before_ns, not_after_ns]`. The window must be shorter than `TAG_RETENTION_NS`.
    pub not_before_ns: u64,
    pub not_after_ns: u64,
    /// Longest time allowed between two checkpoints; shorter than `TAG_RETENTION_NS`.
    pub max_gap_ns: u64,
}

/// How long the aggregator keeps the tags it has seen. A tag forgotten can be used again, so every window the
/// auditor accepts must be shorter than this.
pub const TAG_RETENTION_NS: u64 = 7 * 24 * 3_600_000_000_000;

/// See the module documentation for what this proves and what it does not.
///
/// `journal_heads` are the successive heads of the journal presented: its starting value, then the head
/// after each entry (`journal::heads_from`). Fails closed: anything missing or unreadable is a refusal.
pub fn verify_checkpoints<R: AnchorReader>(
    key: &[u8; 32],
    trust: &AuditTrust,
    journal_heads: &[Hash],
    presented: &[PresentedCheckpoint],
    reader: &R,
) -> Result<CheckpointAudit, String> {
    let max_gap_ns = trust.max_gap_ns;
    if max_gap_ns >= TAG_RETENTION_NS {
        return Err("the maximum gap must be shorter than the aggregator's tag retention".into());
    }
    if trust.not_after_ns < trust.not_before_ns || trust.not_after_ns - trust.not_before_ns >= TAG_RETENTION_NS {
        return Err("the opening window must be shorter than the aggregator's tag retention".into());
    }
    let last_head = journal_heads.last().ok_or("no journal heads")?;
    let last = presented.last().ok_or("no checkpoint presented")?;
    if let Some(expected) = &trust.opening_tag {
        if &checkpoint_tag(key, 0) != expected {
            return Err("the checkpoints do not belong to the expected mission".into());
        }
    }
    let mut prev_leaf = [0u8; 32];
    let mut prev_seq: Option<u64> = None;
    let mut prev_time = 0u64;
    let mut first_time = 0u64;
    let mut position = 0usize;
    for (expected_rank, checkpoint) in presented.iter().enumerate() {
        let rank = checkpoint.rank;
        if rank != expected_rank as u64 {
            return Err(format!("checkpoint {expected_rank}: rank {rank} out of order, missing or repeated"));
        }
        let commitment = commitment_hash(&checkpoint_salt(key, rank), rank, &checkpoint.head, &prev_leaf);
        let leaf = leaf_hash(&checkpoint_tag(key, rank), &commitment);
        let seq = checkpoint.proof.seq;
        let (root, time) = reader
            .anchored_root(seq)?
            .ok_or_else(|| format!("checkpoint {rank}: no anchor {seq} on chain"))?;
        if !verify_inclusion(&leaf, &checkpoint.proof.proof, &root) {
            return Err(format!("checkpoint {rank}: not in anchor {seq}"));
        }
        if let Some(before) = prev_seq {
            if seq <= before {
                return Err(format!("checkpoint {rank}: anchors out of order"));
            }
            if time.saturating_sub(prev_time) > max_gap_ns {
                return Err(format!("checkpoint {rank}: too long since the previous checkpoint"));
            }
        } else {
            if time < trust.not_before_ns || time > trust.not_after_ns {
                return Err("the first checkpoint was not anchored when the mission was opened".into());
            }
            first_time = time;
        }
        let found = journal_heads[position..]
            .iter()
            .position(|h| h == &checkpoint.head)
            .ok_or_else(|| format!("checkpoint {rank}: head is not a later state of this journal"))?;
        position += found;
        prev_leaf = leaf;
        prev_seq = Some(seq);
        prev_time = time;
    }
    if &last.head != last_head {
        return Err("the last checkpoint is not the journal's final head".into());
    }
    Ok(CheckpointAudit { checkpoints: presented.len(), first_anchor_ns: first_time, last_anchor_ns: prev_time })
}

/// A full tree of exactly `CAPACITY` leaves.
pub struct FixedTree {
    levels: Vec<Vec<Hash>>,
}

impl FixedTree {
    pub fn new(leaves: Vec<Hash>) -> Result<Self, &'static str> {
        if leaves.len() != CAPACITY {
            return Err("a tree needs exactly CAPACITY leaves");
        }
        let mut levels = vec![leaves];
        while levels.last().map_or(0, Vec::len) > 1 {
            let below = levels.last().expect("levels is never empty");
            let above = below.chunks(2).map(|pair| node_hash(&pair[0], &pair[1])).collect();
            levels.push(above);
        }
        Ok(Self { levels })
    }

    pub fn root(&self) -> Hash {
        self.levels[DEPTH][0]
    }

    pub fn proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= CAPACITY {
            return None;
        }
        let mut siblings = [[0u8; 32]; DEPTH];
        let mut position = index;
        for (depth, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.levels[depth][position ^ 1];
            position >>= 1;
        }
        Some(InclusionProof { index: u16::try_from(index).ok()?, siblings })
    }
}

/// The real leaves of one batch at random positions, among random filler leaves.
pub struct PaddedBatch {
    tree: FixedTree,
    positions: BTreeMap<Hash, usize>,
}

impl PaddedBatch {
    pub fn build(real: &[Hash]) -> Result<Self, &'static str> {
        if real.len() > CAPACITY {
            return Err("more leaves than the tree holds");
        }
        let mut slots: Vec<usize> = (0..CAPACITY).collect();
        slots.shuffle(&mut OsRng);
        let mut leaves: Vec<Hash> = (0..CAPACITY).map(|_| random_hash()).collect();
        let mut positions = BTreeMap::new();
        for (leaf, slot) in real.iter().zip(&slots) {
            if positions.insert(*leaf, *slot).is_some() {
                return Err("the same leaf appears twice");
            }
            leaves[*slot] = *leaf;
        }
        Ok(Self { tree: FixedTree::new(leaves)?, positions })
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn proof_for(&self, leaf: &Hash) -> Option<InclusionProof> {
        self.positions.get(leaf).and_then(|slot| self.tree.proof(*slot))
    }

    /// The proofs of the real leaves only, and the tree is dropped.
    pub fn into_proofs(self) -> BTreeMap<Hash, InclusionProof> {
        self.positions
            .iter()
            .filter_map(|(leaf, slot)| self.tree.proof(*slot).map(|proof| (*leaf, proof)))
            .collect()
    }
}
