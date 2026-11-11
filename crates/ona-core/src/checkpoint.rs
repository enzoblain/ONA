//! Journal checkpoints, anchored on chain in a Merkle tree of fixed size.
//!
//! Hashing follows RFC 9162: `0x00` before a leaf, `0x01` before a node, so a node can never pass
//! for a leaf. The tree always has `CAPACITY` leaves, filled with random ones, and real leaves sit at
//! random positions: a root is 32 bytes and a proof `DEPTH` hashes, whatever the size of the batch.

use std::collections::BTreeMap;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub const DEPTH: usize = 10;
pub const CAPACITY: usize = 1 << DEPTH;
/// Index on two bytes, little-endian, then the siblings from the leaf up.
pub const PROOF_LEN: usize = 2 + DEPTH * 32;

const LEAF_DOMAIN: &[u8] = b"ona/leaf/v1";

/// `SHA-256(0x00 || "ona/leaf/v1" || salt || head)`.
pub fn leaf_hash(salt: &[u8; 32], head: &Hash) -> Hash {
    Sha256::new().chain_update([0x00]).chain_update(LEAF_DOMAIN).chain_update(salt).chain_update(head).finalize().into()
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new().chain_update([0x01]).chain_update(left).chain_update(right).finalize().into()
}

fn random_hash() -> Hash {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// One checkpoint of a journal. The salt is new for each one, so two leaves of the same mission
/// cannot be linked. Only the agent keeps the salt; it is needed to prove the checkpoint later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub salt: [u8; 32],
    pub head: Hash,
}

impl Checkpoint {
    pub fn new(head: Hash) -> Self {
        Self { salt: random_hash(), head }
    }

    pub fn leaf(&self) -> Hash {
        leaf_hash(&self.salt, &self.head)
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

/// Checks that `leaf` is in the tree whose root is `root`.
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
