//! Fixed-size anchoring tree and the auditor's sealed key.

use ona_core::auditor::*;
use ona_core::checkpoint::*;
use sha2::{Digest, Sha256};

fn leaves(seed: u8) -> Vec<Hash> {
    (0..CAPACITY).map(|i| Sha256::digest([seed, (i >> 8) as u8, i as u8]).into()).collect()
}

/// Written separately from the library, straight from RFC 9162.
fn reference_root(level: &[Hash]) -> Hash {
    if level.len() == 1 {
        return level[0];
    }
    let (left, right) = level.split_at(level.len() / 2);
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(reference_root(left));
    h.update(reference_root(right));
    h.finalize().into()
}

// ---------- leaves ----------

#[test]
fn a_leaf_follows_the_specified_layout() {
    let (salt, head) = ([1u8; 32], [2u8; 32]);
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(b"ona/leaf/v1");
    h.update(salt);
    h.update(head);
    let expected: Hash = h.finalize().into();
    assert_eq!(leaf_hash(&salt, &head), expected);
}

#[test]
fn a_leaf_cannot_pass_for_a_node() {
    let (a, b) = ([3u8; 32], [4u8; 32]);
    let mut as_leaf = Sha256::new();
    as_leaf.update([0u8]);
    as_leaf.update(a);
    as_leaf.update(b);
    let as_leaf: Hash = as_leaf.finalize().into();
    assert_ne!(node_hash(&a, &b), as_leaf, "the domain bytes differ");
}

#[test]
fn two_checkpoints_of_the_same_head_do_not_link() {
    let head = [9u8; 32];
    let (one, two) = (Checkpoint::new(head), Checkpoint::new(head));
    assert_ne!(one.salt, two.salt);
    assert_ne!(one.leaf(), two.leaf());
    assert_eq!(one.leaf(), leaf_hash(&one.salt, &head));
}

// ---------- tree and proofs ----------

#[test]
fn the_root_matches_an_independent_computation() {
    let leaves = leaves(1);
    let tree = FixedTree::new(leaves.clone()).unwrap();
    assert_eq!(tree.root(), reference_root(&leaves));
}

#[test]
fn a_tree_has_exactly_the_fixed_size() {
    let mut short = leaves(1);
    short.pop();
    assert!(FixedTree::new(short).is_err());
    let mut long = leaves(1);
    long.push([0u8; 32]);
    assert!(FixedTree::new(long).is_err());
}

#[test]
fn every_leaf_has_a_proof_of_fixed_size_that_verifies() {
    let leaves = leaves(2);
    let tree = FixedTree::new(leaves.clone()).unwrap();
    let root = tree.root();
    for (index, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(index).unwrap();
        assert_eq!(proof.to_bytes().len(), PROOF_LEN);
        assert_eq!(PROOF_LEN, 2 + 10 * 32);
        assert!(verify_inclusion(leaf, &proof, &root), "leaf {index}");
    }
    assert!(tree.proof(CAPACITY).is_none());
}

#[test]
fn any_change_breaks_a_proof() {
    let leaves = leaves(3);
    let tree = FixedTree::new(leaves.clone()).unwrap();
    let root = tree.root();
    let proof = tree.proof(357).unwrap();
    let leaf = leaves[357];
    assert!(verify_inclusion(&leaf, &proof, &root));

    for depth in 0..DEPTH {
        let mut bad = proof.clone();
        bad.siblings[depth][0] ^= 1;
        assert!(!verify_inclusion(&leaf, &bad, &root), "sibling {depth}");
    }
    for bit in 0..DEPTH {
        let mut moved = proof.clone();
        moved.index ^= 1 << bit;
        assert!(!verify_inclusion(&leaf, &moved, &root), "index bit {bit}");
    }
    let mut other_leaf = leaf;
    other_leaf[31] ^= 1;
    assert!(!verify_inclusion(&other_leaf, &proof, &root));
    let mut other_root = root;
    other_root[0] ^= 1;
    assert!(!verify_inclusion(&leaf, &proof, &other_root));
    let mut outside = proof.clone();
    outside.index = CAPACITY as u16;
    assert!(!verify_inclusion(&leaf, &outside, &root));
}

#[test]
fn proof_bytes_round_trip_and_bad_ones_are_refused() {
    let tree = FixedTree::new(leaves(4)).unwrap();
    let proof = tree.proof(1023).unwrap();
    let bytes = proof.to_bytes();
    assert_eq!(InclusionProof::from_bytes(&bytes).unwrap(), proof);
    assert!(InclusionProof::from_bytes(&bytes[..PROOF_LEN - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(InclusionProof::from_bytes(&longer).is_err());
    let mut outside = bytes;
    outside[..2].copy_from_slice(&(CAPACITY as u16).to_le_bytes());
    assert!(InclusionProof::from_bytes(&outside).is_err());
}

// ---------- padded batches ----------

#[test]
fn a_padded_batch_proves_its_real_leaves_and_nothing_else() {
    let real: Vec<Hash> = (0..5u8).map(|i| Checkpoint::new([i; 32]).leaf()).collect();
    let batch = PaddedBatch::build(&real).unwrap();
    let root = batch.root();
    for leaf in &real {
        assert!(verify_inclusion(leaf, &batch.proof_for(leaf).unwrap(), &root));
    }
    assert!(batch.proof_for(&[7u8; 32]).is_none());
    let proofs = batch.into_proofs();
    assert_eq!(proofs.len(), 5, "no proof is handed out for a filler leaf");
    for (leaf, proof) in &proofs {
        assert!(verify_inclusion(leaf, proof, &root));
    }
}

#[test]
fn an_empty_batch_still_has_a_root_and_two_differ() {
    let (one, two) = (PaddedBatch::build(&[]).unwrap(), PaddedBatch::build(&[]).unwrap());
    assert_ne!(one.root(), two.root(), "filler leaves are random");
}

#[test]
fn positions_are_random() {
    let leaf = Checkpoint::new([1u8; 32]).leaf();
    let indexes: std::collections::BTreeSet<u16> =
        (0..20).map(|_| PaddedBatch::build(&[leaf]).unwrap().proof_for(&leaf).unwrap().index).collect();
    assert!(indexes.len() > 1, "a fixed position would reveal how full a batch is");
}

#[test]
fn a_batch_refuses_too_many_or_repeated_leaves() {
    let too_many: Vec<Hash> = leaves(5).into_iter().chain([[0u8; 32]]).collect();
    assert!(PaddedBatch::build(&too_many).is_err());
    assert!(PaddedBatch::build(&leaves(5)).is_ok(), "a full batch fits");
    let leaf = [8u8; 32];
    assert!(PaddedBatch::build(&[leaf, leaf]).is_err());
}

// ---------- auditor key ----------

#[test]
fn the_auditor_opens_the_master_key_and_the_agent_forgets_it() {
    let (secret, public) = auditor_keypair();
    let original = [42u8; 32];
    let mut master = original;
    let sealed = seal_master_key(&mut master, &public).unwrap();
    assert_eq!(master, [0u8; 32], "wiped from the agent's buffer");
    assert_eq!(sealed.len(), SEALED_LEN);
    assert_eq!(*open_master_key(&secret, &sealed).unwrap(), original);
}

#[test]
fn another_key_cannot_open_it() {
    let (_, public) = auditor_keypair();
    let (other, _) = auditor_keypair();
    let sealed = seal_master_key(&mut [1u8; 32], &public).unwrap();
    assert!(open_master_key(&other, &sealed).is_err());
}

#[test]
fn every_altered_byte_is_detected() {
    let (secret, public) = auditor_keypair();
    let sealed = seal_master_key(&mut [5u8; 32], &public).unwrap();
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 1;
        assert!(open_master_key(&secret, &bad).is_err(), "byte {i}");
    }
    assert!(open_master_key(&secret, &sealed[..SEALED_LEN - 1]).is_err());
}

#[test]
fn each_seal_uses_a_new_ephemeral_key() {
    let (_, public) = auditor_keypair();
    let one = seal_master_key(&mut [6u8; 32], &public).unwrap();
    let two = seal_master_key(&mut [6u8; 32], &public).unwrap();
    assert_ne!(one[1..33], two[1..33]);
    assert_ne!(one, two);
}

#[test]
fn an_invalid_auditor_key_is_refused_and_the_master_key_kept() {
    let mut master = [7u8; 32];
    assert!(seal_master_key(&mut master, &[0u8; 32]).is_err(), "a low-order key would make the seal worthless");
    assert_eq!(master, [7u8; 32], "a failed seal does not lose the journal");
}
