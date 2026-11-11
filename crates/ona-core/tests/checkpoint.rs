//! Fixed-size anchoring tree, checkpoint chains and the auditor's sealed key.

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

const KEY: [u8; 32] = [5u8; 32];

fn some_leaf(i: u8) -> Hash {
    Checkpoint::first(&[i; 32], [i; 32]).leaf()
}

#[test]
fn a_leaf_follows_the_specified_layout() {
    let (salt, head, prev, tag) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
    let mut h = Sha256::new();
    h.update(b"ona/cp/commit/v1");
    h.update(salt);
    h.update(7u64.to_le_bytes());
    h.update(head);
    h.update(prev);
    let commitment: Hash = h.finalize().into();
    assert_eq!(commitment_hash(&salt, 7, &head, &prev), commitment);
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(b"ona/leaf/v3");
    h.update(tag);
    h.update(commitment);
    let expected: Hash = h.finalize().into();
    assert_eq!(leaf_hash(&tag, &commitment), expected);
    let cp = Checkpoint::first(&KEY, head);
    assert_eq!(cp.leaf(), leaf_hash(&cp.tag(), &cp.commitment()), "the tag is inside the leaf");
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
fn checkpoints_chain_and_do_not_link_without_the_key() {
    let head = [9u8; 32];
    let first = Checkpoint::first(&KEY, head);
    let second = first.next(&KEY, head);
    assert_eq!((first.rank, second.rank), (0, 1));
    assert_eq!(second.prev, first.leaf(), "each checkpoint commits to the one before");
    assert_ne!(first.leaf(), second.leaf(), "same head, different leaves");
    assert_ne!(first.tag(), second.tag());
    assert_ne!(Checkpoint::first(&[6u8; 32], head).leaf(), first.leaf(), "another mission's key");
    assert_eq!(Checkpoint::first(&KEY, head), first, "rebuilt from the key, nothing to store");
    assert_eq!(format!("{first:?}"), "Checkpoint { rank: 0, .. }", "Debug prints no secret");
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

#[test]
fn an_anchored_proof_carries_its_seq() {
    let tree = FixedTree::new(leaves(6)).unwrap();
    let anchored = AnchoredProof { seq: 41, proof: tree.proof(9).unwrap() };
    let bytes = anchored.to_bytes();
    assert_eq!(bytes.len(), ANCHORED_PROOF_LEN);
    assert_eq!(AnchoredProof::from_bytes(&bytes).unwrap(), anchored);
    assert!(AnchoredProof::from_bytes(&bytes[1..]).is_err());
}

// ---------- padded batches ----------

#[test]
fn a_padded_batch_proves_its_real_leaves_and_nothing_else() {
    let real: Vec<Hash> = (0..5u8).map(some_leaf).collect();
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
    let leaf = some_leaf(1);
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

// ---------- checkpoint chain ----------

const HOUR: u64 = 3_600_000_000_000;

/// The registry as the auditor reads it: seq -> (root, timestamp), one anchor per hour.
#[derive(Default)]
struct Chain(Vec<(Hash, u64)>);

impl Chain {
    fn anchor(&mut self, leaves: &[Hash], hours_later: u64) -> (u64, PaddedBatch) {
        let batch = PaddedBatch::build(leaves).unwrap();
        let time = self.0.last().map_or(0, |(_, t)| t + hours_later * HOUR);
        self.0.push((batch.root(), time));
        (self.0.len() as u64 - 1, batch)
    }
}

impl AnchorReader for Chain {
    fn anchored_root(&self, seq: u64) -> Result<Option<(Hash, u64)>, String> {
        Ok(self.0.get(seq as usize).copied())
    }
}

/// The successive heads of a journal of `n` entries (chain start first).
fn heads(n: u8) -> Vec<Hash> {
    (0..=n).map(|i| [100 + i; 32]).collect()
}

/// Checkpoints at the journal states `at`, each in its own anchor, `hours` apart.
fn anchored(chain: &mut Chain, key: &[u8; 32], heads: &[Hash], at: &[usize], hours: u64) -> Vec<PresentedCheckpoint> {
    let mut out = Vec::new();
    let mut last: Option<Checkpoint> = None;
    for &i in at {
        let cp = match &last {
            None => Checkpoint::first(key, heads[i]),
            Some(prev) => prev.next(key, heads[i]),
        };
        let (seq, batch) = chain.anchor(&[cp.leaf(), some_leaf(i as u8)], hours);
        let proof = AnchoredProof { seq, proof: batch.proof_for(&cp.leaf()).unwrap() };
        out.push(PresentedCheckpoint { rank: cp.rank, head: cp.head, proof });
        last = Some(cp);
    }
    out
}

/// The test chain's first anchor is at time 0: the mission was opened in the first hour.
fn trust(opening_tag: Option<Hash>, max_gap_ns: u64) -> AuditTrust {
    AuditTrust { opening_tag, not_before_ns: 0, not_after_ns: HOUR, max_gap_ns }
}

fn check(heads: &[Hash], presented: &[PresentedCheckpoint], chain: &Chain) -> Result<CheckpointAudit, String> {
    verify_checkpoints(&KEY, &trust(None, 2 * HOUR), heads, presented, chain)
}

#[test]
fn a_complete_chain_of_checkpoints_verifies() {
    let mut chain = Chain::default();
    let heads = heads(5);
    let presented = anchored(&mut chain, &KEY, &heads, &[1, 3, 3, 5], 1);
    let tag = checkpoint_tag(&KEY, 0);
    let audit = verify_checkpoints(&KEY, &trust(Some(tag), 2 * HOUR), &heads, &presented, &chain).unwrap();
    assert_eq!(audit.checkpoints, 4);
    assert_eq!((audit.first_anchor_ns, audit.last_anchor_ns), (0, 3 * HOUR));
}

/// Rollback: the journal cut at an older checkpoint. Showing every checkpoint the
/// auditor knows of refuses it; hiding the later ones is a gap in time that `max_gap_ns` bounds, and a cut
/// journal does not end with `mission_close` (`journal::audit`).
#[test]
fn a_rollback_to_an_older_state_is_refused() {
    let mut chain = Chain::default();
    let heads = heads(5);
    let presented = anchored(&mut chain, &KEY, &heads, &[1, 3, 5], 1);
    let err = check(&heads[..4], &presented, &chain).unwrap_err();
    assert!(err.contains("not a later state"), "{err}");
    assert!(check(&heads, &presented[..2], &chain).unwrap_err().contains("final head"));
}

/// A missing or repeated rank, a link to the wrong predecessor, or a head that goes back is refused.
#[test]
fn gaps_duplicates_and_reordering_are_refused() {
    let mut chain = Chain::default();
    let heads = heads(5);
    let presented = anchored(&mut chain, &KEY, &heads, &[1, 2, 4, 5], 1);
    assert!(check(&heads, &presented, &chain).is_ok(), "the positive case must hold first");

    let gap: Vec<_> = presented.iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, p)| p.clone()).collect();
    assert!(check(&heads, &gap, &chain).unwrap_err().contains("out of order"), "rank 1 missing");
    let mut duplicate = presented.clone();
    duplicate.insert(2, presented[1].clone());
    assert!(check(&heads, &duplicate, &chain).is_err(), "rank 1 twice");
    let mut swapped = presented.clone();
    swapped.swap(1, 2);
    assert!(check(&heads, &swapped, &chain).is_err());
    let mut relabelled = presented.clone();
    relabelled[2].rank = 1;
    relabelled.remove(1);
    assert!(check(&heads, &relabelled, &chain).is_err(), "rank 2 shown as rank 1");
    assert!(check(&heads, &[], &chain).is_err(), "nothing presented");
}

/// Fork: a parallel history. Built with the same key, it needs a second leaf for a rank whose tag the
/// aggregator already saw (tested in `ona-anchor`). Built with another key from rank 0, it passes alone, and
/// only the opening tag recorded elsewhere refuses it.
#[test]
fn a_parallel_history_is_refused_by_the_opening_tag() {
    let mut chain = Chain::default();
    let heads = heads(3);
    let opening = Checkpoint::first(&KEY, heads[1]).tag();
    let other_key = [8u8; 32];
    let forged = anchored(&mut chain, &other_key, &heads, &[1, 3], 1);
    assert!(verify_checkpoints(&other_key, &trust(None, 2 * HOUR), &heads, &forged, &chain).is_ok(), "without the tag");
    let err = verify_checkpoints(&other_key, &trust(Some(opening), 2 * HOUR), &heads, &forged, &chain).unwrap_err();
    assert!(err.contains("expected mission"), "{err}");
}

/// Fork with the same key past the aggregator: the real leaf goes with the real tag, the parallel one with
/// a made-up tag so the aggregator does not refuse it. Both are anchored; only the real one passes, because
/// the leaf is rebuilt with the tag the key gives for that rank.
#[test]
fn a_parallel_leaf_sent_with_a_made_up_tag_does_not_pass() {
    let mut chain = Chain::default();
    let heads = heads(3);
    let honest = Checkpoint::first(&KEY, heads[1]);
    let forged = Checkpoint::first(&KEY, heads[3]);
    let made_up_tag = [0x5au8; 32];
    let forged_leaf = leaf_hash(&made_up_tag, &forged.commitment());
    let (seq, batch) = chain.anchor(&[honest.leaf(), forged_leaf], 1);
    let proof = |leaf: &Hash| AnchoredProof { seq, proof: batch.proof_for(leaf).unwrap() };
    let shown_forged = PresentedCheckpoint { rank: 0, head: heads[3], proof: proof(&forged_leaf) };
    let err = check(&heads, &[shown_forged], &chain).unwrap_err();
    assert!(err.contains("not in anchor"), "{err}");
    let shown_honest = PresentedCheckpoint { rank: 0, head: heads[1], proof: proof(&honest.leaf()) };
    assert!(check(&heads[..2], &[shown_honest], &chain).is_ok());
}

/// The leaf is recomputed and the root is the one the registry holds, not one the agent supplies.
#[test]
fn the_root_comes_from_the_chain_and_the_leaf_is_recomputed() {
    let mut chain = Chain::default();
    let heads = heads(3);
    let presented = anchored(&mut chain, &KEY, &heads, &[1, 3], 1);
    let mut wrong_seq = presented.clone();
    wrong_seq[1].proof.seq = 0;
    assert!(check(&heads, &wrong_seq, &chain).is_err());
    let mut missing = presented.clone();
    missing[1].proof.seq = 99;
    assert!(check(&heads, &missing, &chain).unwrap_err().contains("no anchor"));
    let mut other_head = presented.clone();
    other_head[1].head = heads[2];
    assert!(check(&heads, &other_head, &chain).is_err());
    assert!(verify_checkpoints(&[1u8; 32], &trust(None, 2 * HOUR), &heads, &presented, &chain).is_err(), "wrong key");
}

#[test]
fn checkpoints_held_back_too_long_are_refused() {
    let mut chain = Chain::default();
    let heads = heads(4);
    let presented = anchored(&mut chain, &KEY, &heads, &[1, 4], 3);
    assert!(verify_checkpoints(&KEY, &trust(None, 3 * HOUR), &heads, &presented, &chain).is_ok());
    let err = verify_checkpoints(&KEY, &trust(None, 3 * HOUR - 1), &heads, &presented, &chain).unwrap_err();
    assert!(err.contains("too long"), "{err}");
}

/// The same chain re-anchored from rank 0 once the aggregator has forgotten its tags: its opening falls
/// outside the window the auditor knows, and windows as long as the retention are refused.
#[test]
fn a_chain_made_again_after_the_tags_expired_is_refused() {
    let mut chain = Chain::default();
    let heads = heads(3);
    let honest = anchored(&mut chain, &KEY, &heads, &[1, 3], 1);
    // Eight days later the tags are forgotten; the same key and opening tag give a second chain.
    chain.anchor(&[some_leaf(9)], 8 * 24);
    let forged_heads: Vec<Hash> = vec![heads[0], heads[1], [55u8; 32]];
    let forged = anchored(&mut chain, &KEY, &forged_heads, &[1, 2], 1);
    let opening = checkpoint_tag(&KEY, 0);
    let err = verify_checkpoints(&KEY, &trust(Some(opening), 2 * HOUR), &forged_heads, &forged, &chain).unwrap_err();
    assert!(err.contains("when the mission was opened"), "{err}");

    let too_wide = AuditTrust { opening_tag: Some(opening), not_before_ns: 0, not_after_ns: TAG_RETENTION_NS, max_gap_ns: HOUR };
    let err = verify_checkpoints(&KEY, &too_wide, &forged_heads, &forged, &chain).unwrap_err();
    assert!(err.contains("opening window"), "{err}");
    let too_long = AuditTrust { opening_tag: None, not_before_ns: 0, not_after_ns: HOUR, max_gap_ns: TAG_RETENTION_NS };
    assert!(verify_checkpoints(&KEY, &too_long, &heads, &honest, &chain).unwrap_err().contains("maximum gap"));
}

// ---------- auditor key ----------

const START: [u8; 32] = [11u8; 32];

fn sealed_for(public: &[u8; 32], master: &mut [u8; 32]) -> Vec<u8> {
    seal_master_key(master, public, &auditor_fingerprint(public), &START).unwrap()
}

#[test]
fn the_auditor_opens_the_master_key_and_the_agent_forgets_it() {
    let (secret, public) = auditor_keypair();
    let original = [42u8; 32];
    let mut master = original;
    let sealed = sealed_for(&public, &mut master);
    assert_eq!(master, [0u8; 32], "wiped from the agent's buffer");
    assert_eq!(sealed.len(), SEALED_LEN);
    assert_eq!(*open_master_key(&secret, &sealed, &START).unwrap(), original);
    assert!(open_master_key(&secret, &sealed, &[12u8; 32]).is_err(), "bound to its journal");
}

/// A key swapped in transit is refused before anything is sealed or wiped.
#[test]
fn a_swapped_auditor_key_is_refused_and_the_master_key_kept() {
    let (_, real) = auditor_keypair();
    let (_, attacker) = auditor_keypair();
    let mut master = [9u8; 32];
    let err = seal_master_key(&mut master, &attacker, &auditor_fingerprint(&real), &START).unwrap_err();
    assert!(err.contains("not the expected auditor key"));
    assert_eq!(master, [9u8; 32], "nothing lost");
}

#[test]
fn another_key_cannot_open_it() {
    let (_, public) = auditor_keypair();
    let (other, _) = auditor_keypair();
    let sealed = sealed_for(&public, &mut [1u8; 32]);
    assert!(open_master_key(&other, &sealed, &START).is_err());
}

#[test]
fn every_altered_byte_is_detected() {
    let (secret, public) = auditor_keypair();
    let sealed = sealed_for(&public, &mut [5u8; 32]);
    for i in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 1;
        assert!(open_master_key(&secret, &bad, &START).is_err(), "byte {i}");
    }
    assert!(open_master_key(&secret, &sealed[..SEALED_LEN - 1], &START).is_err());
}

#[test]
fn each_seal_uses_a_new_ephemeral_key() {
    let (_, public) = auditor_keypair();
    let one = sealed_for(&public, &mut [6u8; 32]);
    let two = sealed_for(&public, &mut [6u8; 32]);
    assert_ne!(one[1..33], two[1..33]);
    assert_ne!(one, two);
}

#[test]
fn an_invalid_auditor_key_is_refused_and_the_master_key_kept() {
    let mut master = [7u8; 32];
    let low = [0u8; 32];
    assert!(seal_master_key(&mut master, &low, &auditor_fingerprint(&low), &START).is_err(), "a low-order key");
    assert_eq!(master, [7u8; 32], "a failed seal does not lose the journal");
}
