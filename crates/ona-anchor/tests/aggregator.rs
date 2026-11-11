//! The aggregator against a fake registry. Nothing here touches a network.

use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_anchor::*;
use ona_core::checkpoint::{leaf_hash, verify_inclusion, Checkpoint, Hash, ANCHORED_PROOF_LEN, CAPACITY};
use serde_json::json;

#[derive(Default)]
struct FakeRegistry {
    anchors: Vec<Hash>,
    /// The call fails before anything is recorded.
    refuse: bool,
    /// The call is recorded but the reply is lost.
    lose_reply: bool,
    /// A lying node: the reply claims success, the chain holds something else.
    lie: bool,
    /// Reads fail too.
    unreadable: bool,
}

impl AnchorChain for FakeRegistry {
    fn anchor(&mut self, root: &Hash) -> Result<u64, String> {
        if self.refuse {
            return Err("rpc error".into());
        }
        if self.lie {
            return Ok(7);
        }
        self.anchors.push(*root);
        if self.lose_reply {
            return Err("timeout".into());
        }
        Ok(self.anchors.len() as u64 - 1)
    }

    fn read_anchor(&mut self, seq: u64) -> Result<Option<Hash>, String> {
        Ok(self.anchors.get(seq as usize).copied())
    }

    fn latest_anchor(&mut self) -> Result<Option<(u64, Hash)>, String> {
        if self.unreadable {
            return Err("node unreachable".into());
        }
        Ok(self.anchors.last().map(|root| (self.anchors.len() as u64 - 1, *root)))
    }
}

const CLIENT: Hash = [1u8; 32];

/// A checkpoint of rank 0 of mission `i`.
fn checkpoint(i: u8) -> Checkpoint {
    Checkpoint::first(&[i; 32], [i; 32])
}

fn submit(aggregator: &mut Aggregator, client: u8, i: u8) -> Result<Hash, &'static str> {
    let cp = checkpoint(i);
    aggregator.submit([client; 32], cp.tag(), cp.commitment())
}

struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("ona-anchor-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn every_sender_gets_a_proof_against_the_anchored_root() {
    let mut aggregator = Aggregator::new();
    let checkpoints: Vec<Checkpoint> = (0..7).map(checkpoint).collect();
    for (i, cp) in checkpoints.iter().enumerate() {
        let leaf = aggregator.submit([i as u8; 32], cp.tag(), cp.commitment()).unwrap();
        assert_eq!(leaf, cp.leaf(), "the aggregator builds the same leaf as the agent");
    }
    let mut chain = FakeRegistry::default();
    let batch = aggregator.flush(&mut chain, 0).unwrap();
    assert_eq!(batch.seq, 0);
    assert_eq!(chain.anchors[0], batch.root, "the proofs refer to what went on chain");
    assert_eq!(batch.proofs.len(), 7);
    for cp in &checkpoints {
        let proof = &batch.proofs[&cp.leaf()];
        assert_eq!(proof.seq, 0, "the proof names its anchor");
        assert_eq!(proof.to_bytes().len(), ANCHORED_PROOF_LEN);
        assert!(verify_inclusion(&cp.leaf(), &proof.proof, &chain.anchors[0]));
    }
}

/// A node that lies about the anchor gets no proofs handed out, and the leaves stay.
#[test]
fn proofs_are_withheld_when_the_chain_does_not_hold_the_root() {
    let mut aggregator = Aggregator::new();
    submit(&mut aggregator, 1, 1).unwrap();
    let mut chain = FakeRegistry { lie: true, ..Default::default() };
    let err = aggregator.flush(&mut chain, 0).err().unwrap();
    assert!(err.contains("proofs withheld"), "{err}");
    assert_eq!(aggregator.pending(), 1);
}

#[test]
fn a_lost_reply_is_recovered_from_the_chain() {
    let mut aggregator = Aggregator::new();
    let cp = checkpoint(3);
    aggregator.submit(CLIENT, cp.tag(), cp.commitment()).unwrap();
    let mut chain = FakeRegistry { lose_reply: true, ..Default::default() };
    let batch = aggregator.flush(&mut chain, 0).unwrap();
    assert_eq!(chain.anchors.len(), 1, "anchored once");
    assert!(verify_inclusion(&cp.leaf(), &batch.proofs[&cp.leaf()].proof, &chain.anchors[0]));
}

#[test]
fn the_original_error_is_kept_when_the_chain_cannot_be_read_either() {
    let mut aggregator = Aggregator::new();
    submit(&mut aggregator, 1, 1).unwrap();
    let mut chain = FakeRegistry { refuse: true, unreadable: true, ..Default::default() };
    let err = aggregator.flush(&mut chain, 0).err().unwrap();
    assert!(err.contains("rpc error") && err.contains("node unreachable"), "{err}");
    assert_eq!(aggregator.pending(), 1);
}

#[test]
fn an_empty_hour_is_anchored_too() {
    let mut aggregator = Aggregator::new();
    let mut chain = FakeRegistry::default();
    let batch = aggregator.flush(&mut chain, 0).unwrap();
    assert!(batch.proofs.is_empty());
    assert_eq!(chain.anchors.len(), 1);
}

#[test]
fn nothing_but_tags_is_kept_once_a_batch_is_anchored() {
    let mut aggregator = Aggregator::new();
    submit(&mut aggregator, 1, 1).unwrap();
    let mut chain = FakeRegistry::default();
    aggregator.flush(&mut chain, 0).unwrap();
    assert_eq!(aggregator.pending(), 0);
    assert_eq!(aggregator.seen_tags(), 1);
    let next = aggregator.flush(&mut chain, 3600).unwrap();
    assert!(next.proofs.is_empty(), "an old leaf is not anchored again");
}

#[test]
fn a_refused_anchor_keeps_the_leaves_for_the_next_attempt() {
    let mut aggregator = Aggregator::new();
    let cp = checkpoint(2);
    aggregator.submit(CLIENT, cp.tag(), cp.commitment()).unwrap();
    let mut chain = FakeRegistry { refuse: true, ..Default::default() };
    assert!(aggregator.flush(&mut chain, 0).is_err());
    assert_eq!(aggregator.pending(), 1);
    assert!(aggregator.is_due(1), "a failed anchor is retried");
    chain.refuse = false;
    let batch = aggregator.flush(&mut chain, 1).unwrap();
    assert!(verify_inclusion(&cp.leaf(), &batch.proofs[&cp.leaf()].proof, &batch.root));
}

#[test]
fn anchors_are_hourly_and_a_clock_that_went_back_does_not_stop_them() {
    let mut aggregator = Aggregator::new();
    assert!(aggregator.is_due(0));
    aggregator.flush(&mut FakeRegistry::default(), 1000).unwrap();
    assert!(!aggregator.is_due(1000 + ANCHOR_INTERVAL_SECS - 1));
    assert!(aggregator.is_due(1000 + ANCHOR_INTERVAL_SECS));
    assert!(aggregator.is_due(999), "a clock set back");
}

/// One checkpoint per rank and per mission: a second leaf with the same tag is refused, in the same batch
/// or a later one.
#[test]
fn a_second_checkpoint_for_the_same_rank_is_refused() {
    let mut aggregator = Aggregator::new();
    let key = [4u8; 32];
    let honest = Checkpoint::first(&key, [1u8; 32]);
    let forged = Checkpoint::first(&key, [2u8; 32]);
    assert_eq!(honest.tag(), forged.tag());
    aggregator.submit(CLIENT, honest.tag(), honest.commitment()).unwrap();
    assert!(aggregator.submit([2u8; 32], forged.tag(), forged.commitment()).unwrap_err().contains("this rank"));
    aggregator.flush(&mut FakeRegistry::default(), 0).unwrap();
    assert!(aggregator.submit([3u8; 32], forged.tag(), forged.commitment()).unwrap_err().contains("this rank"));
    let next = honest.next(&key, [1u8; 32]);
    aggregator.submit(CLIENT, next.tag(), next.commitment()).unwrap();
}

/// A parallel leaf sent with another tag is anchored, but it is not the leaf the key gives for that rank:
/// the leaf is built from the tag, so the auditor's check refuses it (tested in `ona-core`).
#[test]
fn a_leaf_sent_with_another_tag_is_another_leaf() {
    let mut aggregator = Aggregator::new();
    let key = [4u8; 32];
    let forged = Checkpoint::first(&key, [2u8; 32]);
    let random_tag = [0x5au8; 32];
    let anchored = aggregator.submit(CLIENT, random_tag, forged.commitment()).unwrap();
    assert_eq!(anchored, leaf_hash(&random_tag, &forged.commitment()));
    assert_ne!(anchored, forged.leaf());
}

/// Tags survive a restart through their file, and expire after the retention.
#[test]
fn seen_tags_survive_a_restart_and_expire() {
    let file = TempFile::new("tags");
    let mut aggregator = Aggregator::with_tag_file(&file.0, 0).unwrap();
    submit(&mut aggregator, 1, 1).unwrap();
    aggregator.flush(&mut FakeRegistry::default(), 100).unwrap();
    drop(aggregator);

    let mut restarted = Aggregator::with_tag_file(&file.0, 200).unwrap();
    assert_eq!(restarted.seen_tags(), 1);
    assert!(submit(&mut restarted, 2, 1).unwrap_err().contains("this rank"), "not forgotten by the restart");
    drop(restarted);

    let mut later = Aggregator::with_tag_file(&file.0, 100 + TAG_RETENTION_SECS).unwrap();
    assert_eq!(later.seen_tags(), 0, "expired");
    submit(&mut later, 2, 1).unwrap();
    assert_eq!(fs::read_to_string(&file.0).unwrap(), "", "the file was rewritten without expired tags");

    fs::write(&file.0, "not a tag\n").unwrap();
    assert!(Aggregator::with_tag_file(&file.0, 0).err().unwrap().contains("corrupt"));
}

/// When the tags kept reach the limit, new leaves are refused rather than old tags forgotten early; they are
/// accepted again once tags expire.
#[test]
fn new_leaves_are_refused_when_the_tag_limit_is_reached() {
    assert_eq!(MAX_SEEN_TAGS, CAPACITY * 24 * 7);
    let mut aggregator = Aggregator::new().limit_seen_tags(3);
    submit(&mut aggregator, 1, 1).unwrap();
    submit(&mut aggregator, 2, 2).unwrap();
    aggregator.flush(&mut FakeRegistry::default(), 0).unwrap();
    submit(&mut aggregator, 3, 3).unwrap();
    assert!(submit(&mut aggregator, 4, 4).unwrap_err().contains("too many tags"), "two kept, one pending");
    aggregator.flush(&mut FakeRegistry::default(), TAG_RETENTION_SECS).unwrap();
    assert_eq!(aggregator.seen_tags(), 1, "the first two expired");
    submit(&mut aggregator, 4, 4).unwrap();
}

/// One sender cannot fill the hour's batch (as long as senders cannot multiply their identifiers).
#[test]
fn each_sender_is_limited_per_batch() {
    let mut aggregator = Aggregator::new();
    for i in 0..MAX_LEAVES_PER_CLIENT as u8 {
        submit(&mut aggregator, 9, i).unwrap();
    }
    assert!(submit(&mut aggregator, 9, 200).unwrap_err().contains("too many"));
    submit(&mut aggregator, 8, 200).unwrap();
    aggregator.flush(&mut FakeRegistry::default(), 0).unwrap();
    submit(&mut aggregator, 9, 201).unwrap();
}

#[test]
fn duplicates_and_overflow_are_refused() {
    let mut aggregator = Aggregator::new();
    let cp = checkpoint(0);
    aggregator.submit(CLIENT, cp.tag(), cp.commitment()).unwrap();
    assert_eq!(aggregator.submit([2u8; 32], cp.tag(), cp.commitment()).unwrap_err(), "leaf already submitted");
    for i in 1..CAPACITY {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let cp = Checkpoint::first(&id, id);
        aggregator.submit(id, cp.tag(), cp.commitment()).unwrap();
    }
    let extra = checkpoint(0xff);
    assert!(aggregator.submit([0xff; 32], extra.tag(), extra.commitment()).unwrap_err().contains("full"));
    let batch = aggregator.flush(&mut FakeRegistry::default(), 0).unwrap();
    assert_eq!(batch.proofs.len(), CAPACITY);
}

#[test]
fn the_registry_arguments_and_replies_are_encoded_as_near_expects() {
    let root = [3u8; 32];
    let args = anchor_args(&root);
    assert_eq!(args.as_object().unwrap().len(), 1, "no count any more");
    assert_eq!(B64.decode(args["root"].as_str().unwrap()).unwrap(), root.to_vec());
    assert_eq!(parse_seq(&json!("17")).unwrap(), 17);
    assert!(parse_seq(&json!(17)).is_err(), "U64 is always a string");
    assert!(parse_seq(&json!(null)).is_err());

    let anchor = json!({"seq": "4", "root": B64.encode(root), "timestamp": "1700000000000000000"});
    assert_eq!(parse_anchor(&anchor).unwrap(), Some((4, root, 1_700_000_000_000_000_000)));
    assert_eq!(parse_anchor(&json!(null)).unwrap(), None);
    assert!(parse_anchor(&json!({"seq": "4", "root": B64.encode([1u8; 31]), "timestamp": "1"})).is_err());
    assert!(parse_anchor(&json!({"seq": 4, "root": B64.encode(root), "timestamp": "1"})).is_err());
}
