//! The aggregator against a fake registry. Nothing here touches a network.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_anchor::*;
use ona_core::checkpoint::{verify_inclusion, Checkpoint, Hash, CAPACITY, PROOF_LEN};
use serde_json::json;

#[derive(Default)]
struct FakeRegistry {
    anchors: Vec<(Hash, u32)>,
    refuse: bool,
}

impl AnchorChain for FakeRegistry {
    fn anchor(&mut self, root: &Hash, count: u32) -> Result<u64, String> {
        if self.refuse {
            return Err("rpc error".into());
        }
        self.anchors.push((*root, count));
        Ok(self.anchors.len() as u64 - 1)
    }
}

fn leaf(i: u8) -> Hash {
    Checkpoint::new([i; 32]).leaf()
}

#[test]
fn every_sender_gets_a_proof_against_the_anchored_root() {
    let mut aggregator = Aggregator::new();
    let leaves: Vec<Hash> = (0..7).map(leaf).collect();
    for l in &leaves {
        aggregator.submit(*l).unwrap();
    }
    let mut chain = FakeRegistry::default();
    let batch = aggregator.flush(&mut chain, 0).unwrap();
    assert_eq!(batch.seq, 0);
    assert_eq!(chain.anchors[0].0, batch.root, "the proofs refer to what went on chain");
    assert_eq!(batch.proofs.len(), 7);
    for l in &leaves {
        let proof = &batch.proofs[l];
        assert_eq!(proof.to_bytes().len(), PROOF_LEN);
        assert!(verify_inclusion(l, proof, &chain.anchors[0].0));
    }
}

#[test]
fn the_published_count_never_reveals_the_batch_size() {
    let mut chain = FakeRegistry::default();
    for n in [0u8, 1, 30] {
        let mut aggregator = Aggregator::new();
        for i in 0..n {
            aggregator.submit(leaf(i)).unwrap();
        }
        aggregator.flush(&mut chain, 0).unwrap();
    }
    assert!(chain.anchors.iter().all(|(_, count)| *count == CAPACITY as u32));
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
fn nothing_is_kept_once_a_batch_is_anchored() {
    let mut aggregator = Aggregator::new();
    aggregator.submit(leaf(1)).unwrap();
    let mut chain = FakeRegistry::default();
    aggregator.flush(&mut chain, 0).unwrap();
    assert_eq!(aggregator.pending(), 0);
    let next = aggregator.flush(&mut chain, 3600).unwrap();
    assert!(next.proofs.is_empty(), "an old leaf is not anchored again");
}

#[test]
fn a_refused_anchor_keeps_the_leaves_for_the_next_attempt() {
    let mut aggregator = Aggregator::new();
    let l = leaf(2);
    aggregator.submit(l).unwrap();
    let mut chain = FakeRegistry { refuse: true, ..Default::default() };
    assert!(aggregator.flush(&mut chain, 0).is_err());
    assert_eq!(aggregator.pending(), 1);
    assert!(aggregator.is_due(1), "a failed anchor is retried");
    chain.refuse = false;
    let batch = aggregator.flush(&mut chain, 1).unwrap();
    assert!(verify_inclusion(&l, &batch.proofs[&l], &batch.root));
}

#[test]
fn anchors_are_hourly() {
    let mut aggregator = Aggregator::new();
    assert!(aggregator.is_due(0));
    aggregator.flush(&mut FakeRegistry::default(), 1000).unwrap();
    assert!(!aggregator.is_due(1000 + ANCHOR_INTERVAL_SECS - 1));
    assert!(aggregator.is_due(1000 + ANCHOR_INTERVAL_SECS));
}

#[test]
fn duplicates_and_overflow_are_refused() {
    let mut aggregator = Aggregator::new();
    aggregator.submit([0u8; 32]).unwrap();
    assert_eq!(aggregator.submit([0u8; 32]).unwrap_err(), "leaf already submitted");
    for i in 1..CAPACITY {
        let mut l = [0u8; 32];
        l[..8].copy_from_slice(&(i as u64).to_le_bytes());
        aggregator.submit(l).unwrap();
    }
    assert!(aggregator.submit([0xff; 32]).unwrap_err().contains("full"));
    let batch = aggregator.flush(&mut FakeRegistry::default(), 0).unwrap();
    assert_eq!(batch.proofs.len(), CAPACITY);
}

#[test]
fn the_registry_arguments_and_reply_are_encoded_as_near_expects() {
    let root = [3u8; 32];
    let args = anchor_args(&root, 1024);
    assert_eq!(args["count"], 1024);
    assert_eq!(B64.decode(args["root"].as_str().unwrap()).unwrap(), root.to_vec());
    assert_eq!(parse_seq(&json!("17")).unwrap(), 17);
    assert!(parse_seq(&json!(17)).is_err(), "U64 is always a string");
    assert!(parse_seq(&json!(null)).is_err());
}
