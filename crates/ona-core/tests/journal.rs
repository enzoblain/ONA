//! The journal's keys, sealing and audit.

use ona_core::checkpoint::{AnchorReader, AnchoredProof, AuditTrust, Checkpoint, Hash, PaddedBatch, PresentedCheckpoint};
use ona_core::journal::*;
use serde_json::json;
use sha2::{Digest, Sha256};

const SALT: [u8; 32] = [7; 32];
const MASTER: [u8; 32] = [9; 32];

/// Checking the chain needs the chain start only, which does not give the salt back, and fingerprints
/// cannot be recomputed from what a verifier holds.
#[test]
fn whoever_checks_the_chain_cannot_test_guessed_contents() {
    let mut j = Journal::new(SALT);
    let fp = j.fingerprint(b"divorce lawyer Lyon");
    j.append(Kind::ToolCommit, json!({"tool": "search", "query": fp}));
    let start = j.start();
    let bytes = j.to_bytes();
    assert_eq!(verify_from(&start, &bytes, &j.head()), Ok(1), "no salt needed to verify");
    assert_ne!(start, SALT);

    let text = String::from_utf8(bytes).unwrap();
    let dictionary = ["tax lawyer Paris", "divorce lawyer Lyon", "criminal lawyer Lille"];
    let old_formula = |guess: &str, secret: &[u8; 32]| -> String {
        let d: [u8; 32] = Sha256::new().chain_update(b"ona/j/fp").chain_update(secret).chain_update(guess).finalize().into();
        d.iter().map(|b| format!("{b:02x}")).collect()
    };
    for guess in dictionary {
        assert!(!text.contains(&old_formula(guess, &start)), "{guess} found from the chain start");
        assert!(!text.contains(&Journal::new(start).fingerprint(guess.as_bytes())), "{guess} found");
        assert!(!text.contains(&old_formula(guess, &SALT)), "the fingerprint is no longer a plain salted hash");
    }
    assert_eq!(j.fingerprint(b"divorce lawyer Lyon"), fp, "the agent can still prove a content");
}

/// An entry key works in its own journal only.
#[test]
fn an_entry_key_opens_nothing_in_another_journal() {
    let mut a = Journal::new([1; 32]);
    a.append(Kind::MissionOpen, json!({"m": "A"}));
    let mut b = Journal::new([2; 32]);
    b.append(Kind::MissionOpen, json!({"m": "secret of B"}));
    let disclosed_for_a = entry_key(&MASTER, &a.start(), 0);
    let start_b = b.start();
    let sealed_b = String::from_utf8(b.seal(&MASTER).unwrap().bytes).unwrap();
    let line = sealed_b.lines().next().unwrap();
    assert!(open_entry(&disclosed_for_a, line).is_err());
    assert!(open_entry(&entry_key(&MASTER, &start_b, 0), line).unwrap().contains("secret of B"));
}

/// The receiver of an entry key can check it is the one the entry was sealed with.
#[test]
fn a_sealed_line_commits_to_its_key() {
    let mut j = Journal::new(SALT);
    j.append(Kind::MissionOpen, json!({"m": 1}));
    let start = j.start();
    let sealed = String::from_utf8(j.seal(&MASTER).unwrap().bytes).unwrap();
    let err = open_entry(&[3u8; 32], sealed.lines().next().unwrap()).unwrap_err();
    assert!(err.contains("not the one"), "{err}");
    assert!(open_entry(&entry_key(&MASTER, &start, 0), sealed.lines().next().unwrap()).is_ok());
}

/// Nothing is decrypted from a sealed journal whose chain does not reach the expected head.
#[test]
fn open_all_checks_the_chain_before_decrypting() {
    let mut j = Journal::new(SALT);
    for i in 0..3 {
        j.append(Kind::ToolCommit, json!({"n": i}));
    }
    let start = j.start();
    let sealed = j.seal(&MASTER).unwrap();
    let text = String::from_utf8(sealed.bytes.clone()).unwrap();
    let cut: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
    let err = open_all(&MASTER, &start, cut.as_bytes(), &sealed.head).unwrap_err();
    assert!(err.contains("final head differs"), "{err}");
    assert_eq!(open_all(&MASTER, &start, &sealed.bytes, &sealed.head).unwrap().len(), 3);
}

/// A disclosed entry does not carry the chain head before it; the auditor still rebuilds the exact
/// plaintext lines and their chain.
#[test]
fn a_disclosed_entry_holds_no_chain_head() {
    let mut j = Journal::new(SALT);
    j.append(Kind::MissionOpen, json!({"m": 1}));
    j.append(Kind::MissionClose, json!({"steps_done": 1}));
    let plain = String::from_utf8(j.to_bytes()).unwrap();
    let (start, head) = (j.start(), j.head());
    let sealed = j.seal(&MASTER).unwrap();
    let line = String::from_utf8(sealed.bytes.clone()).unwrap().lines().nth(1).unwrap().to_string();
    let disclosed = open_entry(&entry_key(&MASTER, &start, 1), &line).unwrap();
    assert!(disclosed.contains("\"prev\":\"\""), "{disclosed}");
    assert!(disclosed.contains("mission_close"));

    let rebuilt = open_all(&MASTER, &start, &sealed.bytes, &sealed.head).unwrap();
    assert_eq!(rebuilt, plain.lines().collect::<Vec<_>>());
    let bytes: Vec<u8> = rebuilt.iter().flat_map(|l| format!("{l}\n").into_bytes()).collect();
    assert_eq!(verify_from(&start, &bytes, &head), Ok(2));
}

#[test]
fn the_sealed_form_is_versioned() {
    let mut j = Journal::new(SALT);
    j.append(Kind::MissionOpen, json!({}));
    let start = j.start();
    let sealed = String::from_utf8(j.seal(&MASTER).unwrap().bytes).unwrap();
    let old = sealed.lines().next().unwrap().replacen("\"v\":2", "\"v\":1", 1);
    assert!(open_entry(&entry_key(&MASTER, &start, 0), &old).unwrap_err().contains("unknown sealed format"));
}

// ---------- the auditor's full check ----------

struct OneAnchorPerHour(Vec<Hash>);

impl AnchorReader for OneAnchorPerHour {
    fn anchored_root(&self, seq: u64) -> Result<Option<(Hash, u64)>, String> {
        Ok(self.0.get(seq as usize).map(|root| (*root, seq * 3_600_000_000_000)))
    }
}

/// From the agent's journal to the auditor's verdict: seal, open, check the chain, the checkpoints and the
/// closing entry.
#[test]
fn an_auditor_checks_a_whole_mission() {
    let mut j = Journal::new(SALT);
    let key = j.checkpoint_key();
    let mut roots = Vec::new();
    let mut presented = Vec::new();
    let mut last: Option<Checkpoint> = None;
    let mut checkpoint = |j: &Journal, roots: &mut Vec<Hash>, presented: &mut Vec<PresentedCheckpoint>| {
        let cp = match &last {
            None => Checkpoint::first(&key, j.head()),
            Some(prev) => prev.next(&key, j.head()),
        };
        let batch = PaddedBatch::build(&[cp.leaf()]).unwrap();
        roots.push(batch.root());
        let proof = AnchoredProof { seq: roots.len() as u64 - 1, proof: batch.proof_for(&cp.leaf()).unwrap() };
        presented.push(PresentedCheckpoint { rank: cp.rank, head: cp.head, proof });
        last = Some(cp);
    };
    j.append(Kind::MissionOpen, json!({"m": 1}));
    checkpoint(&j, &mut roots, &mut presented);
    let opening = Checkpoint::first(&key, j.head()).tag();
    j.append(Kind::TxSubmitted, json!({"amount": "5000"}));
    j.append(Kind::MissionClose, json!({"steps_done": 2}));
    checkpoint(&j, &mut roots, &mut presented);

    let start = j.start();
    let sealed = j.seal(&MASTER).unwrap();
    let lines = open_all(&MASTER, &start, &sealed.bytes, &sealed.head).unwrap();
    let chain = OneAnchorPerHour(roots);
    let hour = 3_600_000_000_000;
    let trust = AuditTrust { opening_tag: Some(opening), not_before_ns: 0, not_after_ns: hour, max_gap_ns: hour };
    let verdict = audit(&start, &key, &trust, &lines, &presented, &chain).unwrap();
    assert_eq!(verdict.checkpoints, 2);

    // A rollback: the journal cut before the payment, with a new closing entry.
    let mut forged = lines[..1].to_vec();
    let mut tail = Journal::new([0; 32]);
    tail.append(Kind::MissionClose, json!({"steps_done": 1}));
    forged.push(tail.entries()[0].to_string());
    assert!(audit(&start, &key, &trust, &forged, &presented, &chain).is_err());
    assert!(audit(&start, &key, &trust, &lines[..2], &presented, &chain)
        .unwrap_err()
        .contains("mission_close"));
}
