//! Fakes for running the relay without a chain or a model. Used by `ona-mock-relay` so the
//! front ends can be developed. Nothing here is real, and every reply says so.

use std::collections::BTreeSet;

use crate::{Chain, Claim, ModelReply, Upstream};

#[derive(Default)]
pub struct MockChain {
    spent: BTreeSet<[u8; 32]>,
}

impl Chain for MockChain {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.spent.contains(nf))
    }

    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        Ok(claims.iter().map(|c| self.spent.insert(c.token.nullifier())).collect())
    }

    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        Ok(self.spent.contains(nf))
    }
}

pub struct MockModel;

impl Upstream for MockModel {
    fn complete(&mut self, prompt: &str, _max_tokens: u32) -> Result<ModelReply, String> {
        Ok(ModelReply {
            text: format!("[mock reply] received {} bytes", prompt.len()),
            tokens_used: 1,
        })
    }
}
