//! The `ona-pool` formats a note owner needs: domain tags, nullifiers and the digests the owner signs. They copy
//! the contract's, byte for byte (`ona-pool`'s tests check both give the same bytes).

use sha2::{Digest, Sha256};

fn sha256(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

/// Domain tag of a share note of one vault.
pub fn note_dst(network: &str, contract: &str, vault_id: u32) -> String {
    format!("ONA-POOL-V1:{network}:{contract}:{vault_id}:BLS12381G1_XMD:SHA-256_SSWU_RO_")
}

/// Domain tag of a cash note.
pub fn cash_dst(network: &str, contract: &str) -> String {
    format!("ONA-POOL-CASH-V1:{network}:{contract}:BLS12381G1_XMD:SHA-256_SSWU_RO_")
}

/// `SHA-256("ONA-POOL-NF-V1" || vault_id (u32 LE) || tier || pk || nonce)`.
pub fn note_nullifier(vault_id: u32, tier: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut d = b"ONA-POOL-NF-V1".to_vec();
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.push(tier);
    d.extend_from_slice(pk);
    d.extend_from_slice(nonce);
    sha256(&d)
}

/// `SHA-256("ONA-POOL-CASH-NF-V1" || tier || pk || nonce)`.
pub fn cash_nullifier(tier: u8, pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut d = b"ONA-POOL-CASH-NF-V1".to_vec();
    d.push(tier);
    d.extend_from_slice(pk);
    d.extend_from_slice(nonce);
    sha256(&d)
}

fn outputs_bytes(d: &mut Vec<u8>, outputs: &[(u8, u64)]) {
    d.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for (tier, count) in outputs {
        d.push(*tier);
        d.extend_from_slice(&count.to_le_bytes());
    }
}

/// `SHA-256("ONA-POOL-CASH-EXIT-V1" || H(contract) || nf || H(to) || expires_at (u64 LE))`.
pub fn cash_exit_digest(contract: &str, nf: &[u8; 32], to: &str, expires_at: u64) -> [u8; 32] {
    let mut d = b"ONA-POOL-CASH-EXIT-V1".to_vec();
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(nf);
    d.extend_from_slice(&sha256(to.as_bytes()));
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// `SHA-256("ONA-POOL-EXIT-V2" || H(contract) || vault_id (u32 LE) || nf || H(to) || min_amount (u128 LE) || expires_at (u64 LE))`.
pub fn share_exit_digest(contract: &str, vault_id: u32, nf: &[u8; 32], to: &str, min_amount: u128, expires_at: u64) -> [u8; 32] {
    let mut d = b"ONA-POOL-EXIT-V2".to_vec();
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.extend_from_slice(nf);
    d.extend_from_slice(&sha256(to.as_bytes()));
    d.extend_from_slice(&min_amount.to_le_bytes());
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// `SHA-256("ONA-POOL-ENTER-V1" || H(contract) || nf || vault_id (u32 LE) || n (u32 LE) || (tier || count (u64 LE))*n || expires_at (u64 LE))`.
pub fn enter_digest(contract: &str, nf: &[u8; 32], vault_id: u32, outputs: &[(u8, u64)], expires_at: u64) -> [u8; 32] {
    let mut d = b"ONA-POOL-ENTER-V1".to_vec();
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(nf);
    d.extend_from_slice(&vault_id.to_le_bytes());
    outputs_bytes(&mut d, outputs);
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}

/// `SHA-256("ONA-POOL-LEAVE-V1" || H(contract) || vault_id (u32 LE) || nf || n (u32 LE) || (tier || count (u64 LE))*n || expires_at (u64 LE))`.
pub fn leave_digest(contract: &str, vault_id: u32, nf: &[u8; 32], outputs: &[(u8, u64)], expires_at: u64) -> [u8; 32] {
    let mut d = b"ONA-POOL-LEAVE-V1".to_vec();
    d.extend_from_slice(&sha256(contract.as_bytes()));
    d.extend_from_slice(&vault_id.to_le_bytes());
    d.extend_from_slice(nf);
    outputs_bytes(&mut d, outputs);
    d.extend_from_slice(&expires_at.to_le_bytes());
    sha256(&d)
}
