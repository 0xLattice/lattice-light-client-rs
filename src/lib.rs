//! Self-contained state witnesses. These checks authenticate claims under the
//! supplied commitments; they do not establish a canonical header chain.
#![forbid(unsafe_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use lattice_cashew::{cbor, ContentSource, Header, VolumeMerkleDictionary};
use lattice_primitives::{Block, LatticeState};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainHeader {
    pub hash: String,
    pub height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    pub state_root: String,
    pub target: String,
    pub timestamp: i64,
    pub cumulative_work: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessNode {
    pub cid: String,
    pub data: String,
}
impl WitnessNode {
    pub fn new(cid: impl Into<String>, data: &[u8]) -> Self {
        Self {
            cid: cid.into(),
            data: STANDARD.encode(data),
        }
    }
    pub fn raw_data(&self) -> Result<Vec<u8>, VerifyError> {
        STANDARD.decode(&self.data).map_err(|_| VerifyError::Base64)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LightClientProof {
    pub block_hash: String,
    pub block_height: u64,
    pub header: ChainHeader,
    pub state_root: String,
    pub address: String,
    pub balance: u64,
    /// Stored last-used nonce, not the next transaction nonce.
    pub nonce: u64,
    pub account_root: String,
    pub witness: Vec<WitnessNode>,
    pub timestamp: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateKind {
    Deposits,
    Receipts,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDictionaryProof {
    pub block_hash: String,
    pub block_height: u64,
    pub block: WitnessNode,
    pub state_root: String,
    pub dictionary: StateKind,
    pub dictionary_root: String,
    pub claims: Vec<Claim>,
    pub witness: Vec<WitnessNode>,
}
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid witness base64")]
    Base64,
    #[error("duplicate witness CID or claim key")]
    Duplicate,
    #[error("proof metadata or commitment mismatch")]
    Binding,
    #[error("claimed value differs from witnessed value")]
    Claim,
    #[error(transparent)]
    Content(#[from] lattice_cashew::Error),
}
// Deliberately not caller-configurable: a witness cannot fetch missing nodes
// from a cache, broker, fallback, filesystem, or network.
fn sealed_source(nodes: &[WitnessNode]) -> Result<BTreeMap<String, Vec<u8>>, VerifyError> {
    let mut source = BTreeMap::new();
    for node in nodes {
        if source.insert(node.cid.clone(), node.raw_data()?).is_some() {
            return Err(VerifyError::Duplicate);
        }
    }
    Ok(source)
}
fn typed_node<T: DeserializeOwned + Serialize>(
    cid: &str,
    source: &BTreeMap<String, Vec<u8>>,
) -> Result<T, VerifyError> {
    let bytes = source.fetch(cid)?;
    lattice_cashew::verify_content_address(cid, &bytes)?;
    let node: T = cbor::decode(&bytes)?;
    if Header::new(&node)?.raw_cid != cid {
        return Err(VerifyError::Binding);
    }
    Ok(node)
}
/// Verifies only the stated root and duplicated header metadata. Header hash,
/// work, target and ancestry need independent consensus/trust verification.
pub fn verify_account(proof: &LightClientProof) -> bool {
    verify_account_checked(proof).is_ok()
}
pub fn verify_account_checked(proof: &LightClientProof) -> Result<(), VerifyError> {
    if proof.witness.is_empty()
        || proof.state_root.is_empty()
        || proof.account_root.is_empty()
        || proof.header.hash != proof.block_hash
        || proof.header.height != proof.block_height
        || proof.header.state_root != proof.state_root
        || proof.header.timestamp != proof.timestamp
    {
        return Err(VerifyError::Binding);
    }
    let source = sealed_source(&proof.witness)?;
    let state: LatticeState = typed_node(&proof.state_root, &source)?;
    if state.account_state.0.raw_cid != proof.account_root {
        return Err(VerifyError::Binding);
    }
    let nonce_key = format!("_nonce_{}", proof.address);
    let dictionary: VolumeMerkleDictionary<u64> = typed_node(&proof.account_root, &source)?;
    let dictionary = dictionary
        .resolve_key(&proof.address, &source)?
        .resolve_key(&nonce_key, &source)?;
    // Only proven absence defaults to zero; missing or malformed paths fail.
    if dictionary.get(&proof.address)?.copied().unwrap_or(0) != proof.balance
        || dictionary.get(&nonce_key)?.copied().unwrap_or(0) != proof.nonce
    {
        return Err(VerifyError::Claim);
    }
    Ok(())
}
/// Binds the supplied block bytes to its CID, height and post-state, then checks
/// dictionary claims. Does not validate PoW, state transition or chain selection.
pub fn verify_dictionary(proof: &StateDictionaryProof) -> bool {
    verify_dictionary_checked(proof).is_ok()
}
pub fn verify_dictionary_checked(proof: &StateDictionaryProof) -> Result<(), VerifyError> {
    if proof.block.cid != proof.block_hash {
        return Err(VerifyError::Binding);
    }
    let block_source = sealed_source(std::slice::from_ref(&proof.block))?;
    let block: Block = typed_node(&proof.block_hash, &block_source)?;
    if block.height != proof.block_height || block.post_state.0.raw_cid != proof.state_root {
        return Err(VerifyError::Binding);
    }
    let source = sealed_source(&proof.witness)?;
    let state: LatticeState = typed_node(&proof.state_root, &source)?;
    let mut seen = BTreeSet::new();
    for claim in &proof.claims {
        if !seen.insert(claim.key.nfc().collect::<String>()) {
            return Err(VerifyError::Duplicate);
        }
    }
    match proof.dictionary {
        StateKind::Deposits => {
            if state.deposit_state.0.raw_cid != proof.dictionary_root {
                return Err(VerifyError::Binding);
            }
            verify_claims::<u64>(proof, &source, |v| v.to_string())
        }
        StateKind::Receipts => {
            if state.receipt_state.0.raw_cid != proof.dictionary_root {
                return Err(VerifyError::Binding);
            }
            verify_claims::<String>(proof, &source, Clone::clone)
        }
    }
}
fn verify_claims<V: Clone + Serialize + DeserializeOwned>(
    proof: &StateDictionaryProof,
    source: &BTreeMap<String, Vec<u8>>,
    wire: impl Fn(&V) -> String,
) -> Result<(), VerifyError> {
    // Even zero claims must carry a content-bound dictionary root.
    let mut dictionary: VolumeMerkleDictionary<V> = typed_node(&proof.dictionary_root, source)?;
    for claim in &proof.claims {
        dictionary = dictionary.resolve_key(&claim.key, source)?;
    }
    for claim in &proof.claims {
        if dictionary.get(&claim.key)?.map(&wire) != claim.value {
            return Err(VerifyError::Claim);
        }
    }
    Ok(())
}

/// Explicitly named alias for callers sharing account and dictionary APIs.
pub fn verify_state_dictionary(proof: &StateDictionaryProof) -> bool {
    verify_dictionary(proof)
}
pub fn verify_state_dictionary_checked(proof: &StateDictionaryProof) -> Result<(), VerifyError> {
    verify_dictionary_checked(proof)
}
