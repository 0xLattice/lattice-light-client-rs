# Lattice light client for Rust

Shared account, deposits and receipts proof types and verification, matching
`0xLattice/lattice-node` revision `3df9e0a786c7b103a3da88d1c3881efc81706255`,
`Sources/LatticeLightClient/LightClientProtocol.swift`. This crate depends on
Lattice primitives and Cashew, never the daemon, transport or RPC runtime.

`verify_account_checked(&LightClientProof)` and
`verify_state_dictionary_checked(&StateDictionaryProof)` return `Result<(), VerifyError>`;
`verify_account` / `verify_state_dictionary` return booleans. Short dictionary
aliases `verify_dictionary[_checked]` are also available. JSON uses Swift's
camelCase field names; `WitnessNode::new(cid, bytes)` encodes standard base64.
An omitted or null claim value means proven absence. Deposits use canonical
unsigned decimal strings. Account nonce means the stored last-used nonce.

Verification constructs a private in-memory source from the witness. Missing
nodes cannot fall back to any external source. Cashew resolves only claimed
radix paths and verifies content addresses. A missing path is an error, never
zero/absence. Dictionary proofs also authenticate the supplied block bytes and
bind its height and post-state. Empty claim lists still require the dictionary
root bytes. Duplicate claims return an error instead of the Swift dictionary
constructor's trap. Duplicate witness CIDs are rejected for both proof types
(Swift account verification overwrites duplicates; its dictionary verifier
rejects them). Malformed requested values fail rather than default to zero.

**Trust boundary:** account proofs authenticate claims under the supplied
`stateRoot` and check duplicated header metadata. They do not recompute or trust
the claimed header hash. Dictionary proofs bind the supplied block CID but do
not validate proof of work, ancestry, transitions or canonical chain selection.
The caller must authenticate the expected block/state root and match the
requested address/dictionary/claims before accepting an otherwise valid proof.
Unused witness nodes need valid base64 but are not traversed or trusted.

## Validation

`cargo test --all-targets --locked` covers membership, proven absence, missing
paths, nonces, malformed bytes, duplicate claims/witnesses, metadata binding,
empty claims and targeted pruning. `cargo clippy --all-targets -- -D warnings`
checks the library and tests.

`python3 tools/swift-fixtures.py` runs the **unchanged full pinned Swift source**
against Rust-generated witnesses and adversarial mutations. It uses the shared
`/tmp/lattice-genesis-oracle` build cache, verifies original Lattice source bytes
and dependency lock hash before execution, and writes reproducible verdicts and
provenance into `tests/swift-proofs.json` / `tests/swift-evidence.json`.
Local path dependencies need published/pinned equivalents before distribution.
