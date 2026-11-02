use lattice_cashew::{cbor, volume::serialize_recursive, Header, MerkleDictionary, Volume};
use lattice_light_client::*;
use lattice_primitives::*;
use std::collections::BTreeMap;
fn state(nonce: Option<u64>) -> LatticeState {
    let mut state = LatticeState::empty().unwrap();
    let mut account = AccountState::default()
        .inserting("alice", 42)
        .unwrap()
        .inserting("bob", 99)
        .unwrap();
    if let Some(nonce) = nonce {
        account = account.inserting("_nonce_alice", nonce).unwrap();
    }
    state.account_state = Volume::new(account).unwrap();
    state.deposit_state = Volume::new(
        DepositState::default()
            .inserting("chain/alice", u64::MAX)
            .unwrap(),
    )
    .unwrap();
    state.receipt_state = Volume::new(
        ReceiptState::default()
            .inserting("tx/alice", "receipt-cid".into())
            .unwrap(),
    )
    .unwrap();
    state
}
fn witness(state: &LatticeState) -> (String, Vec<WitnessNode>) {
    let root = Volume::new(state.clone()).unwrap();
    let entries: BTreeMap<_, _> = serialize_recursive(&root, &())
        .unwrap()
        .into_iter()
        .flat_map(|v| v.entries)
        .collect();
    (
        root.raw_cid.clone(),
        entries
            .into_iter()
            .map(|(cid, data)| WitnessNode::new(cid, &data))
            .collect(),
    )
}
fn account(nonce: Option<u64>) -> LightClientProof {
    let state = state(nonce);
    let (state_root, witness) = witness(&state);
    LightClientProof {
        block_hash: "untrusted-header-hash".into(),
        block_height: 7,
        header: ChainHeader {
            hash: "untrusted-header-hash".into(),
            height: 7,
            previous_hash: None,
            state_root: state_root.clone(),
            target: "untrusted-target".into(),
            timestamp: 123,
            cumulative_work: "untrusted-work".into(),
        },
        state_root,
        address: "alice".into(),
        balance: 42,
        nonce: nonce.unwrap_or(0),
        account_root: state.account_state.raw_cid.clone(),
        witness,
        timestamp: 123,
    }
}
fn dictionary(kind: StateKind, claims: Vec<Claim>) -> StateDictionaryProof {
    let state = state(None);
    let (state_root, witness) = witness(&state);
    let empty = Volume::new(LatticeState::empty().unwrap()).unwrap();
    let block = Block {
        version: 1,
        parent: None,
        transactions: Header::new(MerkleDictionary::default()).unwrap(),
        target: UInt256([255; 32]),
        next_target: UInt256([255; 32]),
        spec: Volume::new(ChainSpec {
            max_number_of_transactions_per_block: 100,
            max_state_growth: 100_000,
            max_block_size: 1_000_000,
            premine: 0,
            target_block_time: 1000,
            initial_reward: 1024,
            halving_interval: 210_000,
            half_life: 120,
            wasm_policies: vec![],
        })
        .unwrap(),
        parent_state: empty.clone(),
        prev_state: empty,
        post_state: Volume::new(state.clone()).unwrap(),
        children: Header::new(BTreeMap::new()).unwrap(),
        height: 7,
        timestamp: 123,
        reward_recipient: None,
        nonce: 0,
    };
    let block_hash = content_id(&block).unwrap();
    StateDictionaryProof {
        block_hash: block_hash.clone(),
        block_height: 7,
        block: WitnessNode::new(block_hash, &cbor::encode(&block).unwrap()),
        state_root,
        dictionary: kind,
        dictionary_root: match kind {
            StateKind::Deposits => state.deposit_state.raw_cid.clone(),
            StateKind::Receipts => state.receipt_state.raw_cid.clone(),
        },
        claims,
        witness,
    }
}
#[test]
fn accounts_prove_present_and_absent_nonces_and_do_not_validate_header_chain() {
    for nonce in [None, Some(0), Some(9), Some(u64::MAX)] {
        let proof = account(nonce);
        assert!(verify_account(&proof));
        let mut wrong = proof.clone();
        wrong.nonce = if proof.nonce == 0 { 1 } else { 0 };
        assert!(!verify_account(&wrong));
        let mut wrong = proof.clone();
        wrong.balance += 1;
        assert!(!verify_account(&wrong));
    }
    let mut absent = account(None);
    absent.address = "missing".into();
    absent.balance = 0;
    assert!(verify_account(&absent));
    let mut proof = account(None);
    proof.header.hash = "different".into();
    assert!(!verify_account(&proof));
}
#[test]
fn missing_paths_cannot_masquerade_as_zero_or_absence() {
    let mut proof = account(Some(9));
    proof.nonce = 0;
    proof
        .witness
        .retain(|n| n.cid == proof.state_root || n.cid == proof.account_root);
    assert!(!verify_account(&proof));
    let mut proof = account(None);
    proof.witness.retain(|n| n.cid != proof.account_root);
    assert!(!verify_account(&proof));
    for kind in [StateKind::Deposits, StateKind::Receipts] {
        let mut proof = dictionary(
            kind,
            vec![Claim {
                key: if kind == StateKind::Deposits {
                    "chain/alice"
                } else {
                    "tx/alice"
                }
                .into(),
                value: None,
            }],
        );
        proof
            .witness
            .retain(|n| n.cid == proof.state_root || n.cid == proof.dictionary_root);
        assert!(!verify_dictionary(&proof));
    }
}
#[test]
fn dictionary_membership_absence_empty_and_decimal_wire_rules() {
    for (kind, key, value) in [
        (StateKind::Deposits, "chain/alice", u64::MAX.to_string()),
        (StateKind::Receipts, "tx/alice", "receipt-cid".into()),
    ] {
        let proof = dictionary(
            kind,
            vec![
                Claim {
                    key: key.into(),
                    value: Some(value),
                },
                Claim {
                    key: "missing".into(),
                    value: None,
                },
            ],
        );
        assert!(verify_dictionary(&proof));
        let mut wrong = proof.clone();
        wrong.claims[0].value = Some("0".into());
        assert!(!verify_dictionary(&wrong));
        let mut wrong = proof.clone();
        wrong.block_height += 1;
        assert!(!verify_dictionary(&wrong));
        let mut duplicate = proof.clone();
        duplicate.claims.push(duplicate.claims[0].clone());
        assert!(matches!(
            verify_dictionary_checked(&duplicate),
            Err(VerifyError::Duplicate)
        ));
        let mut empty = proof;
        empty.claims.clear();
        assert!(verify_dictionary(&empty));
        empty.witness.retain(|n| n.cid != empty.dictionary_root);
        assert!(!verify_dictionary(&empty));
    }
    let proof = dictionary(
        StateKind::Deposits,
        vec![Claim {
            key: "chain/alice".into(),
            value: Some(format!("0{}", u64::MAX)),
        }],
    );
    assert!(!verify_dictionary(&proof));
}
#[test]
fn corrupted_and_duplicate_witnesses_and_bindings_fail_closed() {
    let proof = account(None);
    for i in 0..proof.witness.len() {
        let mut bad = proof.clone();
        if bad.witness[i].cid != bad.state_root && bad.witness[i].cid != bad.account_root {
            continue;
        }
        bad.witness[i].data = "%%%".into();
        assert!(!verify_account(&bad));
        bad.witness[i] = WitnessNode::new(&proof.witness[i].cid, b"corrupt");
        assert!(!verify_account(&bad));
    }
    let mut duplicate = proof.clone();
    duplicate.witness.push(duplicate.witness[0].clone());
    assert!(!verify_account(&duplicate));
    let mut wrong = proof;
    wrong.account_root = wrong.state_root.clone();
    assert!(!verify_account(&wrong));
    let mut dict = dictionary(StateKind::Deposits, vec![]);
    dict.block.data = "AA==".into();
    assert!(!verify_dictionary(&dict));
}
#[test]
fn targeted_proofs_omit_unrelated_subtrees_and_json_matches_swift_names() {
    let mut proof = account(None);
    let state = state(None);
    let unrelated = state
        .account_state
        .node
        .as_ref()
        .unwrap()
        .children
        .iter()
        .find(|e| e.key == "b")
        .unwrap()
        .value
        .raw_cid
        .clone();
    proof.witness.retain(|n| n.cid != unrelated);
    assert!(verify_account(&proof));
    let json = serde_json::to_value(&proof).unwrap();
    assert!(json.get("blockHash").is_some());
    assert!(json.get("accountRoot").is_some());
    assert!(json["header"].get("previousHash").is_none());
    assert_eq!(
        serde_json::from_value::<LightClientProof>(json).unwrap(),
        proof
    );
}
#[test]
fn export_swift_oracle_inputs_when_requested() {
    if let Ok(path) = std::env::var("LIGHT_CLIENT_FIXTURE_OUTPUT") {
        let zero_account = account(None);
        let account = account(Some(9));
        let deposits = dictionary(
            StateKind::Deposits,
            vec![
                Claim {
                    key: "chain/alice".into(),
                    value: Some(u64::MAX.to_string()),
                },
                Claim {
                    key: "missing".into(),
                    value: None,
                },
            ],
        );
        let receipts = dictionary(
            StateKind::Receipts,
            vec![Claim {
                key: "tx/alice".into(),
                value: Some("receipt-cid".into()),
            }],
        );
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &serde_json::json!({"account":account,"accountZero":zero_account,"deposits":deposits,"receipts":receipts}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn canonically_equivalent_claim_keys_are_duplicates_as_in_swift() {
    let proof = dictionary(
        StateKind::Receipts,
        vec![
            Claim {
                key: "é".into(),
                value: None,
            },
            Claim {
                key: "e\u{301}".into(),
                value: None,
            },
        ],
    );
    assert!(matches!(
        verify_dictionary_checked(&proof),
        Err(VerifyError::Duplicate)
    ));
}

#[test]
fn nonce_absence_requires_the_competing_nonce_branch() {
    let mut state = state(None);
    state.account_state = Volume::new(
        state
            .account_state
            .node
            .as_ref()
            .unwrap()
            .inserting("_nonce_bob", 4)
            .unwrap(),
    )
    .unwrap();
    let (state_root, witness) = witness(&state);
    let mut proof = account(None);
    proof.state_root = state_root.clone();
    proof.header.state_root = state_root;
    proof.account_root = state.account_state.raw_cid.clone();
    proof.witness = witness;
    assert!(verify_account(&proof));
    let nonce_branch = state
        .account_state
        .node
        .as_ref()
        .unwrap()
        .children
        .iter()
        .find(|e| e.key == "_")
        .unwrap()
        .value
        .raw_cid
        .clone();
    proof.witness.retain(|entry| entry.cid != nonce_branch);
    assert!(!verify_account(&proof));
}
