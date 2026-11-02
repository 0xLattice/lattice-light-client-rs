use lattice_light_client::{
    verify_account, verify_dictionary, LightClientProof, StateDictionaryProof,
};
#[test]
fn matches_actual_pinned_swift_verifier_on_rust_witnesses() {
    let rows: serde_json::Value = serde_json::from_str(include_str!("swift-proofs.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let actual = if row["kind"] == "account" {
            verify_account(
                &serde_json::from_value::<LightClientProof>(row["proof"].clone()).unwrap(),
            )
        } else {
            verify_dictionary(
                &serde_json::from_value::<StateDictionaryProof>(row["proof"].clone()).unwrap(),
            )
        };
        assert_eq!(actual, row["swift"].as_bool().unwrap(), "{}", row["name"]);
        assert_eq!(
            actual,
            row["expected"].as_bool().unwrap(),
            "{}",
            row["name"]
        );
    }
}
