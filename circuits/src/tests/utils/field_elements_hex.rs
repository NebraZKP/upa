use crate::utils::field_elements_hex;
use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, group::ff::Field};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct FieldElements {
    #[serde(with = "field_elements_hex")]
    pub a: Vec<Fr>,
}

#[test]
fn test_ser_deser() {
    let rng = OsRng;
    let values = FieldElements {
        a: vec![Fr::random(rng), Fr::random(rng), Fr::random(rng)],
    };
    let serialized = serde_json::to_string(&values).unwrap();
    println!("field elements json: {serialized}");
    let deserialized =
        serde_json::from_str::<FieldElements>(&serialized).unwrap();
    let reserialized = serde_json::to_string(&deserialized).unwrap();
    println!("field elements json: {reserialized}");
    assert_eq!(serialized, reserialized);
}
