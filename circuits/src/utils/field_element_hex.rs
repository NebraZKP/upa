///! JSON (de)serialization of sequences of field elements as hex string.
// TODO: this utils module should not depend on other modules.  Move these
// serialization functions into this module.
use crate::batch_verify::common::native::json::field_element_from_str;
use crate::EccPrimeField;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S: Serializer, F: EccPrimeField>(
    v: &F,
    s: S,
) -> Result<S::Ok, S::Error> {
    let out: String = format!("{v:?}");
    String::serialize(&out, s)
}

pub fn deserialize<'de, D: Deserializer<'de>, F>(d: D) -> Result<F, D::Error>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    Ok(field_element_from_str(
        &String::deserialize(d).expect("invalid field element hex"),
    ))
}
