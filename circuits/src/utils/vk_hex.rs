///! JSON (de)serialization of sequences of field elements as hex string.
use crate::batch_verify::common::{
    native::json::JsonVerificationKey, types::VerificationKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serializes `vk`.
pub fn serialize<S>(vk: &VerificationKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // TODO: create serialization methods for G1 and G2 and use those in the
    // VerificationKey struct.
    let json_vk: JsonVerificationKey = vk.into();
    json_vk.serialize(s)
}

/// Deserializes a [`VerificationKey`].
pub fn deserialize<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<VerificationKey, D::Error> {
    let json_vk = JsonVerificationKey::deserialize(d)?;
    Ok((&json_vk).into())
}
