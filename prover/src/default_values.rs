// Defines some conventions for default file locations
pub const UPA_CONFIG: &str = "upa_config.json";

pub const BV_SRS: &str = "bv.srs";

// Not a typo- the `dummy_srs_setup` script relies on the circuit name being the
// same as the UPA config's field ${circuit_name}_config. This does not hold
// for the UBV circuit- a UPA config does not have a ubv_config field.
// In particular, if one called
// `create_srs_if_config_file ubv`
// this ends up calling `get_circuit_degree()` which looks for a `ubv_config`.
//
// It's simpler not to complicate the `dummy_srs_setup` script with the ubv
// case since we'd want to change it back anyway when we drop the "universal"
// qualifiers.
pub const UBV_SRS: &str = "bv.srs";
pub const UBV_PK: &str = "ubv.pk";
pub const UBV_VK: &str = "ubv.vk";
pub const UBV_GATE_CONFIG: &str = "ubv.specs";
pub const UBV_PROTOCOL: &str = "ubv.protocol";
pub const UBV_PROOF_BASE: &str = "ubv.proof";

pub const KECCAK_SRS: &str = "keccak.srs";
pub const KECCAK_PK: &str = "keccak.pk";
pub const KECCAK_VK: &str = "keccak.vk";
pub const KECCAK_GATE_CONFIG: &str = "keccak.specs";
pub const KECCAK_PROTOCOL: &str = "keccak.protocol";
pub const KECCAK_PROOF: &str = "keccak.proof";

pub const OUTER_SRS: &str = "outer.srs";
pub const OUTER_PK: &str = "outer.pk";
pub const OUTER_VK: &str = "outer.vk";
pub const OUTER_GATE_CONFIG: &str = "outer.specs";
pub const OUTER_PROTOCOL: &str = "outer.protocol";
pub const OUTER_INSTANCE_SIZE: &str = "outer.instance_size";
pub const OUTER_VERIFIER_YUL: &str = "outer.verifier.yul";
pub const OUTER_VERIFIER_BIN: &str = "outer.verifier.bin";
pub const OUTER_PROOF: &str = "outer.proof";
