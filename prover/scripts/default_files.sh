# Defines some conventions for default file locations

CONFIG=upa_config.json
MOUNT_DIR=_test_data

BV_CIRCUIT_NAME=bv

UBV_CIRCUIT_NAME=ubv
# Not a typo- the `dummy_srs_setup` script relies on the circuit name being the
# same as the UPA config's field ${circuit_name}_config. This does not hold
# for the UBV circuit- a UPA config does not have a ubv_config field.
# In particular, if one called
# `create_srs_if_config_file ubv`
# this ends up calling `get_circuit_degree()` which looks for a `ubv_config`.
#
# It's simpler not to complicate the `dummy_srs_setup` script with the ubv
# case since we'd want to change it back anyway when we drop the "universal"
# qualifiers.
UBV_SRS=${BV_CIRCUIT_NAME}.srs
UBV_PK=${UBV_CIRCUIT_NAME}.pk
UBV_VK=${UBV_CIRCUIT_NAME}.vk
UBV_GATE_CONFIG=${UBV_CIRCUIT_NAME}.specs
UBV_PROTOCOL=${UBV_CIRCUIT_NAME}.protocol

KECCAK_CIRCUIT_NAME=keccak
KECCAK_SRS=${KECCAK_CIRCUIT_NAME}.srs
KECCAK_VK=${KECCAK_CIRCUIT_NAME}.vk
KECCAK_PK=${KECCAK_CIRCUIT_NAME}.pk
KECCAK_PROTOCOL=${KECCAK_CIRCUIT_NAME}.protocol
KECCAK_GATE_CONFIG=${KECCAK_CIRCUIT_NAME}.specs

OUTER_CIRCUIT_NAME=outer
OUTER_SRS=${OUTER_CIRCUIT_NAME}.srs
OUTER_PK=${OUTER_CIRCUIT_NAME}.pk
OUTER_VK=${OUTER_CIRCUIT_NAME}.vk
OUTER_PROTOCOL=${OUTER_CIRCUIT_NAME}.protocol
OUTER_GATE_CONFIG=${OUTER_CIRCUIT_NAME}.specs
OUTER_INSTANCE_SIZE=${OUTER_CIRCUIT_NAME}.instance_size
OUTER_VERIFIER_YUL=${OUTER_CIRCUIT_NAME}.verifier.yul
OUTER_VERIFIER_BIN=${OUTER_CIRCUIT_NAME}.verifier.bin
