#!/usr/bin/env bash

# To benchmark large configs it may be necessary to generate the proving key using CPU-only to avoid GPU
# out-of-memory. Then the benchmark can be run with the GPU activated and the key will be loaded.
#
# To be run from `benches` directory

set -x
set -e

# Build UPA prover tool
pushd ../../prover
    cargo build --release
    PROVER="$(pwd)/../target/release/prover"
popd

# Create directories for SRS, keys, test data, logs
if [ ! -d "_srs" ]; then
    mkdir _srs
fi
SRS_DIR="$(pwd)/_srs"

if [ ! -d "_keys" ]; then
    mkdir _keys
fi
KEYS_DIR="$(pwd)/_keys"

if [ ! -d "_test_data" ]; then
    mkdir _test_data
fi
TEST_DATA_DIR="$(pwd)/_test_data"

if [ ! -d "logs" ]; then
    mkdir logs
fi
LOGS_DIR="$(pwd)/logs"

CONFIGS_FILE="$(pwd)/configs/universal_outer_configs.json"

# Generate UBV, Outer Proving Keys without GPU
jq -c '.[]' "$CONFIGS_FILE" | while IFS= read -r config; do
    NUM_PI=$(echo "$config" | jq -r '.max_num_app_public_inputs')
    INNER_BATCH_SIZE=$(echo "$config" | jq -r '.inner_batch_size')
    OUTER_BATCH_SIZE=$(echo "$config" | jq -r '.outer_batch_size')
    BV_CIRCUIT_DEGREE=$(echo "$config" | jq -r '.bv_config.degree_bits')
    KECCAK_CIRCUIT_DEGREE=$(echo "$config" | jq -r '.keccak_config.degree_bits')
    OUTER_CIRCUIT_DEGREE=$(echo "$config" | jq -r '.outer_config.degree_bits')

    # Generate any missing SRS files
    BV_SRS="$SRS_DIR/deg_${BV_CIRCUIT_DEGREE}.srs"
    if [ ! -f $BV_SRS ] && [ "${DRY_RUN}" != "1" ]; then
        $PROVER srs generate --degree-bits $BV_CIRCUIT_DEGREE --srs-file $BV_SRS
    fi
    KECCAK_SRS="$SRS_DIR/deg_${KECCAK_CIRCUIT_DEGREE}.srs"
    if [ ! -f $KECCAK_SRS ] && [ "${DRY_RUN}" != "1" ]; then
        $PROVER srs generate --degree-bits $KECCAK_CIRCUIT_DEGREE --srs-file $KECCAK_SRS
    fi
    OUTER_SRS="$SRS_DIR/deg_${OUTER_CIRCUIT_DEGREE}.srs"
    if [ ! -f $OUTER_SRS ] && [ "${DRY_RUN}" != "1" ]; then
        $PROVER srs generate --degree-bits $OUTER_CIRCUIT_DEGREE --srs-file $OUTER_SRS
    fi

    # UBV: determined by num_pi, deg_bits, inner_batch_size
    BV_IDENTIFIER="ubv_pi_${NUM_PI}_deg_${BV_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}"
    # Keccak: determined by num_pi, deg_bits, inner_batch_size, outer_batch_size
    KECCAK_IDENTIFIER="keccak_pi_${NUM_PI}_deg_${KECCAK_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}_outer_${OUTER_BATCH_SIZE}"
    # Outer: determined by num_pi, deg_bits, inner_batch_size, outer_batch_size, ubv_degree, keccak_degree
    OUTER_IDENTIFIER="outer_pi_${NUM_PI}_deg_${OUTER_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}_outer_${OUTER_BATCH_SIZE}_ubv_deg_${BV_CIRCUIT_DEGREE}_keccak_deg_${KECCAK_CIRCUIT_DEGREE}"

    # Need this config in own file for prover tool
    CONFIG_FILE="${TEST_DATA_DIR}/${OUTER_IDENTIFIER}.config"
    if [ ! -f $CONFIG_FILE ]; then
        echo $config > "$CONFIG_FILE"
    fi

    # Generate any missing proving keys
    pushd $KEYS_DIR
    if [ ! -f "${BV_IDENTIFIER}.gate_config" ]; then
        /usr/bin/time -f "Keygen time: %E, max memory usage: %M KB" \
            $PROVER universal-batch-verifier keygen \
                --config $CONFIG_FILE \
                --srs $BV_SRS \
                --proving-key "${BV_IDENTIFIER}.pk" \
                --verification-key "${BV_IDENTIFIER}.vk" \
                --protocol "${BV_IDENTIFIER}.protocol" \
                --gate-config "${BV_IDENTIFIER}.gate_config" \
                $DRY_RUN_FLAG 2>&1 | tee "${LOGS_DIR}/${BV_IDENTIFIER}_keygen.log"
    fi
    if [ ! -f "${KECCAK_IDENTIFIER}.gate_config" ]; then
        /usr/bin/time -f "Keygen time: %E, max memory usage: %M KB" \
            $PROVER keccak keygen \
                --config $CONFIG_FILE \
                --srs $KECCAK_SRS \
                --proving-key "${KECCAK_IDENTIFIER}.pk" \
                --verification-key "${KECCAK_IDENTIFIER}.vk" \
                --protocol "${KECCAK_IDENTIFIER}.protocol" \
                --gate-config "${KECCAK_IDENTIFIER}.gate_config" \
                $DRY_RUN_FLAG 2>&1 | tee "${LOGS_DIR}/${KECCAK_IDENTIFIER}_keygen.log"
    fi
    if [ ! -f "${OUTER_IDENTIFIER}.gate_config" ]; then
        /usr/bin/time -f "Keygen time: %E, max memory usage: %M KB" \
            $PROVER universal-outer keygen \
                --config $CONFIG_FILE \
                --outer-srs $OUTER_SRS \
                --bv-srs $BV_SRS \
                --keccak-srs $KECCAK_SRS \
                --proving-key "${OUTER_IDENTIFIER}.pk" \
                --verification-key "${OUTER_IDENTIFIER}.vk" \
                --protocol "${OUTER_IDENTIFIER}.protocol" \
                --gate-config "${OUTER_IDENTIFIER}.gate_config" \
                --num-instance "${OUTER_IDENTIFIER}.num_instance" \
                $DRY_RUN_FLAG 2>&1 | tee "${LOGS_DIR}/${OUTER_IDENTIFIER}_keygen.log"

        $PROVER universal-outer generate-verifier \
                --outer-srs $OUTER_SRS \
                --gate-config "${OUTER_IDENTIFIER}.gate_config" \
                --verification-key "${OUTER_IDENTIFIER}.vk" \
                --num-instance "${OUTER_IDENTIFIER}.num_instance" \
                --yul "${OUTER_IDENTIFIER}.yul"
    fi
    popd
done

# Benchmark UBV Prover with GPU
# Must run from saturn directory to have GPU feature
pushd ../../../
    cargo bench --features gpu --bench upa 2>&1 | tee "${LOGS_DIR}/upa_large_config_bench.log"
popd

set +x
set +e
