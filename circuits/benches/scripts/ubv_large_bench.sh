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

CONFIGS_FILE="$(pwd)/configs/ubv_configs.json"

# Generate UBV Proving Keys without GPU
jq -c '.[]' "$CONFIGS_FILE" | while IFS= read -r config; do
    NUM_PI=$(echo "$config" | jq -r '.max_num_app_public_inputs')
    INNER_BATCH_SIZE=$(echo "$config" | jq -r '.inner_batch_size')
    BV_CIRCUIT_DEGREE=$(echo "$config" | jq -r '.bv_config.degree_bits')

    # Generate any missing SRS files
    BV_SRS="$SRS_DIR/deg_${BV_CIRCUIT_DEGREE}.srs"
    if [ ! -f $BV_SRS ] && [ "${DRY_RUN}" != "1" ]; then
        $PROVER srs generate --degree-bits $BV_CIRCUIT_DEGREE --srs-file $BV_SRS
    fi

    # UBV: determined by num_pi, deg_bits, inner_batch_size
    BV_IDENTIFIER="ubv_pi_${NUM_PI}_deg_${BV_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}"

    # Need this config in own file for prover tool
    CONFIG_FILE="${TEST_DATA_DIR}/${BV_IDENTIFIER}.config"
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
                $DRY_RUN_FLAG
    fi
done

# Benchmark UBV Prover with GPU
# Must run from saturn directory to have GPU feature
pushd ../../../
    cargo bench --features gpu --bench universal_batch_verifier | tee "${LOGS_DIR}/ubv_large_config_bench.log"
popd

set +x
set +e
