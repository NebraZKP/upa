#!/usr/bin/env bash

set -x
set -e

# Build UPA prover tool
pushd ../prover
    cargo build --release
    PROVER="$(pwd)/../target/release/prover"
popd

# Create directories for SRS, keys, test data, logs
if [ ! -d "_srs" ]; then
    mkdir _srs
fi
SRS_DIR="$(pwd)/_srs"
CONFIG_DIR="$(pwd)/configs"

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

if [ -z $DRY_RUN ]; then
    DRY_RUN=0
    DRY_RUN_FLAG=""
else
    DRY_RUN=1
    DRY_RUN_FLAG="--dry-run"
    echo "Dry run mode"
fi

# Go through all config files, generate keys for each
for config in $CONFIG_DIR/*.json; do
    echo $config

    NUM_PI=$(jq -r '.max_num_app_public_inputs' $config)
    INNER_BATCH_SIZE=$(jq -r '.inner_batch_size' $config)
    OUTER_BATCH_SIZE=$(jq -r '.outer_batch_size' $config)
    BV_CIRCUIT_DEGREE=$(jq -r '.bv_config.degree_bits'  $config)
    KECCAK_CIRCUIT_DEGREE=$(jq -r '.keccak_config.degree_bits'  $config)
    OUTER_CIRCUIT_DEGREE=$(jq -r '.outer_config.degree_bits'  $config)

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

    # Generate any missing proving keys
    pushd $KEYS_DIR
    # UBV: determined by num_pi, deg_bits, inner_batch_size
    BV_IDENTIFIER="ubv_pi_${NUM_PI}_deg_${BV_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}"
    if [ ! -f "${BV_IDENTIFIER}.gate_config" ]; then
        $PROVER universal-batch-verifier keygen \
            --config $config \
            --srs $BV_SRS \
            --proving-key "${BV_IDENTIFIER}.pk" \
            --verification-key "${BV_IDENTIFIER}.vk" \
            --protocol "${BV_IDENTIFIER}.protocol" \
            --gate-config "${BV_IDENTIFIER}.gate_config" \
            $DRY_RUN_FLAG
    fi

    # Keccak: determined by num_pi, deg_bits, inner_batch_size, outer_batch_size
    KECCAK_IDENTIFIER="keccak_pi_${NUM_PI}_deg_${KECCAK_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}_outer_${OUTER_BATCH_SIZE}"
    if [ ! -f "${KECCAK_IDENTIFIER}.gate_config" ]; then
        $PROVER keccak keygen \
            --config $config \
            --srs $KECCAK_SRS \
            --proving-key "${KECCAK_IDENTIFIER}.pk" \
            --verification-key "${KECCAK_IDENTIFIER}.vk" \
            --protocol "${KECCAK_IDENTIFIER}.protocol" \
            --gate-config "${KECCAK_IDENTIFIER}.gate_config" \
            $DRY_RUN_FLAG
    fi

    # Outer: determined by num_pi, deg_bits, inner_batch_size, outer_batch_size, ubv_degree, keccak_degree
    OUTER_IDENTIFIER="outer_pi_${NUM_PI}_deg_${OUTER_CIRCUIT_DEGREE}_inner_${INNER_BATCH_SIZE}_outer_${OUTER_BATCH_SIZE}_ubv_deg_${BV_CIRCUIT_DEGREE}_keccak_deg_${KECCAK_CIRCUIT_DEGREE}"
    if [ ! -f "${OUTER_IDENTIFIER}.gate_config" ]; then
        $PROVER universal-outer keygen \
            --config $config \
            --outer-srs $OUTER_SRS \
            --bv-srs $BV_SRS \
            --keccak-srs $KECCAK_SRS \
            --proving-key "${OUTER_IDENTIFIER}.pk" \
            --verification-key "${OUTER_IDENTIFIER}.vk" \
            --protocol "${OUTER_IDENTIFIER}.protocol" \
            --gate-config "${OUTER_IDENTIFIER}.gate_config" \
            --num-instance "${OUTER_IDENTIFIER}.num_instance" \
            $DRY_RUN_FLAG
    fi
    popd

    # Generate sample data for aggregation

    pushd $TEST_DATA_DIR
    # Generate VK for producing sample Groth16 proofs
    if [ ! -f "fake_vk_pi_${NUM_PI}.json" ]; then
        $PROVER groth16 generate-fake-vk \
            --num-public-inputs $NUM_PI \
            --app-vk-file "fake_vk_pi_${NUM_PI}.json"
    fi
    # Generate sample Groth16 proofs for an inner batch
    if [ ! -f "proofs_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json" ]; then
        $PROVER groth16 generate-proofs \
            --num-proofs $INNER_BATCH_SIZE \
            --app-vk-file "fake_vk_pi_${NUM_PI}.json" \
            --batch-file "proofs_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json"
    fi
    # Compute the BV instance file to provide to Keccak prover
    if [ ! -f "bv_instance_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json" ]; then
        # Dry run prover computes instance values only, no proof
        $PROVER universal-batch-verifier prove \
            --config $config \
            --srs $BV_SRS \
            --proving-key "${KEYS_DIR}/${BV_IDENTIFIER}.pk" \
            --gate-config "${KEYS_DIR}/${BV_IDENTIFIER}.gate_config" \
            --app-vk-proof-batch "proofs_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json" \
            --proof "dummy_proof.json" \
            --instance "bv_instance_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json" \
            --dry-run
    fi

    # Launch BV and Keccak provers concurrently

    # Clean up any existing proofs, instances
    rm -f proof_bv_${BV_IDENTIFIER}_*.json
    rm -f instance_bv_${BV_IDENTIFIER}_*.json
    rm -f proof_keccak_${KECCAK_IDENTIFIER}.json
    rm -f instance_keccak_${KECCAK_IDENTIFIER}.json
    rm -f proof_outer_${OUTER_IDENTIFIER}.json
    rm -f instance_outer_${OUTER_IDENTIFIER}.json
    rm -f calldata_outer_${OUTER_IDENTIFIER}.json

    # Log in new file
    log_file="${LOGS_DIR}/pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}_outer_${OUTER_BATCH_SIZE}_bv_deg_${BV_CIRCUIT_DEGREE}_keccak_deg_${KECCAK_CIRCUIT_DEGREE}_outer_deg_${OUTER_CIRCUIT_DEGREE}.log"
    echo "Launching BV and Keccak provers for config:" | tee -a $log_file
    cat $config | tee -a $log_file

    # BV instances argument:
    bv_instance_file="bv_instance_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json"
    bv_instances=`yes ' --ubv-instances '${bv_instance_file} | head -n ${OUTER_BATCH_SIZE}`

    # Start time
    start_time=$(date +%s%N)
    # Array to store PIDs
    pids=()

    # Launch BV provers
    for ((i=0; i<$OUTER_BATCH_SIZE; i++)); do
        $PROVER universal-batch-verifier prove \
            --config $config \
            --srs $BV_SRS \
            --proving-key "${KEYS_DIR}/${BV_IDENTIFIER}.pk" \
            --gate-config "${KEYS_DIR}/${BV_IDENTIFIER}.gate_config" \
            --app-vk-proof-batch "proofs_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json" \
            --proof "proof_bv_${BV_IDENTIFIER}_${i}.json" \
            --instance "instance_bv_${BV_IDENTIFIER}_${i}.json" \
            $DRY_RUN_FLAG &
        pids+=($!)
    done
    # Launch Keccak prover
    RUST_BACKTRACE=1 $PROVER keccak prove \
        --config $config \
        --srs $KECCAK_SRS \
        --proving-key "${KEYS_DIR}/${KECCAK_IDENTIFIER}.pk" \
        --gate-config "${KEYS_DIR}/${KECCAK_IDENTIFIER}.gate_config" \
        $bv_instances \
        --proof "proof_keccak_${KECCAK_IDENTIFIER}.json" \
        --instance "instance_keccak_${KECCAK_IDENTIFIER}.json" \
        $DRY_RUN_FLAG &
    pids+=($!)

    # Wait for all processes to complete
    for pid in "${pids[@]}"; do
        wait $pid
    done

    # End time
    end_time=$(date +%s%N)
    # Calculate elapsed time
    bv_keccak_elapsed_time=$(echo "scale=2; ($end_time - $start_time) / 1000000000" | bc)
    echo "BV and Keccak concurrent proving time $bv_keccak_elapsed_time" | tee -a $log_file

    # Outer prover

    # BV proof arguments:
    bv_proofs=""
    for ((i=0; i<$OUTER_BATCH_SIZE; i++)); do
        bv_proofs+=" --ubv-proofs proof_bv_${BV_IDENTIFIER}_${i}.json"
    done
    echo $bv_proofs
    # BV instances argument:
    bv_instance_file="bv_instance_pi_${NUM_PI}_inner_${INNER_BATCH_SIZE}.json"
    bv_instances=`yes ' --ubv-instances '${bv_instance_file} | head -n ${OUTER_BATCH_SIZE}`
    echo $bv_instances

    # Start time
    start_time=$(date +%s%N)
    $PROVER universal-outer prove \
        --config $config \
        --bv-protocol "${KEYS_DIR}/${BV_IDENTIFIER}.protocol" \
        --srs $OUTER_SRS \
        --gate-config "${KEYS_DIR}/${OUTER_IDENTIFIER}.gate_config" \
        --proving-key "${KEYS_DIR}/${OUTER_IDENTIFIER}.pk" \
        $bv_proofs \
        $bv_instances \
        --keccak-proof "proof_keccak_${KECCAK_IDENTIFIER}.json" \
        --keccak-instance "instance_keccak_${KECCAK_IDENTIFIER}.json" \
        --keccak-protocol "${KEYS_DIR}/${KECCAK_IDENTIFIER}.protocol" \
        --proof "proof_outer_${OUTER_IDENTIFIER}.json" \
        --instance "instance_outer_${OUTER_IDENTIFIER}.json" \
        --calldata "calldata_outer_${OUTER_IDENTIFIER}.json" \
        $DRY_RUN_FLAG

    # End time
    end_time=$(date +%s%N)
    # Calculate elapsed time
    outer_elapsed_time=$(echo "scale=2; ($end_time - $start_time) / 1000000000" | bc)
    echo "Outer proving time $outer_elapsed_time" | tee -a $log_file
done

set +x
set +e
