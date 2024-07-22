#!/usr/bin/env bash

set -x
set -e

# Check that the preparation steps have been completed
source .env
if [ -z "$RPC_ENDPOINT" ]; then
    echo "Please provide an RPC endpoint in the .env file"
    exit 1
fi
if [ ! -f "$UPA_CONFIG" ]; then
    echo "Missing UPA Config file. Refer to README for preparation steps."
    exit 1
fi
if [ ! -f "$UPA_INSTANCE" ]; then
    echo "Missing UPA Instance file. Refer to README for preparation steps."
    exit 1
fi

# solc v0.8.17 is required below. Prompt its installation at the beginning.
TOOLCHAIN="stable"
rustup run $TOOLCHAIN cargo install --locked svm-rs && svm install 0.8.17 && svm use 0.8.17

# No further user input is required after this step.
echo "No further input required. Running the script..."

if [ ! -d "_verification_artifacts" ]; then
    mkdir _verification_artifacts
fi
ROOT_DIR="$(pwd)"
ARTIFACTS_DIR="$(pwd)/_verification_artifacts"

# 1. Download the Perpetual Powers of Tau challenge file
CHALLENGE_0087_LINK="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/challenge_0087"
CHALLENGE_FILE="$ARTIFACTS_DIR/challenge_0087"
if [ ! -f "$CHALLENGE_FILE" ]; then
    echo "Downloading challenge_0087 file. File size is 96 GB. This may take a long time."
    curl -o "$CHALLENGE_FILE" "$CHALLENGE_0087_LINK"
else
    echo "challenge_0087 file already exists"
fi

# 2. Transform the challenge file to a Halo2-compatible format

HALO2_CONVERSION_SOURCE="https://github.com/nebraZKP/phase2-bn254.git"
# TODO: Update rev
HALO2_CONVERSION_REV="4958b18184e836920f392984a68d770efdad9d78"
if [ ! -d "phase2-bn254" ]; then
    git clone "$HALO2_CONVERSION_SOURCE"
fi
pushd $ROOT_DIR/phase2-bn254/powersoftau
git fetch
git checkout "$HALO2_CONVERSION_REV"
export RUST_LOG=info
RUSTFLAGS="-Awarnings" cargo build --release --bin convert_to_halo2
CONVERSION_TOOL="$(pwd)/target/release/convert_to_halo2"

BV_CIRCUIT_DEGREE=$(jq -r '.bv_config.degree_bits' "$ROOT_DIR/$UPA_CONFIG")
KECCAK_CIRCUIT_DEGREE=$(jq -r '.keccak_config.degree_bits' "$ROOT_DIR/$UPA_CONFIG")
OUTER_CIRCUIT_DEGREE=$(jq -r '.outer_config.degree_bits' "$ROOT_DIR/$UPA_CONFIG")

# Halo2 SRS files are generated in a `params` directory
BV_SRS="$ARTIFACTS_DIR/params/kzg_bn254_$BV_CIRCUIT_DEGREE.srs"
KECCAK_SRS="$ARTIFACTS_DIR/params/kzg_bn254_$KECCAK_CIRCUIT_DEGREE.srs"
OUTER_SRS="$ARTIFACTS_DIR/params/kzg_bn254_$OUTER_CIRCUIT_DEGREE.srs"

if [ ! -f "$BV_SRS" ] || [ ! -f "$KECCAK_SRS" ] || [ ! -f "$OUTER_SRS" ]; then
    echo "Generating SRS files. This may take a long time."
    $CONVERSION_TOOL $CHALLENGE_FILE 2097152 \
        $BV_CIRCUIT_DEGREE \
        $KECCAK_CIRCUIT_DEGREE \
        $OUTER_CIRCUIT_DEGREE
else
    echo "SRS files already exist"
fi
popd

# 3. Generate Outer Circuit Verifying Key

# Build UPA Prover Tool
# TODO: Replace with open source prover when available
# For now, expects that I've cloned the Saturn repo in working directory
pushd "../prover"
    # TODO: Rev?
    # PROVER_REV="06488f5659a539dc79c77ead61158fe60944acf0"
    # git fetch # Uncomment when public
    # git checkout "$PROVER_REV"
    cargo build --release
PROVER_TOOL="$(pwd)/../target/release/prover"
popd


# Generate Keys, Yul Verifier, Bytecode
pushd $ARTIFACTS_DIR
if [ ! -f "outer.vk" ]; then
    echo "Generating Outer Circuit Verifying Key. This may take a long time."
    $PROVER_TOOL universal-outer keygen \
        --config "$ROOT_DIR/$UPA_CONFIG" \
        --outer-srs $OUTER_SRS \
        --bv-srs $BV_SRS \
        --keccak-srs $KECCAK_SRS \
        --vk-only
else
    echo "outer.vk file already exists"
fi

# 4. Generate the outer circuit verifier Yul code
if [ ! -f "outer.verifier.yul" ]; then
    echo "Generating Outer Circuit Verifier Yul code"
    $PROVER_TOOL universal-outer generate-verifier \
        --outer-srs $OUTER_SRS \
        --gate-config "outer.specs" \
        --verification-key "outer.vk" \
        --num-instance "outer.instance_size"
else
    echo "outer.verifier.yul file already exists"
fi

# 5. Compile to EVM bytecode

# Yul output of previous step contains instructions for contract creation
# followed by the contract code. We only want the contract code.
# This python script separates the two.
CONTRACT_CREATION_CODE="$ARTIFACTS_DIR/outer.verifier.creation.yul"
CONTRACT_RUNTIME_CODE="$ARTIFACTS_DIR/outer.verifier.code.yul"
python3 "$ROOT_DIR/split_yul_code.py" "$ARTIFACTS_DIR/outer.verifier.yul" "$CONTRACT_CREATION_CODE" "$CONTRACT_RUNTIME_CODE"
# Compile the runtime code to EVM bytecode
solc --yul $CONTRACT_RUNTIME_CODE --bin | tail -1 > "expected_verifier.evm"


# 6. Compare to deployed bytecode
DEPLOYED_VERIFIER="$(pwd)/deployed_verifier.evm"
# Build UPA Tool
pushd "$ROOT_DIR/../upa"
    pwd
    yarn
    yarn build
    source scripts/shell_setup.sh
    upa get-verifier-bytecode \
        --endpoint $RPC_ENDPOINT \
        --instance "$ROOT_DIR/$UPA_INSTANCE" > $DEPLOYED_VERIFIER
popd

# Remove quotation marks and leading `0x` from the deployed bytecode
cat $DEPLOYED_VERIFIER | tr -d '"' > temp_file && mv temp_file $DEPLOYED_VERIFIER
cat $DEPLOYED_VERIFIER | sed 's/^0x//' > temp_file && mv temp_file $DEPLOYED_VERIFIER

# Compare the expected verifier bytecode with the deployed bytecode
cmp --silent "expected_verifier.evm" "$DEPLOYED_VERIFIER"
identical=$?

# Check the exit status and print the appropriate message
if [ $identical -eq 0 ]; then
    echo "The deployed bytecode matches the generated bytecode"
    echo "========================================"
    echo "====    Verification Successful!    ===="
    echo "========================================"
else
    echo "========================================"
    echo "====     Verification Failed!       ===="
    echo "========================================"
    echo "Please contact NEBRA via the Telegram channel:"
    echo "https://t.me/c/1924667284/3"
fi
popd

set +e
set +x
