#!/usr/bin/env bash

# Use UPA tool commands to convert gnark data to UPA types

# Build UPA tool, add command
UPA_DIR=`pwd`/../../../../../upa
pushd ${UPA_DIR}
pwd
yarn build
yarn
. scripts/shell_setup.sh
popd
pwd

mkdir -p _upa_format
pushd _upa_format

# 1 - base for filenames
# 2 - (optional) has commitment flag
function convert() {
    if ! [ "$2" = "" ] ; then
        upa convert vk-gnark \
                --gnark-vk ../$1.vk.json \
                --has-commitment \
                --vk-file $1.upa-vk.json
    else
        upa convert vk-gnark \
                --gnark-vk ../$1.vk.json \
                --vk-file $1.upa-vk.json
    fi

    upa convert proof-gnark \
            --gnark-proof ../$1.proof.json \
            --gnark-inputs ../$1.inputs.json \
            --proof-file $1.upa-proof-inputs.json
    # Check its validity
    upa dev groth16-verify \
            --vk-file $1.upa-vk.json \
            --proof-file $1.upa-proof-inputs.json \
            --log
}

convert brevis hasCommitment
convert no_commitment
convert private_commitment hasCommitment
