
if [ "${prover_scripts_dir}" == "" ] ; then
    echo This scripts is only intended to be included via shell_setup.sh.
    return 1
fi

# Assign prover if PROVER is not set
if [ -z "${PROVER}" ]; then
    prover=`realpath ${this_dir}/../../target/release/prover`
else
    prover="${PROVER}"
fi

function keygen_universal_bv() {
    _setup_flags
    if ! [ -e ${UBV_VK} ] ; then
        ${prover} universal-batch-verifier keygen \
               ${PROVER_FLAGS}
    else
        echo Skipping BV keygen.  ${UBV_VK} already exists.
    fi
}

function keygen_universal_keccak() {
    _setup_flags
    if ! [ -e ${KECCAK_VK} ] ; then
        ${prover} keccak keygen \
                ${PROVER_FLAGS}
    else
        echo Skipping variable length KECCAK keygen.  ${KECCAK_VK} already exists.
    fi
}

function keygen_universal_outer() {
    _setup_flags
    if ! [ -e ${OUTER_VK} ] ; then
        ${prover} universal-outer keygen \
            ${PROVER_FLAGS}
    else
        echo Skipping OUTER keygen.  ${OUTER_VK} already exists.
    fi

    # Generate the outer contract on-chain verifier
    if ! [ -e ${OUTER_VERIFIER_BIN} ] ; then
        if [ "${DRY_RUN}" == "1" ] ; then
            cp ${prover_scripts_dir}/../../upa/test/data/test.bin ${OUTER_VERIFIER_BIN}
        else
            # Attempt to set the correct solidity version.
            svm use 0.8.17
            # Get the installed version of Solidity and strip out the part after "+"
            solc_version=$(solc --version | awk '/Version:/ {print $2}' | awk -F '+' '{print $1}')


            if [[ $solc_version != "0.8.17" ]]; then
                echo "Error: Expected solc version 0.8.17 but found version $solc_version."
                echo "Try \`svm use 0.8.17\`"
                exit 1
            fi

            ${prover} universal-outer generate-verifier
            solc --yul ${OUTER_VERIFIER_YUL} --bin | tail -1 > ${OUTER_VERIFIER_BIN}
        fi
    fi
}

function keygen() {
    keygen_universal_bv
    keygen_universal_keccak
    keygen_universal_outer
}
