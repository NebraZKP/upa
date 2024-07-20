# include from the `prover` directory.

[ "${ZSH_VERSION}" = "" ] && prover_scripts_dir=`dirname ${BASH_SOURCE[0]}` || prover_scripts_dir=`dirname ${(%):-%N}`
. ${prover_scripts_dir}/../../upa/scripts/utils.sh

export RUST_LOG=info
export RUST_BACKTRACE=1

. ${prover_scripts_dir}/default_files.sh

function _setup_flags() {
    if [ "${DRY_RUN}" == "1" ] ; then
        PROVER_FLAGS="--dry-run"
    fi
}

# Include the keygen commands from keygen.sh
. ${prover_scripts_dir}/keygen.sh
