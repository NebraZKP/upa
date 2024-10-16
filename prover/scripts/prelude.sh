
# Prelude to all prover-related scripts
#
# Sets some default file names, checks the PROVER variable, and sets up
# PROVER_FLAGS.

[ "${ZSH_VERSION}" = "" ] && prover_scripts_dir=`dirname ${BASH_SOURCE[0]}` || prover_scripts_dir=`dirname ${(%):-%N}`

# Include upa (SDK) utils
. ${prover_scripts_dir}/../../upa/scripts/utils.sh

# Include default file names
. ${prover_scripts_dir}/default_files.sh

echo CONFIG=${CONFIG}

# RUST runtime flags
export RUST_LOG=info
export RUST_BACKTRACE=1

# Checks that the PROVER variable is set correctly, and sets up PROVER_FLAGS
# based on env vars.
if [ "${PROVER}" == "" ] ; then
    echo "No prover.  Did you build the prover executable?"
    exit 1
fi

if [ "${DRY_RUN}" == "1" ] ; then
    PROVER_FLAGS="--dry-run"
fi
