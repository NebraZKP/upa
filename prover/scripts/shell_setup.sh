# Add the `prover` command to the current shell.
[ "${ZSH_VERSION}" = "" ] && this_dir=`dirname ${BASH_SOURCE[0]}` || this_dir=`dirname ${(%):-%N}`
repo_dir=`realpath ${this_dir}/../..`
PROVER=${repo_dir}/target/release/prover
export PATH=$PATH:"${repo_dir}/target/release:${repo_dir}/node_modules/.bin"

# Include all the prover utils commands, such as `start_provers`.  This also
# include all default file location variables.
. ${this_dir}/utils.sh
