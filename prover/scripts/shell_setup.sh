# Add the `prover` command to the current shell.
[ "${ZSH_VERSION}" = "" ] && this_dir=`dirname ${BASH_SOURCE[0]}` || this_dir=`dirname ${(%):-%N}`
repo_dir=`realpath ${this_dir}/../..`

if [ "${PROVER}" == "" ] ; then
    export PROVER=${repo_dir}/target/release/prover
fi
export PATH=$PATH:"${repo_dir}/target/release:${repo_dir}/node_modules/.bin:${this_dir}"
