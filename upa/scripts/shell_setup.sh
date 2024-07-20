# Add the `upa` command to the current shell.
[ "${ZSH_VERSION}" = "" ] && this_dir=`dirname ${BASH_SOURCE[0]}` || this_dir=`dirname ${(%):-%N}`
root_dir=`realpath ${this_dir}/..`

export PATH=$PATH:$root_dir/node_modules/.bin
