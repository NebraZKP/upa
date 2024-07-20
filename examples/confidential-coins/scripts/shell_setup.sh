# Add the `upa` and `confidential-coins` commands to the current shell.
[ "${ZSH_VERSION}" = "" ] && this_dir=`dirname ${BASH_SOURCE[0]}` || this_dir=`dirname ${(%):-%N}`
app_root_dir=`realpath ${this_dir}/..`

if [ -e ${app_root_dir}/node_modules/@nebrazkp ] ; then
    . ${app_root_dir}/node_modules/@nebrazkp/upa/scripts/shell_setup.sh
else
    . ${app_root_dir}/../../upa/scripts/shell_setup.sh
fi

export PATH=$PATH:${app_root_dir}/node_modules/.bin
