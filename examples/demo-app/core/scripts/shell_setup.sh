# Add the `upa` and `demo-app` commands to the current shell.
[ "${ZSH_VERSION}" = "" ] && this_dir=`dirname ${BASH_SOURCE[0]}` || this_dir=`dirname ${(%):-%N}`
demo_app_root_dir=`realpath ${this_dir}/..`

if [ -e ${demo_app_root_dir}/node_modules/@nebrazkp ] ; then
    . ${demo_app_root_dir}/node_modules/@nebrazkp/upa/scripts/shell_setup.sh
else
    . ${demo_app_root_dir}/../../../upa/scripts/shell_setup.sh
fi

export PATH=$PATH:${demo_app_root_dir}/node_modules/.bin
