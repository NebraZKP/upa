export UPA_LOG_LEVEL=debug

# Get location of this script
[ "${ZSH_VERSION}" = "" ] && this_dir=`dirname ${BASH_SOURCE[0]}` || this_dir=`dirname ${(%):-%N}`
this_dir=`realpath ${this_dir}`

# Root of the upa repo
UPA_DIR=`realpath ${this_dir}/../..`

#1 pid
# timeout
function wait_for_pid() {
    pid=$1
    timeout=$2
    xs=`seq -s " " 1 ${timeout}`
    for i in $xs ; do
        if ! (ps $pid > /dev/null 2>&1) ; then
            break
        fi
        echo "Waiting for pid $pid to die ..."
        sleep 1
    done
    if [ "$i" == "$timeout" ] ; then
        echo "Process $pid did not die after $timeout seconds."
        exit 1
    fi
}

# 1 - name
# 2 - start command
# 3 - check command
# 4 - (optional) working dir
function start_daemon() {
    start="$2"
    check="$3"
    log_file="$1.log"

    if (${check}) ; then
        echo "$1 already started ..."
        return 0
    fi

    if [ "${DOCKER}" == "1" ] ; then
        cid_file="$1.cid"
        if [ -e ${cid_file} ] ; then
            echo "cid file ${cid_file} already exists.  shutting down existing server..."
            stop_daemon $1
        fi

        cid=$(eval "${start}")
        echo ${cid} > ${cid_file}
        echo "launched $1 docker container with cid: ${cid}"
        docker logs -f ${cid} &> ${log_file} &

        while ! (${check}) ; do
            if ! [ "$( docker container inspect -f '{{.State.Running}}' ${cid} )" = "true" ] ; then
                echo error: process terminated
                return 1
            fi
            echo "waiting for $1 (cid: ${cid}) ..."
            sleep 0.5
        done
    else
        pid_file="$1.pid"
        if [ -e ${pid_file} ] ; then
            echo "pid file ${pid_file} already exists.  shutting down existing server..."
            stop_daemon $1
        fi

         if [ "$4" == "" ] ; then
            eval "${start} > ${log_file} 2>&1 &"
            pid=$!
        else
            pushd $4
            eval "${start} > ${log_file} 2>&1 &"
            pid=$!
            popd
        fi
        echo ${pid} > ${pid_file}
        echo "launched $1 with pid: ${pid}"
        while ! (${check}) ; do
            if ! (ps ${pid} > /dev/null 2>&1) ; then
                echo error: process terminated
                cat ${log_file}
                return 1
            fi
            echo "waiting for $1 (pid: ${pid}) ..."
            sleep 0.5
        done
    fi

    echo "$1 is up"
}

# 1 - name
function stop_daemon() {
    pid_file="$1.pid"
    cid_file="$1.cid"
    if [ "${DOCKER}" == "1" ] ; then
        cid=$(cat ${cid_file})
        docker container kill ${cid}
        rm ${cid_file}
    else
        if ! [ -e ${pid_file} ] ; then
            echo "$1 has no PID file: ${pid_file}"
            return
        fi

        pid=`cat ${pid_file}`
        kill ${pid} || echo -n
        rm ${pid_file}
    fi
}

# 1 - port
function check_hardhat_node() {
    port=$1
    [ "${port}" == "" ] && port=8545
    curl -H "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"net_version\",\"params\":[],\"id\":0}" http://localhost:${port} > /dev/null 2>&1
}

# 1 - port to use
# 2 - custom launch command
function start_hardhat_node() {
    if ! [ "$1" == "" ] ; then
        port=$1
        node_flags="--port ${port}"
    fi

    launch_command=$2
    if [ "${launch_command}" == "" ] ; then
        # This must be run inside the upa dir, or Hardhat
        # complains we're not in a Hardhat project.
        launch_command="${UPA_DIR}/node_modules/.bin/hardhat node ${node_flags}"
        start_dir=${UPA_DIR}/upa
    fi

    start_daemon \
        Hardhat \
        "${launch_command}" \
        "check_hardhat_node ${port}" \
        "${start_dir}"
}

function stop_hardhat_node() {
    stop_daemon Hardhat
}

# 1 - Batch Size
# 2 - Latency
# 3 - Keyfile
# 4 - Password (optional)
function start_dev_aggregator() {
    flags=""
    if ! [ "$4" == "" ] ; then
        flags="--password $4"
    fi
    upa dev-aggregator \
        --batch-size $1 \
        --latency $2 \
        --keyfile $3 \
        ${flags} > dev_aggregator.log 2>&1 &
    pid=$!
    echo ${pid} > "dev_aggregator.pid"
    echo "Launched dev aggregator with pid: ${pid}"
}

function stop_dev_aggregator() {
    if ! [ -e "dev_aggregator.pid" ] ; then
        echo "No Dev Aggregator Active"
        return
    fi

    pid=`cat "dev_aggregator.pid"`
    kill ${pid} || echo -n
    rm "dev_aggregator.pid"
}
