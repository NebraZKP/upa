# UPA `prover` tool

A `prover` command providing all UPA proof-related functionality.  The tool
is intended to be self-documenting.  See `prover --help` for full details.

## Install

From this directory:

```console
$ cargo build --release
$ alias prover=`pwd`/../target/release/prover
```

## Configuration

Create a directory to hold the UPA config and deployment data.  Create or copy
the relevant config file (`upa_config.json`) into this directory.  See
examples in [tests] directory.

```console
$ mkdir -p upa
$ cd upa
$ cp <this-repo-root>/prover/tests/config_2.json upa_config.json
```

## Enable the tools in the current shell

```console
$ source <this-repo-root>/prover/scripts/shell-setup.sh
```

## SRS files

Create files `bv.srs`, `keccak.srs` and `outer.srs` holding the SRS for each
circuit. To generate dummy srs data for all configs in the current directory,
run the `dummy_srs_setup` script.

```console
$ dummy_srs_setup
```

(Use the `--help` flag to see all options)

## Keygen

Run the `keygen` command to create keys at the expected locations.

```console
$ keygen
```

(Use the `--help` flag to see all options)

## Benchmark

A script is included for benchmarking the total aggregation time for a given configuration. Total aggregation time is defined as the time required to *concurrently* run all UBV and Keccak provers, plus the time required to run the Outer prover.

To use this script, create one or more UPA config files in the `prover/configs` directory (example configs for some small batch sizes can be found there) and run the script from the `prover` directory using
```console
[DRY_RUN=1] ./scripts/aggregation_benchmark.sh
```
(The `DRY_RUN` environment variable tests the script execution without performing heavy computations like keygen or proving.) The benchmark will be run for *all* UPA config files present in the `prover/configs` directory. Results will be logged in the `prover/logs` directory.

### Note
- All UBV and Keccak provers are run concurrently, which may result in high memory usage. We recommend running the benchmark on a machine with at least 128 GB RAM.
- The script creates proving keys, verifying keys, and related artifacts in the `prover/_keys` directory. This may use a lot of disk space, as much as 100 GB per UPA config file present in `prover/configs`.

### WARNING
The keys produced in `prover/_keys` are *NOT SECURE PROVING KEYS*. They are intended only for performance benchmarks and *NEVER FOR PRODUCTION USE*.
