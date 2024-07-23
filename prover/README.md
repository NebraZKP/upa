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
