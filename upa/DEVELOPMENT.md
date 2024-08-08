# Development

## Build

In this directory:

```console
$ yarn
$ yarn build
```

## Contracts

See [note on contracts](contracts/README.md).

## The `upa` command

To make the `upa` command available in the current shell:

```console
$ . scripts/shell_setup.sh
```

The upa command is intended to be self-documenting. Check the output of
`upa` for a description of available commands and options.

## Testing and development

```console
# Unit tests
$ yarn hardhat test

# Linter
$ yarn lint

# Formatter
$ yarn format

# Run Slither analysis
$ yarn slither

# Update db file `slither.db.json` to record false positives to be excluded
# in future slither runs.
$ ./scripts/run_slither --triage-mode

# UPA command tests script
$ ./scripts/test_upa
```

## Custom storage locations

Use [this playground](https://ethfiddle.com/) and this contract:

```solidity
pragma solidity ^0.4.24;

contract Playground {
  function computeStorageLocation(string s1) pure returns (bytes32) {
    return keccak256(abi.encode(uint256(keccak256(s1)) - 1)) & ~bytes32(uint256(0xff));
  }
}
```

to compute custom storage locations.  `UpaContractName` uses the string
`ContractNameStorage`.

## Publishing

### Check version numbers

### Login to npm

```console
$ npm login
```

### Build and publish the package

```console
$ yarn pack
$ npm publish package.tgz --access public
```
