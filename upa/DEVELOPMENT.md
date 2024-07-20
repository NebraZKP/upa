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
