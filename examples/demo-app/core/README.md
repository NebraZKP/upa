# A demo app using NEBRA UPA

*This is an application for demonstration purposes only.*

Clients submit solutions to the equation:

  $$a * b = c * d + e + f$$

to a smart contract, which counts the number of solutions it has seen.
Elements $a$ and $b$ are not published on-chain, and instead a zk-proof is
used to show know knowledge of them.

The application uses the UPA proof aggregation framework.

## Requirements

- [circom](https://docs.circom.io/getting-started/installation/)

## Installation

Setup workspaces:
```console
$ yarn
```

Build `upa` dependency and perform one-time circuit setup.
```console
$ yarn setup
```
This will produce the files
- powersOfTau28_hez_final_08.ptau
- circuits/circuit.zkey
- circuits/snarkjs_verification_key.json
- circuits/upa_verification_key.json
- circuits/circuit_js/circuit.wasm
- contracts/CircuitVerifier.sol

Build demo-app:
```console
$ yarn build
```

# Testing

Run the unit tests with:
```console
$ yarn hardhat test
```

Run a test of the demo-app client (launches a hardhat node in the
background):
```console
$ ./scripts/test-demo-app
```

# Deployment

Enable the `demo-app` and `upa` commands in the current shell

```console
$ . scripts/shell_setup.sh
```

> Note: this command must be run in each shell, and can be run from any directory

Copy the `upa.instance` file for the UPA instance you wish to use into the
current directory.

Deploy the demo-app contract

```console
$ demo-app deploy --keyfile <keyfile-path>
```

which will create a `demo-app.instance` file in the current directory.
Clients interacting with this deployment will need the `upa.instance` and
`demo-app.instance` files.

> Note: some parameters can be specified via a `.env` file for convenience.  See `--help`.

> Note: the `upa dev` commands can be used to generate keyfiles for testing
> purposes, and fund them via hosted keys (e.g. for local development
> networks).
> This is *not* intended for use in production settings.

# Interacting with a demo-app instance

Ensure that the generated files in `circuits` match those created by the demo-app deployer.
> TODO: how do we make this process eaasier?

Place the `upa.instance` and `demo-app.instance` files in the current
directory.

Use the `demo-app` subcommands:
- `submit`
- `submit-once`
- `get-state`
- `submit-direct`

to interact with the contract.
