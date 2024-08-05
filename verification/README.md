# UPA Deployment Verification
This script allows third parties to verify the provenance of the smart contract that verifies aggregated proofs in NEBRA's UPA. Starting from public data and using open-source, audited tools, it computes the verifying key for checking aggregated proofs. It derives from this verifying key the bytecode of a smart contract for verifying aggregated proofs on-chain and checks that this matches the actual byte code used by the current UPA deployment.

In other words, this script provides transparency for the on-chain aggregated proof verifier by demonstrating that NEBRA deployed a verifier contract for the audited, open-source UPA circuits.

# Instructions

The script is intended to require a minimum of expertise. Follow the instructions below and feel free to reach out to NEBRA on [Telegram](https://t.me/c/1924667284/3) for support.

## System Requirements
- `> 110 GB` available disk space
- 75 GB RAM
- Valid RPC Endpoint

You should be aware that:
- The script begins by downloading a large file (100 GB). (This is a [Perpetual Powers of Tau](https://pse.dev/en/projects/perpetual-powers-of-tau) SRS file)
- The script performs CPU-intensive computations. Expect it to use all available threads and up to 75 GB system memory.
- The script performs one RPC query to obtain the actual deployed bytecode for the current UPA instance.

## Preparation
Prepare your environment for verification with the current UPA deployment, configuration, and a valid RPC endpoint.

1. Go to https://docs.nebra.one/developer-guide/deployments
2. Copy the current `upa.instance` into a JSON file named `upa_instance.json` located in the current `verification` directory. (If you use a different filename, modify the `.env` file accordingly.)
3. Copy the current `upa.config` into a JSON file named `upa_config.json` located in the current directory. (If you use a different filename, modify the `.env` file accordingly.)
4. Assign the `RPC_ENDPOINT` variable in the `.env` file with an RPC endpoint. (A free endpoint is fine; only a single query will be made.)

## Verification
From the current `verification` directory, run the script using the command
```console
$ ./key_verification.sh
```
The script requires a specific version (`0.8.17`) of the `solc` compiler. It will install the Solidity Version Manager [tool](https://github.com/alloy-rs/svm-rs) and prompt the user to allow it to use this version. After selecting `Y` no further user input is required. You may leave the script to run in the background.

When finished, the script will display a success/failure message. If you receive a failure message, please reach out to NEBRA for support.
