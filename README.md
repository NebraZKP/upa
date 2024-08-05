NEBRA UPA
=========

NEBRA UPA is the blazingly fast, production ready universal proof aggregation engine built by Nebra team.

Currently, NEBRA UPA (v1.2) takes a batch of Groth16 proofs and aggregates them into a single Etheruem verifiable Halo2<KZG> proofs. NEBRA UPA supports the following 3 versions of Groth16:
- SnarkJS
- Gnark (without commitment)
- Gnark (with commitment)

[Docs](https://docs.nebra.one)
| [demo-app](https://demo-app.nebra.one/)
| [Telegram Chat](https://t.me/+niuKbgHIQ2lmN2Ex)

## For Developers: Integrating with NEBRA UPA

To integrate with NEBRA UPA, you can follow the [developer guide](https://docs.nebra.one/developer-guide). Integrating with NEBRA UPA allows you to lower the [ZKP verification cost](https://docs.nebra.one/developer-guide/gas-costs) by 10x and more. You can use the [NEBRA UPA SDK](https://www.npmjs.com/package/@nebrazkp/upa) to make the client side proof submission easier.

## For Contributors

The repo is arranged as follows:
- [`upa`](./upa) - Typescript SDK and tool to interact with UPA
- [`circuits`](./circuits) - Aggregation circuit code
- [`prover`](./prover) - Executable to create aggregation proofs
- [`examples`](./examples) - Example applications using UPA
- [`spec`](./spec) - Protocol and circuits specification
