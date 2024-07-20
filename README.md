NEBRA UPA
=========

UPA is the proof aggregation engine built by Nebra team.

Currently, UPA takes a batch of Groth16 proofs and aggregates them into a single Etheruem verifiable Halo2<KZG> proofs.

The repo is arranged as follows:
- [`upa`](./upa) - Typescript SDK and tool to interact with UPA
- [`circuits`](./circuits) - Aggregation circuit code
- [`prover`](./prover) - Executable to create aggregation proofs
- [`examples`](./examples) - Example applications using UPA
- [`spec`](./spec) - Protocol and circuits specification