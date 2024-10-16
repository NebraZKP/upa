# Dummy proof

The dummy verification key `dummy_vk.upa.json` was generated as an instance of `demo-app`, that is, in the `examples/demo-app` directory, run
```bash
$ ./scripts/build_standalone
```
and then convert the resulting `circuit.zkey` first with `snarkjs zkey export verificationkey` and then with the `upa convert vk-snarkjs` tool.

Similarly, the `dummy_proof.upa.json` containing the proofs and inputs was generated by running
```typescript
const dummyProofData = await snarkjs.groth16.fullProve(
    inputs,
    circuitWasm,
    circuitZkey
  );
```
on some randomly sampled `inputs`, where `circuitWasm` and `circuitZkey` are read from the `circuit.wasm` and `circuit.zkey` files generated before. They resulting `dummyProofData` is later converted using the `upa convert snarkjs-proof` tool.
