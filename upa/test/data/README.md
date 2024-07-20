# Test data

`outer_2_2.verifier.yul`, along with the example proof and instance data, is
generated via the `prover` tool test scripts (see /prover).

`test.bin` created as:

```console
$ solc --yul test.yul --bin | tail -1 > test.bin
```

`outer_2_2.verifier.bin` created as:

```console
$ solc --yul outer_2_2.verifier.yul --bin | tail -1 > outer_2_2.verifier.bin
```
