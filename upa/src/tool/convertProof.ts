import { command, string, option } from "cmd-ts";
import { loadGnarkProof, loadGnarkInputs } from "./config";
import { Groth16Proof, ProofAndInputs } from "../sdk/application";
import { JSONstringify } from "../sdk/utils";
import * as fs from "fs";

export const convertProofGnark = command({
  name: "convert-proof-gnark",
  args: {
    gnarkProofFile: option({
      type: string,
      long: "gnark-proof",
      description:
        "The proof output by Gnark, to be converted into\
       a UPA proof",
    }),
    gnarkInputsFile: option({
      type: string,
      long: "gnark-inputs",
      description:
        "The public inputs output by Gnark, belonging to above proof",
    }),
    upaProofFile: option({
      type: string,
      long: "proof-file",
      description: "The destination for output UPA proof with inputs",
    }),
  },
  description: "Convert Groth16 verifying key from Gnark to UPA format",
  handler: async function ({
    gnarkProofFile,
    gnarkInputsFile,
    upaProofFile,
  }): Promise<void> {
    const proofAndInputStrings = new ProofAndInputs(
      Groth16Proof.from_gnark(loadGnarkProof(gnarkProofFile)),
      loadGnarkInputs(gnarkInputsFile).map(BigInt)
    );

    fs.writeFileSync(upaProofFile, JSONstringify(proofAndInputStrings));
  },
});

export const convertProofSnarkjs = command({
  name: "convert-proof-snarkjs",
  args: {
    snarkJSProofAndInputsFile: option({
      type: string,
      long: "snarkjs-proof",
      description:
        "The proof output by SnarkJS, to be converted into\
       a UPA proof, together with its inputs",
    }),
    upaProofFile: option({
      type: string,
      long: "proof-file",
      description: "The destination for output UPA proof with inputs",
    }),
  },
  description: "Convert Groth16 verifying key from SnarkJS to UPA format",
  handler: async function ({
    snarkJSProofAndInputsFile,
    upaProofFile,
  }): Promise<void> {
    const { proof, publicSignals } = JSON.parse(
      fs.readFileSync(snarkJSProofAndInputsFile, "ascii")
    );
    const proofAndInputStrings = new ProofAndInputs(
      Groth16Proof.from_snarkjs(proof),
      publicSignals.map(BigInt)
    );

    fs.writeFileSync(upaProofFile, JSONstringify(proofAndInputStrings));
  },
});
