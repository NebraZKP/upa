import { command, string, option, flag, boolean, subcommands } from "cmd-ts";
import {
  loadGnarkProof,
  loadGnarkInputs,
  loadGnarkVK,
  loadSnarkjsVK,
  loadSP1ProofFixture,
} from "./config";
import {
  Groth16Proof,
  Groth16VerifyingKey,
  ProofAndInputs,
} from "../sdk/application";
import { JSONstringify } from "../sdk/utils";
import * as fs from "fs";
import { config } from ".";
import { convertSp1ProofFixture } from "../sdk/sp1";

const convertProofGnark = command({
  name: "proof-gnark",
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

const convertProofSnarkjs = command({
  name: "proof-snarkjs",
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

const convertVkSnarkJs = command({
  name: "vk-snark-js",
  args: {
    snarkjsVkFile: option({
      type: string,
      long: "snarkjs-vk",
      description:
        "The verifying key output by SnarkJS, to be converted into\
       a UPA VK",
    }),
    upaVkFile: option({
      type: string,
      long: "vk-file",
      description: "The destination for output UPA verifying key",
    }),
  },
  description: "Convert Groth16 verifying key from SnarkJS to UPA format",
  handler: async function ({ snarkjsVkFile, upaVkFile }): Promise<void> {
    const snarkjsVk = loadSnarkjsVK(snarkjsVkFile);

    const upaVk = Groth16VerifyingKey.from_snarkjs(snarkjsVk);

    fs.writeFileSync(upaVkFile, JSON.stringify(upaVk));
  },
});

const convertVkGnark = command({
  name: "vk-gnark",
  args: {
    gnarkVkFile: option({
      type: string,
      long: "gnark-vk",
      description:
        "The verifying key output by Gnark, to be converted into\
       a UPA VK",
    }),
    hasCommitment: flag({
      type: boolean,
      long: "has-commitment",
      description:
        "Whether this VK belongs to a circuit that uses LegoSnark commitments",
    }),
    upaVkFile: option({
      type: string,
      long: "vk-file",
      description: "The destination for output UPA verifying key",
    }),
  },
  description: "Convert Groth16 verifying key from Gnark to UPA format",
  handler: async function ({
    gnarkVkFile,
    hasCommitment,
    upaVkFile,
  }): Promise<void> {
    const gnarkVk = loadGnarkVK(gnarkVkFile);

    const upaVk = Groth16VerifyingKey.from_gnark(gnarkVk, hasCommitment);

    fs.writeFileSync(upaVkFile, JSON.stringify(upaVk));
  },
});

const convertVkProofsAndInputsFile = command({
  name: "vk-proofs-inputs",
  args: {
    vkAndProofsFile: option({
      type: string,
      long: "vk-proofs-inputs-file",
      description:
        "File containing a JSON list of objects { vk, proof, inputs }",
    }),
    outCircuitIdProofsAndInputsFile: option({
      type: string,
      long: "circuitid-proofs-inputs-file",
      description:
        "Output file containing JSON list of objects " +
        "{ circuitId, proof, inputs }",
    }),
  },
  description:
    "Converts a JSON list of objects { vk, proof, inputs } " +
    "into a list of { circuitId, proof, inputs }.",
  handler: function ({
    vkAndProofsFile: vkProofsAndInputsFile,
    outCircuitIdProofsAndInputsFile,
  }): void {
    // Read vkProofsAndInputs file
    const circuitIdProofAndInputs =
      config.loadProofFileAsCircuitIdProofAndInputsArray(vkProofsAndInputsFile);

    // Write to output file
    fs.writeFileSync(
      outCircuitIdProofsAndInputsFile,
      JSONstringify(circuitIdProofAndInputs, 2)
    );
  },
});

// Convert JSON file consisting of
// { vkey, publicValuesDiges, proof } generated by SP1
// vkey is the SP1 program verification key
// publicValuesDigest is hash of the public values (see SP1 SDK/contracts)
// proof is the encoded Groth16 proof (see SP1 SDK/contracts)
// to { vk, proof, inputs} UPA File Format
const convertSp1 = command({
  name: "proof-sp1",
  args: {
    sp1ProofFixtureFile: option({
      type: string,
      long: "sp1-proof-fixture",
      description:
        "JSON file { vkey, publicValuesDigest, proof } generated by SP1",
    }),
    sp1Version: option({
      type: string,
      long: "sp1-version",
      description: "SP1 version",
    }),
    upaVkProofInputsFile: option({
      type: string,
      long: "upa-file",
      description: "The destination for output UPA file",
    }),
  },
  description:
    "Convert artifacts generated by SP1 Groth16 wrapper to UPA format",
  handler: async function ({
    sp1ProofFixtureFile,
    sp1Version,
    upaVkProofInputsFile,
  }): Promise<void> {
    const sp1ProofFixture = loadSP1ProofFixture(sp1ProofFixtureFile);

    const upaVkProofInputs = convertSp1ProofFixture(
      sp1ProofFixture,
      sp1Version
    );

    fs.writeFileSync(upaVkProofInputsFile, JSONstringify(upaVkProofInputs));
  },
});

export const convert = subcommands({
  name: "convert",
  description: "Commands converting between proof or vk formats",
  cmds: {
    "proof-gnark": convertProofGnark,
    "proof-snarkjs": convertProofSnarkjs,
    "proof-sp1": convertSp1,
    "vk-snarkjs": convertVkSnarkJs,
    "vk-gnark": convertVkGnark,
    "vk-proofs-inputs": convertVkProofsAndInputsFile,
  },
});
