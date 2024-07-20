import { command, string, option } from "cmd-ts";
import * as fs from "fs";
import { config } from ".";
import { JSONstringify } from "../sdk/utils";

export const convertVkProofsAndInputsFile = command({
  name: "convert-vk-proofs-inputs",
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
      short: "i",
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
