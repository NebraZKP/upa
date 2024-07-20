import { command, positional, string } from "cmd-ts";
import {
  loadProofFileAsCircuitIdProofAndInputsArray,
  loadSingleProofFileAsCircuitIdProofAndInputs,
} from "./config";
import { JSONstringify } from "../sdk/utils";
import * as utils from "../sdk/utils";

export const computeProofId = command({
  name: "compute-proof-id",
  args: {
    proofFile: positional({
      type: string,
      displayName: "proof-file",
      description:
        `JSON file containing either a { VK, proof, input } or ` +
        `a { circuitId, proof, input }`,
    }),
  },
  description:
    `Compute the proofId for a single { VK, proof, input } or ` +
    `{ circuitId, proof, input }`,
  handler: async function ({ proofFile }) {
    const circuitIdProofAndInputsArray =
      loadSingleProofFileAsCircuitIdProofAndInputs(proofFile);
    const { circuitId, inputs } = circuitIdProofAndInputsArray;
    console.log(utils.computeProofId(circuitId, inputs));
  },
});

export const computeProofIds = command({
  name: "compute-proof-ids",
  args: {
    batchFile: positional({
      type: string,
      displayName: "proofs-file",
      description:
        `A JSON file with either a list of { VK, proof, input }` +
        ` or a list of { circuitId, proof, input }`,
    }),
  },
  description: "Locally compute the proofIds for a batch of proofs",
  handler: async function ({ batchFile }) {
    const circuitIdProofAndInputsArray =
      loadProofFileAsCircuitIdProofAndInputsArray(batchFile);
    const proofIds = circuitIdProofAndInputsArray.map((obj) =>
      utils.computeProofId(obj.circuitId, obj.inputs)
    );
    console.log(JSONstringify(proofIds));
  },
});
