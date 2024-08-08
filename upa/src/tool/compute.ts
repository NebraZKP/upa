import {
  command,
  string,
  option,
  positional,
  number,
  subcommands,
} from "cmd-ts";
import * as options from "./options";
import { readFileSync, writeFileSync } from "fs";
import { utils } from "../sdk";
import {
  loadAppVK,
  loadProofFileAsCircuitIdProofAndInputsArray,
  loadSingleProofFileAsCircuitIdProofAndInputs,
} from "./config";
import { Submission } from "../sdk/submission";
import { JSONstringify } from "../sdk/utils";

const computeCircuitId = command({
  name: "compute-circuit-id",
  args: {
    vkFile: positional({
      type: string,
      displayName: "vk-file",
      description: "JSON VK file for the circuit",
    }),
  },
  description: "Use the UPA contract to compute the circuitId of a given VK",
  handler: function ({ vkFile }): void {
    const vk = loadAppVK(vkFile);
    const circuitId = utils.computeCircuitId(vk);

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(circuitId);
  },
});

const computeProofId = command({
  name: "proof-id",
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

const computeProofIds = command({
  name: "proof-ids",
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

const computeProofRef = command({
  name: "proof-ref",
  args: {
    submissionFile: options.submissionFile(),
    proofIdx: option({
      type: number,
      long: "proof-idx",
      short: "i",
      description: "Index of proof within the submission",
    }),
    proofReferenceFile: options.proofReferenceFile(),
  },
  description:
    "Compute ProofReference for proof at given index within submission",
  handler: async function ({
    submissionFile,
    proofIdx,
    proofReferenceFile,
  }): Promise<void> {
    const submission = Submission.from_json(
      readFileSync(submissionFile, "ascii")
    );
    const proofRef = submission.computeProofReference(proofIdx);
    if (!proofRef) {
      console.log("ProofReference not required");
      return;
    }

    if (proofReferenceFile) {
      writeFileSync(proofReferenceFile, proofRef.to_json());
    } else {
      console.log(proofRef.to_json());
    }
  },
});

export const compute = subcommands({
  name: "compute",
  description: "Commands computing objects used for submitting proofs",
  cmds: {
    "circuit-id": computeCircuitId,
    "proof-id": computeProofId,
    "proof-ids": computeProofIds,
    "proof-ref": computeProofRef,
  },
});
