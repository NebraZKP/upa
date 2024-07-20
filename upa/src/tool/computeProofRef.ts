import { command, option, number } from "cmd-ts";
import * as options from "./options";
import { readFileSync, writeFileSync } from "fs";
import { Submission } from "../sdk/submission";

export const computeProofRef = command({
  name: "compute-proof-ref",
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
