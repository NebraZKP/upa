import { command, option, number } from "cmd-ts";
import * as options from "./options";
import { readFileSync } from "fs";
import { Submission } from "../sdk/submission";

export const computeSubmissionProof = command({
  name: "compute-submission-proof",
  args: {
    submissionFile: options.submissionFile(),
    startIdx: option({
      type: number,
      long: "start-idx",
      short: "s",
      description: "Start index of proofs within the on-chain submission",
    }),
    numProofs: option({
      type: number,
      long: "num-proofs",
      short: "n",
      description: "Number of proofs to include in the SubmissionProof",
    }),
  },
  description:
    "Compute ProofReference for proof at given index within submission",
  handler: async function ({
    submissionFile,
    startIdx,
    numProofs,
  }): Promise<void> {
    const submission = Submission.from_json(
      readFileSync(submissionFile, "ascii")
    );
    const submissionProof = submission.computeSubmissionProof(
      startIdx,
      numProofs
    );
    if (!submissionProof) {
      console.log("SubmissionProof not required");
      return;
    }

    console.log(submissionProof.to_json());
  },
});
