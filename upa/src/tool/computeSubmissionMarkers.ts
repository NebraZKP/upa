import { command, option, number, multioption, array, string } from "cmd-ts";
import { readFileSync } from "fs";
import {
  Submission,
  computeUnpackedOffChainSubmissionmarkers,
} from "../sdk/submission";

export const computeSubmissionMarkers = command({
  name: "compute-submission-markers",
  args: {
    submissionFiles: multioption({
      type: array(string),
      long: "submission-files",
    }),
    startIdx: option({
      type: number,
      long: "start-idx",
      short: "s",
      description: "Start index of proofs within the list of submissions",
    }),
    numProofs: option({
      type: number,
      long: "num-proofs",
      short: "n",
      description: "Number of proofs, over all submissions, to be marked",
    }),
  },
  description:
    "Compute unpacked off-chain submission markers for the given submissions.",
  handler: async function ({
    submissionFiles,
    startIdx,
    numProofs,
  }): Promise<void> {
    const submissions = submissionFiles.map((submissionFile) =>
      Submission.from_json(readFileSync(submissionFile, "ascii"))
    );

    const submissionMarkers = computeUnpackedOffChainSubmissionmarkers(
      submissions,
      startIdx,
      numProofs
    );

    console.log(JSON.stringify(submissionMarkers));
  },
});
