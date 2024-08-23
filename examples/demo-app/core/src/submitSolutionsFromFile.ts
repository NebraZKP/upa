import { loadDemoAppInstance, demoAppInstance } from "./utils";
import { SubmissionDescriptor } from "@nebrazkp/upa/sdk";
import * as ethers from "ethers";
import { command, option, number, string } from "cmd-ts";
import { options, config } from "@nebrazkp/upa/tool";
import { DemoApp, DemoApp__factory } from "../typechain-types";

export const submitSolutionsFromFile = command({
  name: "submit-solutions-from-file",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    demoAppInstanceFile: demoAppInstance(),
    submissionFile: option({
      type: string,
      long: "submission-file",
      description: "File containing a verified UPA submission (and solutions).",
    }),
    submitRate: option({
      type: number,
      long: "submit-rate",
      defaultValue: () => 0.5,
      description: "The maximum submission rate per second.",
    }),
  },
  description:
    "Submit solutions to demo-app contract from a file. \
    Proofs must be verified by UPA first.",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    submissionFile,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(keyfile, password, provider);
    const demoAppInstance = loadDemoAppInstance(demoAppInstanceFile);
    const demoApp = DemoApp__factory.connect(demoAppInstance.demoApp).connect(
      wallet
    );
    let nonce = await wallet.getNonce();

    // Read submission from file
    const submission = config.loadSubmission(submissionFile);
    const submissionSize = submission.inputs.length;

    const startTimeMilliseconds = Date.now();
    // Submit solutions to demo-app
    // eslint-disable-next-line
    const submitSolutionTxResponses: Promise<ethers.ContractTransactionResponse>[] =
      [];
    for (let j = 0; j < submissionSize; ++j) {
      const submitSolutionTxResponse = submitSolution(
        wallet,
        demoApp,
        nonce++,
        submission,
        j
      );
      submitSolutionTxResponses.push(submitSolutionTxResponse);
    }

    const endTimeMilliseconds = Date.now(); // Record the end time
    const elapsedTimeSeconds =
      (endTimeMilliseconds - startTimeMilliseconds) / 1000;
    console.log(
      `All ${submissionSize} proofs submitted in ${elapsedTimeSeconds} seconds.`
    );

    const submitSolutionTxReceipts = await Promise.all(
      submitSolutionTxResponses.map(async (txResponse) =>
        (await txResponse).wait()
      )
    );
    const totalGasUsedSubmittingSolutions = submitSolutionTxReceipts.reduce(
      (total, receipt) => total + receipt!.gasUsed,
      0n
    );
    console.table({
      "Gas used for submitting all solutions to demo-app": {
        "Gas Cost": `${totalGasUsedSubmittingSolutions}`,
      },
    });
  },
});

/**
 * Submits a solution to the demo app contract. The solution
 * should already have been verified by the UPA contract.
 *
 * @param wallet - The wallet used to sign the transaction.
 * @param demoApp - The instance of the demo app contract.
 * @param nonce - The nonce value for the transaction.
 * @param submission - The submission object containing the solution.
 * @param solutionIdx - The index of the solution in the submission.
 * @returns A promise that resolves to the transaction response.
 */
export async function submitSolution(
  _wallet: ethers.AbstractSigner,
  demoApp: DemoApp,
  nonce: number,
  submission: SubmissionDescriptor,
  solutionIdx: number
): Promise<ethers.ContractTransactionResponse> {
  const solution = submission.inputs[solutionIdx];
  console.log(`Submitted solution ${solution}`);
  if (submission.isMultiProofSubmission()) {
    // If the proof was part of a multi-proof submission, we
    // need to pass a proof reference to the demo-app
    // contract so it can check the proof's verification
    // status.
    return demoApp.submitSolutionWithProofReference(
      solution,
      submission.computeProofReference(solutionIdx)!.solidity(),
      { nonce: nonce }
    );
  } else {
    // If the proof was sent in a single-proof submission, we
    // only need to pass the solution. A proof reference is not
    // necessary.
    return demoApp.submitSolution(solution, {
      nonce: nonce,
    });
  }
}
