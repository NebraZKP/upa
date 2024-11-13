import { loadDemoAppInstance, demoAppInstance } from "./utils";
import * as ethers from "ethers";
import { command, option, number, string } from "cmd-ts";
import { options, config } from "@nebrazkp/upa/tool";
import { DemoApp__factory } from "../typechain-types";
import { submitSolution } from "./utils";

export const submitSolutionsFromFile = command({
  name: "submit-solutions-from-file",
  args: {
    chainEndpoint: options.chainEndpoint(),
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
    chainEndpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    submissionFile,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
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
