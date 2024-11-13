import {
  generateRandomProofInputs,
  loadDemoAppInstance,
  upaInstance,
  demoAppInstance,
  circuitWasm,
  circuitZkey,
} from "./utils";
import { submitProofs } from "./submitProofsFromFile";
import { submitSolution } from "./utils";
import {
  snarkjs,
  UpaClient,
  CircuitIdProofAndInputs,
  Groth16Proof,
  SubmissionHandle,
  utils,
} from "@nebrazkp/upa/sdk";
import * as ethers from "ethers";
import { ContractTransactionReceipt } from "ethers";
import { command, option, number, boolean, flag } from "cmd-ts";
import { options, config } from "@nebrazkp/upa/tool";
import { strict as assert } from "assert";
import { DemoApp__factory } from "../typechain-types";
import { Sema, RateLimit } from "async-sema";

export const multiSubmit = command({
  name: "multi-submit",
  args: {
    chainEndpoint: options.chainEndpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    demoAppInstanceFile: demoAppInstance(),
    upaInstance: upaInstance(),
    submissionSize: option({
      type: number,
      long: "submission-size",
      short: "s",
      defaultValue: () => 1,
      description: "Number of proofs per submission.",
    }),
    numProofs: option({
      type: number,
      long: "num",
      short: "n",
      defaultValue: () => 0,
      description: "The number of proofs to send. If 0, send unlimited proofs.",
    }),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
    submitRate: option({
      type: number,
      long: "submit-rate",
      defaultValue: () => 0.5,
      description:
        "The maximum submission rate per second. \
      (Measured in submissions/sec, rather than proofs/sec)",
    }),
    maxConcurrentTxs: option({
      type: number,
      long: "max-concurrent-txs",
      defaultValue: () => 2,
      description: "The maximum number of transactions concurrently submitted",
    }),
    skipSolutions: flag({
      type: boolean,
      long: "skip-solutions",
      defaultValue: () => false,
      description: "Submit proofs to UPA without submitting app solutions",
    }),
  },
  description: "Send a number of Demo-app proofs to UPA to be verified.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    upaInstance,
    numProofs,
    circuitWasm,
    circuitZkey,
    submissionSize,
    submitRate,
    maxFeePerGasGwei,
    maxConcurrentTxs,
    skipSolutions,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await config.loadWallet(keyfile, password, provider);
    let nonce = await wallet.getNonce();

    const demoAppInstance = loadDemoAppInstance(demoAppInstanceFile);
    const circuitId = demoAppInstance.circuitId;
    const demoApp = DemoApp__factory.connect(demoAppInstance.demoApp).connect(
      wallet
    );

    const submitProofTxPromises: Promise<SubmissionHandle>[] = [];
    const waitTxReceiptPromises: Promise<ContractTransactionReceipt | null>[] =
      [];
    // eslint-disable-next-line
    const submitSolutionReceiptPromises: Promise<ContractTransactionReceipt>[] =
      [];

    const startTimeMilliseconds = Date.now();

    // Initialize a `UpaClient` for submitting proofs to the UPA.
    const upaClient = await UpaClient.init(
      wallet,
      config.loadInstance(upaInstance)
    );

    // TODO(#515): This will round up to a multiple of `submissionSize`. Make
    // this submit the exact number of proofs.
    //
    // Send submissions of `submissionSize` proofs to the UPA until at least
    // `numProofs` proofs have been submitted. Once a submission has been
    // verified, send the corresponding solution to the demo-app contract.
    const maxConcurrency = maxConcurrentTxs;
    const semaphore = new Sema(maxConcurrency);
    const rateLimiter = RateLimit(submitRate, { uniformDistribution: true });
    // Wrap in semaphore to control number of concurrent transactions.
    const doSubmitTx = async (
      cidProofPIs: CircuitIdProofAndInputs[],
      i: number
    ) => {
      try {
        await semaphore.acquire();
        await rateLimiter();
        return submitProofs(
          wallet,
          nonce++,
          upaInstance,
          cidProofPIs,
          i,
          maxFeePerGasGwei
        );
      } finally {
        semaphore.release();
      }
    };
    for (let i = 0; i < numProofs || numProofs == 0; i += submissionSize) {
      // Start the proof generation for each solution.
      const proofDataP: Promise<snarkjs.SnarkJSProveOutput>[] = [];
      for (let j = 0; j < submissionSize; ++j) {
        proofDataP.push(
          snarkjs.groth16.fullProve(
            generateRandomProofInputs(),
            circuitWasm,
            circuitZkey
          )
        );
      }
      assert(proofDataP.length === submissionSize);

      // For each proof gen, wait for it to complete and construct the
      // CircuitIdProofAndInputs struct required to create the Submission
      // object.
      const cidProofPIs: CircuitIdProofAndInputs[] = [];
      for (const pdp of proofDataP) {
        const pd = await pdp;
        cidProofPIs.push({
          circuitId,
          proof: Groth16Proof.from_snarkjs(pd.proof),
          inputs: pd.publicSignals.map(BigInt),
        });
      }
      assert(cidProofPIs.length === submissionSize);

      const submitTxP = doSubmitTx(cidProofPIs, i);
      // Only accumulate if we are not looping infinitely.
      if (numProofs) {
        submitProofTxPromises.push(submitTxP);
      }
    }
    const submissionHandles = await Promise.all(submitProofTxPromises);
    for (const submissionHandle of submissionHandles) {
      const { txResponse, submission } = submissionHandle;
      console.log(`submissionId: ${submission.getSubmissionId()}`);
      console.log(`contains proofIds:`);
      console.log(submission.getProofIds());
      if (skipSolutions) {
        waitTxReceiptPromises.push(txResponse.wait());
      } else {
        const waitThenSubmitSolution = async () => {
          // Use `upaClient` to wait for this submission to be verified.
          const waitTxReceipt = await upaClient.waitForSubmissionVerified(
            submissionHandle
          );

          for (let j = 0; j < submissionSize; ++j) {
            // Wrap in semaphore to control number of concurrent transactions.
            const doSubmitSolution = async () => {
              try {
                await semaphore.acquire();
                await rateLimiter();
                const txResponse = await submitSolution(
                  wallet,
                  demoApp,
                  nonce++,
                  submission,
                  j
                );

                const txReceipt = await txResponse.wait();
                assert(txReceipt);
                return txReceipt;
              } finally {
                semaphore.release();
              }
            };
            submitSolutionReceiptPromises.push(doSubmitSolution());
          }

          return waitTxReceipt;
        };
        waitTxReceiptPromises.push(waitThenSubmitSolution());
      }
    }

    const txReceipts = await Promise.all(waitTxReceiptPromises);
    const submitSolutionReceipts = await Promise.all(
      submitSolutionReceiptPromises
    );

    const endTimeMilliseconds = Date.now(); // Record the end time
    const elapsedTimeSeconds =
      (endTimeMilliseconds - startTimeMilliseconds) / 1000;

    console.log(
      `All ${numProofs} proofs submitted in ${elapsedTimeSeconds} seconds.`
    );

    const totalGasUsedSubmittingProofs = txReceipts.reduce(
      (total, receipt) => total + receipt!.gasUsed,
      0n
    );
    const totalWeiUsedSubmittingProofs = txReceipts.reduce(
      (total, receipt) => total + receipt!.fee,
      0n
    );
    const totalEthUsedSubmittingProofs = utils.weiToEther(
      totalWeiUsedSubmittingProofs,
      6 /*numDecimalPlaces*/
    );

    const totalGasUsedSubmittingSolutions = submitSolutionReceipts.reduce(
      (total, receipt) => total + receipt!.gasUsed,
      0n
    );
    const totalWeiUsedSubmittingSolutions = txReceipts.reduce(
      (total, receipt) => total + receipt!.fee,
      0n
    );
    const totalEthUsedSubmittingSolutions = utils.weiToEther(
      totalWeiUsedSubmittingSolutions,
      6 /*numDecimalPlaces*/
    );

    const totalGasCost =
      totalGasUsedSubmittingProofs + totalGasUsedSubmittingSolutions;
    const totalEthCost =
      totalEthUsedSubmittingProofs + totalEthUsedSubmittingSolutions;

    console.table({
      "Gas used for submitting all proofs to UPA": {
        "Cost (gas)": `${totalGasUsedSubmittingProofs}`,
        "Cost (ETH, includes UPA fee)": `${totalEthUsedSubmittingProofs}`,
      },
      "Gas used for submitting all solutions to demo-app": {
        "Cost (gas)": `${totalGasUsedSubmittingSolutions}`,
        "Cost (ETH, includes UPA fee)": `${totalEthUsedSubmittingSolutions}`,
      },
      Total: {
        "Cost (gas)": `${totalGasCost}`,
        "Cost (ETH, includes UPA fee)": `${totalEthCost}`,
      },
    });
  },
});
