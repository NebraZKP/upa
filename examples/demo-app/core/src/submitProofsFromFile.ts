import { upaInstance } from "./utils";
import {
  utils,
  UpaClient,
  CircuitIdProofAndInputs,
  SubmissionHandle,
  upa,
} from "@nebrazkp/upa/sdk";
import * as ethers from "ethers";
import * as fs from "fs";
import { ContractTransactionReceipt } from "ethers";
import { command, option, number, string, flag, boolean } from "cmd-ts";
import { options, config } from "@nebrazkp/upa/tool";
import { Sema, RateLimit } from "async-sema";

export const submitProofsFromFile = command({
  name: "submit-proofs-from-file",
  args: {
    chainEndpoint: options.chainEndpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    upaInstance: upaInstance(),
    submissionSize: option({
      type: number,
      long: "submission-size",
      short: "s",
      defaultValue: () => 1,
      description: "Number of proofs per submission.",
    }),
    proofFile: option({
      type: string,
      long: "proof-file",
      description: "Path to the proof(s) file.",
    }),
    circuitID: option({
      type: string,
      long: "circuit-id",
      description: "Circuit ID.",
    }),
    submissionFileRoot: option({
      type: string,
      long: "submission-file-root",
      description: "Root filename for submission outputs.",
    }),
    submitRate: option({
      type: number,
      long: "submit-rate",
      defaultValue: () => 0.5,
      description:
        "The maximum submission rate per second. \
      (Measured in submissions/sec, rather than proofs/sec)",
    }),
    waitForVerified: flag({
      type: boolean,
      long: "wait",
      short: "w",
      defaultValue: () => false,
      description: "Wait for the proofs to be verified by the UPA contract.",
    }),
  },
  description: "Submit proofs to UPA from a file, chunked into submissions.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    upaInstance,
    proofFile,
    submissionFileRoot,
    submissionSize,
    submitRate,
    maxFeePerGasGwei,
    waitForVerified,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await config.loadWallet(keyfile, password, provider);
    let nonce = await wallet.getNonce();

    const submitProofTxPromises: Promise<SubmissionHandle>[] = [];
    const waitTxReceiptPromises: Promise<ContractTransactionReceipt | null>[] =
      [];

    // Read proofs from file
    const cidProofsPIs =
      await config.loadProofFileAsCircuitIdProofAndInputsArray(proofFile);
    const numProofs = cidProofsPIs.length;
    console.log(`Number of proofs: ${numProofs}`);
    console.log(`Circuit ID: ${cidProofsPIs[0].circuitId}`);

    // Chunk into submission size
    const submissions: CircuitIdProofAndInputs[][] = chunkArray(
      cidProofsPIs,
      submissionSize
    );
    console.log(`Number of submissions: ${submissions.length}`);

    // Submit proofs to UPA
    const startTimeMilliseconds = Date.now();

    const maxConcurrency = 5;
    const semaphore = new Sema(maxConcurrency);
    const rateLimiter = RateLimit(submitRate, { uniformDistribution: true });
    const doSubmitTx = async (
      submission: CircuitIdProofAndInputs[],
      i: number
    ) => {
      try {
        await semaphore.acquire();
        await rateLimiter();

        return submitProofs(
          wallet,
          nonce++,
          upaInstance,
          submission,
          i,
          maxFeePerGasGwei
        );
      } finally {
        semaphore.release();
      }
    };
    submissions.forEach(async (submission, i) => {
      submitProofTxPromises.push(doSubmitTx(submission, i));
    });

    const submissionHandles = await Promise.all(submitProofTxPromises);
    submissionHandles.forEach((submissionHandle, i) => {
      const { txResponse, submission } = submissionHandle;
      if (submissionFileRoot) {
        const submissionFilename = `${submissionFileRoot}_${i}.json`;
        fs.writeFileSync(submissionFilename, submission.to_json());
        console.log(`Saved submission to ${submissionFilename}`);
      }

      // Print this submission's proofIds and corresponding solutions.
      const proofIds = submission.getProofIds();
      for (let j = 0; j < submissionSize; ++j) {
        const solution = submission.inputs[j];
        console.log(`  proofId: ${proofIds[j]} , solution ${solution}`);
      }
      waitTxReceiptPromises.push(txResponse.wait());
    });
    const txReceipts = await Promise.all(waitTxReceiptPromises);

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
    console.table({
      "Gas used for submitting all proofs to UPA": {
        "Gas Cost": `${totalGasUsedSubmittingProofs}`,
      },
    });
    if (waitForVerified) {
      console.log(`Waiting for proofs to be verified by the UPA contract...`);
      const upaClient = await UpaClient.init(
        wallet,
        config.loadInstance(upaInstance)
      );
      await Promise.all(
        submissionHandles.map(async (submissionHandle) => {
          await upaClient.waitForSubmissionVerified(submissionHandle);
        })
      );
      console.log(`Proofs have been verified by the UPA contract.`);
    }
  },
});

/**
 * Submits proofs to the UPA contract.
 *
 * @param wallet - Wallet used to sign the transaction.
 * @param nonce - The nonce is passed as an argument rather than
 * queried from the wallet to allow for parallel submissions.
 * @param upaInstance - UPA contract instance.
 * @param submission - Array of CircuitIdProofAndInputs to be submitted.
 * @param submissionIdx - An index identifying the submission.
 * @param submitRate - Useful for rate-limiting RPC providers.
 * @param maxFeePerGasGwei - The maximum fee per gas in Gwei (optional).
 *
 * @returns A (promised) SubmissionHandle.
 */
export async function submitProofs(
  wallet: ethers.AbstractSigner,
  nonce: number,
  upaInstance: string,
  submission: CircuitIdProofAndInputs[],
  submissionIdx: number,
  maxFeePerGasGwei?: string
): Promise<SubmissionHandle> {
  const maxFeePerGas = maxFeePerGasGwei
    ? ethers.parseUnits(maxFeePerGasGwei, "gwei")
    : undefined;

  // Initialize a `UpaClient` for submitting proofs to the UPA.
  const upaClient = await UpaClient.init(
    wallet,
    config.loadInstance(upaInstance)
  );

  // Estimate the fee due for submission.
  const submissionSize = submission.length;
  console.log(`Submission size: ${submissionSize}`);
  const options = await upa.updateFeeOptions(
    upaClient.upaInstance.verifier,
    submissionSize,
    {
      maxFeePerGas,
    }
  );
  // Uses `upaClient` to submit this bundle of proofs to the UPA.
  const submitTxFn = () => {
    return upaClient.submitProofs(submission, { nonce, ...options });
  };
  return await utils.requestWithRetry(
    submitTxFn,
    `${submissionIdx}` /* proofLabel*/,
    10 /* maxRetries*/,
    60 * 1000 /* timeoutMs */
  );
}

function chunkArray<T>(array: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    const chunk = array.slice(i, i + chunkSize);
    chunks.push(chunk);
  }
  return chunks;
}
