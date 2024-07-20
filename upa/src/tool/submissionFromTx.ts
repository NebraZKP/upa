import { command, string, positional } from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import * as ethers from "ethers";
import { writeFileSync } from "fs";
import { Submission } from "../sdk/submission";
import { exit } from "process";

export const submissionFromTx = command({
  name: "submission-from-tx",
  args: {
    endpoint: options.endpoint(),
    instance: options.instance(),
    submissionFile: options.submissionFile(),
    txHash: positional({
      type: string,
      displayName: "tx-hash",
      description: "Hash of the tx to trace",
    }),
  },
  description: "Submit a proof to the UPA contract",
  handler: async function ({
    endpoint,
    instance,
    submissionFile,
    txHash,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = config.upaFromInstanceFile(instance, provider);

    const txReceiptP = provider.getTransactionReceipt(txHash);
    const txP = provider.getTransaction(txHash);

    const txReceipt = await txReceiptP;
    if (!txReceipt) {
      console.error(`failed to get receipt for ${txHash}`);
      exit(1);
    }

    const tx = await txP;
    if (!tx) {
      console.error(`failed to get tx data for ${txHash}`);
      exit(1);
    }

    const submission = Submission.fromTransactionReceiptAndData(
      verifier,
      txReceipt,
      tx
    );

    if (submissionFile) {
      writeFileSync(submissionFile, submission.to_json());
    } else {
      console.log(submission.to_json());
    }
  },
});
