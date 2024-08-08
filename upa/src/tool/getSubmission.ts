import { command, positional, string } from "cmd-ts";
import * as options from "./options";
import * as ethers from "ethers";
import * as config from "./config";
import * as utils from "../sdk/utils";
import { Submission } from "../sdk";

export const getSubmission = command({
  name: "get-submission",
  args: {
    endpoint: options.endpoint(),
    instance: options.instance(),
    txId: positional({
      type: string,
      displayName: "tx-id",
      description: "Tx Id of the submission to retrieve",
    }),
  },
  description: "Get the on-chain submission information associated with a Tx",
  handler: async function ({ endpoint, instance, txId }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = await config.upaFromInstanceFile(instance, provider);

    const txReceipt = await provider.getTransactionReceipt(txId);
    if (!txReceipt) {
      throw `Failed to get receipt for tx ${txId}`;
    }
    const submission = await Submission.fromTransactionReceipt(
      verifier,
      txReceipt
    );

    console.log(utils.JSONstringify(submission));
  },
});
