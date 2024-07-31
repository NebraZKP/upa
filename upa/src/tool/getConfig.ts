import { command } from "cmd-ts";
import { upaFromInstanceFile } from "./config";
import { endpoint, instance } from "./options";
import { utils } from "../sdk";
import * as ethers from "ethers";

/// The json data output from this command.
type ConfigJSON = {
  owner: string;
  worker: string;
  feeRecipient: string;
  outerVerifier: string;
  maxNumPublicInputs: bigint;
  gasFee: bigint;
};

export const getConfig = command({
  name: "get-config",
  args: {
    endpoint: endpoint(),
    instance: instance(),
  },
  description: "Query the UPA config",
  handler: async function ({ endpoint, instance }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = await upaFromInstanceFile(instance, provider);

    const output: ConfigJSON = {
      owner: await verifier.owner(),
      worker: await verifier.worker(),
      feeRecipient: await verifier.feeRecipient(),
      outerVerifier: await verifier.outerVerifier(),
      maxNumPublicInputs: await verifier.maxNumPublicInputs(),
      gasFee: await verifier.fixedGasFeePerProof(),
    };

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(utils.JSONstringify(output, 2));
  },
});
