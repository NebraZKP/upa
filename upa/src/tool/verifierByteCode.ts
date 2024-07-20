import { command } from "cmd-ts";
import { upaFromInstanceFile } from "./config";
import { endpoint, instance } from "./options";
import * as ethers from "ethers";

export const verifierByteCode = command({
  name: "get-verifier-bytecode",
  args: {
    endpoint: endpoint(),
    instance: instance(),
  },
  description: "Query the bytecode of the aggregated proof verifier contract.",
  handler: async function ({ endpoint, instance }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = upaFromInstanceFile(instance, provider);
    const aggregatedProofVerifier = await verifier.outerVerifier();

    const bytecode = await provider.getCode(aggregatedProofVerifier);
    const bytecodeUnprefixed = bytecode.startsWith("0x")
      ? bytecode.slice(2)
      : bytecode;

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(bytecodeUnprefixed);
  },
});
