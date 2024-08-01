import { command, subcommands } from "cmd-ts";
import { stats } from "./stats";
import { getConfig } from "./getConfig";
import { endpoint, instance } from "./options";
import { ethers } from "ethers";
import { config } from ".";
import { upaFromInstanceFile } from "./config";
import { isVerified } from "./isVerified";
import { getAggregatedProofVerifier } from "./aggregatedProofVerifier";

const getMaxNumPublicInputs = command({
  name: "max-num-public-inputs",
  args: {
    endpoint: endpoint(),
    instance: instance(),
  },
  description: "Get the current maximum number of public inputs supported",
  handler: async function ({ endpoint, instance }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = await config.upaFromInstanceFile(instance, provider);
    console.log(await verifier.maxNumPublicInputs());
  },
});

const getVerifierByteCode = command({
  name: "verifier-bytecode",
  args: {
    endpoint: endpoint(),
    instance: instance(),
  },
  description: "Query the bytecode of the aggregated proof verifier contract.",
  handler: async function ({ endpoint, instance }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = await upaFromInstanceFile(instance, provider);
    const aggregatedProofVerifier = await verifier.outerVerifier();

    const bytecode = await provider.getCode(aggregatedProofVerifier);
    const bytecodeUnprefixed = bytecode.startsWith("0x")
      ? bytecode.slice(2)
      : bytecode;

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(bytecodeUnprefixed);
  },
});

export const query = subcommands({
  name: "query",
  description: "Commands to query the UPA contract",
  cmds: {
    "aggregated-proof-verifier": getAggregatedProofVerifier,
    stats,
    config: getConfig,
    "max-num-public-inputs": getMaxNumPublicInputs,
    "verifier-bytecode": getVerifierByteCode,
    "is-verified": isVerified,
  },
});
