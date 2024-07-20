import { command, string, option, optional } from "cmd-ts";
import * as ethers from "ethers";
import * as log from "./log";
import { readFileSync, writeFileSync } from "fs";
import { dummyProofData } from "../sdk/upa";
import { utils } from "../sdk";

export const computeFinalDigest = command({
  name: "compute-final-digest",
  args: {
    proofIdsFile: option({
      type: string,
      long: "proof-ids-file",
      short: "i",
      description: "File containing proofIds of submitted proofs",
    }),
    calldataFile: option({
      type: optional(string),
      long: "calldata-file",
      short: "p",
      description: "Write a fake calldata file",
    }),
  },
  description: "Compute the final digest for a batch of app proofs",
  handler: async function ({ proofIdsFile, calldataFile }): Promise<void> {
    const proofIds: string[] = JSON.parse(readFileSync(proofIdsFile, "ascii"));
    const finalDigest = utils.computeFinalDigest(proofIds);
    console.log(finalDigest);

    if (calldataFile) {
      log.debug("writing calldata");
      const calldata = ethers.getBytes(dummyProofData(proofIds));
      writeFileSync(calldataFile, calldata);
    }
  },
});
