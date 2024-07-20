import { command, flag, boolean } from "cmd-ts";
import { loadAppVkProofInputsFile } from "./config";
import { options } from ".";
import * as log from "./log";
import { Groth16Verifier } from "../sdk";
import { getLogger } from "./log";

export const groth16Verify = command({
  name: "groth16-verify",
  description: "Verify a groth16 proof",
  args: {
    proofFile: options.proofFile(),
    doLog: flag({
      type: boolean,
      long: "log",
      short: "l",
      description: "Log groth16 verification",
    }),
  },
  handler: async function ({ proofFile, doLog }): Promise<void> {
    const { vk, proof, inputs } = loadAppVkProofInputsFile(proofFile);
    const processedInputs = inputs.map((input) => {
      if (typeof input === "number") {
        return BigInt(input);
      } else {
        return input;
      }
    });
    const groth16Verifier = await Groth16Verifier.initialize();
    const logger = doLog ? getLogger() : undefined;
    const verified = await groth16Verifier.verifyGroth16Proof(
      vk,
      proof,
      processedInputs,
      logger
    );

    if (!verified.result) {
      log.info(`Verification error: ${verified.error!}`);
    }

    // write 1/0 to stdout and use exit status to indicate validity
    console.log(verified ? "1" : "0");
    process.exit(verified ? 0 : 1);
  },
});
