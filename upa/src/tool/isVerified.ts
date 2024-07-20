import { command } from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import * as ethers from "ethers";
import { isProofVerifiedMulti, isProofVerifiedSingle } from "../sdk/upa";
import { readFileSync } from "fs";
import { ProofReference } from "../sdk/submission";

export const isVerified = command({
  name: "is-verified",
  args: {
    endpoint: options.endpoint(),
    instance: options.instance(),
    proofFile: options.proofFile(),
    proofReferenceFile: options.proofReferenceFile(),
  },
  description: "Query UPA contract for verification status of a given proof",
  handler: async function ({
    endpoint,
    instance,
    proofFile,
    proofReferenceFile,
  }): Promise<void> {
    const { circuitId, inputs } =
      config.loadSingleProofFileAsCircuitIdProofAndInputs(proofFile);
    const proofRef = (() => {
      if (proofReferenceFile) {
        const proofRef = ProofReference.from_json(
          readFileSync(proofReferenceFile, "ascii")
        );
        return proofRef;
      }

      return undefined;
    })();

    const provider = new ethers.JsonRpcProvider(endpoint);
    const upa = config.upaFromInstanceFile(instance, provider);

    /// Choose which `isVerified` function to call, based on whether there is
    /// a proofRef or not.
    const verified = await (async () => {
      if (proofRef) {
        return await upa.verifier.getFunction(isProofVerifiedMulti)(
          circuitId,
          inputs,
          proofRef.solidity()
        );
      }

      return await upa.verifier.getFunction(isProofVerifiedSingle)(
        circuitId,
        inputs
      );
    })();

    // write 1/0 to stdout and use exit status to indicate validity
    console.log(verified ? "1" : "0");
    process.exit(verified ? 0 : 1);
  },
});
