import { command, positional, string } from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import * as ethers from "ethers";
import {
  isProofVerifiedMulti,
  isProofVerifiedSingle,
  isSubmissionVerifiedById,
} from "../sdk/upa";
import { readFileSync } from "fs";
import { ProofReference } from "../sdk/submission";

export const isSubmissionVerified = command({
  name: "is-submission-verified",
  args: {
    chainEndpoint: options.chainEndpoint(),
    instance: options.instance(),
    submissionId: positional({
      type: string,
      displayName: "submission-id",
      description: "Submission Id to verifiy",
    }),
  },
  description: "Query UPA contract for verification status of a submission",
  handler: async function ({
    chainEndpoint,
    instance,
    submissionId,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const upa = await config.upaFromInstanceFile(instance, provider);

    /// Choose which `isVerified` function to call, based on whether there is
    /// a proofRef or not.
    const verified = await (async () => {
      return await upa.verifier.getFunction(isSubmissionVerifiedById)(
        submissionId
      );
    })();

    // write 1/0 to stdout and use exit status to indicate validity
    console.log(verified ? "1" : "0");
    process.exit(verified ? 0 : 1);
  },
});

export const isVerified = command({
  name: "is-verified",
  args: {
    chainEndpoint: options.chainEndpoint(),
    instance: options.instance(),
    proofFile: options.proofFile(),
    proofReferenceFile: options.proofReferenceFile(),
  },
  description: "Query UPA contract for verification status of a given proof",
  handler: async function ({
    chainEndpoint,
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

    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const upa = await config.upaFromInstanceFile(instance, provider);

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

export const isUnitSubmissionVerified = command({
  name: "is-unit-submission",
  description:
    "Query UPA contract for verification status of a single-proof submission " +
    "with the given proofid",
  args: {
    chainEndpoint: options.chainEndpoint(),
    instance: options.instance(),
    proofId: positional({
      type: string,
      displayName: "proof-id",
      description: "Proof Id to verifiy (must be part of single submission)",
    }),

    proofReferenceFile: options.proofReferenceFile(),
  },
  handler: async function ({
    chainEndpoint,
    instance,
    proofId,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const upa = await config.upaFromInstanceFile(instance, provider);

    const verified = await upa.verifier.getFunction("isProofVerified(bytes32)")(
      proofId
    );

    // write 1/0 to stdout and use exit status to indicate validity
    console.log(verified ? "1" : "0");
    process.exit(verified ? 0 : 1);
  },
});
