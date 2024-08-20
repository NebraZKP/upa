import {
  command,
  string,
  number,
  option,
  optional,
  flag,
  boolean,
} from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import { utils } from "../sdk";
import * as ethers from "ethers";
import * as log from "./log";
import { writeFileSync } from "fs";
import { populateSubmitProofs } from "../sdk/upa";
import { Submission } from "../sdk/submission";
import { JSONstringify } from "../sdk/utils";
import { PayableOverrides } from "../../typechain-types/common";

export const submitProofs = command({
  name: "submit-proofs",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    proofsFile: options.proofsFile(),
    skip: option({
      type: number,
      long: "skip",
      description: "Skip this number of proofs in the file",
      defaultValue: () => 0,
    }),
    numProofs: option({
      type: optional(number),
      long: "num-proofs",
      description: "Number of proofs to submit",
    }),
    overrideUpaFeeGwei: options.overrideUpaFeeGwei(),
    outProofIdsFile: option({
      type: optional(string),
      long: "proof-ids-file",
      description: "Output file containing proofIds of submitted proofs",
    }),
    outSubmissionFile: options.submissionFile(
      "Output file containing the submission data"
    ),
    isDryRun: flag({
      type: boolean,
      long: "dry-run",
      short: "n",
      defaultValue: () => false,
      description: "Only output the proofId and submission files.",
    }),
  },
  description:
    "Make a submission of proofs to UPA.  Outputs Tx hash to stdout.  ",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    estimateGas,
    dumpTx,
    wait,
    maxFeePerGasGwei,
    proofsFile,
    skip,
    numProofs,
    overrideUpaFeeGwei,
    outProofIdsFile,
    outSubmissionFile,
    isDryRun,
  }): Promise<void> {
    const entries =
      config.loadProofFileAsCircuitIdProofAndInputsArray(proofsFile);
    numProofs = numProofs || entries.length;
    const circuitIdProofAndInputs = entries.slice(skip, skip + numProofs);

    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const { verifier } = await config.upaFromInstanceFile(instance, wallet);

    // Create the Submission object
    const submission = Submission.fromCircuitIdsProofsAndInputs(
      circuitIdProofAndInputs
    );

    // Optionally write the submission JSON file
    if (outSubmissionFile) {
      log.debug(`Writing submission to ${outSubmissionFile}`);
      writeFileSync(outSubmissionFile, submission.to_json());
    }

    // Optionally write proofIds to a file
    if (outProofIdsFile) {
      log.debug(`Writing proofIds to ${outProofIdsFile}`);
      writeFileSync(outProofIdsFile, JSONstringify(submission.getProofIds()));
    }

    const optionsPayable: PayableOverrides = {
      value: utils.parseGweiOrUndefined(overrideUpaFeeGwei),
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };

    // Skip the remaining code. We don't use `dumpTx` for this because it can
    // hit an `UnregisteredVK()` error when populating the transaction.
    if (isDryRun) {
      if (!outSubmissionFile && !outProofIdsFile) {
        log.debug("No output file locations were specified.");
      }
      return;
    }

    // Submit to the contract (output tx hash, optionally dump tx, wait,
    // estimate gas, etc)
    const txReq = await populateSubmitProofs(
      verifier,
      submission.circuitIds,
      submission.proofs,
      submission.inputs,
      optionsPayable
    );

    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      verifier.interface
    );
  },
});
