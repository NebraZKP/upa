import { command, flag, boolean } from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import * as ethers from "ethers";
import { Submission, utils } from "../sdk";
import { PayableOverrides } from "../../typechain-types/common";

export const challenge = command({
  name: "challenge",
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
    nextProofOnly: flag({
      type: boolean,
      long: "next-proof-only",
      description: "Submit only the first unverified proof in the submission.",
    }),
  },
  description: "Make a censorship challenge of a submission to UPA.\n",
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
    nextProofOnly: onlyOne,
  }): Promise<void> {
    const circuitIdProofAndInputs =
      config.loadProofFileAsCircuitIdProofAndInputsArray(proofsFile);
    const numProofs = circuitIdProofAndInputs.length;
    if (!onlyOne && numProofs > 1 && (estimateGas || dumpTx)) {
      throw Error(
        "--estimateGas and --dumpTx only allowed for single proof challenges" +
          " or with the --next-proof-only flag."
      );
    }

    // TODO: do everything from the txid so we can parse the dupSubmissionIdx

    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const { verifier } = await config.upaFromInstanceFile(instance, wallet);

    const submission = Submission.fromCircuitIdsProofsAndInputs(
      circuitIdProofAndInputs
    );
    // throw "todo";

    const dupSubmissionIdx = 0;
    const submissionIdx = await verifier.getSubmissionIdx(
      submission.submissionId,
      dupSubmissionIdx
    );
    const skip = Number(
      await verifier.getNumVerifiedForSubmissionIdx(submissionIdx)
    );
    if (skip >= numProofs) {
      throw Error("All proofs in submission already verified!");
    }

    const limit = onlyOne ? skip + 1 : numProofs;

    const optionsPayable: PayableOverrides = {
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };

    for (let i = skip; i < limit; i++) {
      const cpi = circuitIdProofAndInputs[i];
      const txReq = await verifier.challenge.populateTransaction(
        cpi.circuitId,
        cpi.proof.solidity(),
        cpi.inputs,
        submission.submissionId,
        dupSubmissionIdx,
        submission.computeProofIdMerkleProof(i),
        submission.computeProofDataMerkleProof(i),
        optionsPayable
      );

      const populatedTx = await wallet.populateTransaction(txReq);
      // Hardhat underestimates required gas, so we add
      // 200K to prevent revert
      txReq.gasLimit = BigInt(populatedTx!.gasLimit!) + 200000n;

      await config.handleTxRequest(
        wallet,
        txReq,
        estimateGas,
        dumpTx,
        wait,
        verifier.interface
      );
    }
  },
});
