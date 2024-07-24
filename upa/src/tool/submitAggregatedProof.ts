import { command, string, option, array, multioption } from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import * as ethers from "ethers";
import { readFileSync } from "fs";
import { utils } from "../sdk";
import { PayableOverrides } from "../../typechain-types/common";
import {
  SubmissionProof,
  packOffChainSubmissionMarkers,
} from "../sdk/submission";
import assert from "assert";

export const submitAggregatedProof = command({
  name: "submit-aggregated-proof",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    wait: options.wait(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    calldataFile: option({
      type: string,
      long: "calldata-file",
      short: "p",
      description: "Proof file",
    }),
    proofIdsFile: option({
      type: string,
      long: "proof-ids-file",
      short: "i",
      description: "file with JSON list of proofIds to be aggregated",
    }),
    onChainSubmissionProofFiles: multioption({
      type: array(string),
      long: "submission-proof-file",
      short: "s",
      defaultValue: () => [],
      description: "submission proof file(s)",
    }),
    offChainSubmissionMarkersFile: option({
      type: string,
      long: "submission-markers-file",
      short: "s",
      defaultValue: () => "",
      description: "Unpacked submission markers file containing a boolean[]",
    }),
  },
  description: "Submit an aggregated proof to the UPA contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    calldataFile,
    proofIdsFile,
    onChainSubmissionProofFiles,
    offChainSubmissionMarkersFile,
    wait,
    estimateGas,
    dumpTx,
    maxFeePerGasGwei,
  }): Promise<void> {
    const calldata = readFileSync(calldataFile);
    const proofIds: string[] = JSON.parse(readFileSync(proofIdsFile, "ascii"));
    const onChainSubmissionProofs = onChainSubmissionProofFiles.map((f) => {
      return SubmissionProof.from_json(readFileSync(f, "ascii"));
    });

    let offChainSubmissionMarkers: boolean[] = [];
    if (offChainSubmissionMarkersFile != "") {
      offChainSubmissionMarkers = JSON.parse(
        readFileSync(offChainSubmissionMarkersFile, "ascii")
      );
    }

    assert(
      onChainSubmissionProofs.length > 0 || offChainSubmissionMarkers.length > 0
    );

    // Infer the number of on-chain proofs
    const numOnChainProofs = proofIds.length - offChainSubmissionMarkers.length;

    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const { verifier: verifier } = config.upaFromInstanceFile(instance, wallet);

    const submissionProofsSolidity = onChainSubmissionProofs.map((p) =>
      p.solidity()
    );

    const optionsPayable: PayableOverrides = {
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };
    const txReq = await verifier.verifyAggregatedProof.populateTransaction(
      calldata,
      proofIds,
      numOnChainProofs,
      submissionProofsSolidity,
      packOffChainSubmissionMarkers(offChainSubmissionMarkers),
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
