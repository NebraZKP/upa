import {
  command,
  string,
  option,
  optional,
  number,
  multioption,
  array,
  subcommands,
} from "cmd-ts";
import * as ethers from "ethers";
import * as log from "./log";
import { readFileSync, writeFileSync } from "fs";
import { dummyProofData } from "../sdk/upa";
import { utils } from "../sdk";
import {
  computeUnpackedOffChainSubmissionmarkers,
  packOffChainSubmissionMarkers,
  Submission,
  SubmissionProof,
} from "../sdk/submission";
import { config, options } from ".";
import { PayableOverrides } from "../../typechain-types/common";
import assert from "assert";

const allocateAggregatorFee = command({
  name: "allocate-aggregator-fee",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    wait: options.wait(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
  },
  description: "Allocate the aggregator fee in UPA's fee model contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    wait,
    estimateGas,
    dumpTx,
    maxFeePerGasGwei,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const { verifier: verifier } = await config.upaFromInstanceFile(
      instance,
      wallet
    );

    const optionsPayable: PayableOverrides = {
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };
    const txReq = await verifier.allocateAggregatorFee.populateTransaction(
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

const claimAggregatorFee = command({
  name: "claim-aggregator-fee",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    wait: options.wait(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
  },
  description:
    "Claims the allocated aggregator fee in UPA's fee model contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    wait,
    estimateGas,
    dumpTx,
    maxFeePerGasGwei,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const { verifier: verifier } = await config.upaFromInstanceFile(
      instance,
      wallet
    );

    const optionsPayable: PayableOverrides = {
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };
    const txReq = await verifier.claimAggregatorFee.populateTransaction(
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

const computeSubmissionMarkers = command({
  name: "compute-submission-markers",
  args: {
    submissionFiles: multioption({
      type: array(string),
      long: "submission-files",
    }),
    startIdx: option({
      type: number,
      long: "start-idx",
      short: "s",
      description: "Start index of proofs within the list of submissions",
    }),
    numProofs: option({
      type: number,
      long: "num-proofs",
      short: "n",
      description: "Number of proofs, over all submissions, to be marked",
    }),
  },
  description:
    "Compute unpacked off-chain submission markers for the given submissions.",
  handler: async function ({
    submissionFiles,
    startIdx,
    numProofs,
  }): Promise<void> {
    const submissions = submissionFiles.map((submissionFile) =>
      Submission.from_json(readFileSync(submissionFile, "ascii"))
    );

    const submissionMarkers = computeUnpackedOffChainSubmissionmarkers(
      submissions,
      startIdx,
      numProofs
    );

    console.log(JSON.stringify(submissionMarkers));
  },
});

const computeFinalDigest = command({
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

const submitAggregatedProof = command({
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
    const { verifier: verifier } = await config.upaFromInstanceFile(
      instance,
      wallet
    );

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

export const aggregator = subcommands({
  name: "aggregator",
  description: "Commands used by the aggregator",
  cmds: {
    "allocate-aggregator-fee": allocateAggregatorFee,
    "claim-aggregator-fee": claimAggregatorFee,
    "compute-final-digest": computeFinalDigest,
    "compute-submission-markers": computeSubmissionMarkers,
    "submit-aggregated-proof": submitAggregatedProof,
  },
});
