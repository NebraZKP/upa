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
import { Submission } from "../sdk/submission";
import { config, options } from ".";
import { PayableOverrides } from "../../typechain-types/common";
import assert from "assert";
import { sisFromSubmissions } from "../sdk/submissionIntervals";
import { JSONstringify } from "../sdk/utils";
import {
  packDupSubmissionIdxs,
  packOffChainSubmissionMarkers,
  computeAggregatedProofParameters,
} from "../sdk/aggregatedProofParams";
import { deployDeposits } from "./deployDeposits";
import {
  getSignedRequestData,
  OffChainSubmissionRequest,
} from "../sdk/offChainClient";
import { loadWallet } from "./config";
import { Deposits__factory } from "../../typechain-types";
import fs from "fs";

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

const computeFinalDigest = command({
  name: "compute-final-digest",
  args: {
    proofIdsFile: option({
      type: string,
      long: "proof-ids-file",
      description: "File containing proofIds of submitted proofs",
    }),
    calldataFile: option({
      type: optional(string),
      long: "calldata-file",
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
    dumpArguments: option({
      type: optional(string),
      long: "dump-arguments",
      description: "Write a JSON representation of the arguments to a file",
    }),
    calldataFile: option({
      type: string,
      long: "calldata-file",
      description: "Proof file",
    }),
    submissionFiles: multioption({
      type: array(string),
      long: "submission",
      description: "on-chain submission files",
    }),
    offset: option({
      type: number,
      long: "offset",
      defaultValue: () => 0,
      description: "skip proofs in first on-chain submission (default: 0)",
    }),
    finalCount: option({
      type: optional(number),
      long: "final-count",
      description:
        "include only leading proofs from final submission" + " (default: all)",
    }),
    offChainSubmissionFiles: multioption({
      type: array(string),
      long: "off-chain-submission",
      description: "off-chain submission files",
    }),
    offChainOffset: option({
      type: number,
      long: "off-chain-offset",
      defaultValue: () => 0,
      description: "skip proofs in first off-chain submission (default: 0)",
    }),
    offChainFinalCount: option({
      type: optional(number),
      long: "off-chain-final-count",
      description:
        "include only leading proofs from final final submission " +
        "(default: all)",
    }),
  },
  description: "Submit an aggregated proof to the UPA contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    wait,
    estimateGas,
    dumpTx,
    maxFeePerGasGwei,
    dumpArguments,
    calldataFile,
    submissionFiles,
    offset,
    finalCount,
    offChainSubmissionFiles,
    offChainOffset,
    offChainFinalCount,
  }): Promise<void> {
    assert(submissionFiles.length > 0 || offChainSubmissionFiles.length > 0);

    const calldata = readFileSync(calldataFile);

    // Init the on-chain submission config

    const submissions: Submission[] = submissionFiles.map((f) => {
      const s = Submission.from_json(readFileSync(f, "ascii"));
      assert(s.getDupSubmissionIdx() !== undefined);
      return s;
    });

    // Init the off-chain submission config

    const offChainSubmissions: Submission[] = offChainSubmissionFiles.map((f) =>
      Submission.from_json(readFileSync(f, "ascii"))
    );

    // Create the submission intervals

    const submissionIntervals = sisFromSubmissions(
      submissions,
      offset,
      finalCount
    );

    const offChainSubmissionIntervals = sisFromSubmissions(
      offChainSubmissions,
      offChainOffset,
      offChainFinalCount
    );

    log.debug(
      `on-chain: ${submissions.length} submissions, offset: ${offset}, ` +
        `finalCount: ${finalCount}`
    );
    log.debug(
      `off-chain: ${offChainSubmissions.length} submissions, ` +
        `offset: ${offChainOffset}, finalCount: ${offChainFinalCount}`
    );

    // Compute all arguments to verifyAggregatedProof

    const apParams = computeAggregatedProofParameters(
      submissionIntervals,
      offChainSubmissionIntervals
    );

    if (dumpArguments) {
      log.info(`Writing args file to ${dumpArguments}`);
      writeFileSync(dumpArguments, JSONstringify(apParams));
    }

    // Connect

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

    // Create and handle the tx

    const submissionProofsSolidity = apParams.submissionProofs.map((p) =>
      p.solidity()
    );
    const optionsPayable: PayableOverrides = {
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };
    const txReq = await verifier.verifyAggregatedProof.populateTransaction(
      calldata,
      apParams.proofIds,
      apParams.numOnChainProofs,
      submissionProofsSolidity,
      packOffChainSubmissionMarkers(apParams.offChainSubmissionMarkers),
      packDupSubmissionIdxs(apParams.dupSubmissionIdxs),
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

export const claimDepositFees = command({
  name: "claim-deposit-fees",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    depositContract: option({
      type: string,
      long: "deposit-contract",
      description: "Address of the aggregator's deposit contract",
    }),
    signedRequestFile: option({
      type: string,
      long: "signed-request",
      description: "File containing a signed off-chain submission request.",
    }),
  },
  description: "Claim fees from deposit contract (for off-chain submissions)",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    depositContract,
    signedRequestFile,
  }): Promise<void> {
    const parsedJSON: object[] = JSON.parse(
      fs.readFileSync(signedRequestFile, "ascii")
    );
    const signedRequest = OffChainSubmissionRequest.from_json(parsedJSON);
    const signedRequestData = getSignedRequestData(signedRequest);

    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const deposits = Deposits__factory.connect(depositContract);
    const txReq = await deposits.claimFees.populateTransaction(
      signedRequestData,
      signedRequest.signature
    );
    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      deposits.interface
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
    "submit-aggregated-proof": submitAggregatedProof,
    "deploy-deposit-contract": deployDeposits,
    "claim-deposit-fees": claimDepositFees,
  },
});
