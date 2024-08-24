import { subcommands, command, string, option, optional } from "cmd-ts";
import * as log from "./log";
import {
  loadWallet,
  loadAppVkProofInputsBatchFile,
  readAddressFromKeyfile,
} from "./config";
import {
  password,
  getPassword,
  keyfile,
  vkProofInputsBatchFilePositional,
  submissionEndpoint,
  endpoint,
} from "./options";
import {
  computeCircuitId,
  computeProofId,
  computeSubmissionId,
  JSONstringify,
} from "../sdk/utils";
import {
  OffChainClient,
  signOffChainSubmissionRequest,
  UnsignedOffChainSubmissionRequest,
} from "../sdk/offChainClient";
import { ethers } from "ethers";

export const submit = command({
  name: "submit",
  args: {
    endpoint: endpoint(),
    submissionEndpoint: submissionEndpoint(),
    keyfile: keyfile(),
    password: password(),
    proofsFile: vkProofInputsBatchFilePositional(),
    depositsContract: option({
      type: string,
      long: "deposits-contract",
      description: "Address of the aggregator's deposits contract",
    }),
    nonceString: option({
      type: optional(string),
      long: "nonce",
      description: "Submitter nonce (default: query server)",
    }),
    feeGweiString: option({
      type: optional(string),
      long: "fee-gwei",
      description: "Total submission fee, in gwei (default: query server)",
    }),
    expirationBlockString: option({
      type: optional(string),
      long: "fee-per-proof",
      description: "Submission expiry block number (default: query server)",
    }),
  },
  description: "Submit a set of proofs to an off-chain aggregator",
  handler: async function ({
    endpoint,
    submissionEndpoint,
    keyfile,
    password,
    proofsFile,
    depositsContract,
    nonceString,
    feeGweiString,
    expirationBlockString,
  }): Promise<void> {
    const vksProofsInputs = loadAppVkProofInputsBatchFile(proofsFile);
    const proofIds = vksProofsInputs.map((vpi) => {
      const circuitId = computeCircuitId(vpi.vk);
      return computeProofId(circuitId, vpi.inputs);
    });
    const submissionId = computeSubmissionId(proofIds);

    // Create the submission client and load the wallet
    const client = await OffChainClient.init(submissionEndpoint);
    const wallet = await loadWallet(keyfile, getPassword(password));

    // Load submitter state. (A custom client can keep track of nonce, etc and
    // potentially avoid querying at each submission.)
    const address = await wallet.getAddress();
    const submitterState = await client.getSubmitterState(address);
    const submissionParameters = await client.getSubmissionParameters();

    // On-chain provider (for current block number)
    let provider: undefined | ethers.Provider;
    const getProvider = () => {
      if (!provider) {
        provider = new ethers.JsonRpcProvider(endpoint);
      }
      return provider;
    };

    // Use submitter state to fill in nonce, fee, expirationBlock if not given
    const nonce = nonceString
      ? BigInt(nonceString)
      : submitterState.lastNonce + 1n;

    // If not specified explicitly, expiration block is given by the current
    // block number + expected latency.
    const expirationBlock = expirationBlockString
      ? Number(expirationBlockString)
      : (await getProvider().getBlockNumber()) +
        submissionParameters.expectedLatency;

    // If not given explicitly, set a fee of 'minFeePerProof * numProofs'.
    const submissionFee = feeGweiString
      ? ethers.parseUnits(feeGweiString, "gwei")
      : BigInt(vksProofsInputs.length) * submissionParameters.minFeePerProof;
    log.info(`feePerProof: ${submissionParameters.minFeePerProof}`);
    log.info(`numProofs: ${vksProofsInputs.length}`);
    log.info(`submissionFee: ${submissionFee}`);

    const totalFee = submitterState.totalFee + submissionFee;

    // Prepare an UnsignedOffChainSubmissionRequest
    const unsignedSubmission = new UnsignedOffChainSubmissionRequest(
      vksProofsInputs,
      submissionId,
      submissionFee,
      expirationBlock,
      address,
      nonce,
      totalFee
    );

    // Sign the request
    const submission = await signOffChainSubmissionRequest(
      unsignedSubmission,
      wallet,
      depositsContract
    );
    log.debug(`submission: ${JSONstringify(submission)}`);
    const response = await client.submit(submission);
    response as unknown;

    console.log(JSONstringify(response));
  },
});

export const getParameters = command({
  name: "get-parameters",
  args: {
    endpoint: submissionEndpoint(),
  },
  description: "Get the current parameters for an off-chain aggregator",
  handler: async function ({ endpoint }): Promise<void> {
    const client = await OffChainClient.init(endpoint);
    const submissionParameters = await client.getSubmissionParameters();
    console.log(JSONstringify(submissionParameters));
  },
});

export const getState = command({
  name: "get-state",
  args: {
    endpoint: submissionEndpoint(),
    keyfile: keyfile(),
  },
  description: "Get the submitter state held by an off-chain aggregator",
  handler: async function ({ endpoint, keyfile }): Promise<void> {
    // Create the client, read the address and make the query.
    const client = await OffChainClient.init(endpoint);
    const address = readAddressFromKeyfile(keyfile);
    const submitterState = await client.getSubmitterState(address);
    console.log(JSONstringify(submitterState));
  },
});

export const offChain = subcommands({
  name: "off-chain",
  description: "Utilities for off-chain submission",
  cmds: {
    submit,
    "get-state": getState,
    "get-parameters": getParameters,
  },
});
