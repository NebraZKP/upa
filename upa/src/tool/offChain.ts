import { subcommands, command, string, option, optional } from "cmd-ts";
import {
  loadWallet,
  loadAppVkProofInputsBatchFile,
  readAddressFromKeyfile,
} from "./config";
import {
  password,
  getPassword,
  keyfile,
  vkProofInputsBatchFile,
  submissionEndpoint,
} from "./options";
import {
  computeCircuitId,
  computeProofId,
  computeSubmissionId,
  JSONstringify,
} from "../sdk/utils";
import {
  OffChainClient,
  OffChainSubmissionRequest,
} from "../sdk/offchainClient";

export const submit = command({
  name: "submit",
  args: {
    endpoint: submissionEndpoint(),
    keyfile: keyfile(),
    password: password(),
    proofsFile: vkProofInputsBatchFile(),
    nonceString: option({
      type: optional(string),
      long: "nonce",
      description: "Submitter nonce (default: query server)",
    }),
    feeString: option({
      type: optional(string),
      long: "fee-gwei-per-proof",
      description: "Submission fee per proof, in gwei (default: query server)",
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
    keyfile,
    password,
    proofsFile,
    nonceString,
    feeString,
    expirationBlockString,
  }): Promise<void> {
    feeString as unknown;
    expirationBlockString as unknown;

    const vksProofsInputs = loadAppVkProofInputsBatchFile(proofsFile);
    const proofIds = vksProofsInputs.map((vpi) => {
      const circuitId = computeCircuitId(vpi.vk);
      return computeProofId(circuitId, vpi.inputs);
    });
    const submissionId = computeSubmissionId(proofIds);

    // Create the client and load the wallet
    const client = await OffChainClient.init(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password));

    // Load submitter state. (A custom client can keep track of nonce, etc and
    // potentially avoid querying at each submission.)
    const address = await wallet.getAddress();
    const submitterState = await client.getSubmitterState(address);

    // Use submitter state to fill in nonce, fee, expirationBlock if not given
    const nonce = nonceString
      ? BigInt(nonceString)
      : submitterState.submitterNonce;
    const expirationBlock: bigint = await (async () => {
      throw "todo";
    })();
    const feePerProof: bigint = await (async () => {
      throw "todo";
    })();
    const submissionFee = BigInt(vksProofsInputs.length) * feePerProof;
    const totalFee = submitterState.totalFee + submissionFee;

    // Sign
    const signature = "sig";

    // Send the OffChainSubmissionRequest
    const submission = new OffChainSubmissionRequest(
      vksProofsInputs,
      submissionId,
      submissionFee,
      expirationBlock,
      address,
      nonce,
      totalFee,
      signature
    );
    const response = await client.submit(submission);
    response as unknown;

    // Store the result somewhere (stdout or write to a file)
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
