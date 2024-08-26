import { subcommands, command, string, option, optional } from "cmd-ts";
import { loadWallet, loadAppVkProofInputsBatchFile } from "./config";
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
} from "../sdk/utils";
import {
  OffChainClient,
  Signature,
  OffChainSubmissionRequest,
} from "../sdk/offchainClient";

export const submit = command({
  name: "submit",
  args: {
    // endpoint: op
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
  description: "Generate an ethereum key and save to an encrypted keyfile",
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
    const signature: Signature = (() => {
      throw "todo";
    })();

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

export const offChain = subcommands({
  name: "off- chain",
  description: "Utilities for off-chain submission",
  cmds: {
    submit,
  },
});
