import {
  generateRandomProofInputs,
  loadDemoAppInstance,
  upaInstance,
  demoAppInstance,
  circuitWasm,
  circuitZkey,
} from "./utils";
import {
  Groth16Proof,
  snarkjs,
  utils,
  offchain,
  AppVkProofInputs,
  upa,
} from "@nebrazkp/upa/sdk";
import { options, config } from "@nebrazkp/upa/tool";
const { keyfile, endpoint, password, submissionEndpoint } = options;
const { loadWallet, upaFromInstanceFile } = config;
import * as ethers from "ethers";
import { command, number, option, optional, string } from "cmd-ts";
import { DemoApp__factory } from "../typechain-types";
const {
  OffChainClient,
  UnsignedOffChainSubmissionRequest,
  signOffChainSubmissionRequest,
} = offchain;
const { waitForSubmissionVerified } = upa;

export const submitOffchain = command({
  name: "submit-offchain",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    demoAppInstanceFile: demoAppInstance(),
    upaInstance: upaInstance(),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
    numProofs: option({
      type: number,
      long: "num",
      short: "n",
      defaultValue: () => 1,
      description: "The number of proofs to send.",
    }),
    depositContract: option({
      type: string,
      long: "deposit-contract",
      description: "Address of the aggregator's deposit contract",
    }),
    submissionEndpoint: submissionEndpoint(),
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
  description:
    "Send one demo-app proof to UPA, then when it's verified, " +
    "submit the corresponding solution to demo-app.",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    upaInstance,
    circuitWasm,
    circuitZkey,
    depositContract,
    submissionEndpoint,
    nonceString,
    feeGweiString,
    expirationBlockString,
    numProofs,
  }): Promise<void> {
    if (submissionEndpoint == "") {
      throw Error("Need to specify the submission endpoint");
    }
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, password, provider);

    const demoAppInstance = loadDemoAppInstance(demoAppInstanceFile);
    const vk = demoAppInstance.vk;

    const vksProofsInputs: AppVkProofInputs[] = [];
    const solutions = [];
    for (let i = 0; i < numProofs; i++) {
      const proofData = await snarkjs.groth16.fullProve(
        generateRandomProofInputs(),
        circuitWasm,
        circuitZkey
      );
      const proof = Groth16Proof.from_snarkjs(proofData.proof);
      const publicInputs: bigint[] = proofData.publicSignals.map(BigInt);

      vksProofsInputs.push(new AppVkProofInputs(vk, proof, publicInputs));
      solutions.push(publicInputs);
    }

    const proofIds = vksProofsInputs.map((vpi) => {
      const circuitId = utils.computeCircuitId(vpi.vk);
      return utils.computeProofId(circuitId, vpi.inputs);
    });
    const submissionId = utils.computeSubmissionId(proofIds);

    // Create the submission client and load the wallet
    const client = await OffChainClient.init(submissionEndpoint);

    // Check that the deposit contract is as expected.  Don't just trust the
    // aggregator.
    const aggDepositContract = client.getDepositContract();
    if (depositContract !== aggDepositContract) {
      throw `aggregator claims deposit contract ${aggDepositContract}`;
    }

    // Load submitter state. (A custom client can keep track of nonce, etc and
    // potentially avoid querying at each submission.)
    const address = await wallet.getAddress();
    const submitterState = await client.getSubmitterState(address);
    const submissionParameters = await client.getSubmissionParameters();

    // Use submitter state to fill in nonce, fee, expirationBlock if not given
    const nonce = nonceString
      ? BigInt(nonceString)
      : submitterState.lastNonce + 1n;

    // If not specified explicitly, expiration block is given by the current
    // block number + expected latency.
    const expirationBlock = expirationBlockString
      ? Number(expirationBlockString)
      : (await provider.getBlockNumber()) +
        submissionParameters.expectedLatency;

    // If not given explicitly, set a fee of 'minFeePerProof * numProofs'.
    const submissionFee = feeGweiString
      ? ethers.parseUnits(feeGweiString, "gwei")
      : BigInt(vksProofsInputs.length) * submissionParameters.minFeePerProof;
    console.log(`feePerProof: ${submissionParameters.minFeePerProof}`);
    console.log(`numProofs: ${vksProofsInputs.length}`);
    console.log(`submissionFee: ${submissionFee}`);

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
      depositContract
    );
    console.log(`Sending submission: ${utils.JSONstringify(submission)}`);
    const response = await client.submit(submission);
    response as unknown;

    // TODO: write response to file
    console.log("Aggregator response:");
    console.log(utils.JSONstringify(response));

    // Wait for the submission to be verified
    const upa = await upaFromInstanceFile(upaInstance, provider);
    await waitForSubmissionVerified(upa, submission.submissionId);

    const demoApp = DemoApp__factory.connect(demoAppInstance.demoApp).connect(
      wallet
    );

    for (const solution of solutions) {
      const submitSolutionTxResponse = await demoApp.submitSolution(solution);
      await submitSolutionTxResponse.wait();
      console.log(`Successfully submitted solution ${solution}`);
    }
  },
});
