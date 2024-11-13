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
  UpaClient,
  CircuitIdProofAndInputs,
  utils,
} from "@nebrazkp/upa/sdk";
import { options, config } from "@nebrazkp/upa/tool";
const { keyfile, chainEndpoint, password } = options;
const { loadWallet, loadInstance } = config;
import * as ethers from "ethers";
import { command } from "cmd-ts";
import { DemoApp__factory } from "../typechain-types";

export const submit = command({
  name: "submit",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    demoAppInstanceFile: demoAppInstance(),
    upaInstance: upaInstance(),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
  },
  description:
    "Send one demo-app proof to UPA, then when it's verified, " +
    "submit the corresponding solution to demo-app.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    upaInstance,
    circuitWasm,
    circuitZkey,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, password, provider);

    const demoAppInstance = loadDemoAppInstance(demoAppInstanceFile);
    const circuitId = demoAppInstance.circuitId;
    const demoApp = DemoApp__factory.connect(demoAppInstance.demoApp).connect(
      wallet
    );

    // Generate random public inputs along with a proof that they are valid.
    const proofData = await snarkjs.groth16.fullProve(
      generateRandomProofInputs(),
      circuitWasm,
      circuitZkey
    );
    const proof = Groth16Proof.from_snarkjs(proofData.proof);
    const publicInputs: bigint[] = proofData.publicSignals.map(BigInt);

    // Initialize a `UpaClient` for submitting proofs to the UPA.
    const upaClient = await UpaClient.init(wallet, loadInstance(upaInstance));

    // Wrap `circuitId`, `proof`, and `publicInputs` in a type
    const circuitIdProofAndInputs: CircuitIdProofAndInputs[] = [
      { circuitId, proof, inputs: publicInputs },
    ];
    // Submit `circuitIdProofAndInputs` using the `UpaClient`.
    const submissionHandle = await upaClient.submitProofs(
      circuitIdProofAndInputs
    );

    // Wait for an off-chain prover to send an aggregated proof to the UPA
    // contract showing that our submitted `circuitIdProofAndInputs` was valid.
    const submitProofTxReceipt = await upaClient.waitForSubmissionVerified(
      submissionHandle
    );

    const submitProofWeiUsed =
      submitProofTxReceipt!.fee + submissionHandle.txResponse.value;
    const submitProofEtherUsed = utils.weiToEther(
      submitProofWeiUsed,
      6 /*numDecimalPlaces*/
    );

    // Our submitted `circuitIdProofAndInputs` is now marked as valid in the
    // UPA contract so we can now submit the solution to demo-app's contract.
    const submitSolutionTxResponse = await demoApp.submitSolution(publicInputs);

    const submitSolutionTxReceipt = await submitSolutionTxResponse.wait();

    const submitSolutionWeiUsed = submitSolutionTxReceipt!.fee;
    const submitSolutionEtherUsed = utils.weiToEther(
      submitSolutionWeiUsed,
      6 /*numDecimalPlaces*/
    );

    const totalGasUsed =
      submitProofTxReceipt!.gasUsed + submitSolutionTxReceipt!.gasUsed;

    // Convert wei to eth again so that end result is rounded correctly.
    const totalEthUsed = utils.weiToEther(
      submitProofWeiUsed + submitSolutionWeiUsed,
      6 /*numDecimalPlaces*/
    );

    console.log("Gas Cost Summary:");
    console.table({
      "Submit proof to UPA": {
        "Cost (gas)": `${submitProofTxReceipt!.gasUsed}`,
        "Cost (ETH, includes UPA fee)": `${submitProofEtherUsed}`,
      },
      "Submit solution to app contract": {
        "Cost (gas)": `${submitSolutionTxReceipt!.gasUsed}`,
        "Cost (ETH, includes UPA fee)": `${submitSolutionEtherUsed}`,
      },
      Total: {
        "Cost (gas)": `${totalGasUsed}`,
        "Cost (ETH, includes UPA fee)": `${totalEthUsed}`,
      },
    });
  },
});
