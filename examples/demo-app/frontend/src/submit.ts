import * as ethers from "ethers";
const snarkjs = require("snarkjs");
import {
  application,
  UpaClient,
  Groth16Proof,
  utils,
  SubmissionHandle,
  submission,
} from "@nebrazkp/upa/sdk";
import { demoAppFromDescriptor } from "../../core/dist/src/frontend_utils";
import upaInstanceDescriptor from "../public/instances/upa.instance.json";
import demoAppInstanceDescriptor from "../public/instances/demo-app.instance.json";

const sepoliaChainId = "0xaa36a7";
const changeNetwork = async () => {
  if ((window as any).ethereum) {
    try {
      await (window as any).ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: sepoliaChainId }],
      });
    } catch (error) {
      console.error(error);
    }
  }
};

// Generates a random non-negative solution to the equation a*b = c*d + e + f.
export function generateRandomProofInputs(): {
  a: bigint;
  b: bigint;
  c: bigint;
  d: bigint;
  e: bigint;
  f: bigint;
} {
  const c = BigInt(ethers.hexlify(ethers.randomBytes(4)));
  const d = BigInt(ethers.hexlify(ethers.randomBytes(4)));
  const a = c + BigInt(1);
  const b = d + BigInt(1);
  const e = c;
  const f = d + BigInt(1);
  return { a, b, c, d, e, f };
}

// Generating demo-app solution and proof…
export async function generateSolutionAndProof(): Promise<application.CircuitIdProofAndInputs> {
  const circuitId = demoAppInstanceDescriptor.circuitId;

  const proofData = await snarkjs.groth16.fullProve(
    generateRandomProofInputs(),
    "/circuit.wasm",
    "/circuit.zkey",
  );

  const proof = Groth16Proof.from_snarkjs(proofData.proof);
  const publicInputs = proofData.publicSignals.map((x: string) => BigInt(x));

  console.log(`proof: ${proof}`);
  console.log(`publicInputs: ${publicInputs}`);
  console.log(`circuitId ${circuitId}`);

  return { circuitId, proof, inputs: publicInputs };
}

export async function submitProofToUpa(
  proofData: application.CircuitIdProofAndInputs,
  provider: ethers.BrowserProvider,
): Promise<{
  submissionHandle: SubmissionHandle;
  txReceipt: ethers.ContractTransactionReceipt;
}> {
  await changeNetwork();
  await provider.send("eth_requestAccounts", []); // Prompt user to connect their wallet
  const signer = await provider.getSigner();
  const upaClient = await UpaClient.init(signer, upaInstanceDescriptor);

  // TODO: Web version of UpaClient
  const submissionHandle = await upaClient.submitProofs([
    {
      circuitId: proofData.circuitId,
      proof: proofData.proof,
      inputs: proofData.inputs,
    },
  ]);

  const proofId = submissionHandle.submission.proofIds[0];

  const txReceipt = await submissionHandle.txResponse.wait();
  if (!txReceipt) {
    throw new Error(`TransactionReceipt was undefined`);
  }

  console.log(
    `Proof submitted to UPA: https://sepolia.etherscan.io/tx/${txReceipt?.hash}`,
  );
  console.log(`https://sepolia.nebrascan.io/proofId/${proofId}`);

  return { submissionHandle, txReceipt };
}

export async function aggregatingProofOnUpa(
  proofData: application.CircuitIdProofAndInputs,
  submissionHandle: SubmissionHandle,
  provider: ethers.BrowserProvider,
): Promise<void> {
  await changeNetwork();
  const signer = await provider.getSigner();

  const upaClient = await UpaClient.init(signer, upaInstanceDescriptor);

  const proofId = await utils.computeProofId(
    proofData.circuitId,
    proofData.inputs,
  );

  await upaClient.waitForSubmissionVerified(submissionHandle);
}

export async function submittingToDemoApp(
  proofData: application.CircuitIdProofAndInputs,
  provider: ethers.BrowserProvider,
): Promise<ethers.ethers.ContractTransactionReceipt> {
  await changeNetwork();
  const signer = await provider.getSigner();
  const demoApp = demoAppFromDescriptor(
    demoAppInstanceDescriptor.demoApp,
    signer,
  );

  console.log(`Submitting solution to demo-app contract`);
  const submitSolutionTxResponse = await demoApp.submitSolution(
    proofData.inputs,
  );
  const submitSolutionTxReceipt = await submitSolutionTxResponse.wait();
  console.log(
    `Solution successfully submitted: https://sepolia.etherscan.io/tx/${submitSolutionTxReceipt?.hash}`,
  );
  return submitSolutionTxReceipt!;
}
