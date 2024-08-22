import * as ethers from "ethers";
import {
  UpaInstance,
  UpaInstanceDescriptor,
  upaInstanceFromDescriptor,
  submitProofs,
  waitForSubmissionVerified,
  updateFeeOptions,
} from "./upa";
import { Groth16VerifyingKey } from "./application";
import { PayableOverrides } from "../../typechain-types/common";
import { Submission, SubmissionDescriptor } from "./submission";
import { application } from ".";
import { TypedDataDomain } from "ethers";
import assert from "assert";
import { UpaOffChainFee__factory } from "../../typechain-types";

/**
 * Returned by the `submitProofs` method of UpaClient.  Holds a
 * `Submission` object and the `ethers.TransactionResponse` for the
 * transaction that performed the submission.
 */
export type SubmissionHandle = {
  submission: SubmissionDescriptor;
  txResponse: ethers.ContractTransactionResponse;
};

/**
 * Client class exposing high-level operations requiring interaction
 * with the UPA deployment on-chain.
 */
export class UpaClient {
  private constructor(public upaInstance: UpaInstance) {}

  public static async init(
    signer: ethers.ethers.ContractRunner,
    upaInstanceDescriptor: UpaInstanceDescriptor
  ): Promise<UpaClient> {
    return new UpaClient(
      await upaInstanceFromDescriptor(upaInstanceDescriptor, signer)
    );
  }

  // Submit one or more `(circuitId, proof, instance)` tuples to be verified
  // in one transaction.
  public async submitProofs(
    circuitIdProofAndInputs: application.CircuitIdProofAndInputs[],
    options?: PayableOverrides
  ): Promise<SubmissionHandle> {
    const submission = SubmissionDescriptor.fromCircuitIdsProofsAndInputs(
      circuitIdProofAndInputs
    );

    const txResponse = await submitProofs(
      this.upaInstance.verifier,
      submission.circuitIds,
      submission.proofs,
      submission.inputs,
      options
    );

    // console.log(
    //   `SubmissionId ${submission.getSubmissionId()} ` +
    //   `(txid: ${txResponse.hash})`
    // );

    return { submission, txResponse };
  }

  /// Wait for the submission to be successfully sent to the contract, and
  /// extract a full Submission object from the Tx receipt.  Note, this can
  /// fail if the submission is malformed.
  public async getSubmission(
    submissionHandle: SubmissionHandle
  ): Promise<Submission> {
    const txReceipt = await submissionHandle.txResponse.wait();
    if (!txReceipt) {
      throw `Failed to get receipt for tx ${submissionHandle.txResponse.hash}`;
    }
    const submission = await Submission.fromTransactionReceipt(
      this.upaInstance.verifier,
      txReceipt
    );
    if (!submission) {
      throw "failed to read submission from tx receipt";
    }

    return submission;
  }

  // Waits for all of the proofs corresponding to a `SubmissionHandle` to be
  // verified on-chain.
  public async waitForSubmissionVerified(submissionHandle: SubmissionHandle) {
    const txReceipt = await submissionHandle.txResponse.wait();
    if (!txReceipt) {
      throw new Error(`Null TransactionReceipt`);
    }

    // Throws if submission contains rejected proofs.
    await waitForSubmissionVerified(this.upaInstance, txReceipt);

    return txReceipt;
  }

  /**
   * Estimates the fee for a submission of `submissionSize` proofs.  Fee is
   * based on the gas price, which can be set via `options`, otherwise the
   * default from the connected node is used.
   */
  public async estimateFee(
    submissionSize: number,
    options?: PayableOverrides
  ): Promise<bigint> {
    const updatedOptions = await updateFeeOptions(
      this.upaInstance.verifier,
      submissionSize,
      options
    );
    return BigInt(updatedOptions.value!);
  }

  // Estimates the gas needed to submit `cidProofPIs`.
  public async estimateGas(
    cidProofPIs: application.CircuitIdProofAndInputs[]
  ): Promise<bigint> {
    const options = await updateFeeOptions(
      this.upaInstance.verifier,
      cidProofPIs.length
    );

    return await this.upaInstance.verifier.submit.estimateGas(
      cidProofPIs.map((cidProofPI) => cidProofPI.circuitId),
      cidProofPIs.map((cidProofPI) => cidProofPI.proof.compress().solidity()),
      cidProofPIs.map((cidProofPI) => cidProofPI.inputs),
      options
    );
  }

  public async registerVK(
    vk: Groth16VerifyingKey
  ): Promise<ethers.ContractTransactionResponse> {
    return this.upaInstance.verifier.registerVK(vk.solidity());
  }
}

export type UnsignedOffChainSubmissionRequest = {
  circuitIdProofAndInputs: application.CircuitIdProofAndInputs[];
  submissionId: ethers.BytesLike;
  expirationBlockNumber: bigint;
  submitterNonce: bigint;
  fee: bigint;
  totalFee: bigint;
};

// Signed request to be sent out-of-band to an aggregator
export type SignedOffChainSubmissionRequest = {
  circuitIdProofAndInputs: application.CircuitIdProofAndInputs[];
  submissionId: ethers.BytesLike;
  expirationBlockNumber: bigint;
  submitterNonce: bigint;
  fee: bigint;
  totalFee: bigint;
  signature: string;
};

// Data to be signed by the requester
export type SignedRequestData = {
  submissionId: ethers.BytesLike;
  expirationBlockNumber: bigint;
  totalFee: bigint;
};

/// Get the EIP-712 domain for the fee contract, to be used to sign requests.
export async function getEIP712Domain(
  wallet: ethers.Signer,
  offChainFeeContract: ethers.AddressLike
): Promise<TypedDataDomain> {
  const upaOffChainFee = UpaOffChainFee__factory.connect(
    offChainFeeContract.toString()
  ).connect(wallet);
  const { chainId, name, version, verifyingContract } =
    await upaOffChainFee.eip712Domain();
  return {
    // Chain where the fee contract is deployed
    chainId,
    // Name of the fee contract
    name,
    // The version of the fee contract we are sending the request to.
    // (This is different from the UPA package version)
    version,
    // The address of the off-chain aggregator's fee contract
    verifyingContract,
  };
}

/// Gets the EIP-712 message type for `SignedRequestData`.
export function getEIP712RequestType() {
  return {
    SignedRequestData: [
      { name: "submissionId", type: "bytes32" },
      { name: "expirationBlockNumber", type: "uint256" },
      { name: "totalFee", type: "uint256" },
    ],
  };
}

/// Sign an off-chain submission request directed to `feeContract`.
export async function signOffChainSubmissionRequest(
  request: UnsignedOffChainSubmissionRequest,
  wallet: ethers.Signer,
  feeContract: ethers.AddressLike
): Promise<SignedOffChainSubmissionRequest> {
  const domain = await getEIP712Domain(wallet, feeContract);
  const types = getEIP712RequestType();

  const signedRequestData = {
    submissionId: request.submissionId,
    expirationBlockNumber: request.expirationBlockNumber,
    totalFee: request.totalFee,
  };

  const signature = await wallet.signTypedData(
    domain,
    types,
    signedRequestData
  );

  assert(
    ethers.verifyTypedData(domain, types, signedRequestData, signature) ==
      (await wallet.getAddress())
  );

  return { ...request, signature };
}

/// Get the signed portion of the request data.
export function getSignedRequestData(
  signedRequest: SignedOffChainSubmissionRequest
): SignedRequestData {
  return {
    submissionId: signedRequest.submissionId,
    expirationBlockNumber: signedRequest.expirationBlockNumber,
    totalFee: signedRequest.totalFee,
  };
}
