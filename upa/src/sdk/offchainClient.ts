import { ethers, TypedDataDomain } from "ethers";
import { AppVkProofInputs } from "./application";
import assert from "assert";
import { Deposits__factory } from "../../typechain-types";

export class SubmitterState {
  constructor(
    public readonly submitter_nonce: bigint,
    public readonly total_fee: bigint
  ) {}
}

/// The current required parameters for submission.
export class SubmissionParameters {
  constructor(
    public readonly expected_latency: bigint,
    public readonly min_fee_per_proof: bigint
  ) {}
}

/// TODO
export type Signature = string;

/// Pertinent data about a submission
export class OffChainSubmission {
  constructor(
    public readonly proofs: AppVkProofInputs[],
    public readonly submissionId: string,
    public readonly fee: bigint,
    public readonly expirationBlockNumber: bigint,
    public readonly submitterId: string,
    /// Signature over [submission_id, totalFee, aggregatorAddress]
    public readonly signature: Signature
  ) {}
}

export class UnsignedOffChainSubmissionRequest {
  constructor(
    public readonly proofs: AppVkProofInputs[],
    public readonly submissionId: string,
    public readonly expirationBlockNumber: bigint,
    public readonly submitterNonce: bigint,
    public readonly submitterId: string,
    public readonly fee: bigint,
    public readonly totalFee: bigint
  ) {}
}

// Data to be signed by the requester
export class SignedRequestData {
  constructor(
    public readonly submissionId: string,
    public readonly expirationBlockNumber: bigint,
    public readonly totalFee: bigint
  ) {}
}

/// Full request data for a submission
export class OffChainSubmissionRequest extends OffChainSubmission {
  constructor(
    proofs: AppVkProofInputs[],
    submissionId: string,
    fee: bigint,
    expirationBlockNumber: bigint,
    submitterId: string,
    signature: Signature,
    public readonly submitterNonce: bigint,
    public readonly totalFee: bigint
  ) {
    super(
      proofs,
      submissionId,
      fee,
      expirationBlockNumber,
      submitterId,
      signature
    );
  }
}

export class AggregationAgreement {
  constructor(
    public readonly submissionId: string,
    public readonly expirationBlockNumber: bigint,
    public readonly fee: bigint
  ) {}
}

export class OffChainSubmissionResponse {
  constructor(
    public readonly submissionId: string,
    public readonly submitterNonce: bigint,
    public readonly fee: bigint,
    public readonly totalFee: bigint,
    /// Signature over [submissionId, expirationBlockNumber, fee]
    public readonly signature: Signature
  ) {}
}

export class OffChainClient {
  private constructor() {}

  public static async init(endpoint: string): Promise<OffChainClient> {
    throw "todo";
  }

  /// The aggregator's address.
  /// TODO: ideally it should be possible to verify this (on-chain?).
  public async getAddress(): Promise<string> {
    throw "todo";
  }

  /// TODO: should we require a signature here?
  public async getSubmitterState(address: string): Promise<SubmitterState> {
    throw "todo";
  }

  /// Returns the current expected latency in blocks, the expected fee per
  /// proof, etc.  Clients are expected to use recent values of these for
  /// submitting.
  ///
  /// Submissions using these parameters (e.g. with a expiration time of
  /// `cur_block_number + expected_latency`, `fee >= min_fee_per_proof`, etc)
  /// are expected to succeedif the submission is made within a reasonable
  /// time-frame (in the order of 10 blocks).
  public async getSubmissionParameters(): Promise<SubmissionParameters> {
    throw "todo";
  }

  public async submit(
    request: OffChainSubmissionRequest
  ): Promise<OffChainSubmissionResponse> {
    throw "todo";
  }
}

/// Get the EIP-712 domain for the fee contract, to be used to sign requests.
export async function getEIP712Domain(
  wallet: ethers.Signer,
  depositsContract: ethers.AddressLike
): Promise<TypedDataDomain> {
  const deposits = Deposits__factory.connect(
    depositsContract.toString()
  ).connect(wallet);
  const { chainId, name, version, verifyingContract } =
    await deposits.eip712Domain();
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

/// Get the signed portion of the request data.
export function getSignedRequestData(
  signedRequest: OffChainSubmissionRequest
): SignedRequestData {
  return {
    submissionId: signedRequest.submissionId,
    expirationBlockNumber: signedRequest.expirationBlockNumber,
    totalFee: signedRequest.totalFee,
  };
}

/// Sign an off-chain submission request directed to `feeContract`.
export async function signOffChainSubmissionRequest(
  request: UnsignedOffChainSubmissionRequest,
  wallet: ethers.Signer,
  feeContract: ethers.AddressLike
): Promise<OffChainSubmissionRequest> {
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
