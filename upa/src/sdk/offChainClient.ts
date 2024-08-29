import { ethers, TypedDataDomain } from "ethers";
import {
  AppVkProofInputs,
  Groth16Proof,
  Groth16VerifyingKey,
} from "./application";
import assert from "assert";
import { Deposits__factory } from "../../typechain-types";
import * as utils from "./utils";

/// The outer type returned by off-chain submission API calls.
type ResponseObject = {
  data?: object;
  error?: string;
};

export class SubmitterState {
  constructor(
    public readonly lastNonce: bigint,
    public readonly totalFee: bigint
  ) {}

  public static from_json(obj: object): SubmitterState {
    const json = obj as SubmitterState;
    return new SubmitterState(BigInt(json.lastNonce), BigInt(json.totalFee));
  }
}

/// The current required parameters for submission.
export class SubmissionParameters {
  constructor(
    public readonly expectedLatency: number,
    public readonly minFeePerProof: bigint,
    public readonly depositContract: string
  ) {
    assert(typeof expectedLatency === "number");
    assert(typeof minFeePerProof === "bigint");
  }

  public static from_json(obj: object): SubmissionParameters {
    const json = obj as SubmissionParameters;
    return new SubmissionParameters(
      json.expectedLatency,
      BigInt(json.minFeePerProof),
      json.depositContract
    );
  }
}

///
export type Signature = string;

export const SIGNATURE_LENGTH = 132;

export class UnsignedOffChainSubmissionRequest {
  constructor(
    public readonly proofs: AppVkProofInputs[],
    public readonly submissionId: string,
    public readonly fee: bigint,
    public readonly expirationBlockNumber: number,
    public readonly submitterAddress: string,
    public readonly submitterNonce: bigint,
    public readonly totalFee: bigint
  ) {
    proofs.forEach((vpi) => {
      assert(vpi instanceof AppVkProofInputs);
    });
    assert(typeof submissionId === "string");
    assert(typeof expirationBlockNumber === "number");
    assert(typeof submitterAddress === "string");
    assert(typeof submitterNonce === "bigint");
    assert(typeof totalFee === "bigint");
  }

  public static from_json(obj: object): UnsignedOffChainSubmissionRequest {
    const json = obj as UnsignedOffChainSubmissionRequest;
    return new UnsignedOffChainSubmissionRequest(
      json.proofs.map((vpi) =>
        AppVkProofInputs.from_json(
          vpi,
          Groth16VerifyingKey.from_json,
          Groth16Proof.from_json
        )
      ),
      json.submissionId,
      BigInt(json.fee),
      json.expirationBlockNumber,
      json.submitterAddress,
      BigInt(json.submitterNonce),
      BigInt(json.totalFee)
    );
  }
}

// Data to be signed by the requester
export class SignedRequestData {
  constructor(
    /// The submissionId being submitted.
    public readonly submissionId: string,
    public readonly expirationBlockNumber: number,
    /// The totalFee payable to the aggregator after it has aggregated the
    /// submission with the given ID.
    public readonly totalFee: bigint
  ) {}
}

/// Full request data for a submission
// eslint-disable-next-line
export class OffChainSubmissionRequest extends UnsignedOffChainSubmissionRequest {
  constructor(
    proofs: AppVkProofInputs[],
    submissionId: string,
    fee: bigint,
    expirationBlockNumber: number,
    submitterAddress: string,
    submitterNonce: bigint,
    totalFee: bigint,
    public readonly signature: Signature // signature over: SignedRequestData
  ) {
    super(
      proofs,
      submissionId,
      fee,
      expirationBlockNumber,
      submitterAddress,
      submitterNonce,
      totalFee
    );
    assert(typeof signature === "string");
    assert(signature.length == SIGNATURE_LENGTH);
  }

  public static from_json(obj: object): OffChainSubmissionRequest {
    const unsigned = UnsignedOffChainSubmissionRequest.from_json(obj);
    const json = obj as OffChainSubmissionRequest;
    return new OffChainSubmissionRequest(
      unsigned.proofs,
      unsigned.submissionId,
      unsigned.fee,
      unsigned.expirationBlockNumber,
      unsigned.submitterAddress,
      unsigned.submitterNonce,
      unsigned.totalFee,
      json.signature
    );
  }
}

export class AggregationAgreement {
  constructor(
    /// The submission to be verified.
    public readonly submissionId: string,
    /// The block number by which the aggregator agrees to aggregate the
    /// submission.
    public readonly expirationBlockNumber: number,
    /// The fee to be refunded if the aggregator does not aggregate the
    /// submission before `expirationBlockNumber`.
    public readonly fee: bigint,
    /// The address of the submitter who should receive the refund.
    public readonly submitterAddress: string
  ) {}
}

export class UnsignedOffChainSubmissionResponse {
  constructor(
    public readonly submissionId: string,
    public readonly fee: bigint,
    public readonly expirationBlockNumber: number,
    public readonly submitterAddress: string,
    public readonly submitterNonce: bigint,
    public readonly totalFee: bigint
  ) {
    assert(typeof submissionId === "string");
    assert(submissionId.length === 66);
    assert(typeof fee === "bigint");
    assert(typeof expirationBlockNumber === "number");
    assert(typeof submitterAddress === "string");
    assert(submitterAddress.length === 42);
    assert(typeof submitterNonce === "bigint");
    assert(typeof totalFee === "bigint");
  }

  public static from_json(obj: object): UnsignedOffChainSubmissionResponse {
    const json = obj as UnsignedOffChainSubmissionResponse;
    return new UnsignedOffChainSubmissionResponse(
      json.submissionId,
      json.fee,
      json.expirationBlockNumber,
      json.submitterAddress,
      json.submitterNonce,
      json.totalFee
    );
  }
}

// eslint-disable-next-line
export class OffChainSubmissionResponse extends UnsignedOffChainSubmissionResponse {
  constructor(
    public readonly submissionId: string,
    public readonly fee: bigint,
    public readonly expirationBlockNumber: number,
    public readonly submitterAddress: string,
    public readonly submitterNonce: bigint,
    public readonly totalFee: bigint,
    public readonly signature: Signature // Signature over AggregationAgreement
  ) {
    super(
      submissionId,
      fee,
      expirationBlockNumber,
      submitterAddress,
      submitterNonce,
      totalFee
    );
    assert(typeof signature === "string");
    assert(signature.length == SIGNATURE_LENGTH);
  }

  public static from_json(obj: object): OffChainSubmissionResponse {
    const json = obj as OffChainSubmissionResponse;
    return new OffChainSubmissionResponse(
      json.submissionId,
      BigInt(json.fee),
      json.expirationBlockNumber,
      json.submitterAddress,
      BigInt(json.submitterNonce),
      BigInt(json.totalFee),
      json.signature
    );
  }
}

export class OffChainClient {
  private constructor(
    private readonly baseUrl: string,
    private readonly depositContract: string
  ) {
    assert(typeof depositContract === "string");
    assert(baseUrl.endsWith("/"));
  }

  public static async init(baseUrl: string): Promise<OffChainClient> {
    if (!baseUrl.endsWith("/")) {
      baseUrl += "/";
    }
    const { depositContract } = SubmissionParameters.from_json(
      await getRequest(baseUrl + "parameters")
    );
    return new OffChainClient(baseUrl, depositContract);
  }

  public getDepositContract(): string {
    return this.depositContract;
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
    return SubmissionParameters.from_json(
      await getRequest(this.baseUrl + "parameters")
    );
  }

  /// TODO: should we require a signature here?
  public async getSubmitterState(address: string): Promise<SubmitterState> {
    return SubmitterState.from_json(
      await getRequest(this.baseUrl + `submitters/${address}`)
    );
  }

  public async submit(
    request: OffChainSubmissionRequest
  ): Promise<OffChainSubmissionResponse> {
    return OffChainSubmissionResponse.from_json(
      await jsonPostRequest(this.baseUrl + "submit", request)
    );
  }
}

async function processResponse(
  response: Response,
  url: string,
  reqBody?: string
): Promise<object> {
  const body = (await response.json()) as ResponseObject;
  assert(typeof body === "object");
  if (!response.ok) {
    throw (
      `Request (${url}) failed (status ${response.status}): ` +
      `${utils.JSONstringify(body)}\nEND OF RESPONSE` +
      (reqBody ? `\nRequest body:\n${reqBody}\nEND OF REQUEST\n` : "")
    );
  }

  if (body.error) {
    throw `Request (${url}) status OK, but error string: ${body.error}`;
  }

  if (body.data === undefined) {
    throw `Request (${url}) got status OK, but contained no data`;
  }

  return body.data;
}

async function getRequest(url: string): Promise<object> {
  const response = await fetch(url);
  return processResponse(response, url);
}

async function jsonPostRequest<Request>(
  url: string,
  request: Request
): Promise<object> {
  const requestBody = utils.JSONstringify(request);
  const response = await fetch(url, {
    method: "POST",
    body: requestBody,
    headers: { "Content-Type": "application/json" },
  });

  return processResponse(response, url, requestBody);
}

/// Get the EIP-712 domain for the deposits contract, to be used to sign
/// requests.
export async function getEIP712Domain(
  wallet: ethers.Signer,
  depositsContract: string
): Promise<TypedDataDomain> {
  assert(typeof depositsContract === "string");
  // TODO: do we need the signer here?
  const deposits = Deposits__factory.connect(depositsContract).connect(wallet);
  const { chainId, name, version, verifyingContract } =
    await deposits.eip712Domain();
  return {
    // Chain where the deposits contract is deployed
    chainId,
    // Name of the deposits contract
    name,
    // The version of the deposits contract we are sending the request to.
    // (This is different from the UPA package version)
    version,
    // The address of the off-chain aggregator's deposits contract
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

/// Gets the EIP-712 message type for `AggregationAgreement`.
export function getEIP712ResponseType() {
  return {
    AggregationAgreement: [
      { name: "submissionId", type: "bytes32" },
      { name: "expirationBlockNumber", type: "uint256" },
      { name: "fee", type: "uint256" },
      { name: "submitterAddress", type: "address" },
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

/// Sign an off-chain submission request directed to `depositsContract`.
export async function signOffChainSubmissionRequest(
  request: UnsignedOffChainSubmissionRequest,
  wallet: ethers.Signer,
  depositsContract: string
): Promise<OffChainSubmissionRequest> {
  const domain = await getEIP712Domain(wallet, depositsContract);
  const types = getEIP712RequestType();

  const signedRequestData: SignedRequestData = {
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

  return new OffChainSubmissionRequest(
    request.proofs,
    request.submissionId,
    request.fee,
    request.expirationBlockNumber,
    request.submitterAddress,
    request.submitterNonce,
    request.totalFee,
    signature
  );
}

/// Get the signed portion of the response data.
export function getSignedResponseData(
  signedResponse: OffChainSubmissionResponse
): AggregationAgreement {
  return {
    submissionId: signedResponse.submissionId,
    expirationBlockNumber: signedResponse.expirationBlockNumber,
    fee: signedResponse.totalFee,
    submitterAddress: signedResponse.submitterAddress,
  };
}

// Method to sign responses here placed in this file for now, but should be
// moved.
/// Sign an off-chain submission response directed to `depositsContract`.
export async function signOffChainSubmissionResponse(
  response: UnsignedOffChainSubmissionResponse,
  wallet: ethers.Signer,
  depositsContract: string
): Promise<OffChainSubmissionResponse> {
  const domain = await getEIP712Domain(wallet, depositsContract);
  const types = getEIP712ResponseType();

  const aggregationAgreement: AggregationAgreement = {
    submissionId: response.submissionId,
    expirationBlockNumber: response.expirationBlockNumber,
    fee: response.totalFee,
    submitterAddress: response.submitterAddress,
  };

  const signature = await wallet.signTypedData(
    domain,
    types,
    aggregationAgreement
  );

  assert(
    ethers.verifyTypedData(domain, types, aggregationAgreement, signature) ==
      (await wallet.getAddress())
  );

  return new OffChainSubmissionResponse(
    response.submissionId,
    response.fee,
    response.expirationBlockNumber,
    response.submitterAddress,
    response.submitterNonce,
    response.totalFee,
    signature
  );
}
