import { AppVkProofInputs } from "./application";

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

export class OffChainSubmissionRequest {
  constructor(
    public readonly proofs: AppVkProofInputs[],
    public readonly submission_id: string,
    public readonly submitter_nonce: bigint,
    public readonly fee: bigint,
    public readonly total_fee: bigint,
    public readonly expiration_block_number: bigint,
    /// Signature over [submission_id, totalFee, aggregatorAddress]
    public readonly signature: Signature
  ) {}
}

export class AggregationAgreement {
  constructor(
    public readonly submission_id: string,
    public readonly expiration_block_number: bigint
  ) {}
}

export class OffChainSubmissionResponse {
  constructor(
    public readonly submission_id: string,
    public readonly submitter_nonce: bigint,
    public readonly fee: bigint,
    public readonly total_fee: bigint
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
