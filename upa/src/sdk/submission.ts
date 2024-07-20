import * as ethers from "ethers";
import * as application from "./application";
import {
  EventSet,
  ProofSubmittedEventWithProofData,
  getCallDataForSubmitTx,
} from "./events";
import { UpaProofReceiver } from "../../typechain-types";
// eslint-disable-next-line
import { ProofReferenceStruct } from "../../typechain-types/contracts/IUpaVerifier";
// eslint-disable-next-line
import { SubmissionProofStruct } from "../../typechain-types/contracts/UpaVerifier";
import {
  computeMerkleProof,
  createMerkleIntervalProof,
  evmInnerHashFn,
  evmLeafHashFn,
} from "./merkleUtils";
import {
  bytes32IsWellFormed,
  computeProofId,
  computeSubmissionId,
  JSONstringify,
} from "./utils";
import assert from "assert";
import { CompressedGroth16Proof } from "./groth16";

/// This must match the value defined in the ProofReceiver contract.  For now,
/// we use uint16 values as indices, and so the the max submission size is
/// 2^16.
const MAX_SUBMISSION_SIZE = 1 << 16;

const MAX_NUMBER_OF_SUBMISSION_MARKERS = 256;

// TODO: Why do we need to define this?
/// The type of objects passed to `parseLog`.
type Log = { topics: Array<string>; data: string };

export const ZERO_BYTES32 =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

/// The proof that a given sequence of proofIds belong to an existing
/// submission.  This is intended to be sent to the UpaVerifier alongside
/// aggregated proofs.  See the solidity definition of SubmissionProof for
/// details.
export class SubmissionProof {
  constructor(
    public submissionId: ethers.BytesLike,
    public proof: ethers.BytesLike[]
  ) {}

  public static from_json(json: string): SubmissionProof {
    const object = JSON.parse(json);
    return new SubmissionProof(object.submissionId, object.proof);
  }

  public solidity(): SubmissionProofStruct {
    return this;
  }

  public to_json(): string {
    return JSONstringify(this);
  }
}

export class ProofReference {
  constructor(
    public submissionId: ethers.BytesLike,
    public merkleProof: ethers.BytesLike[],
    public location: number
  ) {}

  public static from_json(json: string): ProofReference {
    const object = JSON.parse(json);
    return new ProofReference(
      object.submissionId,
      object.merkleProof,
      object.location
    );
  }

  public solidity(): ProofReferenceStruct {
    return this;
  }

  public to_json(): string {
    return JSONstringify(this);
  }
}

export class Submission {
  public circuitIds: string[];
  public proofs: application.Groth16Proof[];
  public inputs: bigint[][];
  proofIds: string[];
  paddedProofIds: ethers.BytesLike[];
  depth: number;
  submissionId: ethers.BytesLike;

  private constructor(
    proofIds: ethers.BytesLike[],
    circuitIds: string[],
    proofs: application.Groth16Proof[],
    inputs: bigint[][]
  ) {
    assert(proofIds.length > 0);
    assert(proofIds.length <= MAX_SUBMISSION_SIZE);
    assert(proofIds.length === circuitIds.length);
    assert(proofIds.length === proofs.length);
    assert(proofIds.length === inputs.length);
    circuitIds.forEach((x: string) => assert(bytes32IsWellFormed(x)));

    const depth = Math.ceil(Math.log2(proofIds.length));
    const paddedLength = 1 << depth;
    const paddedProofIds = proofIds.slice();
    while (paddedProofIds.length < paddedLength) {
      paddedProofIds.push(ZERO_BYTES32);
    }

    proofIds.forEach((pid) => assert(typeof pid === "string"));

    this.circuitIds = circuitIds;
    this.proofs = proofs;
    this.inputs = inputs;
    this.proofIds = proofIds as string[];
    this.paddedProofIds = paddedProofIds;
    this.depth = depth;
    this.submissionId = computeSubmissionId(this.proofIds);
  }

  public static fromCircuitIdsProofsAndInputs(
    cidProofsAndInputs: application.CircuitIdProofAndInputs[]
  ): Submission {
    const circuitIds: string[] = [];
    const proofs: application.Groth16Proof[] = [];
    const inputs: bigint[][] = [];
    const proofIds: ethers.BytesLike[] = [];
    cidProofsAndInputs.forEach((cpi) => {
      const pubInputs = cpi.inputs.map(BigInt);
      circuitIds.push(cpi.circuitId);
      proofs.push(cpi.proof);
      inputs.push(pubInputs);
      proofIds.push(computeProofId(cpi.circuitId, pubInputs));
    });
    return new Submission(proofIds, circuitIds, proofs, inputs);
  }

  public static async fromTransactionReceipt(
    proofReceiver: UpaProofReceiver,
    txReceipt: ethers.TransactionReceipt
  ): Promise<Submission> {
    const provider = proofReceiver.runner!.provider!;
    const tx = await provider.getTransaction(txReceipt.hash);
    return Submission.fromTransactionReceiptAndData(
      proofReceiver,
      txReceipt,
      tx!
    );
  }

  public static fromTransactionReceiptAndData(
    proofReceiver: UpaProofReceiver,
    txReceipt: ethers.TransactionReceipt,
    tx: ethers.TransactionResponse
  ): Submission {
    const { circuitIds, proofs, publicInputs } = getCallDataForSubmitTx(
      proofReceiver,
      tx
    );
    const groth16Proofs: application.Groth16Proof[] = proofs.map((pf) => {
      return CompressedGroth16Proof.from_solidity(pf).decompress();
    });

    assert(circuitIds.length == txReceipt.logs.length);

    // Extract the proof ids from the events.  As a sanity check, also locally
    // compute each proofId using the circuitId and public inputs from the tx
    // data.

    const proofIds: ethers.BytesLike[] = [];
    txReceipt.logs.forEach((log, i) => {
      const parsed = proofReceiver.interface.parseLog(log as unknown as Log);
      if (parsed) {
        const proofId = parsed.args.proofId;
        assert(proofId === computeProofId(circuitIds[i], [...publicInputs[i]]));
        proofIds.push(proofId);
      }
    });

    return new Submission(proofIds, circuitIds, groth16Proofs, publicInputs);
  }

  public static fromSubmittedEvents(
    events: EventSet<ProofSubmittedEventWithProofData>
  ) {
    const submission = Submission.fromCircuitIdsProofsAndInputs(
      events.events.map((ev) => {
        return {
          circuitId: ev.circuitId,
          proof: CompressedGroth16Proof.from_solidity(ev.proof).decompress(),
          inputs: ev.publicInputs,
        };
      })
    );

    // TODO: check the proofIds in the events against the computed version.

    return submission;
  }

  public static from_json(json: string): Submission {
    const object = JSON.parse(json);
    const proofs: application.Groth16Proof[] = object.proofs.map(
      application.Groth16Proof.from_json
    );
    const inputs: bigint[][] = object.inputs.map((instance: string[]) =>
      instance.map((x: string) => BigInt(x))
    );
    const proofIds: ethers.BytesLike[] = object.proofIds;
    return new Submission(proofIds, object.circuitIds, proofs, inputs);
  }

  public to_json(): string {
    return JSONstringify(this);
  }

  public getProofIds(startIdx?: number, numProofs?: number): string[] {
    if (startIdx || numProofs) {
      startIdx = startIdx || 0;
      const endIdx = numProofs ? startIdx + numProofs : this.proofs.length;
      assert(endIdx <= this.proofIds.length);
      return this.proofIds.slice(startIdx, endIdx);
    }
    return this.proofIds;
  }

  public getSubmissionId(): ethers.BytesLike {
    return this.submissionId;
  }

  /// Extract a sub-interval of the CircuitIdProofAndInputs structures.  Used
  /// primarily by off-chain aggregators to form inner proof batches.
  public getCircuitIdsProofsAndInputs(
    startIdx: number,
    numProofs: number
  ): application.CircuitIdProofAndInputs[] {
    const cpis: application.CircuitIdProofAndInputs[] = [];
    const endIdx = startIdx + numProofs;
    assert(endIdx <= this.proofs.length);
    for (let i = startIdx; i < endIdx; ++i) {
      cpis.push({
        circuitId: this.circuitIds[i],
        proof: this.proofs[i],
        inputs: this.inputs[i],
      });
    }

    return cpis;
  }

  public getUnpackedOffChainSubmissionMarkers(): boolean[] {
    const submissionMarkers: boolean[] = Array(this.proofIds.length).fill(
      false
    );

    // Mark the end of the submission with `true`.
    submissionMarkers[submissionMarkers.length - 1] = true;

    return submissionMarkers;
  }

  /// Return a reference to a proof in this submission.  `undefined` if a
  /// reference is not required (single-entry submissions).
  public computeProofReference(location: number): ProofReference | undefined {
    if (this.proofIds.length === 1) {
      return undefined;
    } else {
      const { root, proof } = computeMerkleProof(
        evmLeafHashFn,
        evmInnerHashFn,
        this.paddedProofIds,
        location
      );
      return new ProofReference(root, proof, location);
    }
  }

  public computeProofIdMerkleProof(location: number): ethers.BytesLike[] {
    const { proof } = computeMerkleProof(
      evmLeafHashFn,
      evmInnerHashFn,
      this.paddedProofIds,
      location
    );
    return proof;
  }

  public computeProofDataMerkleProof(location: number): ethers.BytesLike[] {
    const proofDigests = this.proofs.map((proof) => {
      return proof.compress().proofDigest();
    });
    const { proof } = computeMerkleProof(
      evmLeafHashFn,
      evmInnerHashFn,
      proofDigests,
      location
    );
    return proof;
  }

  /// Returns a Submission proof for the given slice of proofs.  `undefined`
  /// if not required (single-entry submission).
  public computeSubmissionProof(
    offset: number,
    numEntries: number
  ): SubmissionProof | undefined {
    assert(0 <= offset);
    assert(offset < this.proofIds.length);
    assert(0 < numEntries);
    assert(offset + numEntries <= this.proofIds.length);

    // If the submission has a single proof, we don't need a proof.

    if (this.proofIds.length == 1) {
      return undefined;
    }

    // Compute the interval proof for the range of entries.

    const { proof, root } = createMerkleIntervalProof(
      evmLeafHashFn,
      evmInnerHashFn,
      this.paddedProofIds,
      offset,
      numEntries
    );
    return new SubmissionProof(root, proof);
  }

  public isMultiProofSubmission(): boolean {
    return this.proofIds.length > 1;
  }
}

/// Packs a boolean[] containing off-chain submission markers from one or more
/// submissions, into a uint256[] that is ready to be passed into
/// `verifyAggregatedProof`.
export function packOffChainSubmissionMarkers(
  submissionMarkers: boolean[]
): bigint {
  assert(submissionMarkers.length <= MAX_NUMBER_OF_SUBMISSION_MARKERS);

  let packedMarker = BigInt(0);

  for (let i = 0; i < 256; i++) {
    if (i < submissionMarkers.length && submissionMarkers[i]) {
      // Set the bit if the boolean value is true using bitwise-OR
      packedMarker |= BigInt(1) << BigInt(i);
    }
  }

  return packedMarker;
}

/// Computes an interval of unpacked submission markers for an array of
/// submissions.
/// `startIdx` - The index of the first proof to be marked
/// `numProofs` - How many proofs to mark, starting from `startIdx`.
export function computeUnpackedOffChainSubmissionmarkers(
  submissions: Submission[],
  startIdx: number,
  numProofs: number
): boolean[] {
  const unpackedSubmissionMarkers = submissions.flatMap((submission) =>
    submission.getUnpackedOffChainSubmissionMarkers()
  );

  const truncatedMarkers = unpackedSubmissionMarkers.slice(
    startIdx,
    startIdx + numProofs
  );

  return truncatedMarkers;
}
