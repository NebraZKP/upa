import {
  SubmissionInterval,
  siComputeSubmissionProof,
  siNumProofs,
  siProofIds,
} from "./submissionIntervals";
import {
  SubmissionProof,
  computeUnpackedOffChainSubmissionmarkers,
} from "./submission";
import { strict as assert } from "assert";

const MAX_NUMBER_OF_SUBMISSION_MARKERS = 256;

/// The set of arguments that must be passed to the UPA.verifyAggregatedProof
/// contract method.
export type AggregatedProofParameters = {
  proofIds: string[];
  numOnChainProofs: number;
  /// NOTE: must convert to `solidity` form before sending.
  submissionProofs: SubmissionProof[];
  /// Need packing before sending.
  offChainSubmissionMarkers: boolean[];
  dupSubmissionIdxs: number[];
};

/// Given a set of on-chain and off-chain SubmissionIntervals, compute the
/// parameters to the `verifyAggregatedProof` contract method.
export function computeAggregatedProofParameters<T>(
  onChainSubmissionIntervals: SubmissionInterval<T>[],
  offChainSubmissionIntervals: SubmissionInterval<T>[]
): AggregatedProofParameters {
  const allSubmissions = onChainSubmissionIntervals.concat(
    offChainSubmissionIntervals
  );
  const onChainNumProofs = siNumProofs(onChainSubmissionIntervals);
  const offChainNumProofs = siNumProofs(offChainSubmissionIntervals);
  const proofIds = allSubmissions.flatMap(siProofIds);
  const submissionProofs = onChainSubmissionIntervals
    .map(siComputeSubmissionProof)
    .filter((p) => !!p) as SubmissionProof[];

  // TODO: make `computeUnpackedOffChainSubmissionmarkers` accept
  // SubmissionInterval[]
  const offChainSubmissionMarkers: boolean[] = (() => {
    if (offChainSubmissionIntervals.length > 0) {
      const offChainOffset = offChainSubmissionIntervals[0].startIdx;
      const offChainSubmissions = offChainSubmissionIntervals.map(
        (si) => si.submission
      );
      return computeUnpackedOffChainSubmissionmarkers(
        offChainSubmissions,
        offChainOffset,
        offChainNumProofs
      );
    }
    return [];
  })();
  const dupSubmissionIdxs = onChainSubmissionIntervals.map((si) =>
    si.submission.getDupSubmissionIdx()
  );

  assert(onChainNumProofs + offChainNumProofs === proofIds.length);

  return {
    proofIds,
    numOnChainProofs: onChainNumProofs,
    submissionProofs,
    offChainSubmissionMarkers,
    dupSubmissionIdxs,
  };
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

/// `duplicateSubmissionIndices` represents an array of uint8, packed into a
/// single uint256.
export function packDupSubmissionIdxs(
  duplicateSubmissionIndices: number[]
): bigint {
  assert(
    duplicateSubmissionIndices.length <= 32,
    "Cannot pack more than 32 dupSubmissionIndices into a uint256"
  );
  let result: bigint = BigInt(0);

  for (let i = 0; i < duplicateSubmissionIndices.length; i++) {
    const dupSubmissionIdx = duplicateSubmissionIndices[i];
    assert(
      dupSubmissionIdx < 256,
      `invalid dupSubmissionIdx: ${dupSubmissionIdx}`
    );
    // Set the bits corresponding to index `i` to dupSubmissionIdx, using
    // bitwise-OR
    result |= BigInt(dupSubmissionIdx) << BigInt(i * 8);
  }

  return result;
}
