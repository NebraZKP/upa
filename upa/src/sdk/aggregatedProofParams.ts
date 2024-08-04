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
