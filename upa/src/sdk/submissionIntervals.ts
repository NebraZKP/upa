// eslint-disable-next-line
import { EventSet, ProofSubmittedEventWithProofData } from "./events";
import { UpaInstance } from "./upa";
import { Submission } from "./submission";
import { JSONstringify } from "./utils";
import { DUMMY_SUBMISSION_ID } from "./application";
import { strict as assert } from "assert";

// For inner / outer batches that contain full or partial multi-proof
// submissions, we must track the sub-vector of proofs from each submission.
export type SubmissionInterval<T = undefined> = {
  submission: Submission;
  startIdx: number;
  numProofs: number;
  data: T;
};

/// Gives a short string representation of a submission interval
export function siBrief<T>(si: SubmissionInterval<T>): string {
  return JSONstringify({
    submissionId: si.submission.submissionId,
    startIdx: si.startIdx,
    numProofs: si.numProofs,
    data: si.data,
  });
}

/// Returns all proofIds contained in this interval
export function siProofIds<T>(si: SubmissionInterval<T>): string[] {
  return si.submission.proofIds.slice(si.startIdx, si.startIdx + si.numProofs);
}

/// Given an array of entries, each holding a list of submission intervals.
/// Return a single list of all SubmissionIntervals, where neighbouring
/// intervals are merged.  Sanity check that no sub-vectors of proofs are
/// skipped.
export function mergeSubmissionIntervals<T>(
  intervals: SubmissionInterval<T>[]
): SubmissionInterval<T>[] {
  // Trivial cases where length is 0 or 1
  if (intervals.length <= 1) {
    return intervals;
  }

  const mergedIntervals: SubmissionInterval<T>[] = [];
  let curInterval = intervals[0];
  let doNotMerge = false;

  for (let i = 1; i < intervals.length; ++i) {
    const curSubId = curInterval.submission.getSubmissionId();
    const nextInterval = intervals[i];
    const nextSubmissionId = nextInterval.submission.getSubmissionId();

    if (curSubId === DUMMY_SUBMISSION_ID) {
      // The current submission is the dummy proof.
      // After this only more dummy submissions are allowed, and
      // they won't be merged.
      // Assert the next submission is also a dummy submission.
      assert(
        nextSubmissionId === DUMMY_SUBMISSION_ID,
        `Non-dummy proof after dummy proof in batch`
      );
      // Sanity check: make sure the dummy submission consists of
      // only 1 proof
      assert.ok(
        curInterval.submission.proofIds.length === 1,
        `Dummy submission with more than one proof`
      );
      // No intervals shall be merged past this point
      doNotMerge = true;
    }
    if (!doNotMerge && nextSubmissionId == curSubId) {
      if (curInterval.data != nextInterval.data) {
        throw (
          `nextInterval data ${nextInterval.data}` +
          `(expected ${curInterval.data})`
        );
      }
      const curEndIdx = curInterval.startIdx + curInterval.numProofs;
      if (nextInterval.startIdx == curEndIdx) {
        // The intervals can be merged.
        // Add next into the current interval;
        curInterval = {
          submission: curInterval.submission,
          startIdx: curInterval.startIdx,
          numProofs: curInterval.numProofs + nextInterval.numProofs,
          data: curInterval.data,
        };
        continue;
      } else {
        // SubmissionIds match, so indices should line up
        throw (
          `nextInterval w/ startIdx ${nextInterval.startIdx} ` +
          `(expected ${curEndIdx})`
        );
      }
    } else {
      // SubmissionIds do NOT match, so curInterval should include the
      // tail of the submission, and `nextInterval` should include
      // the head.
      if (
        curInterval.startIdx + curInterval.numProofs !=
        curInterval.submission.proofs.length
      ) {
        throw `SubmissionInterval truncated:
                    ${JSONstringify(curInterval)}`;
      }

      if (nextInterval.startIdx !== 0) {
        throw `SubmissionInterval misses head:
                    ${JSONstringify(nextInterval)}`;
      }
    }

    // Intervals cannot be merged.  Push `curInterval` onto the list and
    // assign `curInterval <- nextInterval` for consideration in the next
    // iteration.
    mergedIntervals.push(curInterval);
    curInterval = nextInterval;
  }

  // Always need to push the last interval considered.
  mergedIntervals.push(curInterval);
  return mergedIntervals;
}

/// Given a SubmissionInterval, create an interval that spans the first (up
/// to) `numProofsRequired` proofs, and an interval that contains the
/// remainder, if any.
export function splitSubmissionInterval<T>(
  submissionInterval: SubmissionInterval<T>,
  numProofsRequired: number
): [SubmissionInterval<T>, SubmissionInterval<T> | undefined] {
  const origNumProofs = submissionInterval.numProofs;

  // Early out in the trivial case that we consume the entire interval.
  if (numProofsRequired >= origNumProofs) {
    return [submissionInterval, undefined];
  }

  // A non-trivial split is required.
  const origStartIdx = submissionInterval.startIdx;
  const submission = submissionInterval.submission;
  return [
    {
      submission,
      startIdx: origStartIdx,
      numProofs: numProofsRequired,
      data: submissionInterval.data,
    },
    {
      submission,
      startIdx: origStartIdx + numProofsRequired,
      numProofs: origNumProofs - numProofsRequired,
      data: submissionInterval.data,
    },
  ];
}

/**
 * @param checkVerified True if the first submission in `newEvents`
 * may contain already verified proofs.
 * @param upaInstance
 * @param newEvents Each `EventSet` contains `ProofSubmittedEvent`s
 * @returns An array of `SubmissionInterval`s that does not include
 * any already verified proofs.
 */
export async function submissionIntervalsFromEvents(
  checkVerified: boolean,
  upaInstance: UpaInstance,
  newEvents: EventSet<ProofSubmittedEventWithProofData>[]
): Promise<SubmissionInterval[]> {
  const intervalsP = newEvents.map(async (eventSet) => {
    if (checkVerified) {
      // One or more (or all) of the proofs in the first
      // submission may already have been verified.

      // Subsequent submissions will not contain any verified
      // proofs.
      checkVerified = false;

      const submissionIdx = eventSet.events[0].submissionIdx;
      const submissionSize = eventSet.events.length;
      const numVerified = Number(
        await upaInstance.verifier.getNumVerifiedForSubmissionIdx(submissionIdx)
      );
      assert(numVerified <= submissionSize);

      const submission = Submission.fromSubmittedEvents(eventSet);
      if (numVerified == submissionSize) {
        console.log("  ALREADY FULLY VERIFIED");
        return {
          submission,
          startIdx: numVerified,
          numProofs: 0,
          data: undefined,
        };
      }
      return {
        submission,
        startIdx: numVerified,
        numProofs: submissionSize - numVerified,
        data: undefined,
      };
    } else {
      const submission = Submission.fromSubmittedEvents(eventSet);
      const submissionSize = submission.proofs.length;
      return {
        submission,
        startIdx: 0,
        numProofs: submissionSize,
        data: undefined,
      };
    }
  });

  return Promise.all(intervalsP);
}
