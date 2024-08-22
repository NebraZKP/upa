import { concat, keccak256, BytesLike } from "ethers";
import { strict as assert } from "assert";

export function evmLeafHashFn(l: BytesLike): string {
  return keccak256(l);
}

export function evmInnerHashFn(l: BytesLike, r: BytesLike): string {
  return keccak256(concat([l, r]));
}

/// Given a contiguous series (an "interval") of leaf digests and a proof for
/// it, compute the root of a Merkle tree.
export function computeMerkleIntervalRoot<Entry, Digest>(
  leafHashFn: (l: Entry) => Digest,
  innerHashFn: (l: Digest, r: Digest) => Digest,
  offset: number,
  interval: Entry[],
  intervalProof: Digest[]
): Digest {
  // Hash the proofIds in `interval`
  let hashedInterval = interval.map(leafHashFn);

  // Initialize current interval information. This will be updated over
  // the course of the below loop.
  let intervalProofIdx = 0;
  let newIntervalLength = hashedInterval.length;

  // Each iteration of this while loop uses the current interval and the
  // interval proof to compute the next Merkle interval. The number of
  // iterations will end up being the depth of the Merkle tree.
  //
  // We have done enough iterations when both below conditions are met:
  // - intervalProofIdx == intervalProof.length (All `intervalProof` elts
  // are consumed)
  // - newIntervalLength == 1
  // Note that these two conditions can be met in either order.
  while (
    !(newIntervalLength == 1 && intervalProofIdx == intervalProof.length)
  ) {
    const newInterval: Digest[] = [];
    const newOffset = offset >> 1;
    let newIntervalLengthCounter = 0;

    //   newRow:    AB    CD    EF    GH
    //              /\    /\    /\    /\
    //   row:      A  B  C  D  E  F  G  H
    //
    // Example 1:
    //
    // If we have [B, C, D] (offset = 1), we compute [AB, CD] in the next row,
    // and thus require A from the proof.
    //
    // Example 2:
    //
    // If we have [B, C, D, E] (offset = 1), we compute [AB, CD, EF] in the
    // next row, and thus require A and F from proof.

    // index within our interval (not the row)
    let entryIdx = 0;
    // unconsumed entries in interval
    let remainingEntries = hashedInterval.length;

    // If offset is odd, absorb an element on the left.
    if (offset & 1) {
      newInterval.push(
        innerHashFn(
          intervalProof[intervalProofIdx++],
          hashedInterval[entryIdx++]
        )
      );
      --remainingEntries;
      ++newIntervalLengthCounter;
    }

    // Process all remaining pairs in the current interval (potentially
    // leaving one entry).
    while (remainingEntries > 1) {
      newInterval.push(
        innerHashFn(hashedInterval[entryIdx++], hashedInterval[entryIdx++])
      );
      remainingEntries -= 2;
      ++newIntervalLengthCounter;
    }

    // If an element remains, we absorb an element from the proof to use on
    // the right.
    assert(remainingEntries === 0 || remainingEntries === 1);
    if (remainingEntries === 1) {
      newInterval.push(
        innerHashFn(hashedInterval[entryIdx], intervalProof[intervalProofIdx++])
      );
      ++newIntervalLengthCounter;
    }

    hashedInterval = newInterval;
    newIntervalLength = newIntervalLengthCounter;
    offset = newOffset;
  }

  assert(hashedInterval.length === 1);
  return hashedInterval[0];
}

/// Verify a Merkle proof for a tree with a given interval of leaf elements
/// and expected root.
export function verifyMerkleInterval<Entry, Digest>(
  leafHashFn: (l: Entry) => Digest,
  innerHashFn: (l: Digest, r: Digest) => Digest,
  root: Digest,
  offset: number,
  interval: Entry[],
  intervalProof: Digest[]
): boolean {
  const merkleRoot = computeMerkleIntervalRoot(
    leafHashFn,
    innerHashFn,
    offset,
    interval,
    intervalProof
  );
  return root == merkleRoot;
}

/// Return a (proof, root) pair for a Merkle tree in which the verifier knows
/// the contiguous series ("interval") of leaf nodes specified by `offset` and
/// `numEntries`.
export function createMerkleIntervalProof<Entry, Digest>(
  leafHashFn: (l: Entry) => Digest,
  innerHashFn: (l: Digest, r: Digest) => Digest,
  interval: Entry[],
  offset: number,
  numEntries: number
): { proof: Digest[]; root: Digest } {
  //           ABCDEFGH
  //           /      \
  //       ABCD        EFGH
  //       /  \        /  \
  //     AB    CD    EF    GH
  //     /\    /\    /\    /\
  //    A  B  C  D  E  F  G  H

  const hashedInterval = interval.map(leafHashFn);

  const proof: Digest[] = [];
  const depth = Math.ceil(Math.log2(hashedInterval.length));
  assert(hashedInterval.length == 1 << depth);

  let row = hashedInterval;
  for (let d = depth; d > 0; --d) {
    // console.log(`depth: ${d}, row: ${JSON.stringify(row)}`);
    // console.log(`offset: ${offset}, numEntries: ${numEntries}`);
    const rowLength = row.length;

    // In each iteration, as well as computing the next row, we add enough
    // elements to the proof so that the verifier can compute sufficient
    // elements of the next row.
    //
    //   newRow:    AB    CD    EF    GH
    //              /\    /\    /\    /\
    //   row:      A  B  C  D  E  F  G  H
    //
    // Example:
    //
    // If the verifier knows [B, C, D] (offset = 1, numEntries = 3), he will
    // compute [AB, CD] in the next row.  He therefore needs A from this row.
    //
    // If the verifier knows [B, C, D, E] (offset = 1, numEntries = 4), he
    // will compute [AB, CD, EF] in the next row.  He therefore needs both A
    // and F from this row.

    // Track the number of entries the verifier will have, including entries
    // from the proof.
    let numAvailableEntries = numEntries;

    // If `offset` is odd, push an element on the left from this row.
    if (offset & 1) {
      proof.push(row[offset - 1]);
      ++numAvailableEntries;
    }

    // Compute the index of the final entry in this rows.  If it is even, we
    // need a proof element on the right.
    const finalEntryIdx = offset + numEntries - 1;
    if (!(finalEntryIdx & 1)) {
      proof.push(row[finalEntryIdx + 1]);
      ++numAvailableEntries;
    }

    // Compute the entire next row
    const newRow: Digest[] = [];
    for (let i = 0; i < rowLength; ) {
      newRow.push(innerHashFn(row[i++], row[i++]));
    }

    // Determine what information the verifier has about the next row, and
    // iterate.  `offset` in the next row will always be (floor) `offset/2`, and
    // the verifier will have computed exactly `numAvailableEntries / 2` entries
    // in the next row.
    offset = offset >> 1;
    numEntries = numAvailableEntries >> 1;
    row = newRow;
  }

  assert(row.length === 1);

  return { proof, root: row[0] };
}

export function computeMerkleRoot<Entry, Digest>(
  leafHashFn: (l: Entry) => Digest,
  innerHashFn: (l: Digest, r: Digest) => Digest,
  entries: Entry[]
): Digest {
  let row = entries.map(leafHashFn);

  let numEntries = row.length;
  assert(((numEntries - 1) & numEntries) == 0, "assert POT");
  while (numEntries > 1) {
    // allocate a new array
    const nextRow: Digest[] = [];
    let destIdx = 0;
    for (let srcIdx = 0; srcIdx < numEntries; ) {
      nextRow[destIdx++] = innerHashFn(row[srcIdx++], row[srcIdx++]);
    }

    row = nextRow;
    numEntries = nextRow.length;
  }

  return row[0];
}

export function computeMerkleProof<Entry, Digest>(
  leafHashFn: (l: Entry) => Digest,
  innerHashFn: (l: Digest, r: Digest) => Digest,
  interval: Entry[],
  location: number
): { root: Digest; proof: Digest[] } {
  let rowInterval = interval.map(leafHashFn);

  const proof: Digest[] = [];
  let numEntries = rowInterval.length;
  while (numEntries > 1) {
    assert(((numEntries - 1) & numEntries) == 0, "assert POT");
    // select the left of right value for the proof
    if ((location & 1) == 0) {
      proof.push(rowInterval[location + 1]);
    } else {
      proof.push(rowInterval[location - 1]);
    }

    // compute the next row
    const nextRow: Digest[] = [];
    let destIdx = 0;
    for (let srcIdx = 0; srcIdx < numEntries; ) {
      nextRow[destIdx++] = innerHashFn(
        rowInterval[srcIdx++],
        rowInterval[srcIdx++]
      );
    }

    location = location >> 1;
    rowInterval = nextRow;
    numEntries = nextRow.length;
  }

  return { root: rowInterval[0], proof };
}
