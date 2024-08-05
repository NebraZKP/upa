// SPDX-License-Identifier: MIT
/*
    UPA is Nebra's first generation proof aggregation engine
                                         _.oo.
                 _.u[[/;:,.         .odMMMMMM'
              .o888UU[[[/;:-.  .o@P^    MMM^
             oN88888UU[[[/;::-.        dP^
            dNMMNN888UU[[[/;:--.   .o@P^
           ,MMMMMMN888UU[[/;::-. o@^
           NNMMMNN888UU[[[/~.o@P^
           888888888UU[[[/o@^-..
          oI8888UU[[[/o@P^:--..
       .@^  YUU[[[/o@^;::---..
     oMP     ^/o@P^;:::---..
  .dMMM    .o@^ ^;::---...
 dMMMMMMM@^`       `^^^^
YMMMUP^
 ^^
*/

pragma solidity ^0.8.20;

// Commented but left for debugging purposes
// import "hardhat/console.sol";

error NonPowerOfTwoLeaves();
error IntervalProofTooShortA();
error IntervalProofTooShortB();
error InvalidOffset();

/// Merkle tree functions for UPA.
library Merkle {
    function hash(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32 digest) {
        // Solidity reserves the first 64 bytes of memory (0x00 to 0x3f) as
        // scratch space. We write the preimage in this scratch space instead
        // of writing to newly allocated memory.
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)
            digest := keccak256(0x00, 0x40)
        }
    }

    function hashEntry(
        bytes32 entry
    ) internal pure returns (bytes32 hashedEntry) {
        // Solidity reserves the first 64 bytes of memory (0x00 to 0x3f) as
        // scratch space. We write the preimage in this scratch space instead
        // of writing to newly allocated memory.
        assembly {
            mstore(0x00, entry)
            hashedEntry := keccak256(0x00, 0x20)
        }
    }

    /// Hashes the proofIds in the `entries` array in-place.
    function hashEntriesInPlace(bytes32[] memory entries) internal pure {
        uint256 length = entries.length;

        // The following assembly is equivalent to this for-loop:
        //
        // for (uint16 i = 0; i < length; ++i) {
        //     leaves[i] = keccak256(abi.encodePacked(leaves[i]));
        // }
        //
        assembly {
            let intervalPtr := add(entries, 0x20)
            let intervalEndPtr := add(intervalPtr, mul(length, 0x20))
            for {

            } lt(intervalPtr, intervalEndPtr) {

            } {
                let hashResult := keccak256(intervalPtr, 0x20)
                mstore(intervalPtr, hashResult)
                intervalPtr := add(intervalPtr, 0x20)
            }
        }
    }

    // Hash entries into a new buffer.
    function hashEntries(
        bytes32[] memory entries
    ) internal pure returns (bytes32[] memory digests) {
        uint256 length = entries.length;
        digests = new bytes32[](length);

        // The following assembly is equivalent to this for-loop:
        //
        // for (uint16 i = 0; i < length; ++i) {
        //     digests[i] = keccak256(abi.encodePacked(entries[i]));
        // }
        //
        assembly {
            let dstPtr := add(digests, 0x20)
            let srcPtr := add(entries, 0x20)
            let srcEndPtr := add(srcPtr, mul(length, 0x20))
            for {

            } lt(srcPtr, srcEndPtr) {

            } {
                let hashResult := keccak256(srcPtr, 0x20)
                mstore(dstPtr, hashResult)
                srcPtr := add(srcPtr, 0x20)
                dstPtr := add(dstPtr, 0x20)
            }
        }
    }

    /// WARNING: overwrites the `interval` buffer.
    ///
    /// Given a sequence of contiguous leaf digests, and a proof for the
    /// sequence, compute the Merkle root.
    ///
    /// The "proof" here is similar to a Merkle proof for a single element, in
    /// that it provides the nodes required to complete the Merkle root
    /// calculation, in the order that they are used by the algorithm in this
    /// file.
    ///
    /// For example, consider the following interval of leaves [A, B, C] (with
    /// indices 2, 3,4) in a depth-3 Merkle tree:
    ///
    ///            ROOT
    ///          /      \
    ///         *        *
    ///        / \      / \
    ///       *   *    *  *
    ///      / \ / \  / \ / \
    ///      * * A B  C * * *
    ///
    /// idx: 0 1 2 3  4 5 6 7
    ///
    /// The proof for this interval consists of nodes [p1, p2, p3] at the
    /// following locations:
    ///
    ///            ROOT
    ///          /      \
    ///         *        *
    ///        / \      / \
    ///      p2   *    *  p3
    ///          / \  / \
    ///          A B  C p1
    ///
    function computeMerkleIntervalRoot(
        uint16 offset,
        bytes32[] memory interval,
        bytes32[] calldata intervalProof
    ) internal pure returns (bytes32) {
        // console.log("computeMerkleIntervalRoot:");
        // console.log("  offset: ", offset);
        // console.log("  interval.length: ", interval.length);
        // console.log("  intervalProof.length: ", intervalProof.length);

        // Implementation follows the function of the same name in the
        // Typescript code, except for some Solidity-specific lines.

        // Hash the proofIds in the `interval` array in-place.
        hashEntriesInPlace(interval);

        // Cached constant over the course of the loop below
        uint16 intervalProofLength = (uint16)(intervalProof.length);

        // Initialize current interval information. This will be updated over
        // the course of the below loop.
        uint16 intervalProofIdx = 0;
        uint16 intervalLength = (uint16)(interval.length);

        // Compute each layer (interval) into this array. (For some reason it
        // is cheaper to allocate `newInterval` than reuse `interval`.
        bytes32[] memory newInterval = new bytes32[](
            (interval.length >> 1) + 1
        );
        uint16 newIntervalLength = intervalLength;

        // The interval proof may have 0, 1 or 2 elements per layer of the
        // tree, so there is no connection with the depth (e.g. an interval
        // consisting of all entries requires no proof elements).  Similarly,
        // the interval of 1 before the root of the tree is reached (a single
        // element requires 1 proof element per row).
        //
        // We reach the root when BOTH:
        // - intervalProofIdx == intervalProofLength (consumed proof), AND
        // - newIntervalLength == 1
        // Note that these two conditions can be met in either order.
        while (
            !((newIntervalLength == 1) &&
                (intervalProofIdx == intervalProofLength))
        ) {
            // console.log(
            //     "  newIntervalLength: %s, intervalLength: %s",
            //     newIntervalLength,
            //     intervalLength
            // );
            // console.log("  intervalProofIdx: %s", intervalProofIdx);

            // First compute the length of the current interval + extra values
            // from the proof.  It saves some gas to determine the length of
            // the next interval up-front.

            uint16 availableEntries = intervalLength +
                (offset & 1) +
                ((offset + intervalLength) & 1);
            newIntervalLength = availableEntries >> 1;

            // console.log("  availableEntries: ", availableEntries);
            // console.log(
            //     "  newIntervalLength: %s, newOffset",
            //     newIntervalLength,
            //     newOffset
            // );

            // Now use this interval to compute the next Merkle interval.
            uint256 entryIdx = 0;
            uint16 remainingEntries = intervalLength;

            // console.log(
            //     "  intervalProofIdx: %s, entryIdx: %s, remainingEntries",
            //     intervalProofIdx,
            //     entryIdx,
            //     remainingEntries);

            uint256 newIntervalIdx = 0;
            if ((offset & 1) == 1) {
                require(
                    intervalProofIdx < intervalProofLength,
                    IntervalProofTooShortA()
                );
                newInterval[newIntervalIdx++] = hash(
                    intervalProof[intervalProofIdx++],
                    interval[entryIdx++]
                );
                --remainingEntries;

                // console.log(
                //     "  (absorb left) intervalProofIdx: %s, entryIdx: %s, "
                //     "remainingEntries: %s",
                //     intervalProofIdx,
                //     entryIdx,
                //     remainingEntries);
            }

            // We must now be at an even offset within the row.  Iterate
            // through pairs of entries, computing their hash into the next
            // row, until we have 0 or 1 remaining.

            while (remainingEntries > 1) {
                newInterval[newIntervalIdx++] = hash(
                    interval[entryIdx],
                    interval[entryIdx + 1]
                );
                entryIdx += 2;
                remainingEntries -= 2;

                // console.log(
                //     "  (entry) intervalProofIdx: %s, entryIdx: %s, "
                //     "remainingEntries: %s",
                //     intervalProofIdx,
                //     entryIdx,
                //     remainingEntries);
            }

            // If there is a remaining entry, we must pull an element from the
            // proof in order to use it on the right.

            if (remainingEntries == 1) {
                require(
                    intervalProofIdx < intervalProofLength,
                    IntervalProofTooShortB()
                );
                newInterval[newIntervalIdx++] = hash(
                    interval[entryIdx++],
                    intervalProof[intervalProofIdx++]
                );

                // console.log(
                //     "  (absorb right) intervalProofIdx: %s, entryIdx: %s, "
                //     "remainingEntries: %s",
                //     intervalProofIdx,
                //     entryIdx,
                //     remainingEntries);
            }

            interval = newInterval;
            intervalLength = newIntervalLength;
            offset = offset >> 1;
        }

        // All 1-bits should have been shifted out.
        require(offset == 0, InvalidOffset());

        return interval[0];
    }

    // Intended to be used internall in `computeMerkleRoot*`.  Overwrites
    // leaves.
    function computeMerkleRootFromLeaves(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        uint256 numEntries = leaves.length;
        require(((numEntries - 1) & numEntries) == 0, NonPowerOfTwoLeaves());

        while (numEntries > 1) {
            // The below assembly is equivalent to this for-loop:
            //
            // for (uint16 i = 0; i < numEntries; i += 2) {
            //     leaves[i/2] = hash(leaves[i], leaves[i + 1]);
            // }
            //
            // This loop calculates the internal Merkle hashes layer-by-layer.
            // Each loop iteration writes the hashes of the next layer into
            // the beginning of the `leaves` array. For example, if there
            // were 4 entries then the array would transform as follows:
            //
            // Start:
            // [ l0, l1, l2, l3 ]
            //
            // First iteration:
            // [ hash(l0, l1), hash(l2, l3), l2, l3]
            //
            // Second iteration:
            // [hash(hash(l0, l1), hash(l2, l3)), hash(l2, l3), l2, l3]
            //
            assembly {
                let dstPtr := add(leaves, 0x20)
                let srcPtr := dstPtr
                let srcEndPtr := add(srcPtr, mul(numEntries, 0x20))
                for {

                } lt(srcPtr, srcEndPtr) {

                } {
                    let hashResult := keccak256(srcPtr, 0x40)
                    mstore(dstPtr, hashResult)
                    dstPtr := add(dstPtr, 0x20)
                    srcPtr := add(srcPtr, 0x40)
                }
            }

            numEntries = numEntries >> 1;
        }

        return leaves[0];
    }

    // WARNING: Overwrites the original entries array.
    //
    // Note: this could be implemented in terms of computeMerkleIntervalRoot,
    // with a small gas-overhead.  Since this is used for clients to verify
    // individual proofs we use this implementation specialized for single
    // leaves.
    function computeMerkleRoot(
        bytes32[] memory entries
    ) internal pure returns (bytes32) {
        // Hash in-place and avoid allocation.
        hashEntriesInPlace(entries);
        return computeMerkleRootFromLeaves(entries);
    }

    // Note: "Safe" here means it does not overwrite the original array.
    function computeMerkleRootSafe(
        bytes32[] memory entries
    ) internal pure returns (bytes32) {
        // Hash proofIds into a new array. Compute the Merkle root in-place.
        bytes32[] memory leaves = hashEntries(entries);
        return computeMerkleRootFromLeaves(leaves);
    }

    function computeMerkleRootFromProof(
        bytes32 value,
        uint16 location,
        bytes32[] calldata proof
    ) internal pure returns (bytes32) {
        // Hash the entry to obtain the leaf.
        value = hashEntry(value);

        bytes32 next;
        uint256 proofIdx = 0;
        uint256 depth = proof.length;
        while (depth > 0) {
            if (location & 1 == 0) {
                next = hash(value, proof[proofIdx++]);
            } else {
                next = hash(proof[proofIdx++], value);
            }

            location = location >> 1;
            value = next;
            --depth;
        }

        return value;
    }

    function verifyMerkleProof(
        bytes32 root,
        bytes32 value,
        uint16 location,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        bytes32 computedRoot = computeMerkleRootFromProof(
            value,
            location,
            proof
        );
        return computedRoot == root;
    }

    function merkleDepth(uint16 numEntries) internal pure returns (uint8) {
        // Brute-force, for "small" values of numEntries.
        uint8 depth = 0;
        uint16 capacity = 1;
        while (capacity < numEntries) {
            ++depth;
            capacity <<= 1;
        }
        return depth;
    }
}
