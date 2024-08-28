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

import "./Merkle.sol";

/// Library of UPA utility functions for use by application code as well as
/// UPA contract code.
library UpaLib {
    /// Compute the proofId for a proof given the circuitId and the public
    /// inputs.
    function computeProofId(
        bytes32 circuitId,
        uint256[] memory publicInputs
    ) internal pure returns (bytes32) {
        // `publicInputs` is a memory array of words:
        //   [ <len>, <input_0>, <input_1>, ... ]
        // The below assembly temporarily replaces <len> with circuitId:
        //   [ circuitId, <input_0>, <input_1>, ... ]
        // Then computes proofId as the keccak of the underlying memory.
        // Finally, <len> is rewritten at the start to restore the array.
        bytes32 proofId;
        assembly {
            let length := mload(publicInputs)
            mstore(publicInputs, circuitId)
            proofId := keccak256(publicInputs, mul(add(length, 1), 0x20))

            // Restore the original array.
            mstore(publicInputs, length)
        }

        return proofId;
    }

    /// Compute submissionId when all proofs are for the same `circuitId`.
    function computeSubmissionId(
        bytes32 circuitId,
        uint256[][] memory publicInputsArray
    ) internal pure returns (bytes32) {
        uint256 submissionSize = publicInputsArray.length;

        // Pad `proofIds` to power of 2
        uint8 depth = Merkle.merkleDepth(uint16(submissionSize));
        uint16 fullSize = uint16(1) << depth;
        bytes32[] memory proofIds = new bytes32[](fullSize);

        for (uint256 i; i < submissionSize; i++) {
            proofIds[i] = computeProofId(circuitId, publicInputsArray[i]);
        }

        return Merkle.computeMerkleRoot(proofIds);
    }

    /// Compute submissionId when proofs come from different `circuitId`s.
    function computeSubmissionId(
        bytes32[] calldata circuitIds,
        uint256[][] memory publicInputsArray
    ) internal pure returns (bytes32) {
        uint256 submissionSize = publicInputsArray.length;

        // Pad `proofIds` to power of 2
        uint8 depth = Merkle.merkleDepth(uint16(submissionSize));
        uint16 fullSize = uint16(1) << depth;
        bytes32[] memory proofIds = new bytes32[](fullSize);

        for (uint256 i; i < submissionSize; i++) {
            proofIds[i] = computeProofId(circuitIds[i], publicInputsArray[i]);
        }

        return Merkle.computeMerkleRoot(proofIds);
    }

    /// Compute submissionId for a single-proof submission containing `proofId`
    function computeSubmissionId(
        bytes32 proofId
    ) internal pure returns (bytes32) {
        return Merkle.hashEntry(proofId);
    }

    /// Compute submissionId for a submission containing `proofIds`.
    function computeSubmissionId(
        bytes32[] memory proofIds
    ) internal pure returns (bytes32) {
        uint256 submissionSize = proofIds.length;

        // Pad `proofIds` to power of 2
        uint8 depth = Merkle.merkleDepth(uint16(submissionSize));
        uint16 fullSize = uint16(1) << depth;
        bytes32[] memory paddedProofIds = new bytes32[](fullSize);

        for (uint256 i; i < submissionSize; i++) {
            paddedProofIds[i] = proofIds[i];
        }

        return Merkle.computeMerkleRoot(paddedProofIds);
    }

    function computeFinalDigest(
        bytes32[] calldata proofIDs
    ) internal pure returns (bytes32 finalDigest) {
        bytes32[] memory pids = new bytes32[](proofIDs.length);
        assembly {
            let pid_bytes := mul(proofIDs.length, 0x20)
            calldatacopy(add(pids, 0x20), proofIDs.offset, pid_bytes)
            finalDigest := keccak256(add(pids, 0x20), pid_bytes)
        }
    }

    // Decompose a 32-byte digest into (lower, higher) order 128 bit values,
    // representable as field elements.
    function digestAsFieldElements(
        bytes32 digest
    ) internal pure returns (uint256, uint256) {
        uint256 digestUint = uint256(digest);
        return (digestUint & ((1 << 128) - 1), digestUint >> 128);
    }

    // Recombine two 128-bit field elements into a 32-byte digest.
    function fieldElementsAsDigest(
        uint256 lower,
        uint256 higher
    ) internal pure returns (bytes32) {
        require(lower < (1 << 128), "Lower part too large");
        require(higher < (1 << 128), "Higher part too large");

        uint256 digestUint = (higher << 128) | lower;
        return bytes32(digestUint);
    }

    // The stored proofDigestRoot is actually the keccak of the Merkle root
    // and the submitter address.
    function proofDataDigest(
        bytes32 merkleRoot,
        address sender
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(merkleRoot, sender));
    }
}
