/// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "../Merkle.sol";

contract MerkleTest {
    function hash(
        bytes32 left,
        bytes32 right
    ) public pure returns (bytes32 digest) {
        return Merkle.hash(left, right);
    }

    function computeMerkleIntervalRoot(
        uint8 offset,
        bytes32[] memory interval,
        bytes32[] calldata intervalProof
    ) public pure returns (bytes32) {
        return
            Merkle.computeMerkleIntervalRoot(offset, interval, intervalProof);
    }

    function computeMerkleRoot(
        bytes32[] memory leaves
    ) public pure returns (bytes32) {
        return Merkle.computeMerkleRoot(leaves);
    }

    function verifyMerkleProof(
        bytes32 root,
        bytes32 value,
        uint16 location,
        bytes32[] calldata proof
    ) public pure returns (bool) {
        return Merkle.verifyMerkleProof(root, value, location, proof);
    }

    function merkleDepth(uint16 numEntries) public pure returns (uint8) {
        return Merkle.merkleDepth(numEntries);
    }
}
