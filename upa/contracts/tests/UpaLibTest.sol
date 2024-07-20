// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

import "../UpaLib.sol";
import "../UpaInternalLib.sol";

contract UpaLibTest {
    function computeSubmissionId(
        bytes32 circuitId,
        uint256[][] memory publicInputsArray
    ) public pure returns (bytes32) {
        return UpaLib.computeSubmissionId(circuitId, publicInputsArray);
    }

    function computeSubmissionId(
        bytes32[] calldata circuitIds,
        uint256[][] memory publicInputsArray
    ) public pure returns (bytes32) {
        return UpaLib.computeSubmissionId(circuitIds, publicInputsArray);
    }

    function compressG1Point(
        uint256[2] calldata g1Point
    ) external pure returns (uint256) {
        return UpaInternalLib.compressG1Point(g1Point);
    }

    function compressG2Point(
        uint256[2][2] calldata g2Point
    ) external pure returns (uint256[2] memory) {
        return UpaInternalLib.compressG2Point(g2Point);
    }

    function decomposeFq(
        uint256 fq
    ) public pure returns (uint256, uint256, uint256) {
        return UpaInternalLib.decomposeFq(fq);
    }

    function computeCircuitId(
        Groth16VK calldata vk
    ) public pure returns (bytes32) {
        return UpaInternalLib.computeCircuitId(vk);
    }

    function computeProofId(
        bytes32 circuitId,
        uint256[] calldata inputs
    ) public pure returns (bytes32) {
        return UpaLib.computeProofId(circuitId, inputs);
    }

    function computeFinalDigest(
        bytes32[] calldata proofIDs
    ) public pure returns (bytes32 finalDigest) {
        return UpaLib.computeFinalDigest(proofIDs);
    }

    function digestAsFieldElements(
        bytes32 digest
    ) public pure returns (uint256, uint256) {
        return UpaLib.digestAsFieldElements(digest);
    }
}
