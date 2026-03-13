// SPDX-License-Identifier: MIT

pragma solidity 0.8.26;

// contract that verifies aggregated proofs
interface IUpaProofVerifier {
    // Checks if UPA has verified a proof from a single-proof submission that
    // publicInputs is valid for the circuit `circuitId`.
    function isProofVerified(
        bytes32 circuitId,
        uint256[] calldata publicInputs
    ) external view returns (bool);

    // Checks if UPA has verified a proofId from a single-proof submission.
    function isProofVerified(bytes32 proofId) external view returns (bool);
}
