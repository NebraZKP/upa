//SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.26;

import "./CircuitVerifier.sol";
import "@nebrazkp/upa/contracts/IUpaVerifier.sol";

contract DemoApp is Groth16Verifier {
    IUpaVerifier public upaVerifier;

    string public name = "A Demo App";

    uint256 public proofsVerified = 0;

    bytes32 public circuitId;

    // Stores keccak of submitted solutions to prevent duplicates.
    mapping(bytes32 => bool) private solutions;

    constructor(IUpaVerifier _upaVerifier, bytes32 _circuitId) {
        upaVerifier = _upaVerifier;
        circuitId = _circuitId;
    }

    /**
     * Verifies that the given solution satisfies the DemoApp equation
     * (see circuit.circom) directly on-chain.
     *
     * Updates the `proofsVerified` count if the check passes.
     *
     * @param a Curve point A of the Groth16 proof.
     * @param b Curve point B of the Groth16 proof.
     * @param c Curve point C of the Groth16 proof.
     * @param solution An array of uint256 representing a solution (c,d,e,f).
     * @return r True if `solution` was verified using this proof.
     */
    function submitSolutionDirect(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata solution
    ) public returns (bool r) {
        bool isProofCorrect = this.verifyProof(a, b, c, solution);
        require(isProofCorrect, "Proof was not correct");

        bytes32 solutionHash = keccak256(abi.encode(solution));
        require(!solutions[solutionHash], "Solution already submitted");
        solutions[solutionHash] = true;

        proofsVerified++;

        return isProofCorrect;
    }

    /**
     * Checks that the given solution satisfies the DemoApp equation
     * (see circuit.circom) by querying the UPA contract. A zk proof for this
     * solution's correctness must have been sent to the UPA contract earlier
     * as a single-proof submission.
     *
     * Updates the `proofsVerified` count if the check passes.
     *
     * @param solution An array of uint256 representing a solution (c,d,e,f).
     * @return r True if `solution` was verified on the UPA contract.
     */
    function submitSolution(
        uint256[] calldata solution
    ) public returns (bool r) {
        bool isProofVerified = upaVerifier.isProofVerified(circuitId, solution);

        require(isProofVerified, "Solution not verified by UPA");

        bytes32 solutionHash = keccak256(abi.encode(solution));
        require(!solutions[solutionHash], "Solution already submitted");
        solutions[solutionHash] = true;

        proofsVerified++;

        return isProofVerified;
    }

    /**
     * Checks that the given solution satisfies the DemoApp equation
     * (see circuit.circom) by querying the UPA contract. A zk proof for this
     * solution's correctness must have been sent to the UPA contract earlier
     * as a multi-proof submission.
     *
     * Updates the `proofsVerified` count if the check passes.
     *
     * @param solution An array of uint256 representing a solution (c,d,e,f).
     * @param proofReference The proof reference associated with the solution.
     *        Needed to check proofs that were part of a multi-proof submission.
     * @return r True if `(solution, proofReference)` was verified on the UPA
     *         contract.
     */
    function submitSolutionWithProofReference(
        uint256[] calldata solution,
        ProofReference calldata proofReference
    ) public returns (bool r) {
        bool isProofVerified = upaVerifier.isProofVerified(
            circuitId,
            solution,
            proofReference
        );

        require(isProofVerified, "Solution not verified by UPA");

        bytes32 solutionHash = keccak256(abi.encode(solution));
        require(!solutions[solutionHash], "Solution already submitted");
        solutions[solutionHash] = true;

        proofsVerified++;

        return isProofVerified;
    }
}
