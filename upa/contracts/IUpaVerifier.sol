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

pragma solidity 0.8.26;

import "./IUpaProofReceiver.sol";

/// Reference to a single proof in a Submission.  Used by clients to show that
/// a given proof appears in a submission which has been verified as part of
/// an aggregated proof.  Not required for single-proof submissions, since in
/// this case `submissionId == proofId`, and the `merkleProof` and `location`
/// are trivial.
struct ProofReference {
    bytes32 submissionId;
    bytes32[] merkleProof;
    /// Index into the proofs in the submission.  The sequence of proofs
    /// within the submission starts at this index.
    uint16 location;
}

// Contract which verifies aggregated proofs.
interface IUpaVerifier {
    /// Emitted when a submission has been verified as part of an aggregated
    /// proof.  After this event is emitted, `isProofVerified` will return true
    /// for proofs in the corresponding submission.
    event SubmissionVerified(bytes32 indexed submissionId);

    /// Return the version of this contract. vXX.YY.ZZ is always encoded as
    /// DECIMAL XXYYZZ.
    function version() external view returns (uint32);

    // Functions to look up verification status from public inputs. If the app
    // contract takes in public inputs as calldata, then these will be more
    // gas-efficient than looking up using a proofId or submissionId.

    /// Checks if UPA has verified a proof from a single-proof submission that
    /// publicInputs is valid for the circuit `circuitId`.
    /// This should be renamed to `isProofVerified` when we redeploy.
    function isProofVerified(
        bytes32 circuitId,
        uint256[] calldata publicInputs
    ) external view returns (bool);

    /// Checks if UPA has verified a proof from a multi-proof submission that
    /// `publicInputs` is valid for the circuit `circuitId`.
    /// This should be renamed to `isProofVerified` when we redeploy.
    function isProofVerified(
        bytes32 circuitId,
        uint256[] calldata publicInputs,
        ProofReference calldata proofReference
    ) external view returns (bool);

    /// Checks if UPA has verified a submission corresponding to
    // `publicInputsArray` where each proof is for `circuitId`.
    function isSubmissionVerified(
        bytes32 circuitId,
        uint256[][] memory publicInputsArray
    ) external view returns (bool);

    /// Checks if UPA has verified a submission corresponding to
    /// `circuitIds` and `publicInputsArray`.
    function isSubmissionVerified(
        bytes32[] calldata circuitIds,
        uint256[][] memory publicInputsArray
    ) external view returns (bool);

    // Functions to look up verification status from proofId or submissionId.
    // If the app contract constructs a memory array of public inputs, then it
    // is more gas-efficient for the app contract to compute the
    // proofId/submissionId (see UpaLib.sol) and use that to look up its
    // status.

    /// Checks if UPA has verified a proofId from a single-proof submission.
    function isProofVerified(bytes32 proofId) external view returns (bool);

    /// Checks if UPA has verified a proofId from a multi-proof submission.
    function isProofVerified(
        bytes32 proofId,
        ProofReference calldata proofReference
    ) external view returns (bool);

    /// Checks if UPA has verified a submission corresponding to
    /// `submissionId`.
    function isSubmissionVerified(
        bytes32 submissionId
    ) external view returns (bool);

    /// Make a censorship claim that `proof` for `circuitId` with public
    /// inputs `publicInputs` has been skipped by the aggregator.  If the
    /// claim is upheld by the contract (according to the protocol rules - see
    /// the protocol spec), the aggregator will be punished and the claimant
    /// rewarded.
    ///
    /// Note: The `proofIdMerkleProof` contains the Merkle proof linking the
    /// `submissionId` to the `proofId`. The `proofDataMerkleProof` contains the
    /// Merkle proof linking the `proofDigestRoot` to the `proofDigest`.
    ///
    /// Note that challenges are atomic, i.e. if one of the proofs in a
    /// submission is invalid, the whole submission is considered invalid
    /// and the challenge will fail. Censorship challenges must be submitted in
    /// order, starting from the first invalid proof in the submission.
    function challenge(
        bytes32 circuitId,
        Groth16Proof calldata proof,
        uint256[] calldata publicInputs,
        bytes32 submissionId,
        uint8 dupSubmissionIdx,
        bytes32[] calldata proofIdMerkleProof,
        bytes32[] calldata proofDataMerkleProof
    ) external returns (bool challengeSuccessful);
}
