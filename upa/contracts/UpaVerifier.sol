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

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./IUpaProofReceiver.sol";
import "./UpaProofReceiver.sol";
import "./IUpaVerifier.sol";
import "./IGroth16Verifier.sol";
import "./Uint16VectorLib.sol";
import "./Merkle.sol";

// Commented but left for debugging
// import "hardhat/console.sol";

error OwnerAddressIsZero();
error WorkerAddressIsZero();
error FeeRecipientAddressIsZero();
error OuterVerifierAddressIsZero();
error SidOuterVerifierAddressIsZero();
error BothOuterVerifierAddressesAreZero();
error Groth16VerifierAddressIsZero();
error UnauthorizedWorkerAccount();
error UnauthorizedFeeRecipientAccount();
error InvalidNumberOfVerifiedProofs();
error InvalidMerkleProofForProofId();
error InvalidMerkleIntervalProof();
error InvalidProofDataDigest();
error InvalidProof();
error SubmissionOutOfOrder();
error ProofAlreadyVerified();
error SubmissionAlreadyVerified();
error UnsuccessfulChallenge();
error AssertNoSubmissionProofs();
error MissingSubmissionProof();
error TooManyProofIds();
error SubmissionWasNotSkipped();
error DummyProofIdInChallenge();
error FinalDigestLDoesNotMatch();
error FinalDigestHDoesNotMatch();
error WrongNumberOffchainSubmissionMarkers();
error FixedReimbursementTooHigh();

/// The proof that a given sequence of proofIds belong to an existing
/// submission.  This is intended to be sent to the UpaVerifier alongside
/// aggregated proofs.  The contract can compute the vector of proofIds to
/// prove membership of, and the location that they start within the merkle
/// tree.  The contract also knows the Merkle tree depth.  Hence, this
/// structure only contains the `submissionId` (or the Merkle root of the
/// `proofIds`), and the proof of membership (at the given location) of the
/// proofIds.
struct SubmissionProof {
    /// The submissionId
    bytes32 submissionId;
    /// The number of proofIds and the starting location is determined based
    /// on contract state and parameters.  This is a proof that these entries
    /// are in the merkle tree.
    bytes32[] proof;
}

/// Implementation of IUpaVerifier.  Accepts aggregated
/// proofs that verify application proofs, where the application proofs have
/// been submitted to an instance of UpaProofReceiver contract.
/// @custom:oz-upgrades-unsafe-allow external-library-linking
contract UpaVerifier is
    IUpaVerifier,
    Initializable,
    UUPSUpgradeable,
    UpaProofReceiver
{
    /// @custom:storage-location erc7201:VerifierStorage
    struct VerifierStorage {
        /// Off-chain worker address
        address worker;
        /// Fee recipient address
        address feeRecipient;
        /// The outer contract verifier
        address outerVerifier;
        /// Single Groth16 Proof Verifier
        IGroth16Verifier groth16Verifier;
        /// The submissionIdx of the next submission expected.  Subsequent
        /// proofs to be verified must be from this, or a later submission.
        uint64 nextSubmissionIdxToVerify;
        /// The height at which the last verified proof was submitted.
        /// This intended so that off-chain aggregators can quickly detect
        /// from which height they should start reading proofs.
        uint64 lastVerifiedSubmissionHeight;
        /// Open censorship challenges. The key is the `submissionId`, the
        /// value is the amount to refund if the challenge is sucessful.
        mapping(bytes32 => uint256) openChallengeRefundAmounts;
        /// Fixed reimbursement for censorship challenges. The aggregator must
        /// pay the claimant this amount upon the completion of a successful
        /// censorship claim.
        uint256 fixedReimbursement;
        /// The number of proofs verified for each submission, indexed by
        /// `submissionIdx`.  Since there are 16 entries per 256-bit word, we
        /// should expect to only write to a small number of different slots
        /// per aggregated proof, since indexes are strictly increasing with
        /// generally few gaps.
        ///
        /// Note, the proofs in a submission are considered to appear in order
        /// in the leaves of a Merkle tree (possibly padded on the right with
        /// 0s), and aggregators cannot skip individual proofs within a
        /// submission. Hence, the number stored here completely determines
        /// which proofs in the submission are verified and which are not yet.
        Uint16VectorLib.Uint16Vector numVerifiedInSubmission;
        /// ProofIds for current off-chain submission
        bytes32[] currentSubmissionProofIds;
        /// For off-chain submissions only. Maps a key `submissionId` to the
        /// block at which the submission was verified. Maps unverified
        /// submissions to 0.
        mapping(bytes32 => uint256) verifiedAtBlock;
        /// Contract version
        uint32 version;
        /// Outer verifier for the circuit which outputs the submission id
        address sidOuterVerifier;
    }

    /// Gas per transaction.
    uint256 private constant GAS_PER_TRANSACTION = 21000;

    /// Max fixed reimbursement per challenge
    uint256 private constant MAX_FIXED_REIMBURSEMENT = (1 << 128);

    event UpgradeOuterVerifier(address);

    event UpgradeSidOuterVerifier(address);

    // keccak256(abi.encode(uint256(keccak256("VerifierStorage")) - 1)) &
    // ~bytes32(uint256(0xff));
    bytes32 private constant VERIFIER_STORAGE_LOCATION =
        0x4D7AE96A4105CE9C745382B9DE6F32626723345414218A3198E7DEF859C90A00;

    function _getVerifierStorage()
        private
        pure
        returns (VerifierStorage storage $)
    {
        assembly {
            $.slot := VERIFIER_STORAGE_LOCATION
        }
    }

    function worker() public view returns (address) {
        return _getVerifierStorage().worker;
    }

    function feeRecipient() public view returns (address) {
        return _getVerifierStorage().feeRecipient;
    }

    function outerVerifier() public view returns (address) {
        return _getVerifierStorage().outerVerifier;
    }

    function sidOuterVerifier() public view returns (address) {
        return _getVerifierStorage().sidOuterVerifier;
    }

    function nextSubmissionIdxToVerify() public view returns (uint64) {
        return _getVerifierStorage().nextSubmissionIdxToVerify;
    }

    function lastVerifiedSubmissionHeight() public view returns (uint64) {
        return _getVerifierStorage().lastVerifiedSubmissionHeight;
    }

    /// Prevents initializing the implementation contract outside of the
    /// upgradeable proxy.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _worker,
        address _feeRecipient,
        address _outerVerifier,
        address _groth16Verifier,
        uint256 _fixedReimbursement,
        uint256 _fixedFeePerProof,
        uint256 _aggregatorCollateral,
        uint8 _maxNumPublicInputs,
        address _sidOuterVerifier,
        uint32 _version
    ) public initializer {
        require(_owner != address(0), OwnerAddressIsZero());
        require(_worker != address(0), WorkerAddressIsZero());
        require(_feeRecipient != address(0), FeeRecipientAddressIsZero());
        if (_outerVerifier == address(0) && _sidOuterVerifier == address(0)) {
            revert BothOuterVerifierAddressesAreZero();
        }
        require(_groth16Verifier != address(0), Groth16VerifierAddressIsZero());
        require(_aggregatorCollateral > 0, NotEnoughCollateral());
        require(_maxNumPublicInputs >= 2, MaxNumPublicInputsTooLow());
        require(
            _fixedReimbursement < MAX_FIXED_REIMBURSEMENT,
            FixedReimbursementTooHigh()
        );

        VerifierStorage storage verifierStorage = _getVerifierStorage();

        verifierStorage.worker = _worker;
        verifierStorage.feeRecipient = _feeRecipient;
        emit UpgradeOuterVerifier(_outerVerifier);
        verifierStorage.outerVerifier = _outerVerifier;
        verifierStorage.groth16Verifier = IGroth16Verifier(_groth16Verifier);
        verifierStorage.nextSubmissionIdxToVerify = 1;
        verifierStorage.lastVerifiedSubmissionHeight = (uint64)(block.number);
        verifierStorage.fixedReimbursement = _fixedReimbursement;
        verifierStorage.version = _version;
        verifierStorage.sidOuterVerifier = _sidOuterVerifier;

        __upaProofReceiver_init(
            _owner,
            _fixedFeePerProof,
            _aggregatorCollateral,
            _maxNumPublicInputs
        );
        __UUPSUpgradeable_init();
    }

    function version() external view override returns (uint32) {
        return _getVerifierStorage().version;
    }

    function setVersion(uint32 newVersion) external onlyOwner {
        _getVerifierStorage().version = newVersion;
    }

    /// Only the owner is authorized to upgrade this contract. Required to
    /// inherit from UUPSUpgradeable.
    function _authorizeUpgrade(address) internal view override onlyOwner {
        return;
    }

    /// For a single proof submission with `submissionIdx`, performs the
    /// necessary checks and marks it as verified. Returns the next
    /// submissionIdx.
    function handleSingleProofOnChainSubmission(
        uint64 submissionIdx
    ) private returns (uint64 nextSubmissionIdx) {
        VerifierStorage storage verifierStorage = _getVerifierStorage();
        require(
            submissionIdx >= verifierStorage.nextSubmissionIdxToVerify,
            SubmissionOutOfOrder()
        );

        // Single-proof case - mark as verified
        require(
            Uint16VectorLib.getUint16(
                verifierStorage.numVerifiedInSubmission,
                submissionIdx
            ) == 0,
            ProofAlreadyVerified()
        );
        Uint16VectorLib.setUint16(
            verifierStorage.numVerifiedInSubmission,
            submissionIdx,
            1
        );
        nextSubmissionIdx = submissionIdx + 1;
    }

    /// For a multi-proof submission with `submissionVerification.submissionId`,
    /// performs the necessary consistency checks (e.g. everything is in the
    /// right order, the submission Merkle proof is valid) and marks the number
    /// of proofs of the submissionn present in `proofIds` as verified.
    function handleMultiProofOnChainSubmission(
        SubmissionProof calldata submissionVerification,
        bytes32[] calldata proofIds,
        uint64 nextSubmissionIdx,
        uint16 numOnchainProofs,
        uint16 proofIdIdx,
        uint8 dupSubmissionIdx
    )
        private
        returns (
            uint64 verifiedSubmissionHeight,
            uint64 newNextSubmissionIdx,
            uint16 proofsThisSubmission
        )
    {
        // Read properties of the original submission from
        // UpaProofReceiver.  Read numVerifiedInSubmission from
        // this contract.
        bytes32 submissionId = submissionVerification.submissionId;
        uint64 submissionIdx;
        uint64 submissionBlockNumber;
        uint16 numProofsInSubmission;
        (
            submissionIdx,
            submissionBlockNumber,
            numProofsInSubmission
        ) = getSubmissionIdxHeightNumProofs(submissionId, dupSubmissionIdx);

        // Submissions must be verified in the order submitted.
        require(submissionIdx >= nextSubmissionIdx, SubmissionOutOfOrder());

        // Further, proofs within a submission must appear in order.
        // We can therefore use:
        //
        // - the number of proofs already verified in this submission
        // - the number of proofs left in this aggregated proof
        //
        // to determine exactly which interval of proofs in the
        // submission we expect to see at this point.
        VerifierStorage storage verifierStorage = _getVerifierStorage();
        uint16 verified = Uint16VectorLib.getUint16(
            verifierStorage.numVerifiedInSubmission,
            submissionIdx
        );

        // console.log(
        //     " numProofsInSubmission: %s, verified: %s",
        //     numProofsInSubmission, verified);

        // Compute the number of proofs expected from this submission.
        // We do not need to adjust for the number of dummy proofIds. Dummy
        // proofIds may only appear in the batch if the batch fully verifies
        // all of its submissions. So `proofsThisSubmission` will be
        // `unverified` whenever there are dummy proofs. On the other hand,
        // if this batch ends with a partially verified submission, then it is
        // assumed to not contain dummy proofIds, so `proofsThisSubmission`
        // will be `remainingInAggProof`.
        uint16 unverified = numProofsInSubmission - verified;
        uint16 remainingInAggProof = numOnchainProofs - proofIdIdx;
        proofsThisSubmission = (unverified < remainingInAggProof)
            ? (unverified)
            : (remainingInAggProof);

        // Update state
        uint16 newVerified = verified + proofsThisSubmission;
        assert(newVerified <= numProofsInSubmission);

        // console.log(
        //     " unverified: %s, remainingInAggProof: %s, "
        //     "proofsThisSubmission: %s",
        //     unverified,
        //     remainingInAggProof,
        //     proofsThisSubmission);

        // Check Merkle proof for `proofIds` and `submissionId`
        doHandleMultiProofOnChainSubmission(
            submissionId,
            proofIds,
            submissionVerification.proof,
            proofIdIdx,
            proofsThisSubmission,
            verified
        );

        Uint16VectorLib.setUint16(
            verifierStorage.numVerifiedInSubmission,
            submissionIdx,
            newVerified
        );
        // console.log(
        //   " set numVerifiedInSubmission to %s",
        //   verified + proofsThisSubmission);

        // If the entire submission has been verified, emit an event and
        // ensure that we also mark the submissionIdx for the zeroth
        // duplicated submission with this submissionId.
        if (newVerified == numProofsInSubmission) {
            newNextSubmissionIdx = submissionIdx + 1;
            emit SubmissionVerified(submissionId);
        } else {
            newNextSubmissionIdx = submissionIdx;
        }
        verifiedSubmissionHeight = submissionBlockNumber;
    }

    /// Verify an aggregated proof with the `sidOuterVerifier`.
    function verifyAggregatedProofSid(
        bytes calldata proof
    ) external onlyWorker {
        // Compute submissionId from the calldata
        uint256 proofL;
        uint256 proofH;
        assembly {
            proofL := calldataload(add(proof.offset, /* 12 * 0x20 */ 0x180))
            proofH := calldataload(add(proof.offset, /* 13 * 0x20 */ 0x1a0))
        }
        bytes32 submissionId = UpaLib.fieldElementsAsDigest(proofL, proofH);

        VerifierStorage storage verifierStorage = _getVerifierStorage();

        // require there is a sidOuterVerifier contract
        require(
            verifierStorage.sidOuterVerifier != address(0),
            SidOuterVerifierAddressIsZero()
        );

        // Call the verifier to check the proof
        (bool success, ) = verifierStorage.sidOuterVerifier.call(proof);
        require(success, InvalidProof());

        // Mark the submission Id as verified
        if (verifierStorage.verifiedAtBlock[submissionId] == 0) {
            verifierStorage.verifiedAtBlock[submissionId] = block.number;

            emit SubmissionVerified(submissionId);
        }
    }

    /// Verify an aggregated proof.
    ///
    /// `proof` - An aggregated proof for the validity of this batch.
    /// `proofIds` - The proofIds belonging to this batch. These are assumed
    /// to be arranged in the order: [On-chain, Dummy, Off-chain]. Furthermore,
    /// it is assumed that if there are dummy proofIds in this batch, then
    /// the batch fully verifies its contained on-chain submissions. I.e. the
    /// on-chain proofIds do not end with a partial submission.
    /// `numOnChainProofs` - The number of proofIds that were from on-chain
    /// submissions. This count includes dummy proofs.
    /// `submissionProofs` - Merkle proofs, each showing that each interval of
    /// proofIds belongs to an on-chain submission
    /// `offChainSubmissionMarkers` - encodes a bool[256] where a `1` marks
    /// each proofId that is at the end of an off-chain submission.
    function verifyAggregatedProof(
        bytes calldata proof,
        bytes32[] calldata proofIds,
        uint16 numOnchainProofs,
        SubmissionProof[] calldata submissionProofs,
        uint256 offChainSubmissionMarkers,
        uint256 duplicateSubmissionIndices
    ) external onlyWorker {
        // console.log("verifyAggregatedProof");

        // Expected to fit in a uint16 to match the proof counts.
        require(proofIds.length < (1 << 16), TooManyProofIds());

        VerifierStorage storage verifierStorage = _getVerifierStorage();

        // require there is an outerVerifier contract
        require(
            verifierStorage.outerVerifier != address(0),
            OuterVerifierAddressIsZero()
        );

        // Proofs must appear in the order they were submitted, and (for
        // multi-proof submission) in the order they appear within submission,
        // which enables the following algorithm to mark aggregated proofs as
        // verified:
        //
        // For each proof in the batch, namely each `proofId` in `proofIds`,
        // determine the submission (in particular submissionIdx) it belongs
        // to.
        //
        //  - For single-proof submissions, the `proofId` will also be a
        //    `submissionId`, and set
        //    `numVerifiedInSubmission[submissionIdx] = 1`
        //
        //  - For multi-proof submissions, pull a `SubmissionProof` from the
        //    `submissionProofs` list and use it to verify that `proofId` (and
        //    some number of subsequent proofIds) belong to the submission.
        //    Increment `numVerifiedInSubmission[submissionIdx]` accordingly.
        //
        // The caller is responsible for ensuring that `submissionProofs` is
        // compatible with the algorithm described above.

        // Track the proof indices to ensure proofs are verified in order.
        uint64 nextSubmissionIdx = verifierStorage.nextSubmissionIdxToVerify;
        uint64 verifiedSubmissionHeight = verifierStorage
            .lastVerifiedSubmissionHeight;

        uint16 submissionProofIdx = 0; // idx into submissionProofs
        uint16 proofIdIdx = 0; // idx into proofIds

        // Process the on-chain proofIds.
        while (proofIdIdx < numOnchainProofs) {
            // console.log(" proofIdIdx: %s", proofIdIdx);

            bytes32 proofId = proofIds[proofIdIdx];

            // If the proofId is dummy, all on-chain proofs from here are
            // assumed to be dummy as well and no more on-chain
            // proofs/submissions will be marked as verified.
            if (proofId == DUMMY_PROOF_ID) {
                proofIdIdx = numOnchainProofs;
                break;
            }

            // Attempt to use the hash(proofId) as the submissionId.  If this
            // succeeds (namely, if we find a submission with this Id), then
            // the proof was submitted alone, hence and we do not need a
            // SubmissionProof.
            bytes32 submissionId = UpaLib.computeSubmissionId(proofId);
            // console.log(
            //   " submissionInAggProofIdx: %s",
            //   state.submissionInAggProofIdx
            // );

            // Interpret `duplicateSubmissionIndices` as packed uint8s,
            // reading the lowest-order byte first (shifting below).
            uint8 dupSubmissionIdx = uint8(duplicateSubmissionIndices);

            // console.log(" dupSubmissionIdx: %s", dupSubmissionIdx);

            (
                uint64 submissionIdx,
                uint64 submissionBlockNumber
            ) = getSubmissionIdxAndHeight(submissionId, dupSubmissionIdx);
            // console.log(" submissionIdx: %s", submissionIdx);
            // console.log(" submissionBlockNumber: %s", submissionBlockNumber);

            if (submissionIdx != 0) {
                nextSubmissionIdx = handleSingleProofOnChainSubmission(
                    submissionIdx
                );
                // Emit the event
                emit SubmissionVerified(submissionId);

                proofIdIdx++;
                verifiedSubmissionHeight = submissionBlockNumber;
            } else {
                // This is a multi-entry submission.  Use the next
                // SubmissionProof entry.
                require(
                    submissionProofIdx < submissionProofs.length,
                    MissingSubmissionProof()
                );
                SubmissionProof
                    calldata submissionVerification = submissionProofs[
                        submissionProofIdx++
                    ];
                uint16 proofsThisSubmission;
                (
                    verifiedSubmissionHeight,
                    nextSubmissionIdx,
                    proofsThisSubmission
                ) = handleMultiProofOnChainSubmission(
                    submissionVerification,
                    proofIds,
                    nextSubmissionIdx,
                    numOnchainProofs,
                    proofIdIdx,
                    dupSubmissionIdx
                );

                proofIdIdx += proofsThisSubmission;
            }

            duplicateSubmissionIndices = duplicateSubmissionIndices >> 8;
        }

        // Finished processing on-chain proofIds. Now process proofIds from
        // off-chain submissions.
        for (; proofIdIdx < proofIds.length; ++proofIdIdx) {
            bytes32 proofId = proofIds[proofIdIdx];

            verifierStorage.currentSubmissionProofIds.push(proofId);

            // Shifted index so that the first off-chain proof is at index 0.
            uint256 offChainProofIdIdx = proofIdIdx - numOnchainProofs;
            bool isEndOfSubmission = UpaInternalLib.marksEndOfSubmission(
                offChainProofIdIdx,
                offChainSubmissionMarkers
            );

            if (isEndOfSubmission) {
                bytes32 submissionId = UpaLib.computeSubmissionId(
                    verifierStorage.currentSubmissionProofIds
                );

                // Only update `verifiedAtBlock` for unverified submissions.
                // We do not revert the transaction if the submission was
                // already verified in order to reset the length of
                // `currentSubmissionProofIds`. Otherwise, if the submission
                // was verified over the course of multiple
                // `verifyAggregatedProof` calls, only the last call would
                // revert, leaving `currentSubmissionProofIds` stuck in an
                // intermediate state.
                if (verifierStorage.verifiedAtBlock[submissionId] == 0) {
                    verifierStorage.verifiedAtBlock[submissionId] = block
                        .number;

                    emit SubmissionVerified(submissionId);
                }

                // Reset the length of the array to zero
                bytes32[] storage currentSubmissionProofIdsPtr = verifierStorage
                    .currentSubmissionProofIds;
                assembly {
                    sstore(currentSubmissionProofIdsPtr.slot, 0)
                }
            }
        }

        verifierStorage.nextSubmissionIdxToVerify = nextSubmissionIdx;
        verifierStorage.lastVerifiedSubmissionHeight = verifiedSubmissionHeight;

        // Verify the aggregated proof
        verifyProofForIDs(proofIds, proof);
    }

    /// Checks that `proofIds[proofIdx..proofIdx+proofsThisSubmission]` are
    /// a subset of the leaves (starting from the index `location`) of a Merkle
    /// tree whose root is `submissionId`.
    ///
    /// The `proof` is a Merkle proof for the corresponding interval of
    /// leaf `proofIds`. See the documentation of the function
    /// `Merkle.computeMerkleIntervalRoot` for more details.
    function doHandleMultiProofOnChainSubmission(
        bytes32 submissionId,
        bytes32[] calldata proofIds,
        bytes32[] calldata proof,
        uint16 proofIdx,
        uint16 proofsThisSubmission,
        uint16 location
    ) private pure {
        // Causes "stack too deep" if this is made into an assert.
        require(proofsThisSubmission > 0, AssertNoSubmissionProofs());

        // Copy the proofIds into memory (we must read them from
        // calldata anyway), and emit events.
        bytes32[] memory interval = new bytes32[](proofsThisSubmission);
        for (uint16 i = 0; i < proofsThisSubmission; ++i) {
            bytes32 proofId = proofIds[proofIdx++];
            interval[i] = proofId;
        }

        // Do the Merkle check for the interval of proofIds.

        // Note: location in merkle tree is the number of submission
        // proofs already verified.
        bytes32 computedSubmissionId = Merkle.computeMerkleIntervalRoot(
            location,
            interval,
            proof
        );
        require(
            computedSubmissionId == submissionId,
            InvalidMerkleIntervalProof()
        );
    }
    // See IUpaVerifier.sol
    function isProofVerified(
        bytes32 proofId
    ) public view override returns (bool) {
        bytes32 submissionId = UpaLib.computeSubmissionId(proofId);
        return isSubmissionVerified(submissionId);
    }

    // See IUpaVerifier.sol
    function isProofVerified(
        bytes32 circuitId,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        bytes32 proofId = UpaLib.computeProofId(circuitId, publicInputs);
        return isProofVerified(proofId);
    }

    function isProofVerified(
        bytes32 proofId,
        ProofReference calldata proofReference
    ) public view override returns (bool) {
        if (isSubmissionVerified(proofReference.submissionId)) {
            // Check the Merkle proof, showing that proofId indeed belongs to
            // the given submission.
            return
                Merkle.verifyMerkleProof(
                    proofReference.submissionId,
                    proofId,
                    proofReference.location,
                    proofReference.merkleProof
                );
        }

        return false;
    }

    function isProofVerified(
        bytes32 circuitId,
        uint256[] calldata publicInputs,
        ProofReference calldata proofReference
    ) external view override returns (bool) {
        bytes32 proofId = UpaLib.computeProofId(circuitId, publicInputs);
        return isProofVerified(proofId, proofReference);
    }

    function isSubmissionVerified(
        bytes32 circuitId,
        uint256[][] memory publicInputsArray
    ) external view override returns (bool) {
        bytes32 submissionId = UpaLib.computeSubmissionId(
            circuitId,
            publicInputsArray
        );
        return isSubmissionVerified(submissionId);
    }

    function isSubmissionVerified(
        bytes32[] calldata circuitIds,
        uint256[][] memory publicInputsArray
    ) external view override returns (bool) {
        bytes32 submissionId = UpaLib.computeSubmissionId(
            circuitIds,
            publicInputsArray
        );
        return isSubmissionVerified(submissionId);
    }

    function isSubmissionVerified(
        bytes32 submissionId
    ) public view override returns (bool) {
        VerifierStorage storage verifierStorage = _getVerifierStorage();
        Submission[MAX_DUPLICATE_SUBMISSIONS]
            storage submissions = getSubmissionListStorage(submissionId);

        // Check on-chain submissions first.  If numProofs == 0, there is no
        // on-chain submission so nothing to do.

        uint16 numProofs = submissions[0].numProofs;
        if (numProofs > 0) {
            for (uint16 i = 0; i < MAX_DUPLICATE_SUBMISSIONS; ++i) {
                // Early out if there are no more submissions
                uint64 submissionIdx = submissions[i].submissionIdx;
                if (0 == submissionIdx) {
                    break;
                }

                // Assume all Submissions with the same SubmissionId have the
                // same number of proofs.
                uint16 verified = Uint16VectorLib.getUint16(
                    verifierStorage.numVerifiedInSubmission,
                    submissionIdx
                );
                if (verified == numProofs) {
                    return true;
                }
            }
        }

        // No verified on-chain submission found. Check if there is a verified
        // off-chain submission.

        // TODO: To save on SLOADs, switch to checking off-chain submissions
        // first when that becomes the primary mode of submissions.

        return verifierStorage.verifiedAtBlock[submissionId] > 0;
    }

    function offChainSubmissionVerifiedAtBlock(
        bytes32 submissionId
    ) external view returns (uint256) {
        return _getVerifierStorage().verifiedAtBlock[submissionId];
    }

    /// Checks that `proofId` and `proofDigest` correspond to the first
    /// unproven proof in the submission with `submissionId`.  If so, it
    /// updates the state to reflect that it is valid now.  Returns `true` if
    /// the proof was the last in the submission.
    ///
    /// Note this function is called as part of `challenge`, which
    /// performs the groth16 verification internally.
    function checkSubmission(
        bytes32 proofId,
        bytes32 proofDigest,
        bytes32 submissionId,
        uint8 dupSubmissionIdx,
        bytes32[] calldata proofIdMerkleProof,
        bytes32[] calldata proofDataMerkleProof
    ) private returns (bool isLastProof) {
        // Retrieve the submission into memory
        UpaProofReceiver.Submission memory submission = getSubmissionStorage(
            submissionId,
            dupSubmissionIdx
        );

        VerifierStorage storage verifierStorage = _getVerifierStorage();

        // Location of `proofId` in the Merkle tree. It should be the
        // number of proofs verified for this submission so far.
        uint64 submissionIdx = submission.submissionIdx;
        uint16 location = Uint16VectorLib.getUint16(
            verifierStorage.numVerifiedInSubmission,
            submissionIdx
        );

        // Check `location` is not already beyond the number of proofs in the
        // submission (meaning the submission is already verified).  By the
        // above, this should never happen, but we check to be sure.
        uint16 numProofs = submission.numProofs;
        require(location < numProofs, SubmissionAlreadyVerified());

        // Confirm that the submission has indeed been skipped, i.e.
        // the latest submission to be verified is greater than submissionIdx
        require(
            verifierStorage.nextSubmissionIdxToVerify - 1 > submissionIdx,
            SubmissionWasNotSkipped()
        );

        // Check the Merkle proof that the `proofId` was used at
        // `location` for the computation of `submissionId`.
        require(
            Merkle.verifyMerkleProof(
                submissionId,
                proofId,
                location,
                proofIdMerkleProof
            ),
            InvalidMerkleProofForProofId()
        );

        // Compute the claimed Merkle root if the `proofDigest` was used at
        // the correct `location`.  The claimed root, along with the sender,
        // are keccak-ed to form the claimedProofDataDigest.  This ensures
        // that the claimant is the same as the submitter.
        bytes32 claimedProofDigestRoot = Merkle.computeMerkleRootFromProof(
            proofDigest,
            location,
            proofDataMerkleProof
        );
        bytes32 claimedProofDataDigest = UpaLib.proofDataDigest(
            claimedProofDigestRoot,
            msg.sender
        );
        require(
            claimedProofDataDigest == submission.proofDataDigest,
            InvalidProofDataDigest()
        );

        // Mark the proof as verified.
        uint16 nextLocation = location + 1;
        Uint16VectorLib.setUint16(
            verifierStorage.numVerifiedInSubmission,
            submissionIdx,
            nextLocation
        );

        return nextLocation == numProofs;
    }

    function challenge(
        bytes32 circuitId,
        Groth16Proof calldata proof,
        uint256[] calldata publicInputs,
        bytes32 submissionId,
        uint8 dupSubmissionIdx,
        bytes32[] calldata proofIdMerkleProof,
        bytes32[] calldata proofDataMerkleProof
    ) external returns (bool challengeSuccessful) {
        emit Challenge();

        // We track the gas to reimburse the costs to sucessful
        // challenges
        uint256 startGas = gasleft();

        Groth16CompressedProof memory compressedProof = UpaInternalLib
            .compressProof(proof);

        // Compute the `proofId` and `proofDigest`, and check the submission

        bytes32 proofId = UpaLib.computeProofId(circuitId, publicInputs);
        require(proofId != DUMMY_PROOF_ID, DummyProofIdInChallenge());

        bool isLastProof = checkSubmission(
            proofId,
            UpaInternalLib.computeProofDigest(compressedProof),
            submissionId,
            dupSubmissionIdx,
            proofIdMerkleProof,
            proofDataMerkleProof
        );

        VerifierStorage storage verifierStorage = _getVerifierStorage();

        // Check the number of public inputs doesn't exceed the max allowed
        uint256 numPublicInputs = publicInputs.length + proof.m.length;
        require(numPublicInputs <= maxNumPublicInputs(), TooManyPublicInputs());

        // Check that the challenge proof is valid for the corresponding VK
        // and public inputs.
        Groth16VK memory vk = getVK(circuitId);
        require(
            verifierStorage.groth16Verifier.verifyProof(
                proof,
                publicInputs,
                vk
            ),
            UnsuccessfulChallenge()
        );

        // The challenge so far has been successful, so the claimant will get
        // the gas spent on this call back from the aggregator, at a gasprice
        // equal to the current basefee.
        //
        // The rationale for using block.basefee as the price is to prevent
        // claimants setting an unreasonably high priorityFee and punishing
        // the aggregator arbitrarily.
        uint256 gasSpent = startGas - gasleft() + GAS_PER_TRANSACTION;

        if (isLastProof) {
            uint256 openChallengeRefundAmount = verifierStorage
                .openChallengeRefundAmounts[submissionId];
            delete verifierStorage.openChallengeRefundAmounts[submissionId];
            // If it's the last proof in the submission, the challenge is
            // successful and the aggregator gives the claimant the full amount.
            reimburseFee(
                gasSpent *
                    block.basefee +
                    verifierStorage.fixedReimbursement +
                    openChallengeRefundAmount,
                msg.sender
            );

            emit SubmissionChallengeSuccess();
        } else {
            // If not, it's added to the due balance for this `submissionId`.
            // TODO: can we do without the openChallengeRefundAmounts?
            verifierStorage.openChallengeRefundAmounts[submissionId] +=
                gasSpent *
                block.basefee;
        }

        return true;
    }

    function setFeeRecipient(address _feeRecipient) public onlyWorker {
        require(_feeRecipient != address(0), FeeRecipientAddressIsZero());
        _getVerifierStorage().feeRecipient = _feeRecipient;
    }

    function setWorker(address _worker) public onlyOwner {
        require(_worker != address(0), WorkerAddressIsZero());
        _getVerifierStorage().worker = _worker;
    }

    function setCensorshipReimbursements(
        uint256 _fixedReimbursement
    ) external onlyOwner {
        require(
            _fixedReimbursement < MAX_FIXED_REIMBURSEMENT,
            FixedReimbursementTooHigh()
        );
        VerifierStorage storage verifierStorage = _getVerifierStorage();

        verifierStorage.fixedReimbursement = _fixedReimbursement;
    }

    function setOuterVerifier(
        address _outerVerifier,
        uint8 _maxNumPublicInputs
    ) public onlyOwner {
        emit UpgradeOuterVerifier(_outerVerifier);
        setMaxNumPublicInputs(_maxNumPublicInputs);
        // TODO (#563): Make sure the fee model here matches the proof
        // receiver's fee model.
        _getVerifierStorage().outerVerifier = _outerVerifier;
    }

    function setSidOuterVerifier(address _sidOuterVerifier) public onlyOwner {
        emit UpgradeSidOuterVerifier(_sidOuterVerifier);
        _getVerifierStorage().sidOuterVerifier = _sidOuterVerifier;
    }

    modifier onlyWorker() {
        require(msg.sender == worker(), UnauthorizedWorkerAccount());
        _;
    }

    modifier onlyFeeRecipient() {
        require(
            msg.sender == feeRecipient(),
            UnauthorizedFeeRecipientAccount()
        );
        _;
    }

    /// MUST NOT make any state changes!
    ///
    /// This function is public in order that it can be tested and clients
    /// (aggregators) can check their calldata against the verifier.  However,
    /// since it calls outerVerifier, we cannot make it a view function.  If
    /// future changes modify this function to perform state changes,
    /// malicious aggregators could send transactions calling this function
    /// directly.
    ///
    /// TODO: make this function view or internal.
    function verifyProofForIDs(
        bytes32[] calldata proofIDs,
        bytes calldata proof
    ) public {
        // Check that the call data contains the expected final digest at the
        // correct location.
        bytes32 finalDigest = UpaLib.computeFinalDigest(proofIDs);
        (uint256 expectL, uint256 expectH) = UpaLib.digestAsFieldElements(
            finalDigest
        );
        uint256 proofL;
        uint256 proofH;
        assembly {
            proofL := calldataload(add(proof.offset, /* 12 * 0x20 */ 0x180))
            proofH := calldataload(add(proof.offset, /* 13 * 0x20 */ 0x1a0))
        }
        require(proofL == expectL, FinalDigestLDoesNotMatch());
        require(proofH == expectH, FinalDigestHDoesNotMatch());

        // Call the verifier to check the proof
        (bool success, ) = _getVerifierStorage().outerVerifier.call(proof);
        require(success, InvalidProof());
    }

    /// Allocates the aggregator fee to be claimed once
    /// `lastSubmittedSubmissionIdx` in `proofReceiver` is verified.
    function allocateAggregatorFee() external onlyFeeRecipient {
        uint64 lastSubmittedSubmissionIdx = getNextSubmissionIdx() - 1;
        allocateAggregatorFee(lastSubmittedSubmissionIdx);
    }

    /// Claims the aggregator fee from the `feeModel`.
    function claimAggregatorFee() external {
        claimAggregatorFee(
            feeRecipient(),
            _getVerifierStorage().nextSubmissionIdxToVerify - 1
        );
    }

    /// Withdraws the worker's balance in the `feeModel` contract,
    /// including the collateral.
    function withdrawAggregatorBalance() external onlyOwner {
        uint64 lastSubmittedSubmissionIdx = getNextSubmissionIdx() - 1;
        withdraw(
            worker(),
            _getVerifierStorage().nextSubmissionIdxToVerify - 1,
            lastSubmittedSubmissionIdx
        );
    }

    // For testing
    function getNumVerifiedForSubmissionIdx(
        uint64 submissionIdx
    ) public view returns (uint16) {
        return
            Uint16VectorLib.getUint16(
                _getVerifierStorage().numVerifiedInSubmission,
                submissionIdx
            );
    }
}
