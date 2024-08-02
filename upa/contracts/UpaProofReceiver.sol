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

import "./EllipticCurveUtils.sol";
import "./UpaFixedGasFee.sol";
import "./IUpaProofReceiver.sol";
import "./UpaLib.sol";
import "./UpaInternalLib.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

error UnregisteredVK();
error InvalidVK();
error AlreadyRegisteredVK();
error NotOnCurve(Groth16PointType point);
error TooManyProofs();
error UnequalNumberOfCircuitIdsAndProofs();
error UnequalNumberOfCircuitIdsAndPublicInputs();
error SubmissionAlreadyExists();
error SubmissionDoesNotExist();
error TooManyPublicInputs();
error MaxNumPublicInputsTooLow();
error TooManyCommitmentPoints();
error InconsistentPedersenVK();
error TooManySubmissionsForId();

/// Only used for `NotOnCurve` errors.
enum Groth16PointType {
    Alpha,
    Beta,
    Gamma,
    Delta,
    S,
    H1,
    H2
}

/// Implementation of IUpaProofReceiver. Accepts VK registrations and
/// tracks proofs against each registered VK.
contract UpaProofReceiver is
    Initializable,
    PausableUpgradeable,
    IUpaProofReceiver,
    UpaFixedGasFee
{
    uint16 public constant MAX_NUM_DUPLICATE_SUBMISSIONS = 256;

    uint16 public constant MAX_SUBMISSION_MERKLE_DEPTH = 5;

    uint16 public constant MAX_NUM_PROOFS_PER_SUBMISSION =
        uint16(1) << MAX_SUBMISSION_MERKLE_DEPTH;

    // Per-circuit data.  This only contains the VK, but the compiler
    // complains about mapping(uint256 => Groth16VK), as Groth16VK is
    // considered an internal or recursive type.
    struct CircuitData {
        Groth16VK verificationKey;
    }

    struct Submission {
        /// Merkle root of the proof data digests as seen by the contract
        bytes32 proofDataDigest;
        /// Index of this submission
        uint64 submissionIdx;
        /// Block number at which the submission was made
        uint64 submissionBlockNumber;
        /// The number of proofs in this submission
        uint16 numProofs;
    }

    /// @custom:storage-location erc7201:ProofReceiverStorage
    struct ProofReceiverStorage {
        /// All circuitIds known to the contract.
        bytes32[] _circuitIds;
        /// Data for each registered circuit, indexed by the circuitId.
        mapping(bytes32 => CircuitData) _circuitData;
        /// The full set of submissions, indexed by the submissionId.
        mapping(bytes32 => Submission[]) _submissions;
        /// The next submission index
        uint64 _nextSubmissionIdx;
        /// The next proof index.  (Proof index is not strictly required, but
        /// since it doesn't occupy any extra storage slots, we track this.  It
        /// can be useful for auditing off-chain DBs).
        uint64 _nextProofIdx;
        /// Maximum number of public inputs
        uint8 _maxNumPublicInputs;
    }

    // keccak256(abi.encode(uint256(keccak256("ProofReceiverStorage")) - 1)) &
    // ~bytes32(uint256(0xff));
    bytes32 private constant PROOF_RECEIVER_STORAGE_LOCATION =
        0x5EAF6D4EDCDA82320313B5629BCCDB8F6C8970A3AFDED5B007FAAC4B3121B300;

    function _getProofReceiverStorage()
        private
        pure
        returns (ProofReceiverStorage storage $)
    {
        assembly {
            $.slot := PROOF_RECEIVER_STORAGE_LOCATION
        }
    }

    function nextProofIdx() public view returns (uint64) {
        return _getProofReceiverStorage()._nextProofIdx;
    }

    function maxNumPublicInputs() public view override returns (uint8) {
        return _getProofReceiverStorage()._maxNumPublicInputs;
    }

    /// Changes the `_maxNumPublicInputs`.
    ///
    /// Note this function must always be internal, and should only
    /// be called when changing the `outerVerifier` contract in `UpaVerifier`.
    function setMaxNumPublicInputs(uint8 _maxNumPublicInputs) internal {
        require(_maxNumPublicInputs >= 2, MaxNumPublicInputsTooLow());
        _getProofReceiverStorage()._maxNumPublicInputs = _maxNumPublicInputs;
    }

    /// Return the list of circuit Ids that have been registered.
    function getCircuitIds() public view returns (bytes32[] memory) {
        return _getProofReceiverStorage()._circuitIds;
    }

    function getNextSubmissionIdx() public view returns (uint64) {
        return _getProofReceiverStorage()._nextSubmissionIdx;
    }

    /// Prevents initializing the implementation contract outside of the
    /// upgradeable proxy.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // solhint-disable-next-line
    function __upaProofReceiver_init(
        address _owner,
        uint256 _fixedGasFeePerProof,
        uint256 _aggregatorCollateral,
        uint8 _maxNumPublicInputs
    ) public onlyInitializing {
        ProofReceiverStorage
            storage proofReceiverStorage = _getProofReceiverStorage();

        proofReceiverStorage._nextSubmissionIdx = 1;
        proofReceiverStorage._nextProofIdx = 1;
        proofReceiverStorage._maxNumPublicInputs = _maxNumPublicInputs;

        __upaFixedGasFee_init(
            _owner,
            _fixedGasFeePerProof,
            _aggregatorCollateral
        );
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function registerVK(
        Groth16VK calldata vk
    ) external override whenNotPaused returns (bytes32 circuitId) {
        uint256 sLength = vk.s.length;
        // Ensure that the circuit has at least 1 public input.
        require(sLength > 1, InvalidVK());
        require(sLength <= maxNumPublicInputs() + 1, TooManyPublicInputs());

        uint256 hasCommitment = vk.h1.length;
        // Ensure the VK only has 0 or 1 commitments, and that
        // the `vk.h` is consistent
        require(hasCommitment < 2, TooManyCommitmentPoints());
        require(hasCommitment == vk.h2.length, InconsistentPedersenVK());

        // Record the new circuitId.
        circuitId = UpaInternalLib.computeCircuitId(vk);
        ProofReceiverStorage
            storage proofReceiverStorage = _getProofReceiverStorage();
        proofReceiverStorage._circuitIds.push(circuitId);

        // Record the CircuitData struct
        CircuitData storage cData = proofReceiverStorage._circuitData[
            circuitId
        ];
        require(0 == cData.verificationKey.alpha[0], AlreadyRegisteredVK());
        cData.verificationKey = vk;

        require(
            EllipticCurveUtils.isOnG1Curve(vk.alpha[0], vk.alpha[1]),
            NotOnCurve(Groth16PointType.Alpha)
        );
        require(
            EllipticCurveUtils.isOnG2Curve(vk.beta[0], vk.beta[1]),
            NotOnCurve(Groth16PointType.Beta)
        );
        require(
            EllipticCurveUtils.isOnG2Curve(vk.gamma[0], vk.gamma[1]),
            NotOnCurve(Groth16PointType.Gamma)
        );
        require(
            EllipticCurveUtils.isOnG2Curve(vk.delta[0], vk.delta[1]),
            NotOnCurve(Groth16PointType.Delta)
        );
        for (uint256 i = 0; i < sLength; i++) {
            require(
                EllipticCurveUtils.isOnG1Curve(vk.s[i][0], vk.s[i][1]),
                NotOnCurve(Groth16PointType.S)
            );
        }
        for (uint256 i = 0; i < hasCommitment; i++) {
            require(
                EllipticCurveUtils.isOnG2Curve(vk.h1[i][0], vk.h1[i][1]),
                NotOnCurve(Groth16PointType.H1)
            );
            require(
                EllipticCurveUtils.isOnG2Curve(vk.h2[i][0], vk.h2[i][1]),
                NotOnCurve(Groth16PointType.H2)
            );
        }

        /// Emit the VKRegistered event
        emit VKRegistered(circuitId, vk);
    }

    // See IUpa.sol
    function submit(
        bytes32[] calldata circuitIds,
        Groth16CompressedProof[] calldata proofs,
        uint256[][] calldata publicInputs
    ) public payable override whenNotPaused returns (bytes32 submissionId) {
        uint16 numProofs = uint16(circuitIds.length);
        require(
            proofs.length == numProofs,
            UnequalNumberOfCircuitIdsAndProofs()
        );
        require(
            publicInputs.length == numProofs,
            UnequalNumberOfCircuitIdsAndPublicInputs()
        );
        require(numProofs <= MAX_NUM_PROOFS_PER_SUBMISSION, TooManyProofs());

        uint8 depth = Merkle.merkleDepth(numProofs);
        uint16 fullSize = uint16(1) << depth;

        bytes32[] memory proofIds = new bytes32[](fullSize);
        uint64[] memory proofIdxs = new uint64[](fullSize);
        bytes32[] memory proofDigests = new bytes32[](fullSize);

        ProofReceiverStorage
            storage proofReceiverStorage = _getProofReceiverStorage();
        uint64 proofIdx = proofReceiverStorage._nextProofIdx;
        uint256 _maxNumPublicInputs = proofReceiverStorage._maxNumPublicInputs;

        // Iterate through all proofs.  Compute the proofIds and proofHashes.
        for (uint16 i = 0; i < numProofs; ++i) {
            handleSubmittedProof(
                i,
                circuitIds,
                proofs,
                publicInputs,
                proofIds,
                proofDigests,
                _maxNumPublicInputs
            );

            proofIdxs[i] = proofIdx++;
        }

        proofReceiverStorage._nextProofIdx = proofIdx;

        // Compute the submissionIdx and submissionId, which in turn
        // determines the duplicateSubmissionIdx (required to emit events)
        uint64 submissionIdx = proofReceiverStorage._nextSubmissionIdx++;
        submissionId = Merkle.computeMerkleRoot(proofIds);

        Submission[] storage submissions = proofReceiverStorage._submissions[
            submissionId
        ];
        uint64 dupSubmissionIdx = uint64(submissions.length);
        require(
            dupSubmissionIdx < uint64(MAX_NUM_DUPLICATE_SUBMISSIONS),
            TooManySubmissionsForId()
        );

        // Emit events
        for (uint16 i = 0; i < numProofs; ++i) {
            // TODO: Should we flag submissions separately and avoid all the duplicated data?
            emit ProofSubmitted(
                proofIds[i],
                submissionIdx,
                proofIdxs[i],
                dupSubmissionIdx
            );
        }

        // Record the final submission
        bytes32 proofDataDigest = UpaLib.proofDataDigest(
            Merkle.computeMerkleRoot(proofDigests),
            msg.sender
        );

        // Forward the fee to the fee model
        onProofSubmitted(numProofs);

        submissions.push(
            Submission(
                proofDataDigest,
                submissionIdx,
                uint64(block.number),
                numProofs
            )
        );
    }

    /// Return the VK for a specific circuit Id.
    function getVK(bytes32 circuitId) public view returns (Groth16VK memory) {
        CircuitData storage cData = _getProofReceiverStorage()._circuitData[
            circuitId
        ];
        require(cData.verificationKey.alpha[0] != 0, UnregisteredVK());
        return cData.verificationKey;
    }

    function getSubmissionIdx(
        bytes32 submissionId,
        uint8 dupSubmissionIdx
    ) public view returns (uint64 submissionIdx) {
        Submission storage submission = _getProofReceiverStorage()._submissions[
            submissionId
        ][dupSubmissionIdx];
        submissionIdx = submission.submissionIdx;
    }

    function getSubmissionIdxAndHeight(
        bytes32 submissionId,
        uint8 dupSubmissionIdx
    ) public view returns (uint64 submissionIdx, uint64 submissionBlockNumber) {
        Submission storage submission = _getProofReceiverStorage()._submissions[
            submissionId
        ][dupSubmissionIdx];
        submissionIdx = submission.submissionIdx;
        submissionBlockNumber = submission.submissionBlockNumber;
    }

    function getSubmissionIdxAndNumProofs(
        bytes32 submissionId,
        uint8 dupSubmissionIdx
    ) public view returns (uint64 submissionIdx, uint16 numProofs) {
        Submission storage submission = _getProofReceiverStorage()._submissions[
            submissionId
        ][dupSubmissionIdx];
        submissionIdx = submission.submissionIdx;
        numProofs = submission.numProofs;
    }

    function getSubmissionIdxHeightNumProofs(
        bytes32 submissionId,
        uint8 dupSubmissionIdx
    )
        public
        view
        returns (uint64 submissionIdx, uint64 height, uint16 numProofs)
    {
        Submission storage submission = _getProofReceiverStorage()._submissions[
            submissionId
        ][dupSubmissionIdx];
        submissionIdx = submission.submissionIdx;
        height = submission.submissionBlockNumber;
        numProofs = submission.numProofs;
    }

    function getSubmission(
        bytes32 submissionId,
        uint8 dupSubmissionIdx
    ) public view returns (Submission memory submission) {
        submission = _getProofReceiverStorage()._submissions[submissionId][
            dupSubmissionIdx
        ];
        require(0 != submission.submissionIdx, SubmissionDoesNotExist());
    }

    // Sub-section of the code in `submit`.  This function exists only to
    // avoid a "stack too deep" error in the compiler.
    function handleSubmittedProof(
        uint16 i,
        bytes32[] calldata circuitIds,
        Groth16CompressedProof[] calldata proofs,
        uint256[][] calldata publicInputs,
        bytes32[] memory proofIds,
        bytes32[] memory proofDigests,
        uint256 _maxNumPublicInputs
    ) internal view {
        bytes32 circuitId = circuitIds[i];
        CircuitData storage cData = _getProofReceiverStorage()._circuitData[
            circuitId
        ];
        require(cData.verificationKey.alpha[0] != 0, UnregisteredVK());

        Groth16CompressedProof memory proof = proofs[i];
        bytes32 proofDigest = UpaInternalLib.computeProofDigest(proof);
        proofDigests[i] = proofDigest;

        uint256[] memory publicInput = publicInputs[i];
        bytes32 proofId = UpaLib.computeProofId(circuitId, publicInput);
        proofIds[i] = proofId;

        uint256 numPublicInputs = publicInput.length + proof.m.length;
        require(numPublicInputs <= _maxNumPublicInputs, TooManyPublicInputs());
    }
}
