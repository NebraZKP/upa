// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./IUpaProofReceiver.sol";

error NotEnoughCollateral();
error FailedToSendEther();
error InsufficientBalance();
error InsufficientFee();
error LastSubmittedSubmissionIdxTooLow();
error NotEnoughProofsVerified();
error PendingProofs();

/// A base contract which can be used to implement the fee handling part of
/// IUpaProofReceiver.  The (abstract) `estimateFee` function determines the
/// fee.  Received fees are accumulated on this contract, and are released to
/// aggregators as follows:
///
///   1. Aggregators allocate their fees, by calling `allocateAggregatorFee`.
///      The contract records the current balance of the contract (in
///      `totalFeeDueInWei`), and `lastSubmittedProofIdx`
///      (in `verifiedSubmissionIdxForAllocatedFee`).
///
///   2. Aggregators continue to aggregate until `lastSubmissionVerifier
///
///   3. When:
///
///        `lastSubmissionIdxverified >= verifiedProofIdxForAllocatedFee`
///
///      the Aggregator may claim the allocated fees.
///
abstract contract UpaFeeBase is
    Initializable,
    OwnableUpgradeable,
    IUpaProofReceiver
{
    /// @custom:storage-location erc7201:FeeBaseStorage
    struct FeeBaseStorage {
        /// Total fee due in Wei. This amount can be claimed through
        /// `claimAggregatorFee` by the aggregator once the proof with index
        /// `verifiedProofIdxForAllocatedFee` has been verified (or skipped).
        uint256 totalFeeDueInWei;
        /// Aggregator collateral. This amount in the contract's balance
        /// isn't claimable by the aggregator, and must be kept to pay for
        /// successful censorship challenges.
        uint256 aggregatorCollateral;
        /// Verified proof index for total fee due.
        uint256 verifiedSubmissionIdxForAllocatedFee;
    }

    // keccak256(abi.encode(uint256(keccak256("FeeBaseStorage")) - 1)) &
    // ~bytes32(uint256(0xff));
    bytes32 private constant FEE_BASE_STORAGE_LOCATION =
        0x770f95b87076a34cb0c1b7f53e0e5e9fa5d3e2f5227cae88b7e0771445672b00;

    function _getFeeBaseStorage()
        private
        pure
        returns (FeeBaseStorage storage $)
    {
        assembly {
            $.slot := FEE_BASE_STORAGE_LOCATION
        }
    }

    function aggregatorCollateral() public view returns (uint256) {
        return _getFeeBaseStorage().aggregatorCollateral;
    }

    function verifiedSubmissionIdxForAllocatedFee()
        public
        view
        returns (uint256)
    {
        return _getFeeBaseStorage().verifiedSubmissionIdxForAllocatedFee;
    }

    // solhint-disable-next-line
    function __upaFeeBase_init(
        address _owner,
        uint256 _aggregatorCollateral
    ) public onlyInitializing {
        FeeBaseStorage storage feeBaseStorage = _getFeeBaseStorage();

        feeBaseStorage.totalFeeDueInWei = 0;
        feeBaseStorage.verifiedSubmissionIdxForAllocatedFee = 0;
        feeBaseStorage.aggregatorCollateral = _aggregatorCollateral;

        __Ownable_init(_owner);
    }

    /// We implement the receive/fallback functions so aggregators
    /// can top-up their collateral in case it's depleted after a
    /// successful censorship claim
    receive() external payable {}

    fallback() external payable {}

    function onProofSubmitted(
        uint16 numProofs
    ) internal returns (uint256 refundWei) {
        uint256 feeWei = this.estimateFee(numProofs);
        require(msg.value >= feeWei, InsufficientFee());
        return 0;
    }

    function allocateAggregatorFee(uint64 lastSubmittedSubmissionIdx) internal {
        FeeBaseStorage storage feeBaseStorage = _getFeeBaseStorage();

        require(
            lastSubmittedSubmissionIdx >
                feeBaseStorage.verifiedSubmissionIdxForAllocatedFee,
            LastSubmittedSubmissionIdxTooLow()
        );
        address thisContract = address(this);

        // Aggregators are not able to claim their fees until there's enough
        // funds to cover potential censorship claims
        require(
            thisContract.balance >= aggregatorCollateral(),
            NotEnoughCollateral()
        );

        // All current fees (minus collateral) will be claimable when the
        // lastest submission has been verified.
        feeBaseStorage
            .verifiedSubmissionIdxForAllocatedFee = lastSubmittedSubmissionIdx;
        feeBaseStorage.totalFeeDueInWei =
            thisContract.balance -
            aggregatorCollateral();
    }

    function claimAggregatorFee(
        address aggregator,
        uint64 lastVerifiedSubmissionIdx
    ) internal {
        // Check enough proofs have been verified
        require(
            lastVerifiedSubmissionIdx >= verifiedSubmissionIdxForAllocatedFee(),
            NotEnoughProofsVerified()
        );

        FeeBaseStorage storage feeBaseStorage = _getFeeBaseStorage();
        uint256 totalFeeDueInWei = feeBaseStorage.totalFeeDueInWei;
        // Update the total balance due to zero.
        feeBaseStorage.totalFeeDueInWei = 0;

        require(
            address(this).balance - aggregatorCollateral() >= totalFeeDueInWei,
            InsufficientBalance()
        );

        // Send the `totalFeeDueInWei` to `aggregator`
        (bool sent, ) = aggregator.call{value: totalFeeDueInWei}("");
        require(sent, FailedToSendEther());
    }

    function withdraw(
        address aggregator,
        uint64 lastVerifiedSubmissionIdx,
        uint64 lastSubmittedSubmissionIdx
    ) internal {
        require(
            lastVerifiedSubmissionIdx == lastSubmittedSubmissionIdx,
            PendingProofs()
        );
        // Update the total balance due to zero
        _getFeeBaseStorage().totalFeeDueInWei = 0;

        // Send the balance to `aggregator`
        (bool sent, ) = aggregator.call{value: address(this).balance}("");
        require(sent, FailedToSendEther());
    }

    function claimableFees() external view returns (uint256) {
        return address(this).balance - aggregatorCollateral();
    }

    function feeAllocated() external view returns (uint256) {
        return _getFeeBaseStorage().totalFeeDueInWei;
    }

    function reimburseFee(uint256 amount, address claimant) internal {
        if (address(this).balance < amount) {
            revert InsufficientBalance();
        }
        // After a successful censorship claim, we subtract the
        // amount from the aggregator's fee due.
        FeeBaseStorage storage fixedFeeStorage = _getFeeBaseStorage();
        fixedFeeStorage.totalFeeDueInWei = (fixedFeeStorage.totalFeeDueInWei >
            amount)
            ? (fixedFeeStorage.totalFeeDueInWei - amount)
            : 0;

        (bool sent, ) = claimant.call{value: amount}("");
        require(sent, FailedToSendEther());
    }
}
