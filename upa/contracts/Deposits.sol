// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./IUpaVerifier.sol";
import "./IDeposits.sol";

error NoPendingWithdrawal();
error InsufficientNotice();
error InsufficientBalance();
error FailedToSendEther();
error AlreadyClaimed();
error AlreadyRefunded();
error BadSignature();
error UnauthorizedAggregatorAccount();
error VerifiedBeforeExpiry();
error NotPastExpiry();
error UpaAddressIsZero();
error AggregatorAddressIsZero();

/// Contract that off-chain aggregators may use for handling fee deposits,
/// payments, and claims.
contract Deposits is IDeposits, EIP712 {
    struct SubmitterAccount {
        /// Remaining balance held by the Submitter
        uint256 balance;
        /// Total amount claimed by the aggregator so far
        uint256 totalClaimed;
        /// The block when a pending withdrawal was initiated. Zero if there
        /// is no pending withdrawal.
        uint256 pendingWithdrawalInitializedAtBlock;
    }

    // Data to be signed by the submitter
    struct SignedRequestData {
        bytes32 submissionId;
        uint256 expirationBlockNumber;
        uint256 totalFee;
    }

    // Data to be signed by the aggregator
    struct AggregationAgreement {
        bytes32 submissionId;
        uint256 expirationBlockNumber;
        uint256 fee;
        address submitterAddress;
    }

    /// Aggregtor fee claims are sent here
    address public immutable AGGREGATOR_ADDRESS;

    /// The UPA verifier contract.
    IUpaVerifier public immutable UPA_VERIFIER;

    /// Submitter accounts
    mapping(address => SubmitterAccount) public accounts;

    /// Mapping from an `AggregationAgreement` hash to whether a refund claim
    /// has been issued for that agreement.
    mapping(bytes32 => bool) public submissionRefunded;

    // Withdrawal notice is about 2 days
    uint256 public constant WITHDRAWAL_NOTICE_BLOCKS = 15000;

    bytes32 private constant SIGNED_REQUEST_DATA_TYPE_HASH =
        keccak256(
            // solhint-disable-next-line
            "SignedRequestData(bytes32 submissionId,uint256 expirationBlockNumber,uint256 totalFee)"
        );

    bytes32 private constant SIGNED_AGGREGATION_AGREEMENT_TYPE_HASH =
        keccak256(
            // solhint-disable-next-line
            "AggregationAgreement(bytes32 submissionId,uint256 expirationBlockNumber,uint256 fee,address submitterAddress)"
        );

    /// Gas per Ethereum transaction.
    uint256 private constant GAS_PER_TRANSACTION = 21000;

    /// Gas for the SSTORE used to refund fees.
    uint256 private constant GAS_PER_REFUND_SSTORE = 5000;

    // TODO: collateral, should be some amount larger than user deposits.

    constructor(
        string memory name,
        string memory version,
        address _aggregatorAddress,
        address _upaVerifierAddress
    ) EIP712(name, version) {
        require(_aggregatorAddress != address(0), AggregatorAddressIsZero());
        require(_upaVerifierAddress != address(0), UpaAddressIsZero());
        AGGREGATOR_ADDRESS = _aggregatorAddress;
        UPA_VERIFIER = IUpaVerifier(_upaVerifierAddress);
    }

    /// Return the total wei deposited by this submitter, including fees
    /// that have been claimed by the aggregator, and a flag indicating if
    /// there is a pending withdrawal initiated.
    function getSubmitterTotal(
        address submitter
    ) external view returns (uint256 total, uint256 withdrawalInitBlock) {
        SubmitterAccount storage account = accounts[submitter];
        total = account.balance + account.totalClaimed;
        withdrawalInitBlock = account.pendingWithdrawalInitializedAtBlock;
    }

    function balance(address account) external view returns (uint256) {
        return accounts[account].balance;
    }

    function pendingWithdrawalInitializedAtBlock(
        address account
    ) external view returns (uint256) {
        return accounts[account].pendingWithdrawalInitializedAtBlock;
    }

    /// Top-up submitter's ETH balance
    function deposit() external payable {
        accounts[msg.sender].balance += msg.value;
    }

    /// Start the withdrawal timer. The aggregator is not expected to agree to
    /// aggregate further submissions from this account while it has a pending
    /// withdrawal.
    function initiateWithdrawal() external {
        accounts[msg.sender].pendingWithdrawalInitializedAtBlock = block.number;
    }

    /// Perform a withdrawal. You must first call `initiateWithdrawal` at least
    /// `WITHDRAWAL_NOTICE_BLOCKS` in advance of withdrawing.
    function withdraw(uint256 amountWei) external {
        // There must be a pending withdrawal
        require(
            accounts[msg.sender].pendingWithdrawalInitializedAtBlock != 0,
            NoPendingWithdrawal()
        );
        // The pending withdrawal must have been initiated with enough notice.
        require(
            block.number -
                accounts[msg.sender].pendingWithdrawalInitializedAtBlock >
                WITHDRAWAL_NOTICE_BLOCKS,
            InsufficientNotice()
        );
        // Check the account has a sufficient balance.
        require(
            accounts[msg.sender].balance >= amountWei,
            InsufficientBalance()
        );

        // Update balance and pending withdrawal status
        accounts[msg.sender].balance -= amountWei;
        accounts[msg.sender].pendingWithdrawalInitializedAtBlock = 0;

        // Send the withdrawal amount
        (bool sent, ) = msg.sender.call{value: address(this).balance}("");
        require(sent, FailedToSendEther());
    }

    /// The aggregator uses this to claim the fees paid by a submitter.
    function claimFees(
        SignedRequestData calldata signedRequestData,
        bytes calldata signature
    ) external onlyAggregator {
        address submitter = recoverRequestSigner(signedRequestData, signature);
        // Check that there are unclaimed fees
        SubmitterAccount storage submitterAccount = accounts[submitter];
        require(
            submitterAccount.totalClaimed < signedRequestData.totalFee,
            AlreadyClaimed()
        );
        // Check that the submitter has sufficient deposits
        uint256 feeToBeClaimed = signedRequestData.totalFee -
            submitterAccount.totalClaimed;
        require(
            submitterAccount.balance >= feeToBeClaimed,
            InsufficientBalance()
        );

        // Update the total claimed fees and account balance
        submitterAccount.totalClaimed += feeToBeClaimed;
        submitterAccount.balance -= feeToBeClaimed;

        // Send the claimed fees
        (bool sent, ) = AGGREGATOR_ADDRESS.call{value: feeToBeClaimed}("");
        require(sent, FailedToSendEther());
    }

    /// The submitter may use this to refund fees for submissions that were
    /// not aggregated by the deadline that the aggregator agreed to.
    function refundFees(
        AggregationAgreement calldata aggregationAgreement,
        bytes calldata signature
    ) external {
        // Track gas for this call so it can be refunded.
        uint256 startGas = gasleft();

        address signer = recoverResponseSigner(aggregationAgreement, signature);
        // Check that the aggregation agreement was signed by the aggregator.
        require(signer == AGGREGATOR_ADDRESS, BadSignature());
        // Check that we are past the expirationBlockNumber
        require(
            aggregationAgreement.expirationBlockNumber < block.number,
            NotPastExpiry()
        );
        // Query UPA contract to check that the submission was not aggregated
        // by the expirationBlockNumber.
        uint256 verifiedAtBlock = UPA_VERIFIER
            .offChainSubmissionVerifiedAtBlock(
                aggregationAgreement.submissionId
            );
        require(
            verifiedAtBlock == 0 ||
                verifiedAtBlock > aggregationAgreement.expirationBlockNumber,
            VerifiedBeforeExpiry()
        );
        // Check that no previous successful claims have been made for this
        // aggregation agreement
        bytes32 aggregationAggreementHash = keccak256(
            abi.encode(aggregationAgreement)
        );
        require(
            !submissionRefunded[aggregationAggreementHash],
            AlreadyRefunded()
        );

        // Mark the submission as having been refunded
        submissionRefunded[aggregationAggreementHash] = true;

        // Estimate the gas that will be spent calling this function
        uint256 gasSpent = startGas -
            gasleft() +
            GAS_PER_TRANSACTION +
            GAS_PER_REFUND_SSTORE;
        // Refund fee as well as gas paid to call this function
        uint256 refundAmount = aggregationAgreement.fee +
            gasSpent *
            block.basefee;
        address refundRecipient = aggregationAgreement.submitterAddress;

        // Add the refund amount to submitter's balance
        accounts[refundRecipient].balance += refundAmount;
    }

    // The aggregator uses this to claim fees.
    function recoverRequestSigner(
        SignedRequestData calldata signedRequestData,
        bytes calldata signature
    ) public view returns (address recoveredSigner) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(SIGNED_REQUEST_DATA_TYPE_HASH, signedRequestData)
            )
        );

        recoveredSigner = ECDSA.recover(digest, signature);
    }

    // The client uses this to refund fees for expired, unverified submissions.
    function recoverResponseSigner(
        AggregationAgreement calldata aggregationAgreement,
        bytes calldata signature
    ) public view returns (address recoveredSigner) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    SIGNED_AGGREGATION_AGREEMENT_TYPE_HASH,
                    aggregationAgreement
                )
            )
        );

        recoveredSigner = ECDSA.recover(digest, signature);
    }

    modifier onlyAggregator() {
        require(
            msg.sender == AGGREGATOR_ADDRESS,
            UnauthorizedAggregatorAccount()
        );
        _;
    }

    function eip712Domain()
        public
        view
        virtual
        override(EIP712, IDeposits)
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return EIP712.eip712Domain();
    }
}
