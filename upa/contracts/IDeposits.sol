// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

/// Contract that off-chain aggregators may use for handling fee deposits,
/// payments, and claims.
interface IDeposits {
    // View the balance of an account
    function balance(address account) external view returns (uint256);

    /// Top-up submitter's ETH balance
    function deposit() external payable;

    /// Perform a withdrawal.
    function withdraw(uint256 amountWei) external;

    /// Make sure this function is implemented (usually by inheriting from the
    /// EIP-712 contract).
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}
