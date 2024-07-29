// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// Functions used to compute the Create3 deploy address for a given deployer
/// and salt, when deployed using the CreateX contract.
contract ComputeCreateXDeployAddress {
    // See: https://github.com/Vectorized/solady/blob/main/src/utils/CREATE3.sol
    bytes32 internal constant PROXY_INITCODE_HASH =
        0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /// @dev Returns the deterministic address for `salt` with `deployer`.
    /// This implementation is taken from Solady:
    /// https://github.com/Vectorized/solady/blob/main/src/utils/CREATE3.sol
    function computeCreate3Address(
        bytes32 salt,
        address deployer
    ) public pure returns (address deployed) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, deployer) // Store `deployer`.
            mstore8(0x0b, 0xff) // Store the prefix.
            mstore(0x20, salt) // Store the salt.
            mstore(0x40, PROXY_INITCODE_HASH) // Store the bytecode hash.

            mstore(0x14, keccak256(0x0b, 0x55)) // Store the proxy's address.
            mstore(0x40, m) // Restore the free memory pointer.
            // 0xd6 = 0xc0 (short RLP prefix) + 0x16 (length of: 0x94 ++ proxy ++ 0x01).
            // 0x94 = 0x80 + 0x14 (0x14 = the length of an address, 20 bytes, in hex).
            mstore(0x00, 0xd694)
            mstore8(0x34, 0x01) // Nonce of the proxy contract (1).
            deployed := keccak256(0x1e, 0x17)
        }
    }

    /// Computes the guarded salt that CreateX uses to deploy, in only the case
    /// where frontrunning protection is on (i.e. the first 20 bytes of the
    /// salt are the same as the sender address), and redeploy protection is
    /// off (i.e. the 21st byte is `00`).
    function _guard(
        bytes32 salt,
        address sender
    ) public pure returns (bytes32 guardedSalt) {
        require(
            address(bytes20(salt)) == sender,
            "Expected first 20 bytes to match the sender address"
        );
        require(
            bytes1(salt[20]) == hex"00",
            "Expected cross-chain redeploy to be off"
        );

        guardedSalt = hash(bytes32(uint256(uint160(sender))), salt);
    }

    // From Merkle.sol
    function hash(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32 digest) {
        assembly {
            mstore(0x00, left)
            mstore(0x20, right)
            digest := keccak256(0x00, 0x40)
        }
    }
}
