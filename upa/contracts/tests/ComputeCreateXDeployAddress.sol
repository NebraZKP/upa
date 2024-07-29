// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

// Functions from the CreateX contract used to compute the Create3 deploy
// address for a given deployer and salt. Some functions have been modified to
// take the sender address as an argument instead of using `msg.sender`.
contract ComputeCreateXDeployAddress {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         IMMUTABLES                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @dev Caches the contract address at construction, to be used for the custom errors.
     */
    address internal immutable _SELF = address(this);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                            TYPES                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @dev Enum for the selection of a permissioned deploy protection.
     */
    enum SenderBytes {
        MsgSender,
        ZeroAddress,
        Random
    }

    /**
     * @dev Enum for the selection of a cross-chain redeploy protection.
     */
    enum RedeployProtectionFlag {
        True,
        False,
        Unspecified
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @dev Error that occurs when the salt value is invalid.
     * @param emitter The contract that emits the error.
     */
    error InvalidSalt(address emitter);

    /**
     * @dev Returns the address where a contract will be stored if deployed via `deployer` using
     * the `CREATE3` pattern (i.e. without an initcode factor). Any change in the `salt` value will
     * result in a new destination address. This implementation is based on Solady:
     * https://web.archive.org/web/20230921114120/https://raw.githubusercontent.com/Vectorized/solady/1c1ac4ad9c8558001e92d8d1a7722ef67bec75df/src/utils/CREATE3.sol.
     * @param salt The 32-byte random value used to create the proxy contract address.
     * @param deployer The 20-byte deployer address.
     * @return computedAddress The 20-byte address where a contract will be stored.
     */
    function computeCreate3Address(
        bytes32 salt,
        address deployer
    ) public pure returns (address computedAddress) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(0x00, deployer)
            mstore8(0x0b, 0xff)
            mstore(0x20, salt)
            mstore(
                0x40,
                hex"21_c3_5d_be_1b_34_4a_24_88_cf_33_21_d6_ce_54_2f_8e_9f_30_55_44_ff_09_e4_99_3a_62_31_9a_49_7c_1f"
            )
            mstore(0x14, keccak256(0x0b, 0x55))
            mstore(0x40, ptr)
            mstore(0x00, 0xd694)
            mstore8(0x34, 0x01)
            computedAddress := keccak256(0x1e, 0x17)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPER FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // This function has been modified to take the sender address as an argument.
    function _guard(
        bytes32 salt,
        address sender
    ) public view returns (bytes32 guardedSalt) {
        (
            SenderBytes senderBytes,
            RedeployProtectionFlag redeployProtectionFlag
        ) = _parseSalt(salt, sender);

        if (
            senderBytes == SenderBytes.MsgSender &&
            redeployProtectionFlag == RedeployProtectionFlag.True
        ) {
            // Configures a permissioned deploy protection as well as a cross-chain redeploy protection.
            guardedSalt = keccak256(abi.encode(sender, block.chainid, salt));
        } else if (
            senderBytes == SenderBytes.MsgSender &&
            redeployProtectionFlag == RedeployProtectionFlag.False
        ) {
            // Configures solely a permissioned deploy protection.
            guardedSalt = _efficientHash({
                a: bytes32(uint256(uint160(sender))),
                b: salt
            });
        } else if (senderBytes == SenderBytes.MsgSender) {
            // Reverts if the 21st byte is greater than `0x01` in order to enforce developer explicitness.
            revert InvalidSalt({emitter: _SELF});
        } else if (
            senderBytes == SenderBytes.ZeroAddress &&
            redeployProtectionFlag == RedeployProtectionFlag.True
        ) {
            // Configures solely a cross-chain redeploy protection. In order to prevent a pseudo-randomly
            // generated cross-chain redeploy protection, we enforce the zero address check for the first 20 bytes.
            guardedSalt = _efficientHash({a: bytes32(block.chainid), b: salt});
        } else if (
            senderBytes == SenderBytes.ZeroAddress &&
            redeployProtectionFlag == RedeployProtectionFlag.Unspecified
        ) {
            // Reverts if the 21st byte is greater than `0x01` in order to enforce developer explicitness.
            revert InvalidSalt({emitter: _SELF});
        } else {
            // For the non-pseudo-random cases, the salt value `salt` is hashed to prevent the safeguard mechanisms
            // from being bypassed. Otherwise, the salt value `salt` is not modified.
            guardedSalt = (salt != _generateSalt())
                ? keccak256(abi.encode(salt))
                : salt;
        }
    }

    // This function has been modified to take the sender address as an argument.
    function _parseSalt(
        bytes32 salt,
        address sender
    )
        internal
        pure
        returns (
            SenderBytes senderBytes,
            RedeployProtectionFlag redeployProtectionFlag
        )
    {
        if (address(bytes20(salt)) == sender && bytes1(salt[20]) == hex"01") {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.MsgSender,
                RedeployProtectionFlag.True
            );
        } else if (
            address(bytes20(salt)) == sender && bytes1(salt[20]) == hex"00"
        ) {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.MsgSender,
                RedeployProtectionFlag.False
            );
        } else if (address(bytes20(salt)) == sender) {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.MsgSender,
                RedeployProtectionFlag.Unspecified
            );
        } else if (
            address(bytes20(salt)) == address(0) && bytes1(salt[20]) == hex"01"
        ) {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.ZeroAddress,
                RedeployProtectionFlag.True
            );
        } else if (
            address(bytes20(salt)) == address(0) && bytes1(salt[20]) == hex"00"
        ) {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.ZeroAddress,
                RedeployProtectionFlag.False
            );
        } else if (address(bytes20(salt)) == address(0)) {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.ZeroAddress,
                RedeployProtectionFlag.Unspecified
            );
        } else if (bytes1(salt[20]) == hex"01") {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.Random,
                RedeployProtectionFlag.True
            );
        } else if (bytes1(salt[20]) == hex"00") {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.Random,
                RedeployProtectionFlag.False
            );
        } else {
            (senderBytes, redeployProtectionFlag) = (
                SenderBytes.Random,
                RedeployProtectionFlag.Unspecified
            );
        }
    }

    /**
     * @dev Returns the `keccak256` hash of `a` and `b` after concatenation.
     * @param a The first 32-byte value to be concatenated and hashed.
     * @param b The second 32-byte value to be concatenated and hashed.
     * @return hash The 32-byte `keccak256` hash of `a` and `b`.
     */
    function _efficientHash(
        bytes32 a,
        bytes32 b
    ) internal pure returns (bytes32 hash) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            hash := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev Generates pseudo-randomly a salt value using a diverse selection of block and
     * transaction properties.
     * @return salt The 32-byte pseudo-random salt value.
     */
    function _generateSalt() internal view returns (bytes32 salt) {
        unchecked {
            salt = keccak256(
                abi.encode(
                    // We don't use `block.number - 256` (the maximum value on the EVM) to accommodate
                    // any chains that may try to reduce the amount of available historical block hashes.
                    // We also don't subtract 1 to mitigate any risks arising from consecutive block
                    // producers on a PoS chain. Therefore, we use `block.number - 32` as a reasonable
                    // compromise, one we expect should work on most chains, which is 1 epoch on Ethereum
                    // mainnet. Please note that if you use this function between the genesis block and block
                    // number 31, the block property `blockhash` will return zero, but the returned salt value
                    // `salt` will still have a non-zero value due to the hashing characteristic and the other
                    // remaining properties.
                    blockhash(block.number - 32),
                    block.coinbase,
                    block.number,
                    block.timestamp,
                    block.prevrandao,
                    block.chainid,
                    msg.sender
                )
            );
        }
    }
}
