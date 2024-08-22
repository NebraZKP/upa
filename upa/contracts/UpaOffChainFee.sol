// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// Contract that off-chain aggregators may use for handling fee deposits,
/// payments, and claims.
contract UpaOffChainFee is EIP712 {
    struct SignedData {
        bytes32 submissionId;
        uint256 expirationBlockNumber;
        uint256 totalFee;
    }

    bytes32 private constant SIGNING_DATA_TYPE_HASH =
        keccak256(
            // solhint-disable-next-line
            "SignedData(bytes32 submissionId,uint256 expirationBlockNumber,uint256 totalFee)"
        );

    constructor(
        string memory name,
        string memory version
    ) EIP712(name, version) {}

    // The aggregator will use this to claim fees.
    // Aggregator presents `signedNote`, recovers the signer address, then
    // claims fees from that address.
    function recoverSigner(
        SignedData calldata signedData,
        bytes calldata signature
    ) public view returns (address recoveredSigner) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(SIGNING_DATA_TYPE_HASH, signedData))
        );

        recoveredSigner = ECDSA.recover(digest, signature);
    }
}
