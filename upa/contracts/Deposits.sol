// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// Contract that off-chain aggregators may use for handling fee deposits,
/// payments, and claims.
contract Deposits is EIP712 {
    // Data to be signed by the submitter
    struct SignedRequestData {
        bytes32 submissionId;
        uint256 expirationBlockNumber;
        uint256 totalFee;
    }

    // Data to be signed by the aggregator
    struct SignedResponseData {
        bytes32 submissionId;
        uint256 expirationBlockNumber;
        uint256 fee;
    }

    bytes32 private constant SIGNED_REQUEST_DATA_TYPE_HASH =
        keccak256(
            // solhint-disable-next-line
            "SignedRequestData(bytes32 submissionId,uint256 expirationBlockNumber,uint256 totalFee)"
        );

    bytes32 private constant SIGNED_RESPONSE_DATA_TYPE_HASH =
        keccak256(
            // solhint-disable-next-line
            "SignedResponseData(bytes32 submissionId,uint256 expirationBlockNumber,uint256 fee)"
        );

    constructor(
        string memory name,
        string memory version
    ) EIP712(name, version) {}

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
        SignedResponseData calldata signedResponseData,
        bytes calldata signature
    ) public view returns (address recoveredSigner) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(SIGNED_RESPONSE_DATA_TYPE_HASH, signedResponseData)
            )
        );

        recoveredSigner = ECDSA.recover(digest, signature);
    }
}
