// SPDX-License-Identifier: MIT

pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";

import "./UpaLib.sol";
import "./IUpaVerifier.sol";
import "./IUpaProofVerifier.sol";

error OuterVerifierAddressIsZero();
error OwnerAddressIsZero();
error FinalDigestLDoesNotMatch();
error FinalDigestHDoesNotMatch();
error InvalidProof();

// simple aggregator that mark all proofs in an
// aggregated batch as valid to later be verified

contract SimpleVerifier is IUpaProofVerifier, Ownable {
    address public verifier;
    mapping(bytes32 => bool) private verifiedProofs;

    constructor(
        address verifierAddress,
        address ownerAddress
    ) Ownable(ownerAddress) {
        require(verifierAddress != address(0), OuterVerifierAddressIsZero());
        verifier = verifierAddress;
    }

    function setOuterVerifier(address _outerVerifier) public onlyOwner {
        require(_outerVerifier != address(0), OuterVerifierAddressIsZero());
        verifier = _outerVerifier;
    }

    function isProofVerified(
        bytes32 circuitId,
        uint256[] memory publicInputs
    ) external view returns (bool) {
        bytes32 proofId = UpaLib.computeProofId(circuitId, publicInputs);
        return verifiedProofs[proofId];
    }

    function isProofVerified(
        bytes32 proofId
    ) public view override returns (bool) {
        return verifiedProofs[proofId];
    }

    function verifyAggregatedProof(
        bytes32[] calldata proofIds,
        bytes calldata aggregatedProof
    ) external {
        // computing the final digest
        bytes32 finalDigest = UpaLib.computeFinalDigest(proofIds);

        // checking that final digest matches slots 12/13
        (uint256 expectL, uint256 expectH) = UpaLib.digestAsFieldElements(
            finalDigest
        );
        uint256 proofL;
        uint256 proofH;
        assembly {
            proofL := calldataload(
                add(aggregatedProof.offset, /* 12 * 0x20 */ 0x180)
            )
            proofH := calldataload(
                add(aggregatedProof.offset, /* 13 * 0x20 */ 0x1a0)
            )
        }
        require(proofL == expectL, FinalDigestLDoesNotMatch());
        require(proofH == expectH, FinalDigestHDoesNotMatch());

        (bool success, ) = verifier.staticcall(aggregatedProof);
        require(success, InvalidProof());

        // setting each proofId in proofIds to true
        for (uint256 i = 0; i < proofIds.length; i++) {
            verifiedProofs[proofIds[i]] = true;
        }
    }
}
