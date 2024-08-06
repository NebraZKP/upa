// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "./IGroth16Verifier.sol";

/// Library functions that are not intended to be commonly used by
/// applications.  Certain applications may wish to use these, but they should
/// know what they are doing. We separate these from those in UpaLib.sol,
/// primarily to make the dependencies between files much cleaner.
library UpaInternalLib {
    // These must be consistent with the BatchVerify circuit configuration.
    uint8 internal constant NUM_LIMBS = 3;
    uint8 internal constant LIMB_BITS = 88;
    uint256 internal constant LIMB_MASK = (uint256(1) << LIMB_BITS) - 1;

    uint256 internal constant ALPHA_BETA_GAMMA_DELTA_SIZE_WORDS = (1 *
        2 /*alpha*/ +
        3 *
        4 /*beta,gamma,delta*/);
    uint256 internal constant ALPHA_BETA_GAMMA_DELTA_SIZE_BYTES =
        ALPHA_BETA_GAMMA_DELTA_SIZE_WORDS * 32;

    // Reproduce the calculation with:
    //
    //   `cargo test -- domain --no-capture --include-ignored`
    //
    // in the repo root. See
    // `upa_circuits::tests::hashing::domain_tags` test.
    uint256 internal constant CIRCUIT_ID_DOMAIN_TAG =
        0x4fb2fda778fd224ee633116280b47f502b0d937ce78d390aa16f73d9007c65f2;
    uint256 internal constant CIRCUIT_ID_DOMAIN_TAG_WITH_COMMITMENT =
        0xbe0523909703924017e523b64b54adc1091d895bc2cea0e312c4b2e63c813202;

    /// Compresses `g1Point` into a single `uint256`.  Note that this function
    /// does not check (or care) whether `g1Point` is well-formed.
    function compressG1Point(
        uint256[2] calldata g1Point
    ) internal pure returns (uint256) {
        uint256 x = g1Point[0];
        uint256 y = g1Point[1];
        if (x == 0 && y == 0) {
            return 0;
        }
        // This flag tracks whether `y` is odd or even.
        uint256 sign = y & 1;
        // We add the sign to the first (highest order) bit of `x`.
        return x | (sign << 255);
    }

    /// Compresses `g2Point` into a pair of `uint256`. Note `g2Point` must
    /// have its Fq2 elements reversed, i.e., in the EVM-compatible order, but
    /// the output Fq2 element will come out in the natural order. Note that
    /// this function does not check (or care) whether `g2Point` is
    /// well-formed.
    function compressG2Point(
        uint256[2][2] calldata g2Point
    ) internal pure returns (uint256[2] memory) {
        uint256[2] calldata x = g2Point[0];
        uint256[2] calldata y = g2Point[1];
        uint256[2] memory compressedPoint;
        if (x[0] == 0 && x[1] == 0 && y[0] == 0 && y[1] == 0) {
            compressedPoint[0] = 0;
            compressedPoint[1] = 0;
            return compressedPoint;
        }
        // This flag tracks whether `y` is odd or even.
        uint256 sign = y[0] & 1;
        // We add the sign to the first bit of `x`.
        uint256 x0 = x[1] | (sign << 255);
        // Swap the order of the elements
        compressedPoint[0] = x0;
        compressedPoint[1] = x[0];
        return compressedPoint;
    }

    function decomposeFqToBuffer(
        uint256 fq,
        uint256[] memory output,
        uint256 offset
    ) internal pure {
        (uint256 x0, uint256 x1, uint256 x2) = decomposeFq(fq);
        output[offset] = x0;
        output[offset + 1] = x1;
        output[offset + 2] = x2;
    }

    /// Compute the circuitId for a Groth16 verification key.
    function computeCircuitId(
        Groth16VK calldata vk
    ) internal pure returns (bytes32 circuitId) {
        // Preimage layout:
        //   alpha, beta, gamma, delta,
        //   vk.s.length,
        //   vk.s[...], vk.h1[...], vk.h2[...]

        uint256 vkSLength = vk.s.length;
        uint256 vkSSizeBytes = vkSLength * 32 * 2 /* g1 size */;
        uint256 commitmentSizeBytes = vk.h1.length * 4 * 32 /* h1 */;
        uint256 domainTag = commitmentSizeBytes == 0
            ? CIRCUIT_ID_DOMAIN_TAG
            : CIRCUIT_ID_DOMAIN_TAG_WITH_COMMITMENT;

        uint256 totalSizeBytes = 0x20 /* domain tag */ +
            ALPHA_BETA_GAMMA_DELTA_SIZE_BYTES /* alpha, beta, gamma, delta */ +
            0x20 /* vk.s.length */ +
            vkSSizeBytes /* vk.s */ +
            commitmentSizeBytes /* h1 */ +
            commitmentSizeBytes /* h2 */;

        // Buffer to hold the preimage
        bytes memory preimage = new bytes(totalSizeBytes);

        // solhint-disable
        uint256[2][] calldata vk_s = vk.s;
        uint256[2][2][] calldata vk_h1 = vk.h1;
        uint256[2][2][] calldata vk_h2 = vk.h2;
        // solhint-enable

        assembly {
            let dst := preimage

            // Write preimage.length
            // mstore(dst, totalSizeBytes)
            dst := add(dst, 0x20)

            // Write domain tag
            mstore(dst, domainTag)
            dst := add(dst, 0x20)

            // Write alpha, beta, gamma, delta
            calldatacopy(dst, vk, 0x1c0 /* ALPHA_BETA_GAMMA_DELTA_SIZE_BYTES */)
            dst := add(dst, 0x1c0 /* ALPHA_BETA_GAMMA_DELTA_SIZE_BYTES */)

            // Write vk.s.length
            mstore(dst, vkSLength)
            dst := add(dst, 0x20)

            // Write vk.s
            calldatacopy(dst, vk_s.offset, vkSSizeBytes)
            dst := add(dst, vkSSizeBytes)

            // Write vk.h1,h2
            calldatacopy(dst, vk_h1.offset, commitmentSizeBytes)
            dst := add(dst, commitmentSizeBytes)
            calldatacopy(dst, vk_h2.offset, commitmentSizeBytes)
            dst := add(dst, commitmentSizeBytes)

            circuitId := keccak256(add(preimage, 0x20), totalSizeBytes)
        }
    }

    /// Compresses `proof`.
    function compressProof(
        Groth16Proof calldata proof
    ) internal pure returns (Groth16CompressedProof memory) {
        uint256 pA = compressG1Point(proof.pA);
        uint256[2] memory pB = compressG2Point(proof.pB);
        uint256 pC = compressG1Point(proof.pC);
        uint256[] memory m;
        uint256[] memory pok;
        for (uint256 i = 0; i < proof.m.length; i++) {
            m[i] = compressG1Point(proof.m[i]);
            pok[i] = compressG1Point(proof.pok[i]);
        }
        return Groth16CompressedProof(pA, pB, pC, m, pok);
    }

    /// Compute the digest of a specific Groth16 proof.  Used to commit to
    /// proof data which may later be submitted by a claimant.
    function computeProofDigest(
        Groth16CompressedProof memory proof
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(proof));
    }

    /// Split the given field element into "limbs".  Note, this does not check
    /// the well-formedness of the incoming element.
    function decomposeFq(
        uint256 fq
    ) internal pure returns (uint256, uint256, uint256) {
        assert(NUM_LIMBS == 3);
        uint256 x0 = fq & LIMB_MASK;
        fq = fq >> LIMB_BITS;
        uint256 x1 = fq & LIMB_MASK;
        return (x0, x1, fq >> LIMB_BITS);
    }

    /// Checks whether the `submissionMarkersIdx`-th proof marked by
    /// `offChainSubmissionMarkers` is at the end of a submission.
    function marksEndOfSubmission(
        uint256 submissionMarkersIdx,
        uint256 offChainSubmissionMarkers
    ) internal pure returns (bool) {
        // Interpret `offChainSubmissionMarkers` as a bool[] and check if the
        // `submissionMarkersIdx`-th entry is a 1, which indicates that this
        // entry marks the end of a submission.
        return
            (offChainSubmissionMarkers >> (submissionMarkersIdx & 0xff)) & 1 ==
            1;
    }

    /// `index` is assumed to be less than 32.
    function getUint8At(
        uint256 value,
        uint16 index
    ) internal pure returns (uint8) {
        //require(index < 32, "Index out of bounds");

        // Shift right by index * 8 bits, then mask with 0xFF
        uint8 extractedValue = uint8((value >> (index * 8)) & 0xFF);

        return extractedValue;
    }
}
