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
import "./IGroth16Verifier.sol";

contract Groth16Verifier is IGroth16Verifier {
    /// BN-254 scalar field modulus
    uint256 public constant SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// Computes the public input term, i.e.
    /// `s_0 + \sum s_i p_i + m`, where `m` is the
    /// (potentially empty) LegoSnark commitment term.
    function computePublicInputTerm(
        uint256[2][] calldata s,
        G1Point[] memory m,
        uint256[] memory publicInputs
    ) internal view returns (G1Point memory publicInputTerm) {
        uint256 numPublicInputs = publicInputs.length;
        require(
            numPublicInputs + 1 == s.length,
            "Public inputs don't match vk."
        );
        publicInputTerm = EllipticCurveUtils.intoG1Point(s[0]);
        if (m.length > 0) {
            require(m.length == 1, "Multiple commits");
            publicInputTerm = EllipticCurveUtils.ecAdd(publicInputTerm, m[0]);
        }
        for (uint256 i = 0; i < numPublicInputs; i++) {
            G1Point memory curvePoint = EllipticCurveUtils.intoG1Point(
                s[i + 1]
            );
            uint256 publicInput = publicInputs[i];
            require(publicInput < SCALAR_FIELD, "Invalid public input");
            G1Point memory scaledPoint = EllipticCurveUtils.scalarMul(
                curvePoint,
                publicInput
            );
            publicInputTerm = EllipticCurveUtils.ecAdd(
                publicInputTerm,
                scaledPoint
            );
        }
    }

    /// Verifies `proofBytes` against `publicInputs` for `vk`.
    ///
    /// Note the verifying key has its Fq2 elements in the natural
    /// order, but the proof has them inverted (in the EVM order).
    function verifyProof(
        Groth16Proof calldata proofBytes,
        uint256[] calldata publicInputs,
        Groth16VK calldata vk
    ) external view override returns (bool success) {
        uint256 publicInputsLength = publicInputs.length;
        uint256 numCommitments = proofBytes.m.length;
        require(
            proofBytes.pok.length == numCommitments,
            "m and pok len mismatch"
        );
        require(
            vk.s.length == 1 + publicInputsLength + numCommitments,
            "Invalid vk.s length"
        );
        require(vk.h1.length == numCommitments, "Invalid vk.h1 length");
        require(vk.h2.length == numCommitments, "Invalid vk.h2 length");

        uint256[] memory newPublicInputs = new uint256[](
            publicInputsLength + numCommitments
        );

        // Copy publicInputs into the start of newPublicInputs.  Equivalent to:
        //
        //   for (uint256 i = 0; i < publicInputsLength; i++) {
        //       newPublicInputs[i] = publicInputs[i]);
        //   }
        assembly {
            calldatacopy(
                add(newPublicInputs, 0x20),
                publicInputs.offset,
                mul(publicInputsLength, 0x20)
            )
        }

        G1Point[] memory m = new G1Point[](numCommitments);
        G1Point[] memory pok = new G1Point[](numCommitments);
        G2Point[] memory h1 = new G2Point[](numCommitments);
        G2Point[] memory h2 = new G2Point[](numCommitments);

        if (numCommitments > 0) {
            require(numCommitments == 1, "Multiple commits");
            // TODO: Encapsulate the challenge computation?
            uint256 lastPublicInput = uint256(
                keccak256(
                    abi.encodePacked(proofBytes.m[0][0], proofBytes.m[0][1])
                )
            );
            lastPublicInput %= SCALAR_FIELD;
            newPublicInputs[publicInputsLength] = lastPublicInput;
            m[0] = EllipticCurveUtils.intoG1Point(proofBytes.m[0]);
            pok[0] = EllipticCurveUtils.intoG1Point(proofBytes.pok[0]);
            h1[0] = EllipticCurveUtils.intoG2Point(vk.h1[0], true);
            h2[0] = EllipticCurveUtils.intoG2Point(vk.h2[0], true);
        }
        G1Point memory a1 = EllipticCurveUtils.negate(
            EllipticCurveUtils.intoG1Point(proofBytes.pA)
        );
        G2Point memory a2 = EllipticCurveUtils.intoG2Point(
            proofBytes.pB,
            false
        );
        G1Point memory b1 = EllipticCurveUtils.intoG1Point(vk.alpha);
        G2Point memory b2 = EllipticCurveUtils.intoG2Point(vk.beta, true);
        G1Point memory c1 = computePublicInputTerm(vk.s, m, newPublicInputs);
        G2Point memory c2 = EllipticCurveUtils.intoG2Point(vk.gamma, true);
        G1Point memory d1 = EllipticCurveUtils.intoG1Point(proofBytes.pC);
        G2Point memory d2 = EllipticCurveUtils.intoG2Point(vk.delta, true);

        if (numCommitments > 0) {
            bool pedersenPairingCheck = EllipticCurveUtils.pairingCheck2(
                m[0],
                h1[0],
                pok[0],
                h2[0]
            );
            require(pedersenPairingCheck, "Pedersen pairing check failed");
        }

        return EllipticCurveUtils.pairingCheck4(a1, a2, b1, b2, c1, c2, d1, d2);
    }
}
