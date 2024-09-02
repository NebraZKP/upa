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

/// A compressed Groth16 proof.
struct Groth16CompressedProof {
    uint256 pA;
    uint256[2] pB;
    uint256 pC;
    uint256[] m;
    uint256[] pok;
}

/// A Groth16 proof (with Fq2 elements reversed, to be compatible with the EVM
/// precompiled contracts). The arrays `m` and `pok` hold the optional Pedersen
/// commitment point and its proof of knowledge. They must have the
/// same length, which may be 0 or 1.
struct Groth16Proof {
    uint256[2] pA;
    uint256[2][2] pB;
    uint256[2] pC;
    uint256[2][] m;
    uint256[2][] pok;
}

/// A Groth16 verification key.  This is primarily used by off-chain
/// aggregators, and therefore Fq2 elements use the "natural" ordering, not
/// the EVM-precompiled-contract-compatible ordering.  The generic
/// IGroth16Verifier contract is expected to fix the ordering internally.  The
/// arrays `h1` and `h2` hold the G2 points for verifying optional Pedersen
/// commitments. They must have the same length, which may be 0 or 1.
struct Groth16VK {
    uint256[2] alpha;
    uint256[2][2] beta;
    uint256[2][2] gamma;
    uint256[2][2] delta;
    uint256[2][] s;
    uint256[2][2][] h1;
    uint256[2][2][] h2;
}

/// Interface to a universal Groth16 verifier contract.
interface IGroth16Verifier {
    /// Must fully check that the incoming proof is well-formed, namely that
    /// points are on the curve and that field element representations are
    /// canonical (less than field modulus).
    ///
    /// Note that the Fq2 elements of VK are passed in "natural", not "EVM",
    /// order.
    function verifyProof(
        Groth16Proof calldata proofBytes,
        uint256[] calldata publicInputs,
        Groth16VK calldata vk
    ) external view returns (bool success);
}
