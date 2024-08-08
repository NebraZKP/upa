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

pragma solidity ^0.8.20;

// Based on:
//   solhint-disable-next-line
//   https://github.com/tornadocash/tornado-core/blob/1ef6a263ac6a0e476d063fcb269a9df65a1bd56a/contracts/Verifier.sol
// and
//   solhint-disable-next-line
//   https://github.com/witnet/elliptic-curve-solidity/blob/347547890840fd501809dfe0b855206407136ec0/contracts/EllipticCurve.sol

/// Represents a G1 point which is known to be on the curve, with coordinates
/// in the field (values < field modulus).  Structs should only be created
/// via `intoG1Point`.
struct G1Point {
    uint256 x;
    uint256 y;
}

/// Represents a G2 point which is known to be on the curve, with coordinates
/// in the field (values < field modulus).  Should only be constructed via
/// `intoG2Point`. Note: Encoding of Fq2 elements is: x[0] * z + x[1].
struct G2Point {
    uint256[2] x;
    uint256[2] y;
}

/// Elliptic Curve Utilities
library EllipticCurveUtils {
    /// BN254 base field modulus
    uint256 internal constant PRIME_Q =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    /// Constant `b` in the BN254 G1 equation: `y^2 = x^3 + b`
    uint256 internal constant BN254_G1_B = 3;
    /// Constant `b0` in the BN254 G2 equation: `y^2 = x^3 + b0 + b1*u`
    uint256 internal constant BN254_G2_B0 =
        0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    /// Constant `b1` in the BN254 G2 equation: `y^2 = x^3 + b0 + b1*u`
    uint256 internal constant BN254_G2_B1 =
        0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2;

    /// Adds two Fq elements.
    function fqAdd(uint256 x, uint256 y) internal pure returns (uint256) {
        return addmod(x, y, PRIME_Q);
    }

    /// Subtracts two Fq elements.
    function fqSub(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 yComplement = PRIME_Q - y;
        return addmod(x, yComplement, PRIME_Q);
    }

    /// Multiplies two Fq elements.
    function fqMul(uint256 x, uint256 y) internal pure returns (uint256) {
        return mulmod(x, y, PRIME_Q);
    }

    /// Adds two Fq2 elements.
    function fq2Add(
        uint256[2] memory x,
        uint256[2] memory y
    ) internal pure returns (uint256[2] memory result) {
        result[0] = fqAdd(x[0], y[0]);
        result[1] = fqAdd(x[1], y[1]);
    }

    /// Multiplies two Fq2 elements.
    function fq2Mul(
        uint256[2] memory x,
        uint256[2] memory y
    ) internal pure returns (uint256[2] memory result) {
        result[0] = fqSub(fqMul(x[0], y[0]), fqMul(x[1], y[1]));
        result[1] = fqAdd(fqMul(x[0], y[1]), fqMul(x[1], y[0]));
    }

    /// Checks `x` is a valid Fq element.
    function checkFq(uint256 x) internal pure returns (bool) {
        return x < PRIME_Q;
    }

    /// Checks `x` is a valid Fq2 element.
    function checkFq2(uint256[2] memory x) internal pure returns (bool) {
        return checkFq(x[0]) && checkFq(x[1]);
    }

    /// Returns `true` if `x` is zero.
    function fq2IsZero(uint256[2] memory x) internal pure returns (bool) {
        return x[0] == 0 && x[1] == 0;
    }

    /// Checks `(x, y)` is a non-zero BN254 G1 point.
    function isOnG1Curve(uint256 x, uint256 y) internal pure returns (bool) {
        if (!checkFq(x) || !checkFq(y)) {
            return false;
        }
        if (0 == x || 0 == y) {
            // If `x == 0`, then the equation `y^2 = x^3 + 3` doesn't have a
            // solution because `3` is not a square in `FQ`.
            // If `y == 0`, then `P = (x, y)` must have order 2. There's no
            // order 2 points in G1, so this is impossible.
            return false;
        }
        // y^2
        uint256 lhs = fqMul(y, y);
        // x^3 + b
        uint256 rhs = fqAdd(fqMul(x, fqMul(x, x)), BN254_G1_B);

        return lhs == rhs;
    }

    /// Checks `(x, y)` is a non-zero BN254 G2 point.
    function isOnG2Curve(
        uint256[2] memory x,
        uint256[2] memory y
    ) internal pure returns (bool) {
        if (!checkFq2(x) || !checkFq2(y)) {
            return false;
        }
        if (fq2IsZero(x) || fq2IsZero(y)) {
            // If `x == 0`, then by the doubling formula we get `2P = -P`
            // for `P = (0, y)`, so `P` has order 3 and is not in the right
            // subgroup.
            // If `y == 0`, then `P = (x, y)` (if it exists) must have order 2,
            // which is not in the right subgroup.
            return false;
        }
        // y^2
        uint256[2] memory lhs = fq2Mul(y, y);
        // x^3 + b
        uint256[2] memory rhs = fq2Add(
            [BN254_G2_B0, BN254_G2_B1],
            fq2Mul(fq2Mul(x, x), x)
        );

        return lhs[0] == rhs[0] && lhs[1] == rhs[1];
    }

    /// Converts the pair `g1Point` into a `G1Point`.
    function intoG1Point(
        uint256[2] calldata g1Point
    ) internal pure returns (G1Point memory) {
        uint256 x = g1Point[0];
        uint256 y = g1Point[1];
        require(isOnG1Curve(x, y), "invalid curve point");
        return G1Point(x, y);
    }

    /// Swaps the elements in `input`.
    function swap(
        uint256[2] memory input
    ) internal pure returns (uint256[2] memory output) {
        output = [input[1], input[0]];
    }

    /// Converts the array `g2Point` into a `G2Point`.
    function intoG2Point(
        uint256[2][2] calldata g2Point,
        bool shouldSwap
    ) internal pure returns (G2Point memory) {
        uint256[2] memory x = g2Point[0];
        uint256[2] memory y = g2Point[1];
        if (shouldSwap) {
            require(isOnG2Curve(x, y), "invalid curve point");
            return G2Point(swap(x), swap(y));
        } else {
            require(isOnG2Curve(swap(x), swap(y)), "invalid curve point");
            return G2Point(x, y);
        }
    }

    /// Computes `-p`.
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.x == 0 && p.y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.x, PRIME_Q - p.y);
        }
    }

    /// Computes `p1 + p2`.
    function ecAdd(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;

        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                6,
                input,
                0x80 /* 0x20 * 4 */,
                r,
                0x40 /* 0x20 * 2 */
            )
        }

        require(success, "pairing-add-failed");
    }

    /// Computes `s * p`.
    function scalarMul(
        G1Point memory p,
        uint256 s
    ) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;

        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                7,
                input,
                0x60 /* 0x20 * 3 */,
                r,
                0x40 /* 0x20 * 2 */
            )
        }

        require(success, "pairing-mul-failed");
    }

    /// Checks the following equality in `G_T`:
    /// `e(a1, a2)*e(b1, b2)*e(c1, c2)*e(d1, d2) == 1`
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool result) {
        uint256[24] memory input;
        input[0] = a1.x;
        input[1] = a1.y;
        input[2] = a2.x[0];
        input[3] = a2.x[1];
        input[4] = a2.y[0];
        input[5] = a2.y[1];

        input[6] = b1.x;
        input[7] = b1.y;
        input[8] = b2.x[0];
        input[9] = b2.x[1];
        input[10] = b2.y[0];
        input[11] = b2.y[1];

        input[12] = c1.x;
        input[13] = c1.y;
        input[14] = c2.x[0];
        input[15] = c2.x[1];
        input[16] = c2.y[0];
        input[17] = c2.y[1];

        input[18] = d1.x;
        input[19] = d1.y;
        input[20] = d2.x[0];
        input[21] = d2.x[1];
        input[22] = d2.y[0];
        input[23] = d2.y[1];

        bool success;
        uint256[1] memory out;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                8,
                input,
                0x300 /* 0x20 * 24 */,
                out,
                0x20
            )
        }

        require(success, "pairing-failed");
        return out[0] != 0;
    }

    /// Checks the following equality in `G_T`:
    /// `e(a1, a2)*e(b1, b2) == 1`
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool result) {
        uint256[12] memory input;
        input[0] = a1.x;
        input[1] = a1.y;
        input[2] = a2.x[0];
        input[3] = a2.x[1];
        input[4] = a2.y[0];
        input[5] = a2.y[1];

        input[6] = b1.x;
        input[7] = b1.y;
        input[8] = b2.x[0];
        input[9] = b2.x[1];
        input[10] = b2.y[0];
        input[11] = b2.y[1];

        bool success;
        uint256[1] memory out;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                8,
                input,
                0x180 /* 0x20 * 12 */,
                out,
                0x20
            )
        }

        require(success, "pairing-failed");
        return out[0] != 0;
    }
}
