import { BigNumberish, toBeHex } from "ethers";
import { SnarkJSG1, SnarkJSG2 } from "./snarkjs";
import { GnarkG1Point, GnarkG2Point } from "./gnark";

/// Representation of ECC points.  Used by the Proof and VerifyingKey formats.
/// Conversion to/from EVM, SnarkJS and Gnark formats.

/**
 * A G1Point.  Serializable as JSON.
 *
 * @remarks
 *
 * Field elements are plain decimal or hex values (in non-Montgomery form)
 */
export type G1Point = [string, string];

/**
 * A G2Point.  Serializable as JSON.
 *
 * @remarks
 *
 * Each inner array is an Fq2 `a + b*u` element, represented as 2 Fq elements
 * `[a, b]` (which we refer to as the "natural order").
 */
export type G2Point = [[string, string], [string, string]];

/// Compressed G1 point type
export type CompressedG1Point = string;

/// Compressed G2 point type
export type CompressedG2Point = [string, string];

/// Convert from BigNumberish representation
export function toG1(sol: [BigNumberish, BigNumberish]): G1Point {
  return [toBeHex(sol[0], 32), toBeHex(sol[1], 32)];
}

/// Convert from BigNumberish representation.
// Note this DOES NOT reverse the Fq2 component order.
export function toG2(
  sol: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]]
): G2Point {
  return [
    [toBeHex(sol[0][0], 32), toBeHex(sol[0][1], 32)],
    [toBeHex(sol[1][0], 32), toBeHex(sol[1][1], 32)],
  ];
}

/// Utility function to reverse Fq2 components.
export function reverseFq2Elements<T>(g2: [[T, T], [T, T]]): [[T, T], [T, T]] {
  return [
    [g2[0][1], g2[0][0]],
    [g2[1][1], g2[1][0]],
  ];
}

export function snarkJSG1ToG1(g1: SnarkJSG1): G1Point {
  if (g1[2] !== "1") {
    throw "unexpected form of SnarkJSG1";
  }
  return [g1[0], g1[1]];
}

export function snarkJSG2ToG2(g2: SnarkJSG2): G2Point {
  if (g2[2][0] !== "1" || g2[2][1] !== "0") {
    throw "unexpected form of SnarkJSG2";
  }
  return [g2[0], g2[1]];
}

export function gnarkG1ToG1(g1: GnarkG1Point): G1Point {
  return [g1.X.toString(), g1.Y.toString()];
}

export function gnarkG2ToG2(g2: GnarkG2Point): G2Point {
  return [
    [g2.X.A0.toString(), g2.X.A1.toString()],
    [g2.Y.A0.toString(), g2.Y.A1.toString()],
  ];
}

export function isIdentityG1(g1Point: G1Point): boolean {
  return BigInt(g1Point[0]) == 0n && BigInt(g1Point[1]) == 0n;
}

export function isIdentityG2(g2Point: G2Point): boolean {
  return (
    BigInt(g2Point[0][0]) == 0n &&
    BigInt(g2Point[0][1]) == 0n &&
    BigInt(g2Point[1][0]) == 0n &&
    BigInt(g2Point[1][1]) == 0n
  );
}
