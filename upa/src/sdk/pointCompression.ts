import {
  G1Point,
  G2Point,
  isIdentityG1,
  isIdentityG2,
  CompressedG1Point,
  CompressedG2Point,
} from "./ecc";
import * as utils from "./utils";
const ffjavascript = require("ffjavascript");

/// BN254 base field (FQ) modulus
const PRIME_Q =
  0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
/// FQ field
const FQ = new ffjavascript.ZqField(PRIME_Q);
/// FQ2 field
const FQ2 = new ffjavascript.F2Field(FQ, FQ.negone);

/// Constant `b` in the BN254 G1 equation: `y^2 = x^3 + b`
const BN254_G1_B = 3n;
/// Constant `b0` in the BN254 G2 equation: `y^2 = x^3 + b0 + b1*u`
const BN254_G2_B0 =
  0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5n;
/// Constant `b1` in the BN254 G2 equation: `y^2 = x^3 + b0 + b1*u`
const BN254_G2_B1 =
  0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2n;

function bigintToHex32(b: bigint): string {
  return "0x" + utils.bigintToHex32(b);
}

/// Compresses `g1Point` into a single 32-byte word.
export function compressG1Point(g1Point: G1Point): CompressedG1Point {
  if (isIdentityG1(g1Point)) {
    return bigintToHex32(0n);
  }
  const y = BigInt(g1Point[1]);
  const sign = y & 1n;
  return bigintToHex32(BigInt(g1Point[0]) | (sign << 255n));
}

/// Decompresses `compressedPoint` into a `G1Point`.  Returns `undefined` if
/// the sqrt operation fails.
export function decompressG1Point(
  compressedPoint: CompressedG1Point
): G1Point | undefined {
  let x = BigInt(compressedPoint);
  const ySign = (x >> 255n) & 1n;
  x &= (1n << 255n) - 1n;

  const x2: bigint = FQ.square(x);
  const x3: bigint = FQ.mul(x2, x);
  const x3PlusB: bigint = FQ.add(x3, BN254_G1_B);
  const y: bigint = FQ.sqrt(x3PlusB);
  if (!y) {
    return undefined;
  }

  const sign = y & 1n;
  const signedY: bigint = (ySign ^ sign) == 1n ? FQ.neg(y) : y;
  const g1Point: G1Point = [bigintToHex32(x), bigintToHex32(signedY)];
  return g1Point;
}

/// Compresses `g2Point` into two 32-byte words.
export function compressG2Point(g2Point: G2Point): CompressedG2Point {
  if (isIdentityG2(g2Point)) {
    return [bigintToHex32(0n), bigintToHex32(0n)];
  }
  const [x, y] = g2Point;
  const sign = BigInt(y[1]) & 1n;
  const x0 = BigInt(x[0]) | (sign << 255n);
  return [bigintToHex32(x0), bigintToHex32(BigInt(x[1]))];
}

/// Decompresses `compressedPoint` into a `G2Point`.  Returns `undefined` if
/// the sqrt operation fails.
export function decompressG2Point(
  compressedPoint: CompressedG2Point
): G2Point | undefined {
  const x = compressedPoint.map(BigInt);
  const ySign = (x[0] >> 255n) & 1n;
  x[0] &= (1n << 255n) - 1n;

  const x2: [bigint, bigint] = FQ2.square(x);
  const x3: [bigint, bigint] = FQ2.mul(x2, x);
  const x3PlusB: [bigint, bigint] = FQ2.add(x3, [BN254_G2_B0, BN254_G2_B1]);
  const y: [bigint, bigint] = FQ2.sqrt(x3PlusB);
  if (!y) {
    return undefined;
  }

  const sign = y[1] & 1n;
  const signedY: [bigint, bigint] = (ySign ^ sign) == 1n ? FQ2.neg(y) : y;
  const g2Point: G2Point = [
    [bigintToHex32(x[0]), bigintToHex32(x[1])],
    [bigintToHex32(signedY[0]), bigintToHex32(signedY[1])],
  ];
  return g2Point;
}
