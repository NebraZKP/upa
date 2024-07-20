/// Declarations for gnark types
import { BigNumberish } from "ethers";

export type GnarkG1Point = { X: BigNumberish; Y: BigNumberish };

export type GnarkFq2 = { A0: BigNumberish; A1: BigNumberish };

export type GnarkG2Point = {
  X: GnarkFq2;
  Y: GnarkFq2;
};

export type GnarkVKG1Points = {
  Alpha: GnarkG1Point;
  /// Unused: this is part of Gnark's VK but not ours
  Beta: GnarkG1Point;
  /// Unused: this is part of Gnark's VK but not ours
  Delta: GnarkG1Point;
  K: GnarkG1Point[];
};

export type GnarkVKG2Points = {
  Beta: GnarkG2Point;
  Delta: GnarkG2Point;
  Gamma: GnarkG2Point;
};

export type GnarkVKCommitmentKey = {
  G: GnarkG2Point;
  GRootSigmaNeg: GnarkG2Point;
};

///
export type GnarkVerificationKey = {
  G1: GnarkVKG1Points;
  G2: GnarkVKG2Points;
  /// NB: Non-empty even for Gnark circuits that don't use commitment
  CommitmentKey: GnarkVKCommitmentKey;
  PublicAndCommitmentCommitted: BigNumberish[][];
};

///
export type GnarkProof = {
  Ar: GnarkG1Point;
  Krs: GnarkG1Point;
  Bs: GnarkG2Point;
  Commitments: GnarkG1Point[];
  CommitmentPok: GnarkG1Point;
};

export type GnarkInputs = BigNumberish[];

const mUncompressed: number = 0b00 << 6; // 00000000

// RawBytes returns the binary representation of p (stores X and Y coordinates)
// see Bytes() for a compressed representation
export function rawBytes(p: GnarkG1Point): Uint8Array {
  const res = new Uint8Array(64);

  const X = BigInt(p.X);
  const Y = BigInt(p.Y);

  // Check if p is the infinity point
  if (BigInt(p.X) == 0n && BigInt(p.Y) == 0n) {
    res[0] = mUncompressed;
    return res;
  }

  // Not compressed
  // We store the Y coordinate
  putElement(res.subarray(32, 32 + 32), Y);

  // We store X and mask the most significant word with our metadata mask
  putElement(res.subarray(0, 0 + 32), X);

  res[0] |= mUncompressed;
  // assert mUncompressed === 0 ?

  return res;
}

export function rawBytesSolidity(p: GnarkG1Point): BigNumberish[] {
  const rawBytesResult = rawBytes(p);

  const bigIntArray: BigNumberish[] = [];

  // Assuming each element in the Uint8Array represents a byte
  for (let i = 0; i < rawBytesResult.length; i++) {
    bigIntArray.push(BigInt(rawBytesResult[i]));
  }

  return bigIntArray;
}

function putElement(b: Uint8Array, e: bigint): void {
  for (let i = 0; i < 32; i++) {
    const offset = 31 - i;
    b[offset] = Number((e >> BigInt(8 * i)) & BigInt(0xff));
  }
}
