import { GnarkProof, GnarkVerificationKey } from "./gnark";
import { SnarkJSProof, SnarkJSVKey } from "./snarkjs";
import {
  Groth16VKStruct,
  Groth16ProofStruct,
} from "../../typechain-types/contracts/IGroth16Verifier";
// eslint-disable-next-line
import { Groth16CompressedProofStruct } from "../../typechain-types/contracts/IUpaProofReceiver";
import { BigNumberish, toBeHex, keccak256, AbiCoder } from "ethers";
import assert from "assert";
import {
  G1Point,
  G2Point,
  CompressedG1Point,
  CompressedG2Point,
  toG1,
  toG2,
  snarkJSG1ToG1,
  snarkJSG2ToG2,
  gnarkG1ToG1,
  gnarkG2ToG2,
  reverseFq2Elements,
} from "./ecc";
import {
  compressG1Point,
  compressG2Point,
  decompressG1Point,
  decompressG2Point,
} from "./pointCompression";

/// The Groth16 VK and Proof structs.  These must match the form expected by the
/// smart contacts, and the prover.

/**
 * A Groth16 Verifying Key.  Serializable as JSON.
 *
 * @remarks
 *
 * All Fq2 elements are stored in the natural order `[a, b]` for elements `a +
 * b*u`, as output by snarkjs.zkey.exportVerificationKey.
 */
export class Groth16VerifyingKey {
  public readonly alpha: G1Point;
  public readonly beta: G2Point;
  public readonly gamma: G2Point;
  public readonly delta: G2Point;
  public readonly s: G1Point[];
  public readonly h1: G2Point[];
  public readonly h2: G2Point[];

  constructor(
    alpha: [BigNumberish, BigNumberish],
    beta: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    gamma: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    delta: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    s: [BigNumberish, BigNumberish][],
    h1: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]][],
    h2: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]][]
  ) {
    if (h1.length !== h2.length) {
      throw new Error("Invalid data: h1 and h2 length mismatch.");
    }
    if (h1.length > 1) {
      throw new Error("Invalid data: Multiple commitments are not supported");
    }
    this.alpha = toG1(alpha);
    this.beta = toG2(beta);
    this.gamma = toG2(gamma);
    this.delta = toG2(delta);
    this.s = s.map(toG1);
    this.h1 = h1.map(toG2);
    this.h2 = h2.map(toG2);
  }

  /**
   * Read from the EVM / Solidity-friendly format.
   *
   * @param sol A VerifyingKey in the EVM / Solidity-friendly format.
   * @returns A VerifyingKey
   */
  public static from_solidity(sol: Groth16VKStruct): Groth16VerifyingKey {
    return new Groth16VerifyingKey(
      sol.alpha,
      sol.beta,
      sol.gamma,
      sol.delta,
      sol.s,
      sol.h1,
      sol.h2
    );
  }

  /**
   * Read from JSON.
   *
   * @remarks
   *
   * No conversion should be necessary if the incoming object is the valid
   * JSON representation of this structure, but for safety, conversion from
   * BigNumberish is performed.
   *
   * @param json_obj The object read from JSON.
   * @returns A VerifyingKey.
   */
  public static from_json(json_obj: object): Groth16VerifyingKey {
    const obj = json_obj as Groth16VerifyingKey;
    return new Groth16VerifyingKey(
      obj.alpha,
      obj.beta,
      obj.gamma,
      obj.delta,
      obj.s,
      obj.h1,
      obj.h2
    );
  }

  /**
   * Convert a VerifyingKey from snarkjs format to UPA format.
   *
   * @example
   * ```ts
   * const vkSnarkjs = snarkjs.zkey.exportVerificationKey( ... );
   * const vk = VerifyingKey.from_snarkjs(vkSnarkjs);
   * ```
   *
   * @param snarkjs VerifyingKey as returned from
   * `snarkjs.exportVerificationKey`
   * @returns VerifyingKey
   */
  public static from_snarkjs(snarkjs: SnarkJSVKey): Groth16VerifyingKey {
    // SnarkJS does not support commitment points
    const empty: G2Point[] = [];
    return new Groth16VerifyingKey(
      snarkJSG1ToG1(snarkjs.vk_alpha_1),
      snarkJSG2ToG2(snarkjs.vk_beta_2),
      snarkJSG2ToG2(snarkjs.vk_gamma_2),
      snarkJSG2ToG2(snarkjs.vk_delta_2),
      snarkjs.IC.map(snarkJSG1ToG1),
      empty,
      empty
    );
  }

  /**
   * Convert a VerifyingKey from Gnark format to UPA format.
   *
   * @example
   * ```ts
   * const vkGnark = loadGnarkVK( ... );
   * const hasCommitment = true;
   * const vk = VerifyingKey.from_gnark(vkGnark, hasCommitment);
   * ```
   *
   * @param gnark VerifyingKey as serialized by Gnark, e.g.
   * `gnarkJSON, err = json.Marshal(vk)`
   * @param hasCommitment Flag indicating whether original Gnark
   * circuit uses the optional LegoSnark commitment.
   * @returns VerifyingKey
   */
  public static from_gnark(
    gnark: GnarkVerificationKey,
    hasCommitment: boolean
  ): Groth16VerifyingKey {
    // We do not support commitments to public input values, so
    // we expect gnark.PublicAndCommitmentCommitted = [[]]
    assert(
      gnark.PublicAndCommitmentCommitted.length == Number(hasCommitment),
      "Invalid PublicAndCommitmentCommitted"
    );
    if (hasCommitment) {
      assert(
        gnark.PublicAndCommitmentCommitted[0].length == 0,
        "Invalid PublicAndCommitmentCommitted"
      );
    }
    const h1 = [];
    const h2 = [];
    if (hasCommitment) {
      h1.push(gnarkG2ToG2(gnark.CommitmentKey.G));
      h2.push(gnarkG2ToG2(gnark.CommitmentKey.GRootSigmaNeg));
    }
    return new Groth16VerifyingKey(
      gnarkG1ToG1(gnark.G1.Alpha),
      gnarkG2ToG2(gnark.G2.Beta),
      gnarkG2ToG2(gnark.G2.Gamma),
      gnarkG2ToG2(gnark.G2.Delta),
      gnark.G1.K.map(gnarkG1ToG1),
      h1,
      h2
    );
  }

  /**
   * Convert to EVM / Solidity-friendly format.
   *
   * @remarks
   *
   * Commonly, VKs are passed to the EVM with the Fq2 components in "reversed"
   * order.  Since the UPA does not generally use the VK on-chain, Fq2 appear
   * in natural order.
   *
   * @returns The VerifyingKey in EVM / Solidity friendly format, as expected
   * by the UPA contracts.
   */
  public solidity(): Groth16VKStruct {
    // No conversion necessary
    return this;
  }

  /**
   * Convert to snarkjs
   *
   * @returns
   */
  public snarkjs(): SnarkJSVKey {
    if (this.h1.length || this.h2.length) {
      throw new Error("Attempted to convert VK with commitment to SnarkJS");
    }
    return {
      IC: this.s.map((x) => [x[0], x[1], "1"]),
      nPublic: this.s.length - 1,
      curve: "bn128",
      protocol: "groth",
      vk_alpha_1: [...this.alpha, "1"],
      vk_beta_2: [...this.beta, ["1", "0"]],
      vk_gamma_2: [...this.gamma, ["1", "0"]],
      vk_delta_2: [...this.delta, ["1", "0"]],
    };
  }
}

// TODO: Proof should really have different attributes, instead of matching
// SnarkJSProof, since the representations are not 100% compatible.

/**
 * A proof in the UPA format.  Holds Fq2 elements `a + b*u` in the natural
 * format [a, b].
 *
 * @remarks
 *
 * These fields match a subset of the those returned from snarkjs.fullProve.
 * However, `Proof.from_snarkjs` should be used to create a `Proof` from the
 * output of snarkjs.fullProve.
 *
 * The on-chain version of this struct stores Fq2 elements in the "reversed"
 * or "evm" order, that is `[b, a]` for element `a + b*u`.  This is intended
 * to be useful during development, since this is compatible with most
 * on-chain Groth1 verifiers.
 */
export class Groth16Proof {
  public pi_a: G1Point;
  public pi_b: G2Point;
  public pi_c: G1Point;
  public m: G1Point[];
  public pok: G1Point[];

  /**
   * Assumes that values passed in are in the "natural" order (i.e. Fq2
   * components NOT swapped) as output by snarkjs.fullProve.
   */
  constructor(
    pi_a: [BigNumberish, BigNumberish],
    pi_b: [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    pi_c: [BigNumberish, BigNumberish],
    m: [BigNumberish, BigNumberish][],
    pok: [BigNumberish, BigNumberish][]
  ) {
    if (m.length !== pok.length) {
      throw new Error("Invalid data: m and pok length mismatch.");
    }
    if (m.length > 1) {
      throw new Error("Invalid data: Multiple commitments are not supported");
    }
    this.pi_a = [toBeHex(pi_a[0], 32), toBeHex(pi_a[1], 32)];
    this.pi_b = [
      [toBeHex(pi_b[0][0], 32), toBeHex(pi_b[0][1], 32)],
      [toBeHex(pi_b[1][0], 32), toBeHex(pi_b[1][1], 32)],
    ];
    this.pi_c = [toBeHex(pi_c[0], 32), toBeHex(pi_c[1], 32)];
    this.m = m.map((pt) => [toBeHex(pt[0], 32), toBeHex(pt[1], 32)]);
    this.pok = pok.map((pt) => [toBeHex(pt[0], 32), toBeHex(pt[1], 32)]);
  }

  public static from_solidity(sol: Groth16ProofStruct): Groth16Proof {
    return new Groth16Proof(
      sol.pA,
      reverseFq2Elements(sol.pB),
      sol.pC,
      sol.m,
      sol.pok
    );
  }

  public static from_json(json_obj: object): Groth16Proof {
    const obj = json_obj as Groth16Proof;
    return new Groth16Proof(obj.pi_a, obj.pi_b, obj.pi_c, obj.m, obj.pok);
  }

  /**
   * Create a `Proof` from a snarkjs proof.
   *
   * @example
   *
   * ```ts
   *     // Generate a proof with snarkjs.  Convert to UPA format.
   *     const proofData = await snarkjs.groth16.fullProve(
   *       circuitInputs,
   *       circuitWasm,
   *       circuitZkey
   *     );
   *     const upaProof = Proof.from_snarkjs(proofData.proof);
   *     const upaInstance: string[] = proofData.publicSignals;
   * ```
   */
  public static from_snarkjs(json_obj: SnarkJSProof): Groth16Proof {
    // SnarkJS does not support commitment points
    const empty: G1Point[] = [];
    return new Groth16Proof(
      snarkJSG1ToG1(json_obj.pi_a),
      snarkJSG2ToG2(json_obj.pi_b),
      snarkJSG1ToG1(json_obj.pi_c),
      empty,
      empty
    );
  }

  /**
   * Create a `Proof` from a Gnark proof.
   */
  public static from_gnark(json_obj: GnarkProof): Groth16Proof {
    const m = json_obj.Commitments.map(gnarkG1ToG1);
    // Detect whether this proof includes a Pedersen commitment
    const pok = [];
    if (m.length == 0) {
      // When no commitment is used the PoK should be trivial
      assert.equal(
        json_obj.CommitmentPok.X,
        "0",
        "Invalid proof data: Unexpected CommitmentPoK.X"
      );
      assert.equal(
        json_obj.CommitmentPok.Y,
        "0",
        "Invalid proof data: Unexpected CommitmentPoK.Y"
      );
    } else if (m.length > 1) {
      throw new Error(
        "Invalid proof data: Multiple commitments not supported."
      );
    } else {
      pok.push(gnarkG1ToG1(json_obj.CommitmentPok));
    }
    return new Groth16Proof(
      gnarkG1ToG1(json_obj.Ar),
      gnarkG2ToG2(json_obj.Bs),
      gnarkG1ToG1(json_obj.Krs),
      m,
      pok
    );
  }

  public solidity(): Groth16ProofStruct {
    return {
      pA: this.pi_a,
      pB: reverseFq2Elements(this.pi_b),
      pC: this.pi_c,
      m: this.m,
      pok: this.pok,
    };
  }

  public snarkjs(): SnarkJSProof {
    return {
      pi_a: [...this.pi_a, "1"],
      pi_b: [...this.pi_b, ["1", "0"]],
      pi_c: [...this.pi_c, "1"],
      curve: "bn128",
      protocol: "groth",
    };
  }

  public compress(): CompressedGroth16Proof {
    const pi_a = compressG1Point(this.pi_a);
    const pi_b = compressG2Point(this.pi_b);
    const pi_c = compressG1Point(this.pi_c);
    const m = this.m.map(compressG1Point);
    const pok = this.pok.map(compressG1Point);
    return new CompressedGroth16Proof(pi_a, pi_b, pi_c, m, pok);
  }
}

export class CompressedGroth16Proof {
  public pi_a: CompressedG1Point;
  public pi_b: CompressedG2Point;
  public pi_c: CompressedG1Point;
  public m: CompressedG1Point[];
  public pok: CompressedG1Point[];

  constructor(
    pi_a: BigNumberish,
    pi_b: [BigNumberish, BigNumberish],
    pi_c: BigNumberish,
    m: BigNumberish[],
    pok: BigNumberish[]
  ) {
    if (m.length !== pok.length) {
      throw new Error("Invalid data: m and pok length mismatch.");
    }
    if (m.length > 1) {
      throw new Error("Invalid data: Multiple commitments are not supported");
    }
    this.pi_a = toBeHex(pi_a, 32);
    this.pi_b = [toBeHex(pi_b[0], 32), toBeHex(pi_b[1], 32)];
    this.pi_c = toBeHex(pi_c, 32);
    this.m = m.map((pt) => toBeHex(pt, 32));
    this.pok = pok.map((pt) => toBeHex(pt, 32));
  }

  public static from_solidity(
    sol: Groth16CompressedProofStruct
  ): CompressedGroth16Proof {
    return new CompressedGroth16Proof(sol.pA, sol.pB, sol.pC, sol.m, sol.pok);
  }

  public decompress(): Groth16Proof {
    const pi_a = decompressG1Point(this.pi_a);
    const pi_b = decompressG2Point(this.pi_b);
    const pi_c = decompressG1Point(this.pi_c);
    const m = this.m.map(decompressG1Point);
    const pok = this.pok.map(decompressG1Point);
    return new Groth16Proof(pi_a, pi_b, pi_c, m, pok);
  }

  public solidity(): Groth16CompressedProofStruct {
    return {
      pA: this.pi_a,
      pB: this.pi_b,
      pC: this.pi_c,
      m: this.m,
      pok: this.pok,
    };
  }

  public proofDigest(): string {
    const abiCoder = new AbiCoder();
    const proofString = abiCoder.encode(
      [
        "tuple(uint256 pA,uint256[2] pB,uint256 pC," +
          "uint256[] m,uint256[] pok)",
      ],
      [this.solidity()]
    );
    return keccak256(proofString);
  }
}
