import { Groth16VerifyingKey, Groth16Proof } from "./groth16";
import { snarkjs } from ".";
import { keccak256, AbiCoder } from "ethers";
import { G1Point, G2Point } from "./ecc";
import { Logger } from "winston";
const ffjavascript = require("ffjavascript");

/// Interface for curve types in `ffjavascript`
interface Curve<PointType> {
  fromObject: (point: PointType) => Curve<PointType>;
}

/// Interface for the BN254 pairing engine in `ffjavascript`
interface BN254PairingEngine {
  G1: Curve<G1Point>;
  G2: Curve<G2Point>;
  /// Performs the pairing check.
  pairingEq: (...args: (Curve<G1Point> | Curve<G2Point>)[]) => Promise<boolean>;
}

// TODO: This can probably be imported from ffjavascript
const Bn254Modulus = BigInt(
  // eslint-disable-next-line
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

/// Groth16 verifier.
export class Groth16Verifier {
  private constructor(public bn254PairingEngine: BN254PairingEngine) {}

  /// Creates a new `Groth16Verifier`.
  public static async initialize(): Promise<Groth16Verifier> {
    const bn254PairingEngine = await ffjavascript.buildBn128();
    return new Groth16Verifier(bn254PairingEngine);
  }

  /// Performs a pairing check on the `pairs`.
  public async bn254PairingCheck(pairs: [G1Point, G2Point][]) {
    const preparedPairs = pairs.flatMap((pair) => [
      this.bn254PairingEngine.G1.fromObject(pair[0]),
      this.bn254PairingEngine.G2.fromObject(pair[1]),
    ]);
    return await this.bn254PairingEngine.pairingEq(...preparedPairs);
  }

  /// Verifies a groth16 proof without a commitment point.
  public async verifyGroth16ProofWithoutCommitment(
    vk: Groth16VerifyingKey,
    proof: Groth16Proof,
    inputs: (string | bigint)[],
    logger?: Logger
  ): Promise<boolean> {
    const snarkjsVk = vk.snarkjs();
    return await snarkjs.groth16.verify(
      snarkjsVk,
      inputs,
      proof.snarkjs(),
      logger
    );
  }

  /// Verifies a groth16 proof with a commitment point.
  public async verifyGroth16ProofWithCommitment(
    vk: Groth16VerifyingKey,
    proof: Groth16Proof,
    inputs: (string | bigint)[],
    logger?: Logger
  ): Promise<boolean> {
    const abiCoder = new AbiCoder();
    const mString = abiCoder.encode(["uint256[2]"], [proof.m[0]]);
    const newInput = BigInt(keccak256(mString)) % Bn254Modulus;
    const pokCheck = await this.bn254PairingCheck([
      [proof.m[0], vk.h1[0]],
      [proof.pok[0], vk.h2[0]],
    ]);
    const vkSnarkjs = new Groth16VerifyingKey(
      vk.alpha,
      vk.beta,
      vk.gamma,
      vk.delta,
      vk.s.concat([proof.m[0]]),
      [],
      []
    );
    const proofSnarkJs = new Groth16Proof(
      proof.pi_a,
      proof.pi_b,
      proof.pi_c,
      [],
      []
    );
    const pairingCheck = await this.verifyGroth16ProofWithoutCommitment(
      vkSnarkjs,
      proofSnarkJs,
      inputs.concat([newInput, 1n]),
      logger
    );
    return pokCheck && pairingCheck;
  }

  /// Verifies a groth16 proof, with or without a commitment point.
  public async verifyGroth16Proof(
    vk: Groth16VerifyingKey,
    proof: Groth16Proof,
    inputs: (string | bigint)[],
    logger?: Logger
  ): Promise<Groth16VerificationResult> {
    const numCommitmentPoints = vk.h1.length;
    const numInputs = inputs.length;
    if (numCommitmentPoints > 1) {
      // Too many commitment points. The local Groth16 verifier
      // returns this error when a Groth16 VK has h1.length >= 2.
      //
      // This error is unexpected for on-chain submissions because it is
      // checked in the function `registerVK` of the `UpaProofReceiver`
      // contract.
      return { result: false, error: "Too many commitment points" };
    }
    if (numCommitmentPoints !== vk.h2.length) {
      // Inconsistent VK. The local Groth16 verifier returns this
      // error when a Groth16 VK has h1.length != h2.length.
      //
      // This error is unexpected for on-chain submissions because it is
      // checked in the function `registerVK` of the `UpaProofReceiver`
      // contract.
      return { result: false, error: "Inconsistent VK" };
    }
    if (proof.m.length !== proof.pok.length) {
      // Inconsistent proof. The local Groth16 verifier returns this error
      // when a Groth16 proof has a commitment point but no Pedersen proof
      // of knowledge or viceversa.
      return { result: false, error: "Inconsistent proof" };
    }
    if (numCommitmentPoints !== proof.m.length) {
      // Proof inconsistent with VK. The local Groth16 verifier returns this
      // error when the proof has a commitment point but the VK doesn't have
      // a Pedersen VK or viceversa.
      return { result: false, error: "Proof inconsistent with VK" };
    }
    if (numInputs + 1 + numCommitmentPoints !== vk.s.length) {
      // Wrong number of public inputs. The local Groth16 verifier returns
      // this error when the number of public inputs is incompatible with
      // the VK.
      return { result: false, error: "Wrong number of public inputs" };
    }
    let result: boolean;
    if (numCommitmentPoints == 0) {
      result = await this.verifyGroth16ProofWithoutCommitment(
        vk,
        proof,
        inputs,
        logger
      );
    } else {
      result = await this.verifyGroth16ProofWithCommitment(
        vk,
        proof,
        inputs,
        logger
      );
    }
    if (!result) {
      // Invalid proof. The local Groth16 verifier returns this error
      // when the VK, proof and inputs are well-formed but the
      // verification doesn't pass.
      return { result, error: "Invalid proof" };
    } else {
      return { result };
    }
  }
}

/// Groth16 local verification result
export type Groth16VerificationResult = {
  result: boolean;
  error?: string;
};
