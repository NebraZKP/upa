import assert from "assert";
import { Groth16VerifyingKey, Groth16Proof } from "./groth16";
import { bytes32IsWellFormed, readBytes32 } from "./utils";
4;

export { Groth16VerifyingKey, Groth16Proof };

/// Dummy proof ID
export const DUMMY_PROOF_ID =
  "0x84636c7b9793a9833ef7ca3e1c118d7d21dadb97ef7bf1fbfd549c10bca3553f";
/// Dummy submission ID, which is equal to keccak256(DUMMY_PROOF_ID).
export const DUMMY_SUBMISSION_ID =
  "0xd567a437cec381611ef7244fc6b112d760e3e4e3bc8629468b5e4a57c2fb1402";
/// Dummy proof circuit ID
export const DUMMY_PROOF_CIRCUIT_ID =
  "0xed5ef176f0a27744b95dcdb7dfa467b32ab4a9d640e202eb8c92f9880b31e737";

export class AppVkProofInputs<VK = Groth16VerifyingKey, PROOF = Groth16Proof> {
  constructor(
    public readonly vk: VK,
    public readonly proof: PROOF,
    public readonly inputs: bigint[]
  ) {}

  public static from_json<VK = Groth16VerifyingKey, PROOF = Groth16Proof>(
    o: object,
    vk_from_json: (o: object) => VK,
    proof_from_json: (o: object) => PROOF
  ): AppVkProofInputs<VK, PROOF> {
    const json = o as AppVkProofInputs;
    assert(typeof json.vk === "object");
    assert(typeof json.proof === "object");
    assert(typeof json.inputs === "object");
    assert(json.inputs instanceof Array);
    return new AppVkProofInputs(
      vk_from_json(json.vk),
      proof_from_json(json.proof),
      json.inputs.map(BigInt)
    );
  }
}

export class CircuitIdProofAndInputs {
  constructor(
    public readonly circuitId: string,
    public readonly proof: Groth16Proof,
    public readonly inputs: bigint[]
  ) {
    assert(bytes32IsWellFormed(circuitId));
  }

  public static from_json(o: object): CircuitIdProofAndInputs {
    const json = o as CircuitIdProofAndInputs;
    assert(typeof json.circuitId === "string");
    assert(typeof json.proof === "object");
    assert(typeof json.inputs === "object");
    return new CircuitIdProofAndInputs(
      readBytes32(json.circuitId),
      Groth16Proof.from_json(json.proof),
      json.inputs.map(BigInt)
    );
  }
}

/**
 * The JSON format of a single proof + inputs to be submitted to the UPA
 * system.
 *
 * @remarks
 *
 * Objects of this form serialized to JSON can be used with the `upa
 * submit-proof` command.
 */
export class ProofAndInputs {
  public constructor(
    public readonly proof: Groth16Proof,
    public readonly inputs: bigint[]
  ) {}

  public static from_json(o: object): ProofAndInputs {
    const json = o as { proof: object; inputs: string[] };
    assert(typeof json.proof === "object");
    assert(typeof json.inputs === "object");
    return new ProofAndInputs(
      Groth16Proof.from_json(json.proof),
      json.inputs.map(BigInt)
    );
  }
}
