import { ethers } from "hardhat";
import { assert, expect } from "chai";
import { Groth16Verifier__factory } from "../typechain-types";
import {
  loadGnarkInputs,
  loadGnarkProof,
  loadGnarkVK,
} from "../src/tool/config";
import { application } from "../src/sdk";

describe("Gnark Verifier Tests", () => {
  const gnarkVkNoCommFile =
    "../circuits/src/tests/data/gnark/no_commitment.vk.json";
  const gnarkProofNoCommFile =
    "../circuits/src/tests/data/gnark/no_commitment.proof.json";
  const gnarkInputsNoCommFile =
    "../circuits/src/tests/data/gnark/no_commitment.inputs.json";
  const gnarkVkPrivCommFile =
    "../circuits/src/tests/data/gnark/private_commitment.vk.json";
  const gnarkProofPrivCommFile =
    "../circuits/src/tests/data/gnark/private_commitment.proof.json";
  const gnarkInputsPrivCommFile =
    "../circuits/src/tests/data/gnark/private_commitment.inputs.json";
  const gnarkVkPubCommFile =
    "../circuits/src/tests/data/gnark/invalid/public_commitment.vk.json";
  const wrongHashVkFile =
    // eslint-disable-next-line
    "../circuits/src/tests/data/gnark/invalid/private_commitment_wrong_hash.vk.json";
  const wrongHashProofFile =
    // eslint-disable-next-line
    "../circuits/src/tests/data/gnark/invalid/private_commitment_wrong_hash.proof.json";
  const wrongHashInputsFile =
    // eslint-disable-next-line
    "../circuits/src/tests/data/gnark/invalid/private_commitment_wrong_hash.inputs.json";

  it("verifies gnark proofs", async function () {
    const [deployer] = await ethers.getSigners();
    const groth16VerifierFactory = new Groth16Verifier__factory(deployer);
    const gnarkVerifier = await groth16VerifierFactory.deploy();
    await gnarkVerifier.waitForDeployment();

    async function loadAndVerify(
      vk: string,
      hasCommitment: boolean,
      proof: string,
      inputs: string
    ): Promise<boolean> {
      const gnarkVK = loadGnarkVK(vk);
      const gnarkProof = loadGnarkProof(proof);
      const gnarkInputs = loadGnarkInputs(inputs);

      return gnarkVerifier.verifyProof(
        application.Groth16Proof.from_gnark(gnarkProof).solidity(),
        gnarkInputs,
        application.Groth16VerifyingKey.from_gnark(
          gnarkVK,
          hasCommitment
        ).solidity()
      );
    }

    assert(
      await loadAndVerify(
        gnarkVkNoCommFile,
        false,
        gnarkProofNoCommFile,
        gnarkInputsNoCommFile
      ),
      "No commitment proof should be valid"
    );
    assert(
      await loadAndVerify(
        gnarkVkPrivCommFile,
        true,
        gnarkProofPrivCommFile,
        gnarkInputsPrivCommFile
      ),
      "Private commitment proof should be valid"
    );
    // This proof was produced using Sha256 as the
    // hash to field function, so our contract does
    // not recognize it as valid.
    assert(
      !(await loadAndVerify(
        wrongHashVkFile,
        true,
        wrongHashProofFile,
        wrongHashInputsFile
      )),
      "Wrong hash function proof should be invalid"
    );
  });

  it("Cant deserialize VK w public input commitment", async function () {
    // This VK is for a circuit with Pedersen commitment to
    // public input values, so there should be a deserialization error.
    expect(() => {
      const gnarkVK = loadGnarkVK(gnarkVkPubCommFile);
      return application.Groth16VerifyingKey.from_gnark(gnarkVK, true);
    }).to.throw(Error, "Invalid PublicAndCommitmentCommitted");
  });
});
