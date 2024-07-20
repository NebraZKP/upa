import { ethers } from "hardhat";
import { expect } from "chai";
import { Groth16Verifier__factory } from "../typechain-types";
import {
  loadAppVK,
  loadSingleProofFileAsCircuitIdProofAndInputs,
} from "../src/tool/config";

describe("Groth16 Verifier Tests", () => {
  it("verify groth16 proof", async function () {
    const [deployer] = await ethers.getSigners();
    const groth16VerifierFactory = new Groth16Verifier__factory(deployer);
    const groth16Verifier = await groth16VerifierFactory.deploy();
    await groth16Verifier.waitForDeployment();
    // It should verify valid proofs for a vk
    const vkFile = "../circuits/src/tests/data/vk.json";
    const proofAndInputsFile = "../circuits/src/tests/data/proof1.json";
    const vk = loadAppVK(vkFile);
    const { proof, inputs } =
      loadSingleProofFileAsCircuitIdProofAndInputs(proofAndInputsFile);
    const isValid = await groth16Verifier.verifyProof(
      proof.solidity(),
      inputs,
      vk
    );
    expect(isValid).true;
    // If we change one of the public inputs, verification should fail
    const wrongInputs = inputs.map(BigInt);
    wrongInputs[0] = BigInt(inputs[0]) + 1n;
    const isValidWrongInputs = await groth16Verifier.verifyProof(
      proof.solidity(),
      wrongInputs,
      vk
    );
    expect(isValidWrongInputs).false;
    // If we input invalid data (e.g. a proof with an invalid G1 point)
    // the transaction will be rejected
    const wrongProof = proof;
    wrongProof.pi_a[0] = String(BigInt(proof.pi_a[0]) + 1n);
    await expect(groth16Verifier.verifyProof(wrongProof.solidity(), inputs, vk))
      .to.be.reverted;
  });
});
