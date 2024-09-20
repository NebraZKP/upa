// Convert SP1 Proof Fixture Format to UPA File Format
// Use UPA SDK to Verify the Groth16 Proof

import { ethers } from "hardhat";
import { assert } from "chai";
import { Groth16Verifier__factory } from "../typechain-types";
import { loadSP1ProofFixture } from "../src/tool/config";
import { sp1 } from "../src/sdk";

describe("SP1 Verifier Test", () => {
  it("verifies Groth16 proof parsed from SP1 proof fixture", async function () {
    const [deployer] = await ethers.getSigners();
    const groth16VerifierFactory = new Groth16Verifier__factory(deployer);
    const groth16Verifier = await groth16VerifierFactory.deploy();
    await groth16Verifier.waitForDeployment();

    const sp1ProofFixture = loadSP1ProofFixture(
      "test/data/sp1/v1.2.0_fixture.json"
    );

    const upaVkProofInputs = sp1.convertSp1ProofFixture(
      sp1ProofFixture,
      "v1.2.0"
    );

    const upaVk = upaVkProofInputs.vk;
    const upaProof = upaVkProofInputs.proof;
    const upaInputs = upaVkProofInputs.inputs;

    const isValid = await groth16Verifier.verifyProof(
      upaProof.solidity(),
      upaInputs,
      upaVk.solidity()
    );

    assert(isValid, "SP1 Groth16 proof verification failed");
  });
});
