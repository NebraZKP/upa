import { expect } from "chai";
const snarkjs = require("snarkjs");
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
// eslint-disable-next-line
import { DemoApp__factory } from "../typechain-types/factories/contracts/DemoApp__factory";
import { TransactionReceipt } from "ethers";
import { Groth16Proof, Groth16VerifyingKey } from "@nebrazkp/upa/sdk";
import * as fs from "fs";
import { generateRandomProofInputs } from "../src/utils";

describe("DemoApp contract", function () {
  // We define a fixture to reuse the same setup in every test. We use
  // loadFixture to run this setup once, snapshot that state, and reset Hardhat
  // Network to that snapshot in every test.
  async function deployDemoAppFixture() {
    const [owner] = await ethers.getSigners();

    const demoAppFactory = new DemoApp__factory(owner);
    // Fake UPA address. These tests don't use the UPA component.
    const demoApp = await demoAppFactory.deploy(
      "0x8ba1f109551bd432803012645ac136ddd64dba72",
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );

    return { demoApp, owner };
  }

  describe("Deployment", function () {
    it("Should start with 0 proofs verified", async function () {
      const { demoApp } = await loadFixture(deployDemoAppFixture);

      expect(await demoApp.proofsVerified()).to.equal(0);
    });
  });

  describe("Verify proofs with circom-generated verifier", function () {
    it("UPA Proof and VK should verify with snarkjs", async function () {
      // TODO: this should really be tested in the UPA dir, but
      // it relies on snarkjs, which is a dependency of demo-app.

      // Get snarkjs vkey and proof data.
      const { vkeySnarkjs, proofDataSnarkjs } = await (async () => {
        const vkeySnarkjs = JSON.parse(
          fs.readFileSync("circuits/snarkjs_verification_key.json", "ascii")
        );

        const proofDataSnarkjs = await snarkjs.groth16.fullProve(
          generateRandomProofInputs(),
          "circuits/circuit_js/circuit.wasm",
          "circuits/circuit.zkey"
        );

        return { vkeySnarkjs, proofDataSnarkjs };
      })();

      console.log("proofData: " + JSON.stringify(proofDataSnarkjs));
      console.log("vkey: " + JSON.stringify(vkeySnarkjs));

      // UPA versions
      const vkey = Groth16VerifyingKey.from_snarkjs(vkeySnarkjs);
      const proof = Groth16Proof.from_snarkjs(proofDataSnarkjs.proof);

      // Convert back to snarkjs data and verify.
      const verified = await snarkjs.groth16.verify(
        vkey.snarkjs(),
        proofDataSnarkjs.publicSignals,
        proof.snarkjs()
      );
      expect(verified).is.true;
    });

    it("`proofsVerified` increments for valid solution", async function () {
      const { demoApp } = await loadFixture(deployDemoAppFixture);

      console.log(
        "DemoApp contract deployed to address:",
        await demoApp.getAddress()
      );

      const tx_completed: Promise<TransactionReceipt | null>[] = [];

      for (let i = 0; i < 10; i++) {
        const proofData = await snarkjs.groth16.fullProve(
          generateRandomProofInputs(),
          `circuits/circuit_js/circuit.wasm`,
          `circuits/circuit.zkey`
        );

        const proof = Groth16Proof.from_snarkjs(proofData.proof);
        const proofSolidity = proof.solidity();

        const verifyProofResult = await demoApp.verifyProof(
          proofSolidity.pA,
          proofSolidity.pB,
          proofSolidity.pC,
          proofData.publicSignals
        );

        expect(verifyProofResult).is.true;

        const verifyDemoAppProofTx = demoApp
          .submitSolutionDirect(
            proofSolidity.pA,
            proofSolidity.pB,
            proofSolidity.pC,
            proofData.publicSignals
          )
          .then((tx) => tx.wait());

        tx_completed.push(verifyDemoAppProofTx);
      }

      await Promise.all(tx_completed);
      const proofsVerified = await demoApp.proofsVerified();
      console.log("proofsVerified:", proofsVerified);
      expect(proofsVerified).to.equal(tx_completed.length);
    });

    it("Contract reverts duplicate solution submission", async function () {
      const { demoApp } = await loadFixture(deployDemoAppFixture);

      console.log(
        "DemoApp contract deployed to address:",
        await demoApp.getAddress()
      );

      const c = 3n;
      const d = 3n;
      const a = c + 1n;
      const b = d + 1n;
      const e = c;
      const f = d + 1n;

      const proofData = await snarkjs.groth16.fullProve(
        { a, b, c, d, e, f },
        `circuits/circuit_js/circuit.wasm`,
        `circuits/circuit.zkey`
      );

      const proof = Groth16Proof.from_snarkjs(proofData.proof);
      const proofSolidity = proof.solidity();

      const verifyProofResult = await demoApp.verifyProof(
        proofSolidity.pA,
        proofSolidity.pB,
        proofSolidity.pC,
        proofData.publicSignals
      );

      expect(verifyProofResult).is.true;

      await demoApp
        .submitSolutionDirect(
          proofSolidity.pA,
          proofSolidity.pB,
          proofSolidity.pC,
          proofData.publicSignals
        )
        .then((tx) => tx.wait());

      // Duplicate submission should revert.
      await expect(
        demoApp.submitSolutionDirect(
          proofSolidity.pA,
          proofSolidity.pB,
          proofSolidity.pC,
          proofData.publicSignals
        )
      ).to.be.revertedWith("Solution already submitted");
    });
  });
});
