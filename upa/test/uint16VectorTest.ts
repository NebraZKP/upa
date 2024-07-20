import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ethers } from "hardhat";
import { expect } from "chai";
import {
  Uint16VectorLibTest,
  Uint16VectorLibTest__factory,
} from "../typechain-types";

describe("Uint16VectorTest", () => {
  async function deploy(): Promise<Uint16VectorLibTest> {
    const [owner] = await ethers.getSigners();
    const Uint16VectorLibTestFactory: Uint16VectorLibTest__factory =
      await ethers.getContractFactory("Uint16VectorLibTest", { signer: owner });
    return await Uint16VectorLibTestFactory.deploy();
  }

  describe("Uint16Vector", () => {
    it("correctly sets and resets", async function () {
      const totalNumEntries = 514n;
      const bitVectorTest = await loadFixture(deploy);

      // Set every 3rd entry
      for (let i = totalNumEntries - 1n; i >= 0n; --i) {
        if (i % 3n == 0n) {
          await bitVectorTest.setUint16(i, i);
        }
      }

      // Check the values that have been set
      for (let i = 0n; i < totalNumEntries; ++i) {
        const expectedValue = i % 3n == 0n ? i : 0;
        const value = await bitVectorTest.getUint16(i);
        expect(value).to.equal(expectedValue);
      }

      // Overwrite every 3rd entry
      for (let i = totalNumEntries - 1n; i >= 0n; --i) {
        if (i % 3n == 0n) {
          await bitVectorTest.setUint16(i, i + 2n);
        }
      }

      // Check the values that have been overwritten
      for (let i = 0n; i < totalNumEntries; ++i) {
        const expectedValue = i % 3n == 0n ? i + 2n : 0n;
        const value = await bitVectorTest.getUint16(i);
        expect(value).to.equal(expectedValue);
      }
    });
  });
});
