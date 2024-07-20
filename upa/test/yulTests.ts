import { ethers } from "hardhat";
import { expect } from "chai";
import { readFileSync } from "fs";
import { deployBinaryContract } from "../src/sdk/utils";
import * as fs from "fs";

describe("Yul Tests", () => {
  describe("Deploy test Yul contract", () => {
    it("read and deploy binary contracts", async function () {
      const [deployer] = await ethers.getSigners();
      const contract_hex =
        "0x" + fs.readFileSync("test/data/test.bin", "utf-8").trim();
      const yul_address = await deployBinaryContract(deployer, contract_hex);

      // Invoke via the YulTest contract.
      const YulTest = await ethers.getContractFactory("YulTest");
      const yulTest = await YulTest.deploy();

      // Expect to receive a single uint(19).
      const data = await yulTest.callYul.staticCall(yul_address, "0x01");
      expect(BigInt(data)).to.equal(19n);

      // Expect the yul code to revert
      await expect(yulTest.callYul.staticCall(yul_address, "0x")).reverted;
      await expect(yulTest.callYul(yul_address, "0x")).reverted;
    });
  });

  describe("Deploy verifier Yul contract", () => {
    it("read and deploy binary contracts", async function () {
      const [deployer] = await ethers.getSigners();
      const contract_hex =
        "0x" +
        fs.readFileSync("test/data/outer_2_2.verifier.bin", "utf-8").trim();
      const yul_address = await deployBinaryContract(deployer, contract_hex);

      // Load the test calldata
      const calldata = readFileSync("test/data/outer_2_2.proof.calldata");

      // Invoke via the YulTest contract.
      const YulTest = await ethers.getContractFactory("YulTest");
      const yulTest = await YulTest.deploy();
      await yulTest.callYul.staticCall(yul_address, calldata);

      // Invalid calldata
      await expect(yulTest.callYul.staticCall(yul_address, "0x")).reverted;
      await expect(yulTest.callYul(yul_address, "0x")).reverted;

      calldata[0] = 7;
      await expect(yulTest.callYul.staticCall(yul_address, calldata)).reverted;
      await expect(yulTest.callYul(yul_address, calldata)).reverted;
    });
  });
});
