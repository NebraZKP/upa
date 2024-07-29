import { ethers } from "hardhat";
import { CreateX, CreateX__factory } from "../typechain-types";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { create3DeploySalt } from "../src/tool/deploy";

describe.only("Compute guarded salt", () => {
  async function deploySaltTest(): Promise<CreateX> {
    const [signer] = await ethers.getSigners();
    const GuardedSaltTest = new CreateX__factory(signer);
    const guardedSaltTest = await GuardedSaltTest.deploy();
    await guardedSaltTest.waitForDeployment();
    return guardedSaltTest;
  }
  it("salt 1", async function () {
    const guardedSaltTest = await loadFixture(deploySaltTest);

    const createXAddress = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";
    const ownerAddress = "0xb463603469Bf31f189E3F6625baf8378880Df14e";
    const saltSuffix = ethers
      .keccak256(ethers.toUtf8Bytes(create3DeploySalt))
      .slice(2, 24);
    const salt = ownerAddress + "00" + saltSuffix;
    console.log("salt");
    console.log(salt);

    console.log("guarded salt");
    const guardedSalt = await guardedSaltTest._guardTest(salt, ownerAddress);
    console.log(guardedSalt);

    console.log("expected proxy address");
    const proxyAddress = await guardedSaltTest[
      "computeCreate3Address(bytes32,address)"
    ](guardedSalt, createXAddress);
    console.log(proxyAddress);
  });
});
