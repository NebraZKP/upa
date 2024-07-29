import { ethers } from "hardhat";
import {
  ComputeCreateXDeployAddress,
  ComputeCreateXDeployAddress__factory,
} from "../typechain-types";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { computeCreateXDeploySalt, UPA_DEPLOY_SALT } from "../src/tool/deploy";
import { expect } from "chai";

describe("Salt and Create3 tests", () => {
  async function deploySaltTest(): Promise<ComputeCreateXDeployAddress> {
    const [signer] = await ethers.getSigners();
    const ComputeCreateXDeployAddress =
      new ComputeCreateXDeployAddress__factory(signer);
    const guardedSaltTest = await ComputeCreateXDeployAddress.deploy();
    await guardedSaltTest.waitForDeployment();
    return guardedSaltTest;
  }
  it("Compute proxy address", async function () {
    const guardedSaltTest = await loadFixture(deploySaltTest);

    // Information matching the UPA deployment transaction
    // 0xa8626318b76b71cd21cdfb93ef67c9571d94e01383e852a3eb6dc5dc6188808e
    const expectedProxyAddress = "0x3B946743DEB7B6C97F05B7a31B23562448047E3E";
    const expectedGuardedSalt =
      "0xf1ec3d646b482296c87d97fdb8ff60c5a3e8c5e84c8fa5fecfd2c33a19dc0428";
    const createXAddress = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";
    const ownerAddress = "0xb463603469Bf31f189E3F6625baf8378880Df14e";

    const createXDeploySalt = computeCreateXDeploySalt(UPA_DEPLOY_SALT);
    console.log("createXDeploySalt");
    console.log(createXDeploySalt);

    console.log("Guarded salt");
    const guardedSalt = await guardedSaltTest._guard(
      createXDeploySalt,
      ownerAddress
    );
    console.log(guardedSalt);
    expect(guardedSalt).eql(expectedGuardedSalt);

    console.log("Expected Create3 proxy address");
    const proxyAddress = await guardedSaltTest.computeCreate3Address(
      guardedSalt,
      createXAddress
    );
    console.log(proxyAddress);
    expect(proxyAddress).eql(expectedProxyAddress);
  });
});
