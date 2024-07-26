// UPA tests
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { upgradeVerifierContract } from "../src/tool/upgrade";
import {
  TestUpgradedUpaVerifier__factory,
  UpaVerifier__factory,
} from "../typechain-types";
import { testUpaInstanceFromDescriptor } from "../src/sdk/upa";
import { assert } from "console";
import { deployAndUpgradeUpa, deployUpaWithVerifier } from "./upaTests";
import { versionUintToString } from "../src/sdk/utils";
import * as pkg from "../package.json";

describe("UPA Upgrade", async () => {
  it("Non-owners cannot upgrade", async function () {
    const { upaDesc, worker } = await loadFixture(deployUpaWithVerifier);
    const testUpaVerifierFactory = new TestUpgradedUpaVerifier__factory(worker);

    // TODO: Couldn't make `expect(...).to.be.rejected` fail in a simple
    // non-error case, so checking this manually.

    // Upgrade should throw an error because a non-owner is attempting to
    // upgrade.
    let threw = 0;
    await upgradeVerifierContract(
      upaDesc,
      testUpaVerifierFactory,
      0 /*maxRetries*/,
      false /*prepare*/
    ).catch(() => {
      threw = 1;
    });
    expect(threw).eql(1);
  });

  it("New function and storage after upgrade", async function () {
    const { upaDesc, owner } = await loadFixture(deployUpaWithVerifier);

    // Upgrade the contract
    const testUpaVerifierFactory = new TestUpgradedUpaVerifier__factory(owner);
    await upgradeVerifierContract(
      upaDesc,
      testUpaVerifierFactory,
      3 /*maxRetries*/,
      false /*prepare*/
    );
    const { verifier } = testUpaInstanceFromDescriptor(upaDesc, owner);

    // Query the new storage variable
    assert((await verifier.testVar()) == false);

    // Set the new storage variable
    verifier.setTestVar(true);
    assert((await verifier.testVar()) == true);

    // Check new function returns the right constant.
    assert((await verifier.testNumber()) == 123456n);
  });

  it("deploy/upgrade versioning", async () => {
    const { upa, upaDesc, owner } = await loadFixture(deployAndUpgradeUpa);
    const { verifier } = upa;
    let versionString = versionUintToString(await verifier.version());
    expect(versionString).eql(pkg.version);

    const newVersionNum = 12345n;
    await verifier.setVersion(newVersionNum);
    expect(await verifier.version()).eql(newVersionNum);

    // Upgrade version defaults to package version
    const newUpaVerifierFactory = new UpaVerifier__factory(owner);
    await upgradeVerifierContract(upaDesc, newUpaVerifierFactory, 0);
    versionString = versionUintToString(await verifier.version());
    expect(versionString).eql(pkg.version);

    // Upgrade with a specified version string
    const newVersionString = "12.34.56";
    await upgradeVerifierContract(
      upaDesc,
      newUpaVerifierFactory,
      0,
      newVersionString
    );
    versionString = versionUintToString(await verifier.version());
    expect(versionString).eql(newVersionString);
  });
});
