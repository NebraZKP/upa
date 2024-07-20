import {
  compressG1Point,
  compressG2Point,
  decompressG1Point,
  decompressG2Point,
} from "../src/sdk/pointCompression";
import { loadAppVK } from "../src/tool/config";
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { reverseFq2Elements } from "../src/sdk/ecc";
import { deployUpaLibTest } from "./upaLibTests";

describe("Point compression tests", () => {
  it("Checks g1 points compression", async function () {
    const vk = loadAppVK("../circuits/src/tests/data/vk.json");
    const alpha = vk.alpha;
    const compressedAlpha = compressG1Point(alpha);
    const decompressedAlpha = decompressG1Point(compressedAlpha);
    expect(decompressedAlpha).eql(alpha);
    vk.s.map((s) => {
      const compressedS = compressG1Point(s);
      const decompressedS = decompressG1Point(compressedS);
      expect(decompressedS).eql(s);
    });
  });

  it("Checks g2 points compression", async function () {
    const vk = loadAppVK("../circuits/src/tests/data/vk.json");
    const beta = vk.beta;
    const compressedBeta = compressG2Point(beta);
    const decompressedBeta = decompressG2Point(compressedBeta);
    expect(decompressedBeta).eql(beta);
    const gamma = vk.gamma;
    const compressedGamma = compressG2Point(gamma);
    const decompressedGamma = decompressG2Point(compressedGamma);
    expect(decompressedGamma).eql(gamma);
    const delta = vk.delta;
    const compressedDelta = compressG2Point(delta);
    const decompressedDelta = decompressG2Point(compressedDelta);
    expect(decompressedDelta).eql(delta);
  });

  it("Checks G1 compression in solidity", async function () {
    const upaLibTest = await loadFixture(deployUpaLibTest);
    const vk = loadAppVK("../circuits/src/tests/data/vk.json");
    const alpha = vk.alpha;
    const compressedAlpha = BigInt(compressG1Point(alpha));
    const compressedAlphaSolidity = await upaLibTest.compressG1Point(alpha);
    expect(compressedAlphaSolidity).eql(compressedAlpha);
    for (let i = 0; i < vk.s.length; i++) {
      const s = vk.s[i];
      const compressedS = BigInt(compressG1Point(s));
      const compressedSSolidity = await upaLibTest.compressG1Point(s);
      expect(compressedSSolidity).eql(compressedS);
    }
  });

  it("Checks G2 compression in solidity", async function () {
    const upaLibTest = await loadFixture(deployUpaLibTest);
    const vk = loadAppVK("../circuits/src/tests/data/vk.json");
    const beta = vk.beta;
    const compressedBeta = compressG2Point(beta).map(BigInt) as [
      bigint,
      bigint
    ];
    const compressedBetaSoldity = await upaLibTest.compressG2Point(
      reverseFq2Elements(beta)
    );
    expect(compressedBetaSoldity).eql(compressedBeta);
    const gamma = vk.gamma;
    const compressedGamma = compressG2Point(gamma).map(BigInt) as [
      bigint,
      bigint
    ];
    const compressedGammaSoldity = await upaLibTest.compressG2Point(
      reverseFq2Elements(gamma)
    );
    expect(compressedGammaSoldity).eql(compressedGamma);
    const delta = vk.delta;
    const compressedDelta = compressG2Point(delta).map(BigInt) as [
      bigint,
      bigint
    ];
    const compressedDeltaSoldity = await upaLibTest.compressG2Point(
      reverseFq2Elements(delta)
    );
    expect(compressedDeltaSoldity).eql(compressedDelta);
  });
});
