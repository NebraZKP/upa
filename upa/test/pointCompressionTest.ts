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
import { CompressedGroth16Proof } from "../src/sdk/groth16";

describe("Point (de)compression", () => {
  it("should fail gracefully for malformed data", async function () {
    // Log data leading to decompression failure:
    //
    // {
    //   pi_a:
    //     "0x9e9cfd462aa675a5e01f0d76bf4298f428cb9717099dc6ac292ac096ccae3193",
    //   pi_b: [
    //     "0x03e1f468c8773b7416fb1ec155ec13aba0d820d2d36ef0f357b9dda12f8997ff",
    //     "0x15170de686fdfa030ffdc0b63174767ea136e49e2b541509ad5aefaa8dce2ef7",
    //   ],
    //   pi_c:
    //     "0x1251c54744fffd804ca1b8a8d317252ac6e0ee6ff65170872247464c741d7a92",
    //   m: [],
    //   pok: [],
    // };

    // Results in a non-square y^2 value.  Should fail gracefully.
    const b = decompressG2Point([
      "0x03e1f468c8773b7416fb1ec155ec13aba0d820d2d36ef0f357b9dda12f8997ff",
      "0x15170de686fdfa030ffdc0b63174767ea136e49e2b541509ad5aefaa8dce2ef7",
    ]);
    expect(b).to.be.undefined;

    // Equivalent full Groth16 proof decompression should fail gracefully.

    const comp = new CompressedGroth16Proof(
      "0x9e9cfd462aa675a5e01f0d76bf4298f428cb9717099dc6ac292ac096ccae3193",
      [
        "0x03e1f468c8773b7416fb1ec155ec13aba0d820d2d36ef0f357b9dda12f8997ff",
        "0x15170de686fdfa030ffdc0b63174767ea136e49e2b541509ad5aefaa8dce2ef7",
      ],
      "0x1251c54744fffd804ca1b8a8d317252ac6e0ee6ff65170872247464c741d7a92",
      [],
      []
    );
    expect(comp.decompress()).to.be.undefined;
  });

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
      bigint,
    ];
    const compressedBetaSoldity = await upaLibTest.compressG2Point(
      reverseFq2Elements(beta)
    );
    expect(compressedBetaSoldity).eql(compressedBeta);
    const gamma = vk.gamma;
    const compressedGamma = compressG2Point(gamma).map(BigInt) as [
      bigint,
      bigint,
    ];
    const compressedGammaSoldity = await upaLibTest.compressG2Point(
      reverseFq2Elements(gamma)
    );
    expect(compressedGammaSoldity).eql(compressedGamma);
    const delta = vk.delta;
    const compressedDelta = compressG2Point(delta).map(BigInt) as [
      bigint,
      bigint,
    ];
    const compressedDeltaSoldity = await upaLibTest.compressG2Point(
      reverseFq2Elements(delta)
    );
    expect(compressedDeltaSoldity).eql(compressedDelta);
  });
});
