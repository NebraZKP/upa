import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ethers } from "hardhat";
import { MerkleTest, MerkleTest__factory } from "../typechain-types";
import {
  computeMerkleIntervalRoot,
  computeMerkleProof,
  computeMerkleRoot,
  createMerkleIntervalProof,
  evmInnerHashFn,
  evmLeafHashFn,
} from "../src/sdk/merkleUtils";

/// Dummy hash function
function dummyLeafHash(l: string): string {
  return l;
}

/// Dummy hash function
function dummyInnerHash(l: string, r: string): string {
  return l + r;
}

function verifyMerkleInterval(
  offset: number,
  interval: string[],
  proof: string[]
) {
  const root = computeMerkleIntervalRoot(
    dummyLeafHash,
    dummyInnerHash,
    offset,
    interval,
    proof
  );
  expect(root).eql("abcdefgh");
}

describe("Merkle intervals", () => {
  async function deployMerkleTest(): Promise<MerkleTest> {
    const [signer] = await ethers.getSigners();
    const MerkleTest = new MerkleTest__factory(signer);
    const merkleTest = await MerkleTest.deploy();
    await merkleTest.waitForDeployment();
    return merkleTest;
  }

  // Configs to test "manually".  Represents every combination of odd/even
  // starting/finishing index, single entries, all entries, entries at the
  // edges.
  //
  //    |a|b|c|d|e|f|g|h|
  // 1   *
  // 2   * *
  // 3   * * *
  // 4     *
  // 5     * *
  // 6     * * *
  // 7       *
  // 8       * *
  // 9       * * *
  // 10                *
  // 11              * *
  // 12            * * *
  // 13  * * * * * * * *

  describe("computeMerkleIntervalRoot", () => {
    it("config 1", function () {
      //  |a|b|c|d|e|f|g|h|
      //   *
      verifyMerkleInterval(0, ["a"], ["b", "cd", "efgh"]);
    });

    it("config 2", function () {
      //  |a|b|c|d|e|f|g|h|
      //   * *
      verifyMerkleInterval(0, ["a", "b"], ["cd", "efgh"]);
    });

    it("config 3", function () {
      //  |a|b|c|d|e|f|g|h|
      //   * * *
      verifyMerkleInterval(0, ["a", "b", "c"], ["d", "efgh"]);
    });

    it("config 4", function () {
      //  |a|b|c|d|e|f|g|h|
      //     *
      verifyMerkleInterval(1, ["b"], ["a", "cd", "efgh"]);
    });

    it("config 5", function () {
      //  |a|b|c|d|e|f|g|h|
      //     * *
      verifyMerkleInterval(1, ["b", "c"], ["a", "d", "efgh"]);
    });

    it("config 6", function () {
      //  |a|b|c|d|e|f|g|h|
      //     * * *
      verifyMerkleInterval(1, ["b", "c", "d"], ["a", "efgh"]);
    });

    it("config 7", function () {
      //  |a|b|c|d|e|f|g|h|
      //       *
      verifyMerkleInterval(2, ["c"], ["d", "ab", "efgh"]);
    });

    it("config 8", function () {
      //  |a|b|c|d|e|f|g|h|
      //       * *
      verifyMerkleInterval(2, ["c", "d"], ["ab", "efgh"]);
    });

    it("config 9", function () {
      //  |a|b|c|d|e|f|g|h|
      //       * * *
      verifyMerkleInterval(2, ["c", "d", "e"], ["f", "ab", "gh"]);
    });

    it("config 10", function () {
      //  |a|b|c|d|e|f|g|h|
      //                 *
      verifyMerkleInterval(7, ["h"], ["g", "ef", "abcd"]);
    });

    it("config 11", function () {
      //  |a|b|c|d|e|f|g|h|
      //               * *
      verifyMerkleInterval(6, ["g", "h"], ["ef", "abcd"]);
    });

    it("config 12", function () {
      //  |a|b|c|d|e|f|g|h|
      //             * * *
      verifyMerkleInterval(5, ["f", "g", "h"], ["e", "abcd"]);
    });

    it("config 13", function () {
      //  |a|b|c|d|e|f|g|h|
      //   * * * * * * * *
      verifyMerkleInterval(0, ["a", "b", "c", "d", "e", "f", "g", "h"], []);
    });
  });

  describe("computeMerkleIntervalProof", () => {
    it("all possible configs", function () {
      // Using the leaf nodes:
      //
      //    |a|b|c|d|e|f|g|h|
      //
      // we take every possible interval, create a proof and check that the
      // correct root is generated.

      const leafNodes = ["a", "b", "c", "d", "e", "f", "g", "h"];
      const expectRoot = "abcdefgh";

      for (let offset = 0; offset < 8; ++offset) {
        for (let numEntries = 1; numEntries <= 8 - offset; ++numEntries) {
          const { proof, root: proofRoot } = createMerkleIntervalProof(
            dummyLeafHash,
            dummyInnerHash,
            leafNodes,
            offset,
            numEntries
          );
          expect(proofRoot).equal(expectRoot);

          const interval = leafNodes.slice(offset, offset + numEntries);
          const computedRoot = computeMerkleIntervalRoot(
            dummyLeafHash,
            dummyInnerHash,
            offset,
            interval,
            proof
          );
          expect(computedRoot).equal(
            expectRoot,
            `offset: ${offset}, numEntries: ${numEntries}, ` +
              `interval: ${JSON.stringify(interval)}`
          );
        }
      }
    });
  });

  describe("computeMerkleRoot", () => {
    it("all possible configs", function () {
      // Using the leaf nodes:
      //
      //    |a|b|c|d|e|f|g|h|
      //
      // we take every possible interval, create a proof and check that the
      // correct root is generated.

      const leafNodes = ["a", "b", "c", "d", "e", "f", "g", "h"];
      const expectRoot = "abcdefgh";

      expect(computeMerkleRoot(dummyLeafHash, dummyInnerHash, leafNodes)).eql(
        expectRoot
      );
      expect(
        computeMerkleRoot(dummyLeafHash, dummyInnerHash, leafNodes.slice(0, 4))
      ).eql(expectRoot.slice(0, 4));
    });
  });

  describe("computeMerkleProof", () => {
    it("all possible configs", function () {
      // Using the leaf nodes:
      //
      //    |a|b|c|d|e|f|g|h|
      //
      // we take every entry in turn and check the generated proof.

      const leafNodes = ["a", "b", "c", "d", "e", "f", "g", "h"];

      function getProof(idx: number): string[] {
        return computeMerkleProof(dummyLeafHash, dummyInnerHash, leafNodes, idx)
          .proof;
      }

      expect(getProof(0)).eql(["b", "cd", "efgh"]);
      expect(getProof(1)).eql(["a", "cd", "efgh"]);
      expect(getProof(2)).eql(["d", "ab", "efgh"]);
      expect(getProof(3)).eql(["c", "ab", "efgh"]);
      expect(getProof(4)).eql(["f", "gh", "abcd"]);
      expect(getProof(5)).eql(["e", "gh", "abcd"]);
      expect(getProof(6)).eql(["h", "ef", "abcd"]);
      expect(getProof(7)).eql(["g", "ef", "abcd"]);
    });
  });

  describe("contract", () => {
    const leafNodes = [
      "0x1000000000000000000000000000000000000000000000000000000000000000",
      "0x2000000000000000000000000000000000000000000000000000000000000000",
      "0x3000000000000000000000000000000000000000000000000000000000000000",
      "0x4000000000000000000000000000000000000000000000000000000000000000",
      "0x5000000000000000000000000000000000000000000000000000000000000000",
      "0x6000000000000000000000000000000000000000000000000000000000000000",
      "0x7000000000000000000000000000000000000000000000000000000000000000",
      "0x8000000000000000000000000000000000000000000000000000000000000000",
    ];
    const expectRoot = evmInnerHashFn(
      evmInnerHashFn(
        evmInnerHashFn(
          evmLeafHashFn(leafNodes[0]),
          evmLeafHashFn(leafNodes[1])
        ),
        evmInnerHashFn(evmLeafHashFn(leafNodes[2]), evmLeafHashFn(leafNodes[3]))
      ),
      evmInnerHashFn(
        evmInnerHashFn(
          evmLeafHashFn(leafNodes[4]),
          evmLeafHashFn(leafNodes[5])
        ),
        evmInnerHashFn(evmLeafHashFn(leafNodes[6]), evmLeafHashFn(leafNodes[7]))
      )
    );

    it("evmMerkleDepth", async function () {
      const merkleTest = await loadFixture(deployMerkleTest);
      expect(await merkleTest.merkleDepth(4)).equals(2);
      expect(await merkleTest.merkleDepth(5)).equals(3);
      expect(await merkleTest.merkleDepth(6)).equals(3);
      expect(await merkleTest.merkleDepth(7)).equals(3);
      expect(await merkleTest.merkleDepth(8)).equals(3);
      expect(await merkleTest.merkleDepth(255)).equals(8);
      expect(await merkleTest.merkleDepth(256)).equals(8);
      expect(await merkleTest.merkleDepth(257)).equals(9);
    });

    it("evmComputeMerkleRoot", async function () {
      const merkleTest = await loadFixture(deployMerkleTest);
      const computedRoot = computeMerkleRoot(
        evmLeafHashFn,
        evmInnerHashFn,
        leafNodes
      );
      expect(computedRoot).eql(expectRoot);

      const evmRoot = await merkleTest.computeMerkleRoot(leafNodes);
      expect(evmRoot).eql(expectRoot);
    });

    it("evmVerifyMerkleProof", async function () {
      const merkleTest = await loadFixture(deployMerkleTest);
      // for (let i = 0; i < leafNodes.length; ++i) {
      for (let i = 0; i < 1; ++i) {
        const { proof } = computeMerkleProof(
          evmLeafHashFn,
          evmInnerHashFn,
          leafNodes,
          i
        );
        const verified = merkleTest.verifyMerkleProof(
          expectRoot,
          leafNodes[i],
          i,
          proof
        );
        const verifiedInvalidIdx = merkleTest.verifyMerkleProof(
          expectRoot,
          leafNodes[i],
          (i + 1) % leafNodes.length,
          proof
        );
        // Swap the first 2 entries of the proof
        const tmp = proof[0];
        proof[0] = proof[1];
        proof[1] = tmp;
        const verifiedInvalidProof = merkleTest.verifyMerkleProof(
          expectRoot,
          leafNodes[i],
          (i + 1) % leafNodes.length,
          proof
        );

        expect(await verified).equal(true);
        expect(await verifiedInvalidIdx).equal(false);
        expect(await verifiedInvalidProof).equal(false);
      }
    });

    it("evmHashFn", async function () {
      const merkleTest = await loadFixture(deployMerkleTest);
      const l = ethers.hexlify(ethers.randomBytes(32));
      const r = ethers.hexlify(ethers.randomBytes(32));
      const expected = await merkleTest.hash(l, r);
      const actual = evmInnerHashFn(l, r);
      expect(actual).equal(expected);
      console.log(`hash(hash(${l}), hash(${r}))=${expected}`);
    });

    it("evmHashFn all possible configs", async function () {
      const merkleTest = await loadFixture(deployMerkleTest);

      // Using the leaf nodes:
      //
      //    |0x10..00|0x20..00|0x30..00|...|0x80..00|
      //
      // we take every possible interval, create a proof and check that the
      // correct root is generated.

      for (let offset = 0; offset < 8; ++offset) {
        for (let numEntries = 1; numEntries <= 8 - offset; ++numEntries) {
          const { proof, root: proofRoot } = createMerkleIntervalProof(
            evmLeafHashFn,
            evmInnerHashFn,
            leafNodes,
            offset,
            numEntries
          );
          expect(proofRoot).equal(expectRoot);

          // Typescript verification function
          const interval = leafNodes.slice(offset, offset + numEntries);
          const computedRootTs = computeMerkleIntervalRoot(
            evmLeafHashFn,
            evmInnerHashFn,
            offset,
            interval,
            proof
          );
          expect(computedRootTs).equal(
            expectRoot,
            `(ts) offset: ${offset}, numEntries: ${numEntries}, ` +
              `interval: ${JSON.stringify(interval)}`
          );

          // Solidity verification function
          const computedRootSol = await merkleTest.computeMerkleIntervalRoot(
            offset,
            interval,
            proof
          );
          expect(computedRootSol).equal(
            expectRoot,
            `(sol) offset: ${offset}, numEntries: ${numEntries}, ` +
              `interval: ${JSON.stringify(interval)}`
          );
        }
      }
    });
  });
});
