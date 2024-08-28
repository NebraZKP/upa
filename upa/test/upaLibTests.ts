// UPA tests
import { UpaLibTest, UpaLibTest__factory } from "../typechain-types";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { pf_a, pf_b } from "./upaTests";
import { deployUpaDummyVerifier } from "./deploy";
import { expect } from "chai";
import {
  CircuitIdProofAndInputs,
  DUMMY_PROOF_CIRCUIT_ID,
  DUMMY_PROOF_ID,
  DUMMY_SUBMISSION_ID,
} from "../src/sdk/application";
import { loadAppVK, loadDummyProofData } from "../src/tool/config";
import {
  bigintToHex32,
  computeProofId,
  computeCircuitId,
  computeFinalDigest,
  digestAsFieldElements,
  readBytes32,
} from "../src/sdk/utils";
import { ethers } from "hardhat";
import { hexlify } from "ethers";
import { Submission } from "../src/sdk/submission";
import { Groth16Verifier } from "../src/sdk";

export async function deployUpaLibTest(): Promise<UpaLibTest> {
  const [owner] = await ethers.getSigners();
  const upaLibTestFactory = new UpaLibTest__factory(owner);
  const upaLibTest = await upaLibTestFactory.deploy();
  await upaLibTest.waitForDeployment();
  return upaLibTest;
}

const cidsProofsAndInputs_a: CircuitIdProofAndInputs[] = [
  {
    circuitId: bigintToHex32(123n),
    proof: pf_a,
    inputs: [1n, 0n, 0n],
  },
  {
    circuitId: bigintToHex32(234n),
    proof: pf_b,
    inputs: [2n, 0n, 0n],
  },
  {
    circuitId: bigintToHex32(345n),
    proof: pf_a,
    inputs: [3n, 0n, 0n],
  },
].map(CircuitIdProofAndInputs.from_json);

const cidsProofsAndInputs_b: CircuitIdProofAndInputs[] = [
  {
    circuitId: bigintToHex32(12345n),
    proof: pf_a,
    inputs: [1n, 0n, 0n],
  },
  {
    circuitId: bigintToHex32(12345n),
    proof: pf_b,
    inputs: [2n, 0n, 0n],
  },
  {
    circuitId: bigintToHex32(12345n),
    proof: pf_a,
    inputs: [3n, 0n, 0n],
  },
  {
    circuitId: bigintToHex32(12345n),
    proof: pf_b,
    inputs: [4n, 0n, 0n],
  },
].map(CircuitIdProofAndInputs.from_json);

const cidsProofsAndInputs_c: CircuitIdProofAndInputs[] = [
  {
    circuitId: bigintToHex32(12345n),
    proof: pf_a,
    inputs: [1n, 0n, 0n],
  },
].map(CircuitIdProofAndInputs.from_json);

// UPA tests
describe("UpaLib Tests", async () => {
  describe("Compute ProofId", () => {
    // Test vector:
    //
    //   keccak([
    //     uint256(0x1),
    //     uint256(0x2),
    //     uint256(0x3),
    //     uint256(0x100000000000000000000000000000000),
    //     uint256(
    //       0x200000000000000000000000000000000000000000000000000000000000000)
    //   ]) = 0x227ba65a7f156e2a72f88325abe99b31b0c5bd09eec1499eb48617aaa2d33fb7
    //
    // generated with Python code of the form:
    //
    //   from web3 import Web3
    //   public_inputs = [1, 2, 3, pow(2,128), pow(2, 253)]
    //   bytes = [x.to_bytes(32, byteorder="big") for x in public_inputs]
    //   full_data = b''.join(bytes)
    //   print(Web3.keccak(full_data))

    const circuit_id = readBytes32(bigintToHex32(1n));
    const PIs: string[] = [
      "0x2",
      "0x3",
      "0x100000000000000000000000000000000",
      "0x2000000000000000000000000000000000000000000000000000000000000000",
    ];

    const PIs_bigint = PIs.map((x) => BigInt(x));

    it("should match test vector 0", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const pid = await upaLib.computeProofId(circuit_id, PIs.slice(0, 0));
      expect(pid).equals(
        "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
      );
      expect(pid).equals(computeProofId(circuit_id, PIs_bigint.slice(0, 0)));
    });

    it("dummy proof id", async () => {
      const { upa } = await loadFixture(deployUpaDummyVerifier);
      const { verifier } = upa;
      const verifierDummyProofId = await verifier.DUMMY_PROOF_ID();

      // Check the dummy circuitId comes from the dummy vk
      const dummyVk = loadAppVK("../upa/test/dummy/dummy_vk.upa.json");
      const dummyCircuitId = computeCircuitId(dummyVk);
      expect(dummyCircuitId).eqls(
        DUMMY_PROOF_CIRCUIT_ID,
        "Hard-coded DUMMY_PROOF_CIRCUIT_ID is out of date.\n" +
          `Update to ${dummyCircuitId}`
      );

      // Check the dummy proofId comes from the dummy circuitId and
      // the dummy proof
      const { proof, inputs } = loadDummyProofData();
      const dummyProofId = computeProofId(dummyCircuitId, inputs);
      console.log(dummyProofId);
      expect(dummyProofId).eqls(
        DUMMY_PROOF_ID,
        `Hard-coded DUMMY_PROOF_ID is out of date.\nUpdate to ${dummyProofId}`
      );
      // Check the dummy proof Id in the verifier contract matches
      // that of the sdk.
      expect(verifierDummyProofId).eqls(
        DUMMY_PROOF_ID,
        "Hard-coded DUMMY_PROOF_ID in contract is out of date.\n" +
          `Update to ${dummyProofId}`
      );
      // Check that the dummy submission Id is equal to keccak256 of the
      // dummy proof Id.
      expect(ethers.keccak256(DUMMY_PROOF_ID)).eqls(
        DUMMY_SUBMISSION_ID,
        "Hard-coded DUMMY_SUBMISSION_ID in SDK is out of date."
      );

      // Check the dummy proof is valid
      const groth16Verifier = await Groth16Verifier.initialize();
      const isDummyProofValid = await groth16Verifier.verifyGroth16Proof(
        dummyVk,
        proof,
        inputs
      );
      expect(isDummyProofValid.result).to.be.true;
    });

    it("should match test vector 1", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const pid = await upaLib.computeProofId(circuit_id, PIs.slice(0, 1));
      expect(pid).equals(
        "0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0"
      );
      expect(pid).equals(computeProofId(circuit_id, PIs_bigint.slice(0, 1)));
    });

    it("should match test vector 2", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const pid = await upaLib.computeProofId(circuit_id, PIs.slice(0, 2));
      expect(pid).equals(
        "0x6e0c627900b24bd432fe7b1f713f1b0744091a646a9fe4a65a18dfed21f2949c"
      );
      expect(pid).equals(computeProofId(circuit_id, PIs_bigint.slice(0, 2)));
    });

    it("should match test vector 3", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const pid = await upaLib.computeProofId(circuit_id, PIs.slice(0, 3));
      expect(pid).equals(
        "0x39235ab0d413c40e063cdebb9c8c3f1407bf5622597831333acb1f64f052216b"
      );
      expect(pid).equals(computeProofId(circuit_id, PIs_bigint.slice(0, 3)));
    });

    it("should match test vector 4", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const pid = await upaLib.computeProofId(circuit_id, PIs.slice(0, 4));
      expect(pid).equals(
        "0x227ba65a7f156e2a72f88325abe99b31b0c5bd09eec1499eb48617aaa2d33fb7"
      );
      expect(pid).equals(computeProofId(circuit_id, PIs_bigint.slice(0, 4)));
    });
  });

  describe("Compute SubmissionId", () => {
    // Multi-proof, many circuit_ids
    it("Check computed correctly for submission_a", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);

      const submission_a = Submission.fromCircuitIdsProofsAndInputs(
        cidsProofsAndInputs_a
      );

      const circuit_ids = cidsProofsAndInputs_a.map((item) => item.circuitId);
      const public_inputs = cidsProofsAndInputs_a.map((item) => item.inputs);

      const sid = await upaLib["computeSubmissionId(bytes32[],uint256[][])"](
        circuit_ids,
        public_inputs
      );
      expect(sid).equals(submission_a.submissionId);
    });

    // Multi-proof, one circuit_id
    it("Check computed correctly for submission_b", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);

      const submission_b = Submission.fromCircuitIdsProofsAndInputs(
        cidsProofsAndInputs_b
      );

      // Single circuit_id case
      const circuit_id = cidsProofsAndInputs_b[0].circuitId;
      const public_inputs = cidsProofsAndInputs_b.map((item) => item.inputs);

      const sid = await upaLib["computeSubmissionId(bytes32,uint256[][])"](
        circuit_id,
        public_inputs
      );
      expect(sid).equals(submission_b.submissionId);
    });

    // Single-proof
    it("Check computed correctly for submission_c", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);

      const submission_c = Submission.fromCircuitIdsProofsAndInputs(
        cidsProofsAndInputs_c
      );

      // Single circuit_id case
      const circuit_id = cidsProofsAndInputs_c[0].circuitId;
      const public_inputs = cidsProofsAndInputs_c.map((item) => item.inputs);

      const sid_1 = await upaLib["computeSubmissionId(bytes32,uint256[][])"](
        circuit_id,
        public_inputs
      );
      expect(sid_1).equals(submission_c.submissionId);

      const sid_2 = await upaLib["computeSubmissionId(bytes32[],uint256[][])"](
        [circuit_id],
        public_inputs
      );
      expect(sid_2).equals(submission_c.submissionId);
    });
  });

  describe("Decompose digest", () => {
    it("should decompose in the expected way", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const digest =
        "0x0123456789abcdef123456789abcdef023456789abcdef013456789abcdef012";
      const expect_l = 0x23456789abcdef013456789abcdef012n;
      const expect_h = 0x0123456789abcdef123456789abcdef0n;
      const evmResult = await upaLib.digestAsFieldElements(digest);
      const tsResult = digestAsFieldElements(digest);
      expect(evmResult).eql(tsResult);
      expect(evmResult).eql([expect_l, expect_h]);
    });

    it("should decompose the test vector in the expected way", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const digest =
        "0x227ba65a7f156e2a72f88325abe99b31b0c5bd09eec1499eb48617aaa2d33fb7";
      const expect_l = 0xb0c5bd09eec1499eb48617aaa2d33fb7n;
      const expect_h = 0x227ba65a7f156e2a72f88325abe99b31n;
      const evmResult = await upaLib.digestAsFieldElements(digest);
      const tsResult = digestAsFieldElements(digest);
      expect(evmResult).eql(tsResult);
      expect(evmResult).eql([expect_l, expect_h]);
    });

    it("reverts decomposition", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);
      const digest =
        "0x227ba65a7f156e2a72f88325abe99b31b0c5bd09eec1499eb48617aaa2d33fb7";
      const decomposition = await upaLib.digestAsFieldElements(digest);
      const recomposition = await upaLib.fieldElementsAsDigest(
        decomposition[0],
        decomposition[1]
      );
      expect(recomposition).eql(digest);
    });
  });

  /// Test vectors from `circuits::tests::batch_verifier::components`

  describe("Compute CircuitId", () => {
    // Test vectors generated by the circuits crate:
    //
    // $ cargo test -- circuit_id_test_vector_universal --nocapture
    const TEST_VECTOR_CID =
      "0x6144828f857cd0e0bc6b6a40f426b186b897ba5ec2cd10becf94e404e91a26e2";
    const TEST_VECTOR_CID_WITH_COMMITMENT =
      "0x02122a4231fd731b27924a916456c87c26cd5d1f226ecc9ddabde9b8dc7758e8";

    it("circuitId without commitment (client-side)", () => {
      const vk = loadAppVK("../circuits/src/tests/data/vk.json");
      const circuit_id = computeCircuitId(vk);
      expect(circuit_id).equals(TEST_VECTOR_CID);
    });

    it("computes circuitId with commitment (client-side)", () => {
      const vk = loadAppVK("../circuits/src/tests/data/vk_commitment.json");
      const circuit_id = computeCircuitId(vk);
      expect(circuit_id).equals(TEST_VECTOR_CID_WITH_COMMITMENT);
    });

    it("circuitId without commitment (contract)", async () => {
      const vk = loadAppVK("../circuits/src/tests/data/vk.json");
      const upaLibTest = await loadFixture(deployUpaLibTest);
      const circuit_id = await upaLibTest.computeCircuitId(vk.solidity());
      expect(circuit_id).equals(TEST_VECTOR_CID);
    });

    it("computes circuitId with commitment (contract)", async () => {
      const vk = loadAppVK("../circuits/src/tests/data/vk_commitment.json");
      const upaLibTest = await loadFixture(deployUpaLibTest);
      const circuit_id = await upaLibTest.computeCircuitId(vk.solidity());
      expect(circuit_id).equals(TEST_VECTOR_CID_WITH_COMMITMENT);
    });
  });

  describe("Compute final digest", async () => {
    it("decomposeFq", async () => {
      const upaLibTest = await loadFixture(deployUpaLibTest);
      const result = await upaLibTest.decomposeFq(
        0x2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e2n
      );
      const expected = [
        0x0000000000000000000000000000000000000000006c643b22f599a2be6df2e2n,
        0x0000000000000000000000000000000000000000009d5507949d05dbea33fbb1n,
        0x000000000000000000000000000000000000000000002d4d9aa7e302d9df4174n,
      ];
      expect(result).to.eql(expected);
    });

    it("compute final digest", async () => {
      const upaLib = await loadFixture(deployUpaLibTest);

      // Load test calldata corresponding to these pids:
      const pids = [
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
      ];
      const expectFinalDigest =
        "0x956bf49add4e777484e59667915c0d584466562a63d49a5a07b6eb6c4e258c29";

      // Check solidity version and JS version against test vector.
      const evmFinalDigest = await upaLib.computeFinalDigest(pids);
      const tsFinalDigest = computeFinalDigest(pids);
      expect(hexlify(evmFinalDigest)).equals(tsFinalDigest);
      expect(hexlify(evmFinalDigest)).equals(expectFinalDigest);
    });
  });
});
