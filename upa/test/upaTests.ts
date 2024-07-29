import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import {
  JSONstringify,
  computeCircuitId,
  computeProofId,
  readBytes32,
} from "../src/sdk/utils";
import { loadAppVK } from "../src/tool/config";
import { readFileSync } from "fs";
import { Signer, ContractTransactionResponse } from "ethers";
import {
  CircuitIdProofAndInputs,
  Groth16VerifyingKey,
} from "../src/sdk/application";
import { CompressedGroth16Proof } from "../src/sdk/groth16";
import {
  dummyProofData,
  submitProof,
  isProofVerifiedSingle,
  isProofVerifiedMulti,
  submitProofs,
  UpaInstanceDescriptor,
  upaInstanceFromDescriptor,
  UpaInstance,
  isSubmissionVerified,
  isSubmissionVerifiedById,
  isSingleCircuitSubmissionVerified,
  isProofVerifiedByIdSingle,
  isProofVerifiedbyIdMulti,
  updateFeeOptions,
} from "../src/sdk/upa";
import {
  computeMerkleRoot,
  evmInnerHashFn,
  evmLeafHashFn,
} from "../src/sdk/merkleUtils";
import {
  OffChainSubmission,
  Submission,
  ZERO_BYTES32,
} from "../src/sdk/submission";
import {
  packDupSubmissionIdxs,
  packOffChainSubmissionMarkers,
} from "../src/sdk/aggregatedProofParams";
import { UpaFixedGasFee__factory } from "../typechain-types";
import { SubmissionProof } from "../src/sdk/submission";
import * as fs from "fs";
import { deployUpa } from "../src/tool/deploy";

/// The type of objects passed to `parseLog`.
type Log = { topics: Array<string>; data: string };

// eslint-disable-next-line
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

function appVKMakeInvalid(vk: Groth16VerifyingKey): Groth16VerifyingKey {
  const vk_invalid = Groth16VerifyingKey.from_json(vk); // clone
  vk_invalid.alpha[1] = vk_invalid.alpha[0];
  return vk_invalid;
}

function appVKMakeInvalidBeta(vk: Groth16VerifyingKey): Groth16VerifyingKey {
  const vk_invalid = Groth16VerifyingKey.from_json(vk);
  vk_invalid.beta[0][1] = vk_invalid.beta[0][0];
  return vk_invalid;
}

// Dummy proofs and PIs
export const pf_a = new CompressedGroth16Proof(
  "1",
  ["3", "4"],
  "7",
  [],
  []
).decompress();
export const pi_a = [11n, 12n, 13n];

export const pf_b = new CompressedGroth16Proof(
  "1",
  ["3", "4"],
  "8",
  [],
  []
).decompress();
export const pi_b = [21n, 22n, 23n];

export const pf_c = new CompressedGroth16Proof(
  "1",
  ["3", "4"],
  "9",
  [],
  []
).decompress();
export const pi_c = [31n, 32n, 33n];

export const pf_d = pf_c;
export const pi_d = [41n, 42n, 43n];

export const pf_e = pf_c;
export const pi_e = [51n, 52n, 53n];

export const pf_f = pf_c;
export const pi_f = [61n, 62n, 63n];

export const pf_comm = new CompressedGroth16Proof(
  "1",
  ["3", "4"],
  "9",
  ["11"],
  ["13"]
).decompress();

export type DeployResult = {
  upa: UpaInstance;
  upaDesc: UpaInstanceDescriptor;
  owner: Signer;
  worker: Signer;
  user1: Signer;
  user2: Signer;
};

// UPA tests

export async function deployUpaWithVerifier(
  verifier?: string,
  maxNumPublicInputs?: number,
  version?: string
): Promise<DeployResult> {
  const [deployer, owner, worker, user1, user2] = await ethers.getSigners();

  verifier = verifier || "test/data/outer_2_2.verifier.bin";
  maxNumPublicInputs = maxNumPublicInputs || 16;
  const contract_hex = "0x" + fs.readFileSync(verifier, "utf-8").trim();

  const upaDesc = await deployUpa(
    deployer,
    contract_hex,
    maxNumPublicInputs,
    3 /*maxRetries*/,
    false /*prepare*/,
    undefined /*groth16Verifier*/,
    owner.address,
    worker.address,
    undefined /* feeRecipient */,
    undefined /* feeInGas */,
    undefined /* aggregatorCollateral */,
    undefined /* fixedReimbursement */,
    version
  );
  const upa = await upaInstanceFromDescriptor(upaDesc!, owner);

  return { upa, upaDesc: upaDesc!, owner, worker, user1, user2 };
}

export async function deployUpaDummyVerifier(version?: string) {
  return deployUpaWithVerifier("test/data/test.bin", undefined, version);
}

export async function deployAndUpgradeUpa() {
  const { upa, upaDesc, owner, worker, user1, user2 } =
    await deployUpaWithVerifier();

  return {
    upa,
    upaDesc,
    owner,
    worker,
    user1,
    user2,
  };
}

export type DeployAndSubmitResult = DeployResult & {
  s1: OffChainSubmission;
  s2: OffChainSubmission;
  s3: OffChainSubmission;
  s1_tx: ContractTransactionResponse;
  s2_tx: ContractTransactionResponse;
  s3_tx: ContractTransactionResponse;
  cid_a: string;
};

/// Submit 3 submissions (all against cid_a):
///   1: [ pf_a ]
///   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
///   3: [ pf_e, pf_f ]        (Merkle depth 2, full)
export async function makeSubmissions(
  upa: UpaInstance
): Promise<
  [OffChainSubmission, OffChainSubmission, OffChainSubmission, string]
> {
  const { verifier } = upa;
  const vk = loadAppVK("../circuits/src/tests/data/vk.json");
  await verifier.registerVK(vk);
  const cid_a = computeCircuitId(vk);

  // Submissions
  const submission_1 = Submission.fromCircuitIdsProofsAndInputs([
    { circuitId: cid_a, proof: pf_a, inputs: pi_a },
  ]);
  const submission_2 = Submission.fromCircuitIdsProofsAndInputs([
    { circuitId: cid_a, proof: pf_b, inputs: pi_b },
    { circuitId: cid_a, proof: pf_c, inputs: pi_c },
    { circuitId: cid_a, proof: pf_d, inputs: pi_d },
  ]);
  const submission_3 = Submission.fromCircuitIdsProofsAndInputs([
    { circuitId: cid_a, proof: pf_e, inputs: pi_e },
    { circuitId: cid_a, proof: pf_f, inputs: pi_f },
  ]);

  return [submission_1, submission_2, submission_3, cid_a];
}

async function deployAndSubmit(): Promise<DeployAndSubmitResult> {
  const deployResult = await deployUpaDummyVerifier();
  const { upa } = deployResult;

  const [s1, s2, s3, cid_a] = await makeSubmissions(upa);
  const { verifier } = upa;

  // Submit 1
  const s1_tx = await submitProof(
    verifier,
    s1.circuitIds[0],
    s1.proofs[0],
    s1.inputs[0]
  );

  // Submit 2
  const s2_tx = await submitProofs(
    verifier,
    s2.circuitIds,
    s2.proofs,
    s2.inputs
  );

  // Submit 3
  const s3_tx = await submitProofs(
    verifier,
    s3.circuitIds,
    s3.proofs,
    s3.inputs
  );

  return { ...deployResult, s1, s2, s3, s1_tx, s2_tx, s3_tx, cid_a };
}

// UPA tests
describe("UPA", async () => {
  const vk = loadAppVK("../circuits/src/tests/data/vk.json");
  const vk_invalid = appVKMakeInvalid(vk);

  describe("Simple Contract Operations", () => {
    it("register VK", async () => {
      const { upa } = await loadFixture(deployAndUpgradeUpa);
      const { verifier } = upa;

      const circuitId = computeCircuitId(vk);
      const vk_invalid_beta = appVKMakeInvalidBeta(vk);

      // Register vk and vk_invalid in order.  Check events from vk.
      const tx = await verifier.registerVK(vk);
      await expect(verifier.registerVK(vk_invalid))
        .to.be.revertedWithCustomError(verifier, "NotOnCurve")
        .withArgs(0 /* Groth16PointType.Alpha */);
      await expect(verifier.registerVK(vk_invalid_beta))
        .to.be.revertedWithCustomError(verifier, "NotOnCurve")
        .withArgs(1 /* Groth16PointType.Beta */);

      {
        const receipt = await tx.wait();
        const parsedLogs = verifier.interface.parseLog(
          receipt?.logs[0] as unknown as Log
        );
        const event_vk = Groth16VerifyingKey.from_solidity(parsedLogs?.args.vk);
        expect(JSON.stringify(event_vk)).eql(JSON.stringify(vk));
        expect(JSON.stringify(event_vk)).eql(JSON.stringify(vk));
        expect(parsedLogs?.args.circuitId).eql(circuitId);
      }

      // Query the contract state on the proof receiver
      const circuitIds = await verifier.getCircuitIds();
      expect(circuitIds.length).equals(1);

      const [vk_sol_0] = await Promise.all([verifier.getVK(circuitIds[0])]);

      // TODO: Once we deserialize these struct, check all entries.
      expect(Groth16VerifyingKey.from_solidity(vk_sol_0)).to.eql(vk);
    });

    it("submitAndVerifyProof", async () => {
      const { upa, worker } = await loadFixture(deployUpaDummyVerifier);
      const { verifier } = upa;

      // Register vk and vk_invalid in order.
      await verifier.registerVK(vk);

      const circuitIds: string[] = (await verifier.getCircuitIds()).map(
        readBytes32
      );

      // Convention pid_<pf>_<cid>

      const pid_a_c0 = computeProofId(circuitIds[0], pi_a);
      expect(pid_a_c0).equals(computeProofId(circuitIds[0], pi_a));
      const pid_b_c0 = computeProofId(circuitIds[0], pi_b);
      const pid_c_c0 = computeProofId(circuitIds[0], pi_c);
      expect(pid_c_c0).equals(computeProofId(circuitIds[0], pi_c));
      const height_1 = await ethers.provider.getBlockNumber();

      // Detrmine gasPrice and value for a single submission
      const options = await updateFeeOptions(verifier, 1, undefined);

      // Submit proof for cid[0]
      expect(await verifier.getNextSubmissionIdx()).eql(1n);
      const sid_a_c0 = await verifier.submit.staticCall(
        [circuitIds[0]],
        [pf_a.compress().solidity()],
        [pi_a],
        options
      );
      const sid_b_c0 = await verifier.submit.staticCall(
        [circuitIds[0]],
        [pf_a.compress().solidity()],
        [pi_b],
        options
      );
      expect(sid_a_c0).not.eql(sid_b_c0);
      expect(sid_a_c0).eql(evmLeafHashFn(pid_a_c0));
      const submitTx = await verifier.submit(
        [circuitIds[0]],
        [pf_a.compress().solidity()],
        [pi_a],
        options
      );

      // Check event emitted from submitProof

      {
        const receipt = await submitTx.wait();
        const parsedLogs = verifier.interface.parseLog(
          receipt?.logs[0] as unknown as Log
        );
        expect(parsedLogs?.args.proofId).eql(pid_a_c0);
        expect(parsedLogs?.args.submissionIdx).eql(1n);
        expect(parsedLogs?.args.proofIdx).eql(1n);
        expect(parsedLogs?.args.dupSubmissionIdx).eql(0n);
      }

      // Check records for the submission
      expect(await verifier.getNextSubmissionIdx()).eql(2n);
      const [submissionIdx, submissionBlockNumber] =
        await verifier.getSubmissionIdxAndHeight(sid_a_c0, 0);
      expect(submissionIdx).equals(1n);
      expect(submissionBlockNumber).greaterThan(0n);

      // Next proof idx should be 2
      expect(await verifier.getNextSubmissionIdx()).eql(2n);

      // 2 more proofs (pf_b, pf_c) with cid[0], so we should have
      // proofIndices:
      //
      //  idx 2: pid_b
      //  idx 3: pid_c
      await submitProof(verifier, circuitIds[0], pf_b, pi_b, options);
      await submitProof(verifier, circuitIds[0], pf_c, pi_c, options);
      const height_2 = await ethers.provider.getBlockNumber();
      expect(height_2).greaterThan(height_1);

      // nextSubmissionIdx should now be 4
      expect(await verifier.getNextSubmissionIdx()).eql(4n);

      // Verify:
      //   proof_a (cid[0])
      //   (skip proof_b)
      //   proof_c (cid[0])
      console.log("circuitIds[0]: " + circuitIds[0]);
      console.log("[pid_a_c0, pid_c_c0]: " + [pid_a_c0, pid_c_c0]);

      const vapTx = await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData([pid_a_c0, pid_c_c0]),
          [pid_a_c0, pid_c_c0],
          2,
          [],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );
      const vapReceipt = await vapTx.wait();
      console.log(
        "verifyAggregatedProof cost (dummy verifier): " + vapReceipt?.gasUsed
      );

      // To recap, we submitted 3 proofs:
      //
      //   [
      //     pid_a_c0 (idx: 1), *
      //     pid_b_c0 (idx: 2), (skipped)
      //     pid_c_c0 (idx: 3), *
      //   ]
      //
      // A batch containing [pid_a_c0, pid_c_c0] was verified, so
      // only the proofs marked * should be verified.

      expect(await verifier.nextSubmissionIdxToVerify()).equals(4n);
      expect(await verifier.lastVerifiedSubmissionHeight()).equals(height_2);

      const [
        a_c0_valid,
        b_c0_valid,
        c_c0_valid,
        a_c0_valid_id,
        b_c0_valid_id,
        c_c0_valid_id,
      ] = await Promise.all([
        verifier.getFunction(isProofVerifiedSingle)(circuitIds[0], pi_a),
        verifier.getFunction(isProofVerifiedSingle)(circuitIds[0], pi_b),
        verifier.getFunction(isProofVerifiedSingle)(circuitIds[0], pi_c),
        verifier.getFunction(isProofVerifiedByIdSingle)(pid_a_c0),
        verifier.getFunction(isProofVerifiedByIdSingle)(pid_b_c0),
        verifier.getFunction(isProofVerifiedByIdSingle)(pid_c_c0),
      ]);
      expect(a_c0_valid).is.true;
      expect(b_c0_valid).is.false;
      expect(c_c0_valid).is.true;
      expect(a_c0_valid_id).is.true;
      expect(b_c0_valid_id).is.false;
      expect(c_c0_valid_id).is.true;
    });

    it("submissions with too many public inputs should fail", async () => {
      const { upa, owner } = await deployUpaWithVerifier(undefined, 2);
      const { verifier } = upa;

      // It should reject VKs with too many public inputs
      await expect(verifier.registerVK(vk)).to.be.revertedWithCustomError(
        verifier,
        "TooManyPublicInputs"
      );

      // Upgrade the max number of public inputs
      const outerVerifierAddr = await verifier.outerVerifier();
      await verifier.connect(owner).setOuterVerifier(outerVerifierAddr, 16);

      // registering the VK again should now work
      await verifier.registerVK(vk.solidity());
      const circuitId = computeCircuitId(vk);

      // submitting a proof with too many public inputs should fail
      const publicInputs: bigint[] = Array.from({ length: 17 }, (_, i) =>
        BigInt(i)
      );
      const options = await updateFeeOptions(verifier, 1, undefined);
      await expect(
        verifier.submit(
          [circuitId],
          [pf_a.compress().solidity()],
          [publicInputs],
          options
        )
      ).to.be.revertedWithCustomError(verifier, "TooManyPublicInputs");
    });

    it("testFeeModel", async () => {
      const { upa, owner, worker, user1 } = await loadFixture(
        deployUpaDummyVerifier
      );
      const { verifier } = upa;

      // Let's compute the collateral that should stay in the contract.
      const feeModelAddress = await verifier.getAddress();
      const upaFixedFee = UpaFixedGasFee__factory.connect(
        feeModelAddress,
        owner
      );
      const collateral = await upaFixedFee.aggregatorCollateral();

      // We check the initial balance of the fee model contract. It
      // should equal the provided collateral.
      expect(await ethers.provider.getBalance(feeModelAddress)).equals(
        collateral
      );

      // Register vk
      await verifier.registerVK(vk);

      const circuitIds = (await verifier.getCircuitIds()).map(readBytes32);

      // Dummy proofs and PIs, and the corresponding proof IDs
      const pid_a_c0 = computeProofId(circuitIds[0], pi_a);
      const pid_b_c0 = computeProofId(circuitIds[0], pi_b);
      const pid_c_c0 = computeProofId(circuitIds[0], pi_c);

      // fee charged per proof. When calling submitProof,
      // it's called with this value automatically
      const options = await updateFeeOptions(verifier, 1, undefined);
      const value = BigInt(options.value!);

      // When no fee is paid the submission should be rejected. This should
      // also happen when the amount paid is not enough.
      await expect(
        submitProof(verifier, circuitIds[0], pf_a, pi_a, {
          ...options,
          value: 0,
        })
      ).to.be.revertedWithCustomError(verifier, "InsufficientFee");
      await expect(
        submitProof(verifier, circuitIds[0], pf_a, pi_a, {
          ...options,
          value: value / 2n,
        })
      ).to.be.revertedWithCustomError(verifier, "InsufficientFee");

      // Force a `gasPrice` equal to `maxFeePerGas` (used for estimating the
      // fee), but decrement the `value`.
      const valueMinusOneOptions = {
        ...options,
        gasPrice: options.maxFeePerGas,
        maxFeePerGas: undefined,
        maxPriorityFeePerGas: undefined,
        value: value - 1n,
      };
      await expect(
        submitProof(verifier, circuitIds[0], pf_a, pi_a, valueMinusOneOptions)
      ).to.be.revertedWithCustomError(verifier, "InsufficientFee");

      // Submit two proofs for cid[0]
      await submitProof(verifier, circuitIds[0], pf_a, pi_a, options);
      await submitProof(verifier, circuitIds[0], pf_b, pi_b, options);

      // After the submissions, the balance of the fee model
      // contract should equal the fee paid
      const feeModelBalance = await ethers.provider.getBalance(feeModelAddress);
      expect(feeModelBalance).equals(2n * value + collateral);

      // The total fee due should be zero because
      // it hasn't been allocated yet
      expect(await verifier.feeAllocated()).equals(0n);

      // Now the worker allocates the aggregator fee on the verifier contract.
      // The fee due must now equal the balance minus the collateral.
      await verifier.connect(worker).allocateAggregatorFee();
      const feeDue = await verifier.feeAllocated();
      expect(feeDue).equals(feeModelBalance - collateral);

      // After allocation, we change the fixed fee to be thrice as much
      // and submit the third proof. The balance should change accordingly,
      // but not the allocated fee.

      // Let's check that a user can't change the fee
      await expect(
        upaFixedFee.connect(user1).changeGasFee(3n * value)
      ).to.be.revertedWithCustomError(verifier, "OwnableUnauthorizedAccount");
      // Now we change it from the owner address

      const gasFeePerProof = await upaFixedFee.fixedGasFeePerProof();
      await upaFixedFee.changeGasFee(3n * gasFeePerProof);
      await submitProof(verifier, circuitIds[0], pf_c, pi_c, {
        value: 3n * value,
      });
      const newFeeModelBalance = await ethers.provider.getBalance(
        feeModelAddress
      );
      expect(newFeeModelBalance).equals(feeModelBalance + 3n * value);
      expect(await verifier.feeAllocated()).equals(feeDue);

      // The verifier tries to claim the fee and it fails because
      // it hasn't verified the submitted proofs yet.
      await expect(
        verifier.connect(worker).claimAggregatorFee()
      ).to.be.revertedWithCustomError(verifier, "NotEnoughProofsVerified");

      // Now it verifies one proof, but it still shouldn't be enough
      // to claim the allocated fee (which will be unlocked upon verifying
      // two proofs).
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData([pid_a_c0]),
          [pid_a_c0],
          1,
          [],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0])
        );
      await expect(
        verifier.connect(worker).claimAggregatorFee()
      ).to.be.revertedWithCustomError(verifier, "NotEnoughProofsVerified");

      // Now it verifies the second
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData([pid_b_c0]),
          [pid_b_c0],
          1,
          [],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0])
        );
      // If the worker claims it, it will succeed. Let's check the worker
      // received the funds.
      const workerBalanceBeforeClaim = await ethers.provider.getBalance(worker);
      const claimTx = await verifier.connect(worker).claimAggregatorFee();
      const claimTxReceipt = await claimTx.wait();
      const claimTxCost = claimTxReceipt!.gasUsed * claimTxReceipt!.gasPrice;
      expect(await ethers.provider.getBalance(worker)).equals(
        workerBalanceBeforeClaim - claimTxCost + feeDue
      );
      // And that the due balance is reset to zero.
      expect(await verifier.feeAllocated()).equals(0n);
      // but it still holds the funds corresponding to the third proof
      expect(await ethers.provider.getBalance(feeModelAddress)).equals(
        newFeeModelBalance - feeDue
      );
      // finally, we allocate funds for the third proof, verify it and claim the
      // remaining claimable funds
      await verifier.connect(worker).allocateAggregatorFee();
      expect(await verifier.feeAllocated()).equals(3n * value);
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData([pid_c_c0]),
          [pid_c_c0],
          1,
          [],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0])
        );
      await verifier.connect(worker).claimAggregatorFee();
      expect(await verifier.feeAllocated()).equals(0n);
      expect(await ethers.provider.getBalance(verifier)).equals(collateral);
    });
  });

  describe("Complex Submissions", () => {
    it("submitMultipleRaw", async () => {
      const { upa } = await loadFixture(deployUpaDummyVerifier);
      const { verifier } = upa;

      await verifier.registerVK(vk);
      const cid_a = computeCircuitId(vk);

      // Submit (all against cid_a):
      // 1: [ pf_a ]
      // 2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      // 3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      // Test single proof submission via submitProofs
      /* const submit_1 = */ await submitProofs(
        verifier,
        [cid_a],
        [pf_a],
        [pi_a]
      );

      // Check that multi-proof submissions fail with insufficient fees
      await expect(
        submitProofs(
          verifier,
          [cid_a, cid_a, cid_a],
          [pf_b, pf_c, pf_d],
          [pi_b, pi_c, pi_d],
          { value: 1n }
        )
      ).to.be.rejected;

      /* const submit_2 = */ await submitProofs(
        verifier,
        [cid_a, cid_a, cid_a],
        [pf_b, pf_c, pf_d],
        [pi_b, pi_c, pi_d]
      );

      /* const submit_3 = */ await submitProofs(
        verifier,
        [cid_a, cid_a],
        [pf_e, pf_f],
        [pi_e, pi_f]
      );

      // Compute the expected submission indices
      const pid_a = computeProofId(cid_a, pi_a);
      const pid_b = computeProofId(cid_a, pi_b);
      const pid_c = computeProofId(cid_a, pi_c);
      const pid_d = computeProofId(cid_a, pi_d);
      const pid_e = computeProofId(cid_a, pi_e);
      const pid_f = computeProofId(cid_a, pi_f);

      const sid_1 = evmLeafHashFn(pid_a);
      const sid_2 = computeMerkleRoot(evmLeafHashFn, evmInnerHashFn, [
        pid_b,
        pid_c,
        pid_d,
        ZERO_BYTES32,
      ]);
      const sid_3 = computeMerkleRoot(evmLeafHashFn, evmInnerHashFn, [
        pid_e,
        pid_f,
      ]);

      expect(await verifier.getNextSubmissionIdx()).equals(4);

      expect(await verifier.getSubmissionIdx(sid_1, 0)).equals(1);
      expect(await verifier.getSubmissionIdx(sid_2, 0)).equals(2);
      expect(await verifier.getSubmissionIdx(sid_3, 0)).equals(3);

      expect(await verifier.getSubmissionIdxAndNumProofs(sid_1, 0)).eql([
        1n,
        1n,
      ]);
      expect(await verifier.getSubmissionIdxAndNumProofs(sid_2, 0)).eql([
        2n,
        3n,
      ]);
      expect(await verifier.getSubmissionIdxAndNumProofs(sid_3, 0)).eql([
        3n,
        2n,
      ]);
    });

    it("submissionInterface", async () => {
      const { upa } = await loadFixture(deployUpaDummyVerifier);

      // Compute the expected submission indices
      const cid_a = computeCircuitId(vk);
      const pid_a = computeProofId(cid_a, pi_a);
      const pid_b = computeProofId(cid_a, pi_b);
      const pid_c = computeProofId(cid_a, pi_c);
      const pid_d = computeProofId(cid_a, pi_d);
      const pid_e = computeProofId(cid_a, pi_e);
      const pid_f = computeProofId(cid_a, pi_f);

      const [s1, s2, s3] = await makeSubmissions(upa);

      // Check the submission structures and their methods

      expect(s1.getProofIds()).eql([pid_a]);
      expect(s1.getSubmissionId()).eql(
        computeMerkleRoot(evmLeafHashFn, evmInnerHashFn, [pid_a])
      );
      // Submission 1 doesn't require ProofReferences
      expect(s1.computeProofReference(0)).is.undefined;
      // Submission 1 doesn't require a SubmissionProof
      expect(s1.computeSubmissionProof(0, 1)).is.undefined;

      expect(s2.getProofIds()).eql([pid_b, pid_c, pid_d]);
      expect(s2.getSubmissionId()).eql(
        computeMerkleRoot(evmLeafHashFn, evmInnerHashFn, [
          pid_b,
          pid_c,
          pid_d,
          ZERO_BYTES32,
        ])
      );
      // Submission 2 requires ProofReferences
      expect(s2.computeProofReference(0)).is.not.undefined;
      expect(s2.computeProofReference(1)).is.not.undefined;
      expect(s2.computeProofReference(2)).is.not.undefined;
      // Submission 2 requires SubmissionProofs
      expect(s2.computeSubmissionProof(0, 3)).is.not.undefined;

      expect(s3.getProofIds()).eql([pid_e, pid_f]);
      expect(s3.getSubmissionId()).eql(
        computeMerkleRoot(evmLeafHashFn, evmInnerHashFn, [pid_e, pid_f])
      );
      // Submission 3 requires ProofReferences
      expect(s3.computeProofReference(0)).is.not.undefined;
      expect(s3.computeProofReference(1)).is.not.undefined;
      // Submission 3 requires SubmissionProofs
      expect(s3.computeSubmissionProof(0, 2)).is.not.undefined;
    });

    it("submitMultipleCheckReceipts", async () => {
      const { upa, s1, s2, s3, s1_tx, s2_tx, s3_tx } = await loadFixture(
        deployAndSubmit
      );
      const { verifier } = upa;

      // Recover submissions from the tx and check they matches the original.

      const s1_chain = await Submission.fromTransactionReceipt(
        verifier,
        (await s1_tx.wait())!
      );
      expect(s1_chain.getProofIds()).eql(s1.getProofIds());

      const s2_chain = await Submission.fromTransactionReceipt(
        verifier,
        (await s2_tx.wait())!
      );
      expect(s2_chain.getProofIds()).eql(s2.getProofIds());

      const s3_chain = await Submission.fromTransactionReceipt(
        verifier,
        (await s3_tx.wait())!
      );
      expect(s3_chain.getProofIds()).eql(s3.getProofIds());
    });

    it("submitMultipleAndVerifyAll", async () => {
      const { upa, worker, s1, s2, s3, cid_a } = await loadFixture(
        deployAndSubmit
      );
      const { verifier } = upa;

      // Submissions
      const s3_height = await ethers.provider.getBlockNumber();

      // Verify submissions 1, 2, 3
      const aggBatch = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds(),
        s3.getProofIds()
      );
      const aggBatchSIDs = Array.prototype.concat(
        s1.getSubmissionId(),
        s2.getSubmissionId(),
        s3.getSubmissionId()
      );
      console.log("aggBatch: " + JSONstringify(aggBatch));
      const calldata = dummyProofData(aggBatch);

      const verifyAggTx = await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata,
          aggBatch,
          aggBatch.length,
          [
            s2.computeSubmissionProof(0, 3)!.solidity(),
            s3.computeSubmissionProof(0, 2)!.solidity(),
          ],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0, 0])
        );
      expect(await verifier.nextSubmissionIdxToVerify()).eql(4n);

      // Check SubmissionVerified events emitted

      {
        const verifyAggReceipt = await verifyAggTx.wait();
        const parsedSIDs = verifyAggReceipt!.logs.map((log) => {
          return verifier.interface.parseLog(log as unknown as Log)!.args
            .submissionId;
        });
        expect(parsedSIDs).eql(aggBatchSIDs);
      }

      // Check last verified index, last verified height, etc
      expect(await verifier.lastVerifiedSubmissionHeight()).equals(s3_height);

      // Get proof references
      const proof_ref_b = s2.computeProofReference(0)!;
      const proof_ref_c = s2.computeProofReference(1)!;
      const proof_ref_d = s2.computeProofReference(2)!;
      const proof_ref_e = s3.computeProofReference(0)!;
      const proof_ref_f = s3.computeProofReference(1)!;

      // Check verified status
      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      const isProofVerifiedByIdSingleFn = verifier.getFunction(
        isProofVerifiedByIdSingle
      );
      const isProofVerifiedByIdMultiFn = verifier.getFunction(
        isProofVerifiedbyIdMulti
      );
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const isSubmissionVerifiedFn = verifier.getFunction(isSubmissionVerified);
      const isSingleCircuitSubmissionVerifiedFn = verifier.getFunction(
        isSingleCircuitSubmissionVerified
      );
      const isSubmissionVerifiedByIdFn = verifier.getFunction(
        isSubmissionVerifiedById
      );
      const a_verified = await isProofVerifiedSingleFn(cid_a, pi_a);
      const b_verified = await isProofVerifiedMultiFn(cid_a, pi_b, proof_ref_b);
      const c_verified = await isProofVerifiedMultiFn(cid_a, pi_c, proof_ref_c);
      const d_verified = await isProofVerifiedMultiFn(cid_a, pi_d, proof_ref_d);
      const e_verified = await isProofVerifiedMultiFn(cid_a, pi_e, proof_ref_e);
      const f_verified = await isProofVerifiedMultiFn(cid_a, pi_f, proof_ref_f);
      const invalid_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_b,
        proof_ref_c
      );

      const a_verified_id = await isProofVerifiedByIdSingleFn(
        computeProofId(cid_a, pi_a)
      );
      const b_verified_id = await isProofVerifiedByIdMultiFn(
        computeProofId(cid_a, pi_b),
        proof_ref_b
      );
      const c_verified_id = await isProofVerifiedByIdMultiFn(
        computeProofId(cid_a, pi_c),
        proof_ref_c
      );
      const d_verified_id = await isProofVerifiedByIdMultiFn(
        computeProofId(cid_a, pi_d),
        proof_ref_d
      );
      const e_verified_id = await isProofVerifiedByIdMultiFn(
        computeProofId(cid_a, pi_e),
        proof_ref_e
      );
      const f_verified_id = await isProofVerifiedByIdMultiFn(
        computeProofId(cid_a, pi_f),
        proof_ref_f
      );
      const invalid_verified_id = await isProofVerifiedByIdMultiFn(
        computeProofId(cid_a, pi_b),
        proof_ref_c
      );

      expect(a_verified).is.true;
      expect(b_verified).is.true;
      expect(c_verified).is.true;
      expect(d_verified).is.true;
      expect(e_verified).is.true;
      expect(f_verified).is.true;
      expect(invalid_verified).is.false;
      expect(a_verified_id).is.true;
      expect(b_verified_id).is.true;
      expect(c_verified_id).is.true;
      expect(d_verified_id).is.true;
      expect(e_verified_id).is.true;
      expect(f_verified_id).is.true;
      expect(invalid_verified_id).is.false;

      // Check submission verified status
      const s1_verified_id = await isSubmissionVerifiedByIdFn(
        s1.getSubmissionId()
      );
      const s1_verified = await isSubmissionVerifiedFn(
        s1.circuitIds,
        s1.inputs
      );
      const s1_verified_single_cid = await isSingleCircuitSubmissionVerifiedFn(
        s1.circuitIds[0],
        s1.inputs
      );
      const s2_verified_id = await isSubmissionVerifiedByIdFn(
        s2.getSubmissionId()
      );
      const s2_verified = await isSubmissionVerifiedFn(
        s2.circuitIds,
        s2.inputs
      );
      const s2_verified_single_cid = await isSingleCircuitSubmissionVerifiedFn(
        s2.circuitIds[0],
        s2.inputs
      );
      const s3_verified_id = await isSubmissionVerifiedByIdFn(
        s3.getSubmissionId()
      );
      const s3_verified = await isSubmissionVerifiedFn(
        s3.circuitIds,
        s3.inputs
      );
      const s3_verified_single_cid = await isSingleCircuitSubmissionVerifiedFn(
        s3.circuitIds[0],
        s3.inputs
      );
      const invalid_submission = Submission.fromCircuitIdsProofsAndInputs([
        { circuitId: cid_a, proof: pf_a, inputs: pi_b },
      ]);
      const invalid_submission_verified = await isSubmissionVerifiedByIdFn(
        invalid_submission.getSubmissionId()
      );

      expect(s1_verified_id).is.true;
      expect(s1_verified).is.true;
      expect(s1_verified_single_cid).is.true;
      expect(s2_verified_id).is.true;
      expect(s2_verified).is.true;
      expect(s2_verified_single_cid).is.true;
      expect(s3_verified_id).is.true;
      expect(s3_verified).is.true;
      expect(s3_verified_single_cid).is.true;
      expect(invalid_submission_verified).is.false;
    });

    it("submitMultipleAndVerifySubsetsCaseA", async () => {
      const { upa, worker, s1, s2, s3, cid_a } = await loadFixture(
        deployAndSubmit
      );
      const { verifier } = upa;

      const isSubmissionVerifiedFn = verifier.getFunction(isSubmissionVerified);
      const isSubmissionVerifiedByIdFn = verifier.getFunction(
        isSubmissionVerifiedById
      );

      expect(await isSubmissionVerifiedByIdFn(s1.getSubmissionId())).is.false;
      expect(await isSubmissionVerifiedFn(s1.circuitIds, s1.inputs)).is.false;

      // Submit 3 submissions (all against cid_a):
      //
      //   s1: [ pf_a ]
      //   s2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   s3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c, pid_d] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      // Verify subsets:
      //
      //   agg1: [ pf_a, pf_b ]
      //   agg2: [ pf_c, pf_d ]

      const agg1 = [pid_a, pid_b];
      const calldata1 = dummyProofData(agg1);
      const pf2_1 = s2.computeSubmissionProof(0, 1)!; // proof for pf_b only
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata1,
          agg1,
          agg1.length,
          [pf2_1.solidity()],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );

      // Check the UpaVerifier state.
      {
        expect(await verifier.nextSubmissionIdxToVerify()).eql(2n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(1)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(2)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(3)).eql(0n);

        expect(await isSubmissionVerifiedByIdFn(s1.getSubmissionId())).is.true;
        expect(await isSubmissionVerifiedFn(s1.circuitIds, s1.inputs)).is.true;
        expect(await isSubmissionVerifiedByIdFn(s2.getSubmissionId())).is.false;
        expect(await isSubmissionVerifiedFn(s2.circuitIds, s2.inputs)).is.false;
      }

      const agg2 = [pid_c, pid_d];
      const calldata2 = dummyProofData(agg2);
      const pf2_2 = s2.computeSubmissionProof(1, 2)!; // proof for pf_c, pf_d
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata2,
          agg2,
          agg2.length,
          [pf2_2.solidity()],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );

      // Check the UpaVerifier state.
      {
        expect(await verifier.nextSubmissionIdxToVerify()).eql(3n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(1)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(2)).eql(3n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(3)).eql(0n);

        expect(await isSubmissionVerifiedByIdFn(s2.getSubmissionId())).is.true;
      }

      // Check verified status

      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const a_verified = await isProofVerifiedSingleFn(cid_a, pi_a);
      const b_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_b,
        s2.computeProofReference(0)!
      );
      const c_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_c,
        s2.computeProofReference(1)!
      );
      const d_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_d,
        s2.computeProofReference(2)!
      );
      const e_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_e,
        s3.computeProofReference(0)!
      );
      const f_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_f,
        s3.computeProofReference(1)!
      );
      expect(a_verified).is.true;
      expect(b_verified).is.true;
      expect(c_verified).is.true;
      expect(d_verified).is.true;
      expect(e_verified).is.false;
      expect(f_verified).is.false;
    });

    it("submitMultipleAndVerifySubsetsCaseB", async () => {
      const { upa, worker, s1, s2, s3, cid_a } = await loadFixture(
        deployAndSubmit
      );
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c, pid_d] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      // Case B:
      //
      //   agg1: [ pf_a, pf_b ]
      //   agg2: [ pf_c ]
      //   agg3: [ pf_d ]

      // Submit agg1: [ pf_a, pf_b ]
      {
        const agg1 = [pid_a, pid_b];
        const calldata1 = dummyProofData(agg1);
        const pf2_1 = s2.computeSubmissionProof(0, 1)!; // proof for pf_b only
        await verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [pf2_1.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0])
          );
      }

      // Check the UpaVerifier state.
      {
        expect(await verifier.nextSubmissionIdxToVerify()).eql(2n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(1)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(2)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(3)).eql(0n);
      }

      // Submit agg2: [ pf_c ]
      {
        const agg2 = [pid_c];
        const calldata2 = dummyProofData(agg2);
        const pf2_2 = s2.computeSubmissionProof(1, 1)!; // proof for pf_c
        await verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata2,
            agg2,
            agg2.length,
            [pf2_2.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0])
          );
      }

      // Check the UpaVerifier state.
      {
        expect(await verifier.nextSubmissionIdxToVerify()).eql(2n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(1)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(2)).eql(2n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(3)).eql(0n);
      }

      // Submit agg3: [ pf_d ]
      {
        const agg3 = [pid_d];
        const calldata3 = dummyProofData(agg3);
        const pf2_3 = s2.computeSubmissionProof(2, 1)!; // proof for pf_d
        await verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata3,
            agg3,
            agg3.length,
            [pf2_3.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0])
          );
      }

      // Check the UpaVerifier state.
      {
        expect(await verifier.nextSubmissionIdxToVerify()).eql(3n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(1)).eql(1n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(2)).eql(3n);
        expect(await verifier.getNumVerifiedForSubmissionIdx(3)).eql(0n);
      }

      // Check verified status

      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const a_verified = await isProofVerifiedSingleFn(cid_a, pi_a);
      const b_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_b,
        s2.computeProofReference(0)!
      );
      const c_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_c,
        s2.computeProofReference(1)!
      );
      const d_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_d,
        s2.computeProofReference(2)!
      );
      const e_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_e,
        s3.computeProofReference(0)!
      );
      const f_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_f,
        s3.computeProofReference(1)!
      );
      expect(a_verified).is.true;
      expect(b_verified).is.true;
      expect(c_verified).is.true;
      expect(d_verified).is.true;
      expect(e_verified).is.false;
      expect(f_verified).is.false;
    });

    it("submitMultipleAndVerifySubsetsCaseC", async () => {
      const { upa, worker, s1, s2, s3, cid_a } = await loadFixture(
        deployAndSubmit
      );
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c, pid_d, pid_e, pid_f] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds(),
        s3.getProofIds()
      );

      // Case C:
      //
      //   agg1: [ pf_a, pf_b ]
      //   agg2: [ pf_c, pf_d, pf_e, pf_f ]

      const agg1 = [pid_a, pid_b];
      const calldata1 = dummyProofData(agg1);
      const pf2_1 = s2.computeSubmissionProof(0, 1)!; // proof for pf_b only
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata1,
          agg1,
          agg1.length,
          [pf2_1.solidity()],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );

      const agg2 = [pid_c, pid_d, pid_e, pid_f];
      const calldata2 = dummyProofData(agg2);
      const pf2_2 = s2.computeSubmissionProof(1, 2)!; // proof for pf_c, pf_d
      const pf3_1 = s3.computeSubmissionProof(0, 2)!; // proof for pf_e, pf_f
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata2,
          agg2,
          agg2.length,
          [pf2_2.solidity(), pf3_1.solidity()],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );
      expect(await verifier.nextSubmissionIdxToVerify()).eql(4n);

      // Check verified status

      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const a_verified = await isProofVerifiedSingleFn(cid_a, pi_a);
      const b_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_b,
        s2.computeProofReference(0)!
      );
      const c_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_c,
        s2.computeProofReference(1)!
      );
      const d_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_d,
        s2.computeProofReference(2)!
      );
      const e_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_e,
        s3.computeProofReference(0)!
      );
      const f_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_f,
        s3.computeProofReference(1)!
      );
      expect(a_verified).is.true;
      expect(b_verified).is.true;
      expect(c_verified).is.true;
      expect(d_verified).is.true;
      expect(e_verified).is.true;
      expect(f_verified).is.true;
    });

    it("submitMultipleAndVerifySubsetsCaseD", async () => {
      const { upa, worker, s1, s2, s3, cid_a } = await loadFixture(
        deployAndSubmit
      );
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c, pid_d, pid_e, pid_f] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds(),
        s3.getProofIds()
      );

      // Case C:
      //
      //   agg1: [ pf_a, pf_e, pf_f ] (Skip submission 2)

      const agg1 = [pid_a, pid_e, pid_f];
      const calldata1 = dummyProofData(agg1);
      const pf3_1 = s3.computeSubmissionProof(0, 2)!; // proof for pf_e, pf_f
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata1,
          agg1,
          agg1.length,
          [pf3_1.solidity()],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );
      expect(await verifier.nextSubmissionIdxToVerify()).eql(4n);

      // Check verified status

      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const isProofIdVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedByIdSingle
      );
      const isProofIdVerifiedMultiFn = verifier.getFunction(
        isProofVerifiedbyIdMulti
      );
      const isSubmissionVerifiedFn = verifier.getFunction(isSubmissionVerified);
      const isSingleCircuitSubmissionVerifiedFn = verifier.getFunction(
        isSingleCircuitSubmissionVerified
      );
      const isSubmissionVerifiedByIdFn = verifier.getFunction(
        isSubmissionVerifiedById
      );
      const a_verified = await isProofVerifiedSingleFn(cid_a, pi_a);
      const b_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_b,
        s2.computeProofReference(0)!
      );
      const c_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_c,
        s2.computeProofReference(1)!
      );
      const d_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_d,
        s2.computeProofReference(2)!
      );
      const e_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_e,
        s3.computeProofReference(0)!
      );
      const f_verified = await isProofVerifiedMultiFn(
        cid_a,
        pi_f,
        s3.computeProofReference(1)!
      );
      const a_verified_id = await isProofIdVerifiedSingleFn(pid_a);
      const b_verified_id = await isProofIdVerifiedMultiFn(
        pid_b,
        s2.computeProofReference(0)!
      );
      const c_verified_id = await isProofIdVerifiedMultiFn(
        pid_c,
        s2.computeProofReference(1)!
      );
      const d_verified_id = await isProofIdVerifiedMultiFn(
        pid_d,
        s2.computeProofReference(2)!
      );
      const e_verified_id = await isProofIdVerifiedMultiFn(
        pid_e,
        s3.computeProofReference(0)!
      );
      const f_verified_id = await isProofIdVerifiedMultiFn(
        pid_f,
        s3.computeProofReference(1)!
      );
      expect(a_verified).is.true;
      expect(b_verified).is.false;
      expect(c_verified).is.false;
      expect(d_verified).is.false;
      expect(e_verified).is.true;
      expect(f_verified).is.true;
      expect(a_verified_id).is.true;
      expect(b_verified_id).is.false;
      expect(c_verified_id).is.false;
      expect(d_verified_id).is.false;
      expect(e_verified_id).is.true;
      expect(f_verified_id).is.true;

      // Check submission verified status
      const s1_verified_id = await isSubmissionVerifiedByIdFn(
        s1.getSubmissionId()
      );
      const s1_verified = await isSubmissionVerifiedFn(
        s1.circuitIds,
        s1.inputs
      );
      const s1_verified_single_cid = await isSingleCircuitSubmissionVerifiedFn(
        s1.circuitIds[0],
        s1.inputs
      );
      const s2_verified_id = await isSubmissionVerifiedByIdFn(
        s2.getSubmissionId()
      );
      const s2_verified = await isSubmissionVerifiedFn(
        s2.circuitIds,
        s2.inputs
      );
      const s2_verified_single_cid = await isSingleCircuitSubmissionVerifiedFn(
        s2.circuitIds[0],
        s2.inputs
      );
      const s3_verified_id = await isSubmissionVerifiedByIdFn(
        s3.getSubmissionId()
      );
      const s3_verified = await isSubmissionVerifiedFn(
        s3.circuitIds,
        s3.inputs
      );
      const s3_verified_single_cid = await isSingleCircuitSubmissionVerifiedFn(
        s3.circuitIds[0],
        s3.inputs
      );

      expect(s1_verified_id).is.true;
      expect(s1_verified).is.true;
      expect(s1_verified_single_cid).is.true;
      expect(s2_verified_id).is.false;
      expect(s2_verified).is.false;
      expect(s2_verified_single_cid).is.false;
      expect(s3_verified_id).is.true;
      expect(s3_verified).is.true;
      expect(s3_verified_single_cid).is.true;
    });

    it("submit and verify 32 proofs (gas costs)", async () => {
      const AGG_BATCH_SIZE = 32;

      // Submit 32 proofs as submissions of the given size.
      async function deployAndSubmit(submissionSize: number) {
        const { upa, worker } = await loadFixture(deployUpaDummyVerifier);
        const { verifier } = upa;

        await verifier.registerVK(vk.solidity());
        const cid_a = computeCircuitId(vk);

        // Num submissions:
        const numSubmissions = (AGG_BATCH_SIZE / submissionSize) | 0;
        expect(numSubmissions * submissionSize).eql(AGG_BATCH_SIZE);

        let proofIdx = 0;
        const submissions: OffChainSubmission[] = [];
        for (
          let submissionIdx = 0;
          submissionIdx < numSubmissions;
          ++submissionIdx
        ) {
          // Submission of n proofs:
          const submissionParams: CircuitIdProofAndInputs[] = [];
          for (let i = 0; i < submissionSize; ++i) {
            submissionParams.push({
              circuitId: cid_a,
              proof: pf_a,
              inputs: [BigInt(proofIdx++)],
            });
          }

          const submission =
            OffChainSubmission.fromCircuitIdsProofsAndInputs(submissionParams);
          {
            const submitTx = await submitProofs(
              verifier,
              submission.circuitIds,
              submission.proofs,
              submission.inputs
            );

            if (submissionIdx == 0) {
              const submitReceipt = await submitTx.wait();
              const gasUsed = submitReceipt!.gasUsed;
              console.log(
                ` submit(${submissionSize} pfs, 1 submission): ${gasUsed} gas`
              );
            }
          }

          submissions.push(submission);
        }

        return { upa, worker, submissions };
      }

      // Very 32 proofs, submitted as submission of the given size.
      async function verifySubmissions(submissionSize: number) {
        const { upa, worker, submissions } = await deployAndSubmit(
          submissionSize
        );
        const { verifier } = upa;

        const proofIds = submissions.flatMap((s) => s.getProofIds());
        const calldata = dummyProofData(proofIds);
        const submitPfs: SubmissionProof[] = submissions
          .map((s) => {
            return s.computeSubmissionProof(0, submissionSize);
          })
          .filter((x) => x) as SubmissionProof[];
        const dupSubmissionIdxs = submissions.map(() => 0);
        const verifyTx = await verifier.connect(worker).verifyAggregatedProof(
          calldata,
          proofIds,
          proofIds.length,
          submitPfs.map((s) => s.solidity()),
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs(dupSubmissionIdxs)
        );
        const verifyReceipt = await verifyTx.wait();
        console.log(
          ` verify cost (${submissionSize} proofs/submission (dummy verif))` +
            ` = ${verifyReceipt!.gasUsed} gas`
        );

        // isVerified

        const verifyProofIdx = 0;
        const cid = submissions[0].circuitIds[0];
        const inputs = submissions[0].inputs[0];
        const isVerifiedTx = await (() => {
          const proofRef = submissions[0].computeProofReference(0);
          if (proofRef) {
            return verifier
              .getFunction(isProofVerifiedMulti)
              .send(cid, inputs, proofRef);
          }
          return verifier.getFunction(isProofVerifiedSingle).send(cid, inputs);
        })();
        const isVerifiedReceipt = await isVerifiedTx.wait();
        console.log(
          ` isVerified(${verifyProofIdx}) (submissionSize: ${submissionSize})` +
            ` cost = ${isVerifiedReceipt!.gasUsed} gas`
        );
      }

      // Verify

      await verifySubmissions(1);
      await verifySubmissions(2);
      await verifySubmissions(4);
      await verifySubmissions(8);
      await verifySubmissions(16);
      await verifySubmissions(32);
    }).timeout(60000);

    it("rejects aggregated proofs with invalid final digest", async () => {
      const { upa, worker, s1, s2 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c, pid_d] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      // Aggregate submissions 1 and 2, but use invalid final digest:
      //
      const agg1 = [pid_a, pid_b, pid_c, pid_d];
      const calldata1 = dummyProofData([pid_a, pid_b]);
      const pf2_1 = s2.computeSubmissionProof(0, 3)!; // proof for pf_e, pf_f
      await expect(
        verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [pf2_1.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0])
          )
      ).to.be.rejected;
    });

    it("rejects aggregated proofs with invalid merkle proofs", async () => {
      const { upa, worker, s1, s2 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      //   agg1: [ pf_a, pf_b, pf_c ]
      //         with invalid submission proof

      const agg1 = [pid_a, pid_b, pid_c];
      const calldata1 = dummyProofData(agg1);
      const pf2_1 = s2.computeSubmissionProof(0, 1)!; // proof for pf_b only
      await expect(
        verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [pf2_1.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0])
          )
      ).to.be.revertedWithCustomError(verifier, "InvalidMerkleIntervalProof");
    });

    it("rejects aggregated proofs with out-of-order proofs", async () => {
      const { upa, worker, s1, s2 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      //   agg1: [ pf_a, pf_c, pf_b ]
      //   - proofs in submission verified out of order
      const agg1 = [pid_a, pid_c, pid_b];
      const calldata1 = dummyProofData(agg1);
      const pf2_1 = s2.computeSubmissionProof(0, 2)!; // proof for pf_b only
      await expect(
        verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [pf2_1.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0])
          )
      ).to.be.revertedWithCustomError(verifier, "InvalidMerkleIntervalProof");
    });

    it("rejects aggregated proofs with missing submission proof", async () => {
      const { upa, worker, s1, s2 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, pid_c] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      //   agg1: [ pf_a, pf_b, pf_c ]
      const agg1 = [pid_a, pid_b, pid_c];
      const calldata1 = dummyProofData(agg1);
      await expect(
        verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0])
          )
      ).to.be.revertedWithCustomError(verifier, "MissingSubmissionProof");
    });

    it("rejects aggregated proofs with out-of-order submissions", async () => {
      const { upa, worker, s1, s2, s3 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]        (Merkle depth 2, full)

      const [pid_a, pid_b, , , pid_e, pid_f] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds(),
        s3.getProofIds()
      );

      //   agg2: [ pf_a, pf_e, pf_f, pf_b ]
      //   - submissions out of order

      const agg1 = [pid_a, pid_e, pid_f, pid_b];
      const calldata1 = dummyProofData(agg1);
      const pf3_1 = s3.computeSubmissionProof(0, 2)!; // proof for pf_e, pf_f
      const pf2_1 = s2.computeSubmissionProof(0, 1)!; // proof for pf_b only
      await expect(
        verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [pf3_1.solidity(), pf2_1.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0, 0])
          )
      ).to.be.revertedWithCustomError(verifier, "SubmissionOutOfOrder");
    });

    it("rejects agg proof if a submission's proof is skipped", async () => {
      const { upa, worker, s1, s2 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)

      const [pid_a, pid_b, pid_c] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds()
      );

      //   agg1: [ pf_a, pf_c, pf_d ]
      //   - skipped pf_b in submission 2
      const agg1 = [pid_a, pid_c, pid_b];
      const calldata1 = dummyProofData(agg1);
      const pf2_1 = s2.computeSubmissionProof(1, 2)!; // proof for pf_c, pf_d
      await expect(
        verifier
          .connect(worker)
          .verifyAggregatedProof(
            calldata1,
            agg1,
            agg1.length,
            [pf2_1.solidity()],
            packOffChainSubmissionMarkers([]),
            packDupSubmissionIdxs([0, 0])
          )
      ).to.be.revertedWithCustomError(verifier, "InvalidMerkleIntervalProof");
    });

    it("Accepts agg proof skipping a full submission", async () => {
      const { upa, worker, s1, s2, s3 } = await loadFixture(deployAndSubmit);
      const { verifier } = upa;

      // Submit 3 submissions (all against cid_a):
      //
      //   1: [ pf_a ]
      //   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
      //   3: [ pf_e, pf_f ]

      const [pid_a, , , , pid_e, pid_f] = Array.prototype.concat(
        s1.getProofIds(),
        s2.getProofIds(),
        s3.getProofIds()
      );

      //   agg1: [ pf_a ]
      //   agg3: [ pf_e, pf_f ]
      //   - skipped all proofs in submission 2
      const agg1 = [pid_a];
      const calldata1 = dummyProofData(agg1);
      const agg3 = [pid_e, pid_f];
      const calldata3 = dummyProofData(agg3);
      const pf3 = s3.computeSubmissionProof(0, 2)!; // proof for pf_e, pf_f
      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata1,
          agg1,
          agg1.length,
          [],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0, 0])
        );

      await verifier
        .connect(worker)
        .verifyAggregatedProof(
          calldata3,
          agg3,
          agg3.length,
          [pf3.solidity()],
          packOffChainSubmissionMarkers([]),
          packDupSubmissionIdxs([0])
        );
    });
  });

  describe("Calldata verification", () => {
    it("verify calldata", async () => {
      const { upa } = await loadFixture(deployAndUpgradeUpa);
      const { verifier: verifier } = upa;
      const calldata = readFileSync("test/data/outer_2_2.proof.calldata");

      // Load test calldata corresponding to these pids:
      const pids = [
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
        "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765f",
      ];

      // Invalid PIDs should cause a failure
      {
        pids[3] =
          "0x096b71958a31f9198721fdbae1b697a4845ea39d31cf34ea5324e716b48e765e";
        await expect(verifier.verifyProofForIDs(pids, calldata)).reverted;
        pids[3] = pids[2];
      }

      // Invalid public input data should cause a failure
      {
        const x = calldata[0x19f]; // final bytes of digest_l
        calldata[0x19f] += 1;
        await expect(verifier.verifyProofForIDs(pids, calldata)).reverted;
        calldata[0x19f] = x;
      }

      // Invalid proof data should cause an error
      {
        const offset = 0x1c0; // byte immediately after digest PI entries
        const x = calldata[offset];
        calldata[offset] += 1;
        await expect(verifier.verifyProofForIDs(pids, calldata)).reverted;
        calldata[offset] = x;
      }

      await verifier.verifyProofForIDs(pids, calldata);
    });
  });
});
