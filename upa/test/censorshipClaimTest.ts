import { deployUpaDummyVerifier } from "./deploy";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { loadAppVkProofInputsBatchFile } from "../src/tool/config";
import { BigNumberish, Signer } from "ethers";
import { Groth16Proof, Groth16VerifyingKey } from "../src/sdk/application";
import {
  isProofVerifiedSingle,
  submitProof,
  submitProofs,
  UpaInstance,
  dummyProofData,
  isProofVerifiedMulti,
  isSubmissionVerifiedById,
} from "../src/sdk/upa";
import {
  computeProofId,
  computeCircuitId,
  JSONstringify,
} from "../src/sdk/utils";
import { expect } from "chai";
import { Submission } from "../src/sdk";
import { UpaVerifier } from "../typechain-types";
import {
  packDupSubmissionIdxs,
  packOffChainSubmissionMarkers,
} from "../src/sdk/aggregatedProofParams";
// eslint-disable-next-line
import { computeAggregatedProofParameters } from "../src/sdk/aggregatedProofParams";
import { siFromSubmission } from "../src/sdk/submissionIntervals";
import { decompressG1Point } from "../src/sdk/pointCompression";
import {
  ChallengeEventGetter,
  getCalldataForChallengeTx,
  SubmissionChallengeSuccessEventGetter,
} from "../src/sdk/events";

describe("Censorship challenge tests", () => {
  type DeployAndSubmitResult = DeployAndRegisterResult & {
    s1: Submission;
    s2: Submission;
    s3: Submission;
    user1StartBalance: bigint;
  };
  type DeployAndRegisterResult = {
    upa: UpaInstance;
    worker: Signer;
    user1: Signer;
    user2: Signer;
    circuitIds: string[];
    proofs: Groth16Proof[];
    inputs: BigNumberish[][];
    proofIds: string[];
  };

  /// Deploys a Upa instance. Registers all VKs and returns an array with the
  /// circuitIds, proofs and public inputs.
  async function deployAndRegister(
    withCommitment: boolean
  ): Promise<DeployAndRegisterResult> {
    // Deploy upa
    const { upa, worker, user1, user2 } = await loadFixture(
      deployUpaDummyVerifier
    );
    const { verifier } = upa;
    const vkProofInputsBatchFile = withCommitment
      ? "../circuits/src/tests/data/commitment_proof_batch_8_proofs.json"
      : "../circuits/src/tests/data/universal_batch_verifier_10_proofs.json";
    console.log(`loaded proof batch: ${vkProofInputsBatchFile}`);

    const vkProofsAndInputs = loadAppVkProofInputsBatchFile(
      vkProofInputsBatchFile
    );

    const vks: Groth16VerifyingKey[] = [];
    const proofs: Groth16Proof[] = [];
    const inputs: BigNumberish[][] = [];
    vkProofsAndInputs.forEach((element) => {
      vks.push(element.vk);
      proofs.push(element.proof);
      inputs.push(element.inputs);
    });

    // register all vks and compute the proofIds
    const circuitIds: string[] = [];
    for (const vk of vks) {
      try {
        await verifier.connect(user1).registerVK(vk);
      } catch {
        // the vk had been registered before. do nothing
      }
      circuitIds.push(computeCircuitId(vk));
    }

    const proofIds = circuitIds.map((circuitId, i) =>
      computeProofId(circuitId, inputs[i])
    );

    return {
      upa,
      worker,
      user1,
      user2,
      circuitIds,
      proofs,
      inputs,
      proofIds,
    };
  }

  /// Deploys and registers the VKs. Then user1 submits a single proof, then two
  /// proofs and then user2 submits two proofs.
  async function deployAndSubmit(
    withCommitment: boolean
  ): Promise<DeployAndSubmitResult> {
    const deployAndRegisterResult = await deployAndRegister(withCommitment);
    const { upa, user1, user2, circuitIds, proofs, inputs } =
      deployAndRegisterResult;
    const { verifier } = upa;

    const user1StartBalance = await verifier.runner!.provider!.getBalance(
      user1
    );

    // User 1 submits a valid proof
    const firstTx = await submitProof(
      verifier.connect(user1),
      circuitIds[0],
      proofs[0],
      inputs[0]
    );
    // User 1 submits a submission consisting of 2 valid proofs
    const secondTx = await submitProofs(
      verifier.connect(user1),
      circuitIds.slice(1, 3),
      proofs.slice(1, 3),
      inputs.slice(1, 3)
    );
    // User 2 submits 2 valid proofs
    const thirdTx = await submitProofs(
      verifier.connect(user2),
      circuitIds.slice(3, 5),
      proofs.slice(3, 5),
      inputs.slice(3, 5)
    );

    const s1P = Submission.fromTransactionReceipt(
      verifier,
      (await firstTx.wait())!
    );
    const s2P = Submission.fromTransactionReceipt(
      verifier,
      (await secondTx.wait())!
    );
    const s3P = Submission.fromTransactionReceipt(
      verifier,
      (await thirdTx.wait())!
    );

    return {
      ...deployAndRegisterResult,
      s1: (await s1P)!,
      s2: (await s2P)!,
      s3: (await s3P)!,
      user1StartBalance,
    };
  }

  /// Verifies the submission
  async function verifySubmission(
    verifier: UpaVerifier,
    worker: Signer,
    s: Submission
  ) {
    const submissionInterval = siFromSubmission(s, undefined);
    const aggProofParams = computeAggregatedProofParameters(
      [submissionInterval],
      []
    );

    await verifier.connect(worker).verifyAggregatedProof(
      dummyProofData(aggProofParams.proofIds),
      aggProofParams.proofIds,
      aggProofParams.numOnChainProofs,
      aggProofParams.submissionProofs.map((p) => p.solidity()),
      packOffChainSubmissionMarkers(aggProofParams.offChainSubmissionMarkers),
      packDupSubmissionIdxs(aggProofParams.dupSubmissionIdxs)
    );
  }

  // Cannot use anonymous functions as fixtures so name them here.
  const deployAndSubmitWithoutCommitment = () => deployAndSubmit(false);
  const deployAndSubmitWithCommitment = () => deployAndSubmit(true);

  const testFixtures = [
    deployAndSubmitWithoutCommitment,
    deployAndSubmitWithCommitment,
  ];

  // Run each test with or without a commitment point.
  testFixtures.forEach(function (fixture) {
    it("single censorship challenge", async function () {
      const { upa, worker, user1, s1, s2 } = await loadFixture(fixture);
      const { verifier } = upa;
      // The aggregator will aggregate the second submission,
      // skipping the first
      await verifySubmission(verifier, worker, s2);
      // Check the proof in s1 is not verified
      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to
        .be.false;
      // user1 submits a censorship challenge
      await verifier
        .connect(user1)
        .challenge(
          s1.circuitIds[0],
          s1.proofs[0].solidity(),
          s1.inputs[0],
          s1.submissionId,
          0,
          s1.computeProofIdMerkleProof(0),
          s1.computeProofDataMerkleProof(0)
        );
      // The challenge passes and the proof is now marked as verified
      expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to
        .be.true;
    }).timeout(200000);

    it("duplicate submission censorship challenge", async function () {
      const { upa, worker, user1, s2, s3 } = await loadFixture(fixture);
      const { verifier } = upa;

      // Re-submit s2 as user 1
      const dupSubmissionTx = await submitProofs(
        verifier.connect(user1),
        s2.circuitIds,
        s2.proofs,
        s2.inputs
      );
      const dupSubmission = (await Submission.fromTransactionReceipt(
        verifier,
        (await dupSubmissionTx.wait())!
      ))!;

      // Verify the 3rd submission and this duplicate.
      await verifySubmission(verifier, worker, s3);
      await verifySubmission(verifier, worker, dupSubmission);

      expect(
        await verifier.getFunction(isSubmissionVerifiedById)(s2.submissionId)
      ).is.true;

      const numProofsInS2 = s2.circuitIds.length;

      // Challenge to upa should fail
      for (let i = 0; i < numProofsInS2; i++) {
        await expect(
          verifier
            .connect(user1)
            .challenge(
              s2.circuitIds[i],
              s2.proofs[i].solidity(),
              s2.inputs[i],
              s2.submissionId,
              dupSubmission.getDupSubmissionIdx(),
              s2.computeProofIdMerkleProof(i),
              s2.computeProofDataMerkleProof(i)
            )
        ).to.be.revertedWithCustomError(verifier, "SubmissionAlreadyVerified");
      }

      // Challenge to the initial s2, as user1, should work.
      for (let i = 0; i < numProofsInS2; i++) {
        await verifier
          .connect(user1)
          .challenge(
            s2.circuitIds[i],
            s2.proofs[i].solidity(),
            s2.inputs[i],
            s2.submissionId,
            s2.getDupSubmissionIdx(),
            s2.computeProofIdMerkleProof(i),
            s2.computeProofDataMerkleProof(i)
          );
      }
    }).timeout(200000);
    it("multi censorship challenge", async function () {
      const { upa, worker, user1, s1, s2, s3, user1StartBalance } =
        await loadFixture(fixture);
      const { verifier } = upa;
      // The aggregator will aggregate the first and third submissions,
      // skipping the second
      await verifySubmission(verifier, worker, s1);
      await verifySubmission(verifier, worker, s3);
      // Check the proofs in s2 are not verified
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const numProofsInS2 = s2.circuitIds.length;
      for (let i = 0; i < numProofsInS2; i++) {
        expect(
          await isProofVerifiedMultiFn(
            s2.circuitIds[i],
            s2.inputs[i],
            s2.computeProofReference(i)!
          )
        ).to.be.false;
      }

      const provider = verifier.runner!.provider!;
      const balance0 = await provider.getBalance(user1);
      const submitCost = user1StartBalance - balance0;
      let balance1;

      // user1 submits a censorship challenge
      for (let i = 0; i < numProofsInS2; i++) {
        if (i == numProofsInS2 - 1) {
          balance1 = await provider.getBalance(user1);
        }

        await verifier
          .connect(user1)
          .challenge(
            s2.circuitIds[i],
            s2.proofs[i].solidity(),
            s2.inputs[i],
            s2.submissionId,
            0,
            s2.computeProofIdMerkleProof(i),
            s2.computeProofDataMerkleProof(i),
            {
              maxPriorityFeePerGas: 0n,
            }
          );
      }

      const balance2 = await provider.getBalance(user1);

      // Expect balance2 > balance 1
      expect(balance2).is.greaterThan(balance1);
      // Expect costAfterRefund < submitCost * 2% (we tolerate some minimal
      // loss to the caller, but it should be very small compared to the
      // overall cost)
      const costAfterRefund = balance2 - user1StartBalance;
      expect(costAfterRefund * 50n).is.lessThan(submitCost);

      // The challenge passes and the proofs are now marked as verified
      for (let i = 0; i < numProofsInS2; i++) {
        expect(
          await isProofVerifiedMultiFn(
            s2.circuitIds[i],
            s2.inputs[i],
            s2.computeProofReference(i)!
          )
        ).to.be.true;
      }

      // Test Challenge Event Getters
      const startHeight = upa.deploymentBlockNumber;
      const currHeight = await provider.getBlockNumber();
      const challengeEventGetter = new ChallengeEventGetter(upa.verifier);
      const cEventSets = await challengeEventGetter.getFullGroupedByTransaction(
        startHeight,
        currHeight
      );
      const successChallengeEventGetter =
        new SubmissionChallengeSuccessEventGetter(upa.verifier);
      const scEventSets =
        await successChallengeEventGetter.getFullGroupedByTransaction(
          startHeight,
          currHeight
        );

      // Number of challenge events should be
      // equal to number of proofs in submission
      expect(cEventSets.length).equal(numProofsInS2);
      // Number of success challenge events should be 1
      expect(scEventSets.length).equal(1);
      const firstChallengeTxHash = cEventSets[0].txHash;
      const firstChallengeTx = await provider.getTransaction(
        firstChallengeTxHash
      );
      expect(firstChallengeTx).to.not.be.null;
      const firstChallengeCalldata = getCalldataForChallengeTx(
        upa.verifier,
        firstChallengeTx!
      );

      // Test calldata parsing function (getCalldataForChallengeTx)
      expect(firstChallengeCalldata.circuitId).equal(s2.circuitIds[0]);
      expect(firstChallengeCalldata.proof).deep.equal(s2.proofs[0]);
      expect(firstChallengeCalldata.publicInputs).eql(s2.inputs[0]);
      expect(firstChallengeCalldata.submissionId).equal(s2.submissionId);
      expect(firstChallengeCalldata.dupSubmissionIdx).equal(0);
      expect(firstChallengeCalldata.proofIdMerkleProof).eql(
        s2.computeProofIdMerkleProof(0)
      );
      expect(firstChallengeCalldata.proofDataMerkleProof).eql(
        s2.computeProofDataMerkleProof(0)
      );
    }).timeout(200000);

    it("wrong claimant should fail", async function () {
      const { upa, worker, user2, s1, s2 } = await loadFixture(fixture);
      const { verifier } = upa;
      // The aggregator will aggregate the second submission,
      // skipping the first
      await verifySubmission(verifier, worker, s2);
      // Check the proof in s1 is not verified
      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to
        .be.false;
      // user2 submits a censorship challenge, which should
      // fail because he wasn't the original submitter
      await expect(
        verifier
          .connect(user2)
          .challenge(
            s1.circuitIds[0],
            s1.proofs[0].solidity(),
            s1.inputs[0],
            s1.submissionId,
            0,
            s1.computeProofIdMerkleProof(0),
            s1.computeProofDataMerkleProof(0)
          )
      ).to.be.revertedWithCustomError(verifier, "InvalidProofDataDigest");
    }).timeout(100000);

    it("already verified proof should fail", async function () {
      const { upa, worker, user1, s1, s2 } = await loadFixture(fixture);
      const { verifier } = upa;
      // The aggregator will aggregate both the first and second
      // submissions
      await verifySubmission(verifier, worker, s1);
      await verifySubmission(verifier, worker, s2);
      // Check the proof in s1 is verified
      const isProofVerifiedSingleFn = verifier.getFunction(
        isProofVerifiedSingle
      );
      expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to
        .be.true;
      // user1 submits a censorship challenge, which should
      // fail because the first proof is aggregated
      await expect(
        verifier
          .connect(user1)
          .challenge(
            s1.circuitIds[0],
            s1.proofs[0].solidity(),
            s1.inputs[0],
            s1.submissionId,
            0,
            s1.computeProofIdMerkleProof(0),
            s1.computeProofDataMerkleProof(0)
          )
      ).to.be.revertedWithCustomError(verifier, "SubmissionAlreadyVerified");
    }).timeout(100000);

    it("not yet skipped proof should fail", async function () {
      const { upa, worker, user2, s1, s2, s3 } = await loadFixture(fixture);
      const { verifier } = upa;
      // The aggregator will aggregate both the first and second
      // submissions, but not the third
      await verifySubmission(verifier, worker, s1);
      await verifySubmission(verifier, worker, s2);
      // Check the proofs in s3 are not verified
      const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
      const numProofsInS3 = s3.circuitIds.length;
      for (let i = 0; i < numProofsInS3; i++) {
        expect(
          await isProofVerifiedMultiFn(
            s3.circuitIds[i],
            s3.inputs[i],
            s3.computeProofReference(i)!
          )
        ).to.be.false;
      }
      // user2 submits a censorship challenge, which should
      // fail because the aggregator didn't skip the batch s3: there
      // aren't any batches with higher index verified
      for (let i = 0; i < numProofsInS3; i++) {
        await expect(
          verifier
            .connect(user2)
            .challenge(
              s3.circuitIds[i],
              s3.proofs[i].solidity(),
              s3.inputs[i],
              s3.submissionId,
              0,
              s3.computeProofIdMerkleProof(i),
              s3.computeProofDataMerkleProof(i)
            )
        ).to.be.revertedWithCustomError(verifier, "SubmissionWasNotSkipped");
      }
    }).timeout(100000);

    it("false proof should fail", async function () {
      const { upa, worker, user1, s1, s2, s3, circuitIds, proofs, inputs } =
        await loadFixture(fixture);
      const { verifier } = upa;

      // user1 submits a false proof. We fuzz the first coordinate of
      // proofs[5].pi_a in such a way that `x^3 + b` is still a square
      // in Fr.
      const wrongProof = proofs[5];
      let xCoordinateWrongProof = BigInt(proofs[5].pi_a[0]) + 1n;
      // This loop will end very early because half the elements
      // in the field Fr are squares (which is what may cause
      // `decompressG1Point` to fail).
      while (!decompressG1Point(String(xCoordinateWrongProof))) {
        xCoordinateWrongProof += 1n;
      }
      wrongProof.pi_a[0] = String(xCoordinateWrongProof);
      const invalidTx = await submitProof(
        verifier.connect(user1),
        circuitIds[5],
        wrongProof,
        inputs[5]
      );
      const invalidSubmission = (await Submission.fromTransactionReceipt(
        verifier,
        (await invalidTx.wait())!
      ))!;

      // and a valid one
      const validTx = await submitProof(
        verifier.connect(user1),
        circuitIds[6],
        proofs[6],
        inputs[6]
      );
      const validSubmission = (await Submission.fromTransactionReceipt(
        verifier,
        (await validTx.wait())!
      ))!;

      // the aggregator verifies all valid ones
      await verifySubmission(verifier, worker, s1);
      await verifySubmission(verifier, worker, s2);
      await verifySubmission(verifier, worker, s3);
      await verifySubmission(verifier, worker, validSubmission);

      // user1 makes a censorship claim, which should fail because
      // the proof is false

      console.log(`invalidSubmission: ${JSONstringify(invalidSubmission)}`);
      const invalidCircuitIds = invalidSubmission.circuitIds;
      console.log(`invalidCircuitIds: ${JSONstringify(invalidCircuitIds)}`);
      const invalidCid = invalidSubmission.circuitIds[0];

      await expect(
        verifier.connect(user1).challenge(
          // invalidSubmission.circuitIds[0],
          invalidCid,
          invalidSubmission.proofs[0].solidity(),
          invalidSubmission.inputs[0],
          invalidSubmission.submissionId,
          0,
          invalidSubmission.computeProofIdMerkleProof(0),
          invalidSubmission.computeProofDataMerkleProof(0)
        )
      ).to.be.revertedWithCustomError(verifier, "UnsuccessfulChallenge");

      // user1 makes a censorship claim, this time with a correct
      // proof, but should fail anyway because the proofDigest won't
      // match with that of `wrongProof`
      await expect(
        verifier
          .connect(user1)
          .challenge(
            invalidSubmission.circuitIds[0],
            proofs[5].solidity(),
            invalidSubmission.inputs[0],
            invalidSubmission.submissionId,
            0,
            invalidSubmission.computeProofIdMerkleProof(0),
            invalidSubmission.computeProofDataMerkleProof(0)
          )
      ).to.be.revertedWith("invalid curve point");
    }).timeout(100000);
  });
});
