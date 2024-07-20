import { deployUpaDummyVerifier } from "./upaTests";
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
} from "../src/sdk/upa";
import { computeProofId, computeCircuitId } from "../src/sdk/utils";
import { expect } from "chai";
import { Submission } from "../src/sdk";
import { UpaVerifier } from "../typechain-types";
import { packOffChainSubmissionMarkers } from "../src/sdk/submission";

describe("Censorship challenge tests", () => {
  type DeployAndSubmitResult = DeployAndRegisterResult & {
    s1: Submission;
    s2: Submission;
    s3: Submission;
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
  async function deployAndRegister(): Promise<DeployAndRegisterResult> {
    // Deploy upa
    const { upa, worker, user1, user2 } = await loadFixture(
      deployUpaDummyVerifier
    );
    const { verifier } = upa;
    const vkProofsAndInputs = loadAppVkProofInputsBatchFile(
      "../circuits/src/tests/data/universal_batch_verifier_10_proofs.json"
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
  async function deployAndSubmit(): Promise<DeployAndSubmitResult> {
    const deployAndRegisterResult = await deployAndRegister();
    const { upa, user1, user2, circuitIds, proofs, inputs } =
      deployAndRegisterResult;
    const { verifier } = upa;
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
      s1: await s1P,
      s2: await s2P,
      s3: await s3P,
    };
  }

  /// Verifies the submission
  async function verifySubmission(
    verifier: UpaVerifier,
    worker: Signer,
    s: Submission
  ) {
    const proofIds = s.proofIds;
    const submissionProof = s.computeSubmissionProof(0, proofIds.length);
    await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        proofIds.length,
        submissionProof ? [submissionProof] : [],
        packOffChainSubmissionMarkers([])
      );
  }

  it("single censorship challenge", async function () {
    const { upa, worker, user1, s1, s2 } = await loadFixture(deployAndSubmit);
    const { verifier } = upa;
    // The aggregator will aggregate the second submission,
    // skipping the first
    await verifySubmission(verifier, worker, s2);
    // Check the proof in s1 is not verified
    const isProofVerifiedSingleFn = verifier.getFunction(isProofVerifiedSingle);
    expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to.be
      .false;
    // user1 submits a censorship challenge
    await verifier
      .connect(user1)
      .challenge(
        s1.circuitIds[0],
        s1.proofs[0].solidity(),
        s1.inputs[0],
        s1.submissionId,
        s1.computeProofIdMerkleProof(0),
        s1.computeProofDataMerkleProof(0)
      );
    // The challenge passes and the proof is now marked as verified
    expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to.be
      .true;
  }).timeout(200000);

  it("multi censorship challenge", async function () {
    const { upa, worker, user1, s1, s2, s3 } = await loadFixture(
      deployAndSubmit
    );
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
    // user1 submits a censorship challenge
    for (let i = 0; i < numProofsInS2; i++) {
      await verifier
        .connect(user1)
        .challenge(
          s2.circuitIds[i],
          s2.proofs[i].solidity(),
          s2.inputs[i],
          s2.submissionId,
          s2.computeProofIdMerkleProof(i),
          s2.computeProofDataMerkleProof(i)
        );
    }
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
  }).timeout(200000);

  it("wrong claimant should fail", async function () {
    const { upa, worker, user2, s1, s2 } = await loadFixture(deployAndSubmit);
    const { verifier } = upa;
    // The aggregator will aggregate the second submission,
    // skipping the first
    await verifySubmission(verifier, worker, s2);
    // Check the proof in s1 is not verified
    const isProofVerifiedSingleFn = verifier.getFunction(isProofVerifiedSingle);
    expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to.be
      .false;
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
          s1.computeProofIdMerkleProof(0),
          s1.computeProofDataMerkleProof(0)
        )
    ).to.be.revertedWithCustomError(verifier, "InvalidProofDataDigest");
  }).timeout(100000);

  it("already verified proof should fail", async function () {
    const { upa, worker, user1, s1, s2 } = await loadFixture(deployAndSubmit);
    const { verifier } = upa;
    // The aggregator will aggregate both the first and second
    // submissions
    await verifySubmission(verifier, worker, s1);
    await verifySubmission(verifier, worker, s2);
    // Check the proof in s1 is verified
    const isProofVerifiedSingleFn = verifier.getFunction(isProofVerifiedSingle);
    expect(await isProofVerifiedSingleFn(s1.circuitIds[0], s1.inputs[0])).to.be
      .true;
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
          s1.computeProofIdMerkleProof(0),
          s1.computeProofDataMerkleProof(0)
        )
    ).to.be.revertedWithCustomError(verifier, "LocationOutOfRange");
  }).timeout(100000);

  it("not yet skipped proof should fail", async function () {
    const { upa, worker, user2, s1, s2, s3 } = await loadFixture(
      deployAndSubmit
    );
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
            s3.computeProofIdMerkleProof(i),
            s3.computeProofDataMerkleProof(i)
          )
      ).to.be.revertedWithCustomError(verifier, "SubmissionWasNotSkipped");
    }
  }).timeout(100000);

  it("false proof should fail", async function () {
    const { upa, worker, user1, s1, s2, s3, circuitIds, proofs, inputs } =
      await loadFixture(deployAndSubmit);
    const { verifier } = upa;

    // user1 submits a false proof
    const wrongProof = proofs[5];
    wrongProof.pi_a[0] = String(BigInt(proofs[5].pi_a[0]) + 3n);
    const invalidTx = await submitProof(
      verifier.connect(user1),
      circuitIds[5],
      wrongProof,
      inputs[5]
    );
    const invalidSubmission = await Submission.fromTransactionReceipt(
      verifier,
      (await invalidTx.wait())!
    );

    // and a valid one
    const validTx = await submitProof(
      verifier.connect(user1),
      circuitIds[6],
      proofs[6],
      inputs[6]
    );
    const validSubmission = await Submission.fromTransactionReceipt(
      verifier,
      (await validTx.wait())!
    );

    // the aggregator verifies all valid ones
    await verifySubmission(verifier, worker, s1);
    await verifySubmission(verifier, worker, s2);
    await verifySubmission(verifier, worker, s3);
    await verifySubmission(verifier, worker, validSubmission);

    // user1 makes a censorship claim, which should fail because
    // the proof is false
    await expect(
      verifier
        .connect(user1)
        .challenge(
          invalidSubmission.circuitIds[0],
          invalidSubmission.proofs[0].solidity(),
          invalidSubmission.inputs[0],
          invalidSubmission.submissionId,
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
          invalidSubmission.computeProofIdMerkleProof(0),
          invalidSubmission.computeProofDataMerkleProof(0)
        )
    ).to.be.revertedWith("invalid curve point");
  }).timeout(100000);
});
