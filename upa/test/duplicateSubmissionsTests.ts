import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import {
  DeployResult,
  deployUpaDummyVerifier,
  makeSubmissions,
} from "./upaTests";
import { Submission, UpaClient } from "../src/sdk";
import { strict as assert } from "assert";
import { dummyProofData, updateFeeOptions } from "../src/sdk/upa";
import { OffChainSubmission } from "../src/sdk/submission";
import {
  packDupSubmissionIdxs,
  packOffChainSubmissionMarkers,
} from "../src/sdk/aggregatedProofParams";

/// Submit 3 submissions (all against cid_a):
///   1: [ pf_a ]
///   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
///   3: [ pf_e, pf_f ]        (Merkle depth 2, full)
type DeployResultAndSubs = DeployResult & {
  s1: OffChainSubmission;
  s2: OffChainSubmission;
  s3: OffChainSubmission;
  cid_a: string;
};

async function deployAndMakeSubmissions(): Promise<DeployResultAndSubs> {
  const deployResult = await deployUpaDummyVerifier();
  const { upa } = deployResult;
  const [s1, s2, s3, cid_a] = await makeSubmissions(upa);
  return { ...deployResult, s1, s2, s3, cid_a };
}

describe("Duplicate Submissions", () => {
  it("increment dupSubmissionIdx for repeated submissions", async () => {
    const { upa, upaDesc, user1, user2, s2 } = await loadFixture(
      deployAndMakeSubmissions
    );
    const { verifier } = upa;

    const client1 = await UpaClient.init(user1, upaDesc);
    const client2 = await UpaClient.init(user2, upaDesc);

    const cidProofsAndInputs = s2.getCircuitIdsProofsAndInputs();

    const submitA = await client1.submitProofs(cidProofsAndInputs);
    const submitB = await client2.submitProofs(cidProofsAndInputs);
    const submitC = await client1.submitProofs(cidProofsAndInputs);

    const submitAReceipt = await submitA.txResponse.wait();
    const submitBReceipt = await submitB.txResponse.wait();
    const submitCReceipt = await submitC.txResponse.wait();
    assert(submitAReceipt);
    assert(submitBReceipt);
    assert(submitCReceipt);

    const sub1A = await Submission.fromTransactionReceipt(
      verifier,
      submitAReceipt
    );
    const sub1B = await Submission.fromTransactionReceipt(
      verifier,
      submitBReceipt
    );
    const sub1C = await Submission.fromTransactionReceipt(
      verifier,
      submitCReceipt
    );

    expect(sub1A.submissionId).eql(s2.submissionId);
    expect(sub1B.submissionId).eql(s2.submissionId);
    expect(sub1C.submissionId).eql(s2.submissionId);
    expect(sub1A.getDupSubmissionIdx()).eql(0);
    expect(sub1B.getDupSubmissionIdx()).eql(1);
    expect(sub1C.getDupSubmissionIdx()).eql(2);
  });

  it("should not allow too many submissions of same Id", async () => {
    const { upa, upaDesc, user1, s2 } = await loadFixture(
      deployAndMakeSubmissions
    );
    const { verifier } = upa;
    const client = await UpaClient.init(user1, upaDesc);

    const cidProofsAndInputs = s2.getCircuitIdsProofsAndInputs();
    const maxDupSubmissions = Number(
      await verifier.MAX_DUPLICATE_SUBMISSIONS()
    );
    const submitPromises = new Array(maxDupSubmissions)
      .fill(0)
      .map(() => client.submitProofs(cidProofsAndInputs));
    await Promise.all(submitPromises);

    const options = await updateFeeOptions(verifier, s2.proofs.length);
    await expect(
      verifier.submit(
        s2.circuitIds,
        s2.proofs.map((pf) => pf.compress().solidity()),
        s2.inputs,
        options
      )
    ).to.be.revertedWithCustomError(verifier, "TooManySubmissionsForId");
  });

  it("mark submission verified if duplicate is verified", async () => {
    const { upa, upaDesc, worker, user1, user2, s2 } = await loadFixture(
      deployAndMakeSubmissions
    );
    const { verifier } = upa;

    const client1 = await UpaClient.init(user1, upaDesc);
    const client2 = await UpaClient.init(user2, upaDesc);

    const cidProofsAndInputs = s2.getCircuitIdsProofsAndInputs();
    const cidProofsAndInputsInvalid = s2.getCircuitIdsProofsAndInputs();
    cidProofsAndInputsInvalid[0].proof.pi_a =
      cidProofsAndInputsInvalid[0].proof.pi_c;

    // Simulate the valid proof being front-run by an invalid proof

    await client1.submitProofs(cidProofsAndInputsInvalid);
    const submitB = await client2.submitProofs(cidProofsAndInputs);

    const submitBReceipt = await submitB.txResponse.wait();
    assert(submitBReceipt);

    const subB = await Submission.fromTransactionReceipt(
      verifier,
      submitBReceipt
    );

    // Verify the valid submission (with dupSubmissionIdx = 1)
    await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(subB.proofIds),
        subB.proofIds,
        subB.proofIds.length,
        [subB.computeSubmissionProof()!],
        packOffChainSubmissionMarkers([]),
        packDupSubmissionIdxs([subB.getDupSubmissionIdx()])
      );

    expect(await verifier["isSubmissionVerified(bytes32)"](subB.submissionId))
      .to.be.true;
  });

  it("not mark verified if dups are partially verified", async () => {
    const { upa, upaDesc, worker, user1, user2, s2 } = await loadFixture(
      deployAndMakeSubmissions
    );
    const { verifier } = upa;

    const client1 = await UpaClient.init(user1, upaDesc);
    const client2 = await UpaClient.init(user2, upaDesc);

    const cidProofsAndInputs = s2.getCircuitIdsProofsAndInputs();
    const cidProofsAndInputsInvalid = s2.getCircuitIdsProofsAndInputs();
    cidProofsAndInputsInvalid[0].proof.pi_a =
      cidProofsAndInputsInvalid[0].proof.pi_c;

    await client1.submitProofs(cidProofsAndInputsInvalid);
    const submitB = await client2.submitProofs(cidProofsAndInputs);

    const submitBReceipt = await submitB.txResponse.wait();
    assert(submitBReceipt);

    const subB = await Submission.fromTransactionReceipt(
      verifier,
      submitBReceipt
    );

    // Verify the first 2 of the 3 proofs in the submission.
    const proofIds = subB.proofIds.slice(0, 2);
    const subProof = subB.computeSubmissionProof(0, 2)!;

    // Verify the first 2 proofs of submission A
    await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        proofIds.length,
        [subProof],
        packOffChainSubmissionMarkers([]),
        packDupSubmissionIdxs([0])
      );

    // Verify the first 2 proofs of submission B
    await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        proofIds.length,
        [subProof],
        packOffChainSubmissionMarkers([]),
        packDupSubmissionIdxs([1])
      );

    expect(await verifier["isSubmissionVerified(bytes32)"](subB.submissionId))
      .to.be.false;
  });
});
