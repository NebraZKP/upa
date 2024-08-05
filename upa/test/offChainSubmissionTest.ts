import { expect } from "chai";
import {
  CircuitIdProofAndInputs,
  DUMMY_PROOF_ID,
  Groth16Proof,
} from "../src/sdk/application";
import {
  OffChainSubmission,
  Submission,
  SubmissionProof,
  packOffChainSubmissionMarkers,
} from "../src/sdk/submission";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployUpaDummyVerifier, DeployResult } from "./upaTests";
import {
  dummyProofData,
  isProofVerifiedMulti,
  isProofVerifiedSingle,
  isSubmissionVerified,
} from "../src/sdk/upa";
import { UpaClient } from "../src/sdk/client";
import { UpaVerifier } from "../typechain-types";
import { loadAppVK } from "../src/tool/config";
import { computeCircuitId } from "../src/sdk/utils";

type OffchainTestDeployResult = DeployResult & {
  cid_a: string;
};

async function deploy(): Promise<OffchainTestDeployResult> {
  const deployRes = await deployUpaDummyVerifier();

  const vk = loadAppVK("../circuits/src/tests/data/vk-2.json");
  await deployRes.upa.verifier.registerVK(vk.solidity());
  const cid_a = computeCircuitId(vk);

  return { ...deployRes, cid_a };
}

// Fake proofs
const pf_a = new Groth16Proof(
  ["1", "2"],
  [
    ["3", "4"],
    ["5", "6"],
  ],
  ["7", "8"],
  [],
  []
);

const pf_b = new Groth16Proof(
  ["1", "2"],
  [
    ["3", "4"],
    ["5", "6"],
  ],
  ["7", "9"],
  [],
  []
);

// Deterministically generates `cidProofsAndInputs` of different sizes for a
// fixed circuitId. `inputsOffset` is used to generate different submissions
// with the same circuitId, numProofs and numInputs.
function generateCidProofsAndInputs(
  circuitId: string,
  numProofs: number,
  numInputs: number,
  inputsOffset: number
): CircuitIdProofAndInputs[] {
  const cidProofsAndInputs: CircuitIdProofAndInputs[] = [];

  for (let i = 0; i < numProofs; i++) {
    const proof = i % 2 === 0 ? pf_a : pf_b;
    const inputs: bigint[] = [];

    for (let j = 1; j <= numInputs; j++) {
      inputs.push(BigInt(i + j + inputsOffset));
    }

    cidProofsAndInputs.push({
      circuitId: circuitId,
      proof,
      inputs: inputs,
    });
  }

  return cidProofsAndInputs;
}

// Returns true iff all proofs are individually verified and the submission
// is also verified.
async function checkProofsAndSubmissionVerified(
  submission: OffChainSubmission,
  verifier: UpaVerifier
): Promise<boolean> {
  const isProofVerifiedMultiFn = verifier.getFunction(isProofVerifiedMulti);
  const isSubmissionVerifiedFn = verifier.getFunction(isSubmissionVerified);

  const numProofsInSubmission = submission.getProofIds.length;
  // Check each proof is individually marked as verified.
  for (let index = 0; index < numProofsInSubmission; index++) {
    const proofReference = submission.computeProofReference(index)!;
    const isProofVerified = await isProofVerifiedMultiFn(
      submission.circuitIds[index],
      submission.inputs[index],
      proofReference
    );
    if (!isProofVerified) {
      return false;
    }
  }

  // Check that the entire submission is marked as verified
  const onChainIsSubmissionVerified = await isSubmissionVerifiedFn(
    submission.circuitIds,
    submission.inputs
  );

  if (!onChainIsSubmissionVerified) {
    return false;
  }

  return true;
}

describe("Submissions verified in one aggregation", async () => {
  it("1 on-chain + 1 off-chain + 10 dummy, 1 aggregation", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);

    const isProofVerifiedSingleFn = upa.verifier.getFunction(
      isProofVerifiedSingle
    );

    const numProofsInSubmission = 1;
    const numPublicInputs = 3;
    const numDummyProofs = 10;

    const onChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      0
    );

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      1
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandle = await upaClient.submitProofs(
      onChainCidsProofsAndInputs
    );
    const onChainSubmissionProofs: SubmissionProof[] = [];

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );
    const offChainSubmissionMarkers = packOffChainSubmissionMarkers(
      offChainSubmission.getUnpackedOffChainSubmissionMarkers()
    );

    // Should not yet be verified.
    expect(
      await isProofVerifiedSingleFn(
        onChainCidsProofsAndInputs[0].circuitId,
        onChainCidsProofsAndInputs[0].inputs
      )
    ).to.be.false;

    expect(
      await isProofVerifiedSingleFn(
        offChainCidsProofsAndInputs[0].circuitId,
        offChainCidsProofsAndInputs[0].inputs
      )
    ).to.be.false;

    const dummyProofIds = Array(numDummyProofs).fill(DUMMY_PROOF_ID);

    const proofIds = [
      ...onChainSubmissionHandle.submission.proofIds,
      ...dummyProofIds,
      ...offChainSubmission.proofIds,
    ];

    const verifyAggProofTx = await upa.verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        numProofsInSubmission + numDummyProofs,
        onChainSubmissionProofs,
        offChainSubmissionMarkers,
        [0]
      );

    await verifyAggProofTx.wait();

    // Should be verified.
    expect(
      await isProofVerifiedSingleFn(
        onChainCidsProofsAndInputs[0].circuitId,
        onChainCidsProofsAndInputs[0].inputs
      )
    ).to.be.true;

    expect(
      await isProofVerifiedSingleFn(
        offChainCidsProofsAndInputs[0].circuitId,
        offChainCidsProofsAndInputs[0].inputs
      )
    ).to.be.true;
  });
  it("8 on-chain + 8 off-chain, 1 aggregation", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier } = upa;

    const numProofsInSubmission = 8;
    const numPublicInputs = 3;

    const onChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      0
    );

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      1
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandle = await upaClient.submitProofs(
      onChainCidsProofsAndInputs
    );

    const onChainSubmissionProofs: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(
        0,
        onChainCidsProofsAndInputs.length
      )!,
    ];

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );
    const offChainSubmissionMarkers = packOffChainSubmissionMarkers(
      offChainSubmission.getUnpackedOffChainSubmissionMarkers()
    );

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    const proofIds = [
      ...onChainSubmissionHandle.submission.proofIds,
      ...offChainSubmission.proofIds,
    ];

    const verifyAggProofTx = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        numProofsInSubmission,
        onChainSubmissionProofs,
        offChainSubmissionMarkers,
        [0]
      );

    await verifyAggProofTx.wait();

    // Now each individual proof and the entire submission should be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.true;
  });

  it("7 on-chain + 13 off-chain + 10 dummy, 1 aggregation", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier: verifier } = upa;

    const numProofsInOnChainSubmission = 7;
    const numProofsInOffChainSubmission = 13;
    const numPublicInputs = 3;
    const numDummyProofs = 10;

    const onChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInOnChainSubmission,
      numPublicInputs,
      0
    );

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInOffChainSubmission,
      numPublicInputs,
      1
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandle = await upaClient.submitProofs(
      onChainCidsProofsAndInputs
    );

    const onChainSubmissionProofs: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(
        0,
        onChainCidsProofsAndInputs.length
      )!,
    ];

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );
    const offChainSubmissionMarkers = packOffChainSubmissionMarkers(
      offChainSubmission.getUnpackedOffChainSubmissionMarkers()
    );

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    const dummyProofIds = Array(numDummyProofs).fill(DUMMY_PROOF_ID);

    const proofIds = [
      ...onChainSubmissionHandle.submission.proofIds,
      ...dummyProofIds,
      ...offChainSubmission.proofIds,
    ];

    const verifyAggProofTx = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        numProofsInOnChainSubmission + numDummyProofs,
        onChainSubmissionProofs,
        offChainSubmissionMarkers,
        [0]
      );

    await verifyAggProofTx.wait();

    // Now each individual proof and the entire submission should be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.true;
  });

  it("0 on-chain + 10 off-chain, 1 aggregation", async () => {
    const { upa, worker, cid_a } = await loadFixture(deploy);
    const { verifier } = upa;

    const numProofsInSubmission = 10;
    const numPublicInputs = 3;

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      1
    );

    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );

    const offChainSubmissionMarkers = packOffChainSubmissionMarkers(
      offChainSubmission.getUnpackedOffChainSubmissionMarkers()
    );

    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    const verifyAggProofTx = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(offChainSubmission.proofIds),
        offChainSubmission.proofIds,
        0,
        [] /*onChainSubmissionProofs*/,
        offChainSubmissionMarkers,
        [0]
      );

    await verifyAggProofTx.wait();

    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.true;
  });
});

describe("Submissions verified over multiple aggregations", async () => {
  it("9 on-chain + 9 off-chain, aggregate 3+3 each time", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier: verifier } = upa;

    const numProofsInSubmission = 9;
    const numPublicInputs = 3;

    const onChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      0
    );

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInSubmission,
      numPublicInputs,
      1
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandle = await upaClient.submitProofs(
      onChainCidsProofsAndInputs
    );

    const onChainSubmissionProofs_1: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(0, 3)!,
    ];
    const onChainSubmissionProofs_2: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(3, 3)!,
    ];
    const onChainSubmissionProofs_3: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(6, 3)!,
    ];

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );
    const unpackedOffChainSubmissionMarkers =
      offChainSubmission.getUnpackedOffChainSubmissionMarkers();

    const offChainSubmissionMarkers_1 = packOffChainSubmissionMarkers(
      unpackedOffChainSubmissionMarkers.slice(0, 3)
    );
    const offChainSubmissionMarkers_2 = packOffChainSubmissionMarkers(
      unpackedOffChainSubmissionMarkers.slice(3, 6)
    );
    const offChainSubmissionMarkers_3 = packOffChainSubmissionMarkers(
      unpackedOffChainSubmissionMarkers.slice(6, 9)
    );

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    // First aggregated batch
    const proofIds_1 = [
      ...onChainSubmissionHandle.submission.proofIds.slice(0, 3),
      ...offChainSubmission.proofIds.slice(0, 3),
    ];

    const verifyAggProofTx_1 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds_1),
        proofIds_1,
        3,
        onChainSubmissionProofs_1,
        offChainSubmissionMarkers_1,
        [0]
      );

    await verifyAggProofTx_1.wait();

    // Second aggregated batch
    const proofIds_2 = [
      ...onChainSubmissionHandle.submission.proofIds.slice(3, 6),
      ...offChainSubmission.proofIds.slice(3, 6),
    ];

    const verifyAggProofTx_2 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds_2),
        proofIds_2,
        3,
        onChainSubmissionProofs_2,
        offChainSubmissionMarkers_2,
        [0]
      );

    await verifyAggProofTx_2.wait();

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    // Third aggregated batch
    const proofIds_3 = [
      ...onChainSubmissionHandle.submission.proofIds.slice(6, 9),
      ...offChainSubmission.proofIds.slice(6, 9),
    ];

    const verifyAggProofTx_3 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds_3),
        proofIds_3,
        3,
        onChainSubmissionProofs_3,
        offChainSubmissionMarkers_3,
        [0]
      );

    await verifyAggProofTx_3.wait();

    // Now each individual proof and the entire submission should be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.true;
  });

  it("5 on-chain + 20 off-chain + 12 dummy, 3 different aggs", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier: verifier } = upa;

    const numOnChainProofsInSubmission = 5;
    const numOffChainProofsInSubmission = 20;
    const numPublicInputs = 3;
    const numDummyProofsPerAgg = 4;
    const dummyProofIds = Array(numDummyProofsPerAgg).fill(DUMMY_PROOF_ID);

    const onChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numOnChainProofsInSubmission,
      numPublicInputs,
      0
    );

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numOffChainProofsInSubmission,
      numPublicInputs,
      1
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandle = await upaClient.submitProofs(
      onChainCidsProofsAndInputs
    );

    // We will aggregate 3, then 0, then 2 proofs from the on-chain submission.
    const onChainSubmissionProofs_1: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(0, 3)!,
    ];
    const onChainSubmissionProofs_2: SubmissionProof[] = [];
    const onChainSubmissionProofs_3: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(3, 2)!,
    ];

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );

    // We will aggregate 9, then 11, then 0 proofs from the off-chain
    // submission.
    const unpackedOffChainSubmissionMarkers =
      offChainSubmission.getUnpackedOffChainSubmissionMarkers();

    const offChainSubmissionMarkers_1 = packOffChainSubmissionMarkers(
      unpackedOffChainSubmissionMarkers.slice(0, 9)
    );
    const offChainSubmissionMarkers_2 = packOffChainSubmissionMarkers(
      unpackedOffChainSubmissionMarkers.slice(9, 20)
    );
    const offChainSubmissionMarkers_3 = packOffChainSubmissionMarkers([]);

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    // First aggregated batch
    const proofIds_1 = [
      ...onChainSubmissionHandle.submission.proofIds.slice(0, 3),
      ...offChainSubmission.proofIds.slice(0, 9),
    ];

    const verifyAggProofTx_1 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds_1),
        proofIds_1,
        3,
        onChainSubmissionProofs_1,
        offChainSubmissionMarkers_1,
        [0]
      );

    await verifyAggProofTx_1.wait();

    // Second aggregated batch
    const proofIds_2 = [
      ...dummyProofIds,
      ...offChainSubmission.proofIds.slice(9, 20),
    ];

    const verifyAggProofTx_2 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds_2),
        proofIds_2,
        numDummyProofsPerAgg,
        onChainSubmissionProofs_2,
        offChainSubmissionMarkers_2,
        [0]
      );

    await verifyAggProofTx_2.wait();

    // Only the off-chain submission should be verified now.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.true;

    // Third aggregated batch
    const proofIds_3 = [
      ...onChainSubmissionHandle.submission.proofIds.slice(3, 5),
      ...dummyProofIds,
    ];

    const verifyAggProofTx_3 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds_3),
        proofIds_3,
        2 + numDummyProofsPerAgg,
        onChainSubmissionProofs_3,
        offChainSubmissionMarkers_3,
        [0]
      );

    await verifyAggProofTx_3.wait();

    // Now the on-chain submission should also be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.true;
  });
});

describe("Aggregations containing multiple submissions", async () => {
  it("3 on-chain submissions, 3 off-chain submissions, 2 aggs", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier } = upa;

    const numProofsInSubmission = 5;
    const numPublicInputs = 3;
    const numDummyProofsPerAgg = 4;

    // 3 on-chain submissions containing 5 proofs each.
    const onChainCidsProofsAndInputsArray = [
      generateCidProofsAndInputs(
        cid_a,
        numProofsInSubmission,
        numPublicInputs,
        0
      ),
      generateCidProofsAndInputs(
        cid_a,
        numProofsInSubmission,
        numPublicInputs,
        1
      ),
      generateCidProofsAndInputs(
        cid_a,
        numProofsInSubmission,
        numPublicInputs,
        2
      ),
    ];

    // 3 off-chain submissions containing 5 proofs each.
    const offChainCidsProofsAndInputsArray = [
      generateCidProofsAndInputs(
        cid_a,
        numProofsInSubmission,
        numPublicInputs,
        3
      ),
      generateCidProofsAndInputs(
        cid_a,
        numProofsInSubmission,
        numPublicInputs,
        4
      ),
      generateCidProofsAndInputs(
        cid_a,
        numProofsInSubmission,
        numPublicInputs,
        5
      ),
    ];

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandles = [
      await upaClient.submitProofs(onChainCidsProofsAndInputsArray[0]),
    ];
    onChainSubmissionHandles.push(
      await upaClient.submitProofs(onChainCidsProofsAndInputsArray[1])
    );
    onChainSubmissionHandles.push(
      await upaClient.submitProofs(onChainCidsProofsAndInputsArray[2])
    );

    // The first aggregation goes up to the second proof of the second on-chain
    // submission.
    const firstAggSubmissionProofs: SubmissionProof[] = [
      onChainSubmissionHandles[0].submission.computeSubmissionProof(
        0,
        numProofsInSubmission
      )!,
      onChainSubmissionHandles[1].submission.computeSubmissionProof(0, 2)!,
    ];
    const secondAggSubmissionProofs: SubmissionProof[] = [
      onChainSubmissionHandles[1].submission.computeSubmissionProof(
        2,
        numProofsInSubmission - 2
      )!,
      onChainSubmissionHandles[2].submission.computeSubmissionProof(
        0,
        numProofsInSubmission
      )!,
    ];

    // Prepare off-chain submissions
    const offChainSubmissions = await Promise.all(
      offChainCidsProofsAndInputsArray.map(async (item) => {
        return Submission.fromCircuitIdsProofsAndInputs(item);
      })
    );

    const offChainSubmissionMarkersArray = await Promise.all(
      offChainSubmissions.map(async (item) => {
        return item.getUnpackedOffChainSubmissionMarkers();
      })
    );

    // The first aggregation goes up to the first proof of the second off-chain
    // submission.
    const firstAggMarkers = packOffChainSubmissionMarkers([
      ...offChainSubmissionMarkersArray[0],
      ...offChainSubmissionMarkersArray[1].slice(0, 1),
    ]);
    const secondAggMarkers = packOffChainSubmissionMarkers([
      ...offChainSubmissionMarkersArray[1].slice(1, numProofsInSubmission),
      ...offChainSubmissionMarkersArray[2],
    ]);

    const dummyProofIds = Array(numDummyProofsPerAgg).fill(DUMMY_PROOF_ID);

    // First aggregated batch. The on-chain portion ends with a partially
    // verified submission, so we may not add dummy proofIds.
    const firstAggProofIds = [
      ...onChainSubmissionHandles[0].submission.proofIds,
      ...onChainSubmissionHandles[1].submission.proofIds.slice(0, 2),
      ...offChainSubmissions[0].proofIds,
      ...offChainSubmissions[1].proofIds.slice(0, 1),
    ];

    // Second aggregated batch. The on-chain submissions are fully verified,
    // so we may add dummy proofIds.
    const secondAggProofIds = [
      ...onChainSubmissionHandles[1].submission.proofIds.slice(
        2,
        numProofsInSubmission
      ),
      ...onChainSubmissionHandles[2].submission.proofIds,
      ...dummyProofIds,
      ...offChainSubmissions[1].proofIds.slice(1, numProofsInSubmission),
      ...offChainSubmissions[2].proofIds,
    ];

    const verifyAggProofTx_1 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(firstAggProofIds),
        firstAggProofIds,
        7,
        firstAggSubmissionProofs,
        firstAggMarkers,
        [0, 0]
      );

    await verifyAggProofTx_1.wait();

    // The first on-chain submission should be verified, but the rest
    // unverified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[0].submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[1].submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[2].submission,
        upa.verifier
      )
    ).to.be.false;

    // The first off-chain submission should be verified, but the rest
    // unverified.
    expect(
      await checkProofsAndSubmissionVerified(
        offChainSubmissions[0],
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(
        offChainSubmissions[1],
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(
        offChainSubmissions[2],
        upa.verifier
      )
    ).to.be.false;

    const verifyAggProofTx_2 = await verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(secondAggProofIds),
        secondAggProofIds,
        8 + numDummyProofsPerAgg,
        secondAggSubmissionProofs,
        secondAggMarkers,
        [0, 0]
      );

    await verifyAggProofTx_2.wait();

    // Now each individual proof and submission should be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[0].submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[1].submission,
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[2].submission,
        upa.verifier
      )
    ).to.be.true;

    expect(
      await checkProofsAndSubmissionVerified(
        offChainSubmissions[0],
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(
        offChainSubmissions[1],
        upa.verifier
      )
    ).to.be.true;
    expect(
      await checkProofsAndSubmissionVerified(
        offChainSubmissions[2],
        upa.verifier
      )
    ).to.be.true;
  });
});

describe("Offchain Benchmarks", async () => {
  it("Offchain aggregation (gas costs)", async () => {
    const { upa, worker, cid_a } = await loadFixture(deploy);
    const { verifier } = upa;

    async function offChainAggregateProofs(
      submissionSize: number,
      shift: number
    ) {
      const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
        cid_a,
        submissionSize,
        3,
        shift
      );
      const submission = Submission.fromCircuitIdsProofsAndInputs(
        offChainCidsProofsAndInputs
      );
      const packedSubmissionMarkers = packOffChainSubmissionMarkers(
        submission.getUnpackedOffChainSubmissionMarkers()
      );

      const txResponse = await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(submission.proofIds),
          submission.proofIds,
          0,
          [],
          packedSubmissionMarkers,
          [0]
        );

      const txReceipt = await txResponse.wait();
      console.log(
        `offchain verifyAggregatedProof(${submissionSize} pfs, 1 submission)` +
          `: ${txReceipt?.gasUsed} gas`
      );
    }

    // Fill the array so we are reusing the storage in this measurement.
    await offChainAggregateProofs(32, 0);

    console.log("\n*** With reused storage ***");
    const shift = 1;
    await offChainAggregateProofs(1, shift);
    await offChainAggregateProofs(2, shift);
    await offChainAggregateProofs(4, shift);
    await offChainAggregateProofs(8, shift);
    await offChainAggregateProofs(16, shift);
    await offChainAggregateProofs(32, shift);
  });
});

describe("Failure cases", async () => {
  it("On-chain and off-chain proofIds in the wrong order", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier: verifier } = upa;

    const numProofsInOnChainSubmission = 7;
    const numProofsInOffChainSubmission = 13;
    const numPublicInputs = 3;

    const onChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInOnChainSubmission,
      numPublicInputs,
      0
    );

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numProofsInOffChainSubmission,
      numPublicInputs,
      1
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandle = await upaClient.submitProofs(
      onChainCidsProofsAndInputs
    );

    const onChainSubmissionProofs: SubmissionProof[] = [
      onChainSubmissionHandle.submission.computeSubmissionProof(
        0,
        onChainCidsProofsAndInputs.length
      )!,
    ];

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );
    const offChainSubmissionMarkers = packOffChainSubmissionMarkers(
      offChainSubmission.getUnpackedOffChainSubmissionMarkers()
    );

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandle.submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    const dummyProofIds = Array(10).fill(DUMMY_PROOF_ID);

    const proofIds = [
      ...offChainSubmission.proofIds,
      ...onChainSubmissionHandle.submission.proofIds,
      ...dummyProofIds,
    ];

    expect(
      verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(proofIds),
          proofIds,
          numProofsInOnChainSubmission,
          onChainSubmissionProofs,
          offChainSubmissionMarkers,
          [0]
        )
    ).to.be.revertedWithCustomError(upa.verifier, "InvalidMerkleIntervalProof");
  });

  it("Agg partial on-chain submission and dummy proofs", async () => {
    const { upa, worker, user1, cid_a, upaDesc } = await loadFixture(deploy);
    const { verifier: verifier } = upa;

    const numOnChainProofsInSubmission = 5;
    const numOffChainProofsInSubmission = 20;
    const numPublicInputs = 3;
    const numDummyProofs = 4;
    const dummyProofIds = Array(numDummyProofs).fill(DUMMY_PROOF_ID);

    // 3 on-chain submissions containing 5 proofs each.
    const onChainCidsProofsAndInputsArray = [
      generateCidProofsAndInputs(
        cid_a,
        numOnChainProofsInSubmission,
        numPublicInputs,
        0
      ),
      generateCidProofsAndInputs(
        cid_a,
        numOnChainProofsInSubmission,
        numPublicInputs,
        1
      ),
      generateCidProofsAndInputs(
        cid_a,
        numOnChainProofsInSubmission,
        numPublicInputs,
        2
      ),
    ];

    const offChainCidsProofsAndInputs = generateCidProofsAndInputs(
      cid_a,
      numOffChainProofsInSubmission,
      numPublicInputs,
      1
    );

    // Prepare an off-chain submission
    const offChainSubmission = Submission.fromCircuitIdsProofsAndInputs(
      offChainCidsProofsAndInputs
    );

    // We will attempt to aggregate 9 proofs from the off-chain submission.
    const unpackedOffChainSubmissionMarkers =
      offChainSubmission.getUnpackedOffChainSubmissionMarkers();

    const offChainSubmissionMarkers = packOffChainSubmissionMarkers(
      unpackedOffChainSubmissionMarkers.slice(0, 9)
    );

    // Submit on-chain
    const upaClient = await UpaClient.init(user1, upaDesc);
    const onChainSubmissionHandles = [
      await upaClient.submitProofs(onChainCidsProofsAndInputsArray[0]),
    ];
    onChainSubmissionHandles.push(
      await upaClient.submitProofs(onChainCidsProofsAndInputsArray[1])
    );
    onChainSubmissionHandles.push(
      await upaClient.submitProofs(onChainCidsProofsAndInputsArray[2])
    );

    // First agg: Attempt to aggregate 3 of the 5 proofs from the on-chain
    // submission.
    const onChainSubmissionProofs_1: SubmissionProof[] = [
      onChainSubmissionHandles[0].submission.computeSubmissionProof(0, 3)!,
    ];

    // Second agg: Attempt to aggregate the first submission fully, and 3 of
    // the 5 proofs from the next submission.
    const onChainSubmissionProofs_2: SubmissionProof[] = [
      onChainSubmissionHandles[0].submission.computeSubmissionProof(0, 5)!,
      onChainSubmissionHandles[1].submission.computeSubmissionProof(0, 3)!,
    ];

    // Should not yet be verified.
    expect(
      await checkProofsAndSubmissionVerified(
        onChainSubmissionHandles[0].submission,
        upa.verifier
      )
    ).to.be.false;
    expect(
      await checkProofsAndSubmissionVerified(offChainSubmission, upa.verifier)
    ).to.be.false;

    // Add dummy proofIds incorrectly to both aggregated batches.
    // `verifyAggregatedProof` assumes that if there are dummy proofs, then
    // the on-chain proofIds do not end with a partial submission.
    const proofIds_1 = [
      ...onChainSubmissionHandles[0].submission.proofIds.slice(0, 3),
      ...dummyProofIds,
      ...offChainSubmission.proofIds.slice(0, 9),
    ];

    const proofIds_2 = [
      ...onChainSubmissionHandles[0].submission.proofIds,
      ...onChainSubmissionHandles[1].submission.proofIds.slice(0, 3),
      ...dummyProofIds,
      ...offChainSubmission.proofIds.slice(0, 9),
    ];

    expect(
      verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(proofIds_1),
          proofIds_1,
          3 + numDummyProofs,
          onChainSubmissionProofs_1,
          offChainSubmissionMarkers,
          [0]
        )
    ).to.be.revertedWithCustomError(verifier, "InvalidMerkleIntervalProof");

    expect(
      verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(proofIds_2),
          proofIds_2,
          8 + numDummyProofs,
          onChainSubmissionProofs_2,
          offChainSubmissionMarkers,
          [0]
        )
    ).to.be.revertedWithCustomError(verifier, "InvalidMerkleIntervalProof");
  });
});
