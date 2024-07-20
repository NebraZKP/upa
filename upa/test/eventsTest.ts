import { loadAppVK } from "../src/tool/config";
import { dummyProofData } from "../src/sdk/upa";
import * as utils from "../src/sdk/utils";
import { deployUpaDummyVerifier } from "./upaTests";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import {
  ProofSubmittedEventGetter,
  SubmissionVerifiedEventGetter,
  getCallDataForVerifyAggregatedProofTx,
} from "../src/sdk/events";
import { submitProofs } from "../src/sdk/upa";
import {
  Submission,
  packOffChainSubmissionMarkers,
} from "../src/sdk/submission";
import { CompressedGroth16Proof } from "../src/sdk/groth16";

describe("EventGetter for events", () => {
  // Dummy proofs and PIs
  const pf_a_compressed = new CompressedGroth16Proof(
    "1",
    ["3", "4"],
    "9",
    ["8"],
    ["2"]
  );
  const pf_b_compressed = new CompressedGroth16Proof(
    "1",
    ["3", "4"],
    "8",
    [],
    []
  );
  const pf_a = pf_a_compressed.decompress();
  const pf_b = pf_b_compressed.decompress();
  const pi_a = [11n, 12n, 13n, 14n];
  const pi_b = [21n, 22n, 23n, 24n];
  const pi_c = [31n, 32n, 33n, 34n];
  const pi_d = [41n, 42n, 43n, 44n];
  const pi_e = [51n, 52n, 53n, 54n];
  const pi_f = [61n, 62n, 63n, 64n];
  const pi_offchain = [71n, 72n, 73n, 74n];

  // On-chain submissions:
  //   1: [ A, B ],
  //   2: [ C ],
  //   3: [ D, E, F]
  // Off-chain submissions:
  //   1: [ offchain ]
  //
  // Verify:
  //   1: [ A, offchain ],
  //   2: [ B, C, D ],
  //   3: [ E, F ],
  const deploySubmitVerify = async () => {
    const { upa, worker } = await loadFixture(deployUpaDummyVerifier);
    const { verifier } = upa;

    const vk = loadAppVK("../circuits/src/tests/data/vk.json");
    await verifier.registerVK(vk);
    const cid = utils.readBytes32((await verifier.getCircuitIds())[0]);
    const pid_a = utils.computeProofId(cid, pi_a);
    const pid_b = utils.computeProofId(cid, pi_b);
    const pid_c = utils.computeProofId(cid, pi_c);
    const pid_d = utils.computeProofId(cid, pi_d);
    const pid_e = utils.computeProofId(cid, pi_e);
    const pid_f = utils.computeProofId(cid, pi_f);
    const pid_offchain = utils.computeProofId(cid, pi_offchain);

    const startHeight = await ethers.provider.getBlockNumber();

    // On-chain submissions:
    //   1: [ A, B ],
    //   2: [ C ],
    //   3: [ D, E, F]
    // Off-chain submissions:
    //   1: [ offchain ]

    const sub_1 = Submission.fromCircuitIdsProofsAndInputs([
      { circuitId: cid, proof: pf_a, inputs: pi_a },
      { circuitId: cid, proof: pf_b, inputs: pi_b },
    ]);
    const sub1TxHash = await (async () => {
      const s1Tx = await submitProofs(
        verifier,
        sub_1.circuitIds,
        sub_1.proofs,
        sub_1.inputs
      );
      return s1Tx.hash;
    })();

    const sub_2 = Submission.fromCircuitIdsProofsAndInputs([
      { circuitId: cid, proof: pf_a, inputs: pi_c },
    ]);
    const sub2TxHash = await (async () => {
      const s2Tx = await submitProofs(
        verifier,
        sub_2.circuitIds,
        sub_2.proofs,
        sub_2.inputs
      );
      return s2Tx.hash;
    })();

    const sub_3 = Submission.fromCircuitIdsProofsAndInputs([
      { circuitId: cid, proof: pf_b, inputs: pi_d },
      { circuitId: cid, proof: pf_a, inputs: pi_e },
      { circuitId: cid, proof: pf_b, inputs: pi_f },
    ]);
    const sub3TxHash = await (async () => {
      const s3Tx = await submitProofs(
        verifier,
        sub_3.circuitIds,
        sub_3.proofs,
        sub_3.inputs
      );
      return s3Tx.hash;
    })();

    const sub_offchain = Submission.fromCircuitIdsProofsAndInputs([
      { circuitId: cid, proof: pf_a, inputs: pi_offchain },
    ]);
    const submissionMarkers = packOffChainSubmissionMarkers(
      sub_offchain.getUnpackedOffChainSubmissionMarkers()
    );

    // Verify:
    //   1: [ A, offchain ],
    //   2: [ B, C, D ],
    //   3: [ E, F ],

    const agg1TxHash = await (async () => {
      const proofIds = [pid_a, pid_offchain];
      const agg1Tx = await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(proofIds),
          proofIds,
          proofIds.length - 1,
          [sub_1.computeSubmissionProof(0, 1)!.solidity()],
          submissionMarkers
        );
      return agg1Tx.hash;
    })();

    const agg2TxHash = await (async () => {
      const proofIds = [pid_b, pid_c, pid_d];
      const agg2Tx = await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(proofIds),
          proofIds,
          proofIds.length,
          [
            sub_1.computeSubmissionProof(1, 1)!.solidity(),
            sub_3.computeSubmissionProof(0, 1)!.solidity(),
          ],
          packOffChainSubmissionMarkers([])
        );
      return agg2Tx.hash;
    })();

    const agg3TxHash = await (async () => {
      const proofIds = [pid_e, pid_f];
      const agg3Tx = await verifier
        .connect(worker)
        .verifyAggregatedProof(
          dummyProofData(proofIds),
          proofIds,
          proofIds.length,
          [sub_3.computeSubmissionProof(1, 2)!.solidity()],
          packOffChainSubmissionMarkers([])
        );
      return agg3Tx.hash;
    })();

    return {
      upa,
      startHeight,
      pid_a,
      pid_b,
      pid_c,
      pid_d,
      pid_e,
      pid_f,
      pid_offchain,
      sub1TxHash,
      sub2TxHash,
      sub3TxHash,
      sub_1,
      sub_2,
      sub_3,
      sub_offchain,
      agg1TxHash,
      agg2TxHash,
      agg3TxHash,
    };
  };

  it("should find all events group them by tx", async function () {
    const {
      upa,
      startHeight,
      pid_a,
      pid_b,
      pid_c,
      pid_d,
      pid_e,
      pid_f,
      sub1TxHash,
      sub2TxHash,
      sub3TxHash,
      sub_1,
      sub_2,
      sub_3,
      sub_offchain,
      agg1TxHash,
      agg2TxHash,
      agg3TxHash,
    } = await loadFixture(deploySubmitVerify);
    const curHeight = await ethers.provider.getBlockNumber();

    const submittedEventGetter = new ProofSubmittedEventGetter(upa.verifier);
    const verifiedEventGetter = new SubmissionVerifiedEventGetter(upa.verifier);

    const groupedSubmittedEvents =
      await submittedEventGetter.getFullGroupedByTransaction(
        startHeight,
        curHeight
      );
    const groupedVerifiedEvents =
      await verifiedEventGetter.getFullGroupedByTransaction(
        startHeight,
        curHeight
      );

    // 3 groups, of the correct sizes

    // On-chain submissions:
    //   1: [ A, B ],
    //   2: [ C ],
    //   3: [ D, E, F]
    // Off-chain submissions:
    //   1: [ offchain ]
    expect(groupedSubmittedEvents.length).equal(3);

    // proof ids are as expected
    expect(groupedSubmittedEvents[0].events.map((ev) => ev.proofId)).eql([
      pid_a,
      pid_b,
    ]);
    expect(groupedSubmittedEvents[1].events.map((ev) => ev.proofId)).eql([
      pid_c,
    ]);
    expect(groupedSubmittedEvents[2].events.map((ev) => ev.proofId)).eql([
      pid_d,
      pid_e,
      pid_f,
    ]);

    expect(groupedSubmittedEvents[0].txHash).eql(sub1TxHash);
    expect(groupedSubmittedEvents[1].txHash).eql(sub2TxHash);
    expect(groupedSubmittedEvents[2].txHash).eql(sub3TxHash);
    // Verify:
    //   1: [ A, offchain ],
    //   2: [ B, C, D ],
    //   3: [ E, F ],
    expect(groupedVerifiedEvents.length).equal(3);

    // submissionIds are as expected.
    expect(groupedVerifiedEvents[0].events.map((ev) => ev.submissionId)).eql([
      sub_offchain.getSubmissionId(),
    ]);
    expect(groupedVerifiedEvents[1].events.map((ev) => ev.submissionId)).eql([
      sub_1.getSubmissionId(),
      sub_2.getSubmissionId(),
    ]);
    expect(groupedVerifiedEvents[2].events.map((ev) => ev.submissionId)).eql([
      sub_3.getSubmissionId(),
    ]);

    // tx hashes are grouped as expected
    expect(groupedVerifiedEvents[0].txHash).eql(agg1TxHash);
    expect(groupedVerifiedEvents[1].txHash).eql(agg2TxHash);
    expect(groupedVerifiedEvents[2].txHash).eql(agg3TxHash);
  });

  it("extract proof and input data", async function () {
    const { upa, startHeight, pid_a, pid_b, pid_c, pid_d, pid_e, pid_f } =
      await loadFixture(deploySubmitVerify);
    const curHeight = await ethers.provider.getBlockNumber();

    const submittedEventGetter = new ProofSubmittedEventGetter(upa.verifier);
    const eventSets = await submittedEventGetter.getFullGroupedByTransaction(
      startHeight,
      curHeight
    );
    const withData = await submittedEventGetter.getProofDataForSubmittedEvents(
      eventSets
    );

    // Extract proof and input data

    expect(withData[0].events.length).eql(2);
    expect(withData[0].events[0].proofId).eql(pid_a);
    expect(
      CompressedGroth16Proof.from_solidity(withData[0].events[0].proof)
    ).eql(pf_a_compressed);
    expect(withData[0].events[0].publicInputs).eql(pi_a);
    expect(withData[0].events[1].proofId).eql(pid_b);
    expect(
      CompressedGroth16Proof.from_solidity(withData[0].events[1].proof)
    ).eql(pf_b_compressed);
    expect(withData[0].events[1].publicInputs).eql(pi_b);

    expect(withData[1].events.length).eql(1);
    expect(withData[1].events[0].proofId).eql(pid_c);
    expect(
      CompressedGroth16Proof.from_solidity(withData[1].events[0].proof)
    ).eql(pf_a_compressed);
    expect(withData[1].events[0].publicInputs).eql(pi_c);

    expect(withData[2].events.length).eql(3);
    expect(withData[2].events[0].proofId).eql(pid_d);
    expect(
      CompressedGroth16Proof.from_solidity(withData[2].events[0].proof)
    ).eql(pf_b_compressed);
    expect(withData[2].events[0].publicInputs).eql(pi_d);
    expect(withData[2].events[1].proofId).eql(pid_e);
    expect(
      CompressedGroth16Proof.from_solidity(withData[2].events[1].proof)
    ).eql(pf_a_compressed);
    expect(withData[2].events[1].publicInputs).eql(pi_e);
    expect(withData[2].events[2].proofId).eql(pid_f);
    expect(
      CompressedGroth16Proof.from_solidity(withData[2].events[2].proof)
    ).eql(pf_b_compressed);
    expect(withData[2].events[2].publicInputs).eql(pi_f);
  });

  it("extract verifyAggregatedProof calldata", async function () {
    const {
      upa,
      pid_a,
      pid_b,
      pid_c,
      pid_d,
      pid_e,
      pid_f,
      pid_offchain,
      sub_1,
      sub_3,
      agg1TxHash,
      agg2TxHash,
      agg3TxHash,
    } = await loadFixture(deploySubmitVerify);

    const provider = upa.verifier.runner!.provider!;
    const agg1Tx = await provider.getTransaction(agg1TxHash);
    const agg2Tx = await provider.getTransaction(agg2TxHash);
    const agg3Tx = await provider.getTransaction(agg3TxHash);

    const {
      proof: agg1Tx_proof,
      proofIds: agg1Tx_proofIds,
      numOnchainProofs: agg1Tx_numOnchainProofs,
      submissionProofs: agg1Tx_submissionProofs,
      offChainSubmissionMarkers: agg1Tx_offChainSubmissionMarkers,
    } = getCallDataForVerifyAggregatedProofTx(upa.verifier, agg1Tx!);

    expect(agg1Tx_proof).eql(dummyProofData(agg1Tx_proofIds));
    expect(agg1Tx_proofIds).eql([pid_a, pid_offchain]);
    expect(agg1Tx_numOnchainProofs).eql(1n);
    expect(agg1Tx_submissionProofs).eql([
      sub_1.computeSubmissionProof(0, 1)!.solidity(),
    ]);
    expect(agg1Tx_offChainSubmissionMarkers).eql(1n);

    const {
      proof: agg2Tx_proof,
      proofIds: agg2Tx_proofIds,
      numOnchainProofs: agg2Tx_numOnchainProofs,
      submissionProofs: agg2Tx_submissionProofs,
      offChainSubmissionMarkers: agg2Tx_offChainSubmissionMarkers,
    } = getCallDataForVerifyAggregatedProofTx(upa.verifier, agg2Tx!);

    expect(agg2Tx_proof).eql(dummyProofData(agg2Tx_proofIds));
    expect(agg2Tx_proofIds).eql([pid_b, pid_c, pid_d]);
    expect(agg2Tx_numOnchainProofs).eql(3n);
    expect(agg2Tx_submissionProofs).eql([
      sub_1.computeSubmissionProof(1, 1)!.solidity(),
      sub_3.computeSubmissionProof(0, 1)!.solidity(),
    ]);
    expect(agg2Tx_offChainSubmissionMarkers).eql(0n);

    const {
      proof: agg3Tx_proof,
      proofIds: agg3Tx_proofIds,
      numOnchainProofs: agg3Tx_numOnchainProofs,
      submissionProofs: agg3Tx_submissionProofs,
      offChainSubmissionMarkers: agg3Tx_offChainSubmissionMarkers,
    } = getCallDataForVerifyAggregatedProofTx(upa.verifier, agg3Tx!);

    expect(agg3Tx_proof).eql(dummyProofData(agg3Tx_proofIds));
    expect(agg3Tx_proofIds).eql([pid_e, pid_f]);
    expect(agg3Tx_numOnchainProofs).eql(2n);
    expect(agg3Tx_submissionProofs).eql([
      sub_3.computeSubmissionProof(1, 2)!.solidity(),
    ]);
    expect(agg3Tx_offChainSubmissionMarkers).eql(0n);
  });
  it("should support event filtering", async function () {
    const { upa, startHeight, pid_b, sub1TxHash, sub_3, agg3TxHash } =
      await loadFixture(deploySubmitVerify);
    const curHeight = await ethers.provider.getBlockNumber();

    const submittedEventGetter = new ProofSubmittedEventGetter(
      upa.verifier,
      pid_b /* proofId */
    );
    const verifiedEventGetter = new SubmissionVerifiedEventGetter(
      upa.verifier,
      sub_3.submissionId /* submissionId */
    );

    const submittedEvents = await submittedEventGetter.getFull(
      startHeight,
      curHeight
    );
    const verifiedEvents = await verifiedEventGetter.getFull(
      startHeight,
      curHeight
    );

    // Submissions:
    //   1: [ A, *B ],
    //   2: [ C ],
    //   3: [ D, E, F]
    //
    // *- expect to only see this

    expect(submittedEvents.length).equal(1);
    expect(submittedEvents[0].txHash).eql(sub1TxHash);
    expect(submittedEvents[0].event.proofId).eql(pid_b);

    // Verify:
    //   1: [ A, offchain ],
    //   2: [ B, C, D ],
    //   3: *[ E, F ],
    //
    // *- expect to only see this

    expect(verifiedEvents.length).equal(1);
    expect(verifiedEvents[0].txHash).eql(agg3TxHash);
    expect(verifiedEvents[0].event.submissionId).eql(sub_3.submissionId);
  });
});
