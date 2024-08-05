import { expect } from "chai";
import { CircuitIdProofAndInputs, Groth16Proof } from "../src/sdk/application";
import {
  ProofReference,
  Submission,
  SubmissionProof,
  computeUnpackedOffChainSubmissionmarkers,
  packOffChainSubmissionMarkers,
} from "../src/sdk/submission";
import { bigintToHex32 } from "../src/sdk/utils";

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

const cidsProofsAndInputs: CircuitIdProofAndInputs[] = [
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
  {
    circuitId: bigintToHex32(456n),
    proof: pf_b,
    inputs: [4n, 0n, 0n],
  },
].map(CircuitIdProofAndInputs.from_json);

// Fake submissions
const submission1 = Submission.fromCircuitIdsProofsInputsAndDupIdx(
  cidsProofsAndInputs,
  0
);
const submission2 = Submission.fromCircuitIdsProofsInputsAndDupIdx(
  cidsProofsAndInputs.slice(0, 3),
  0
);

describe("Submission", () => {
  it("(de)serialize Submission", function () {
    const submissionJSON = submission1.to_json();
    const submissionFromJSON = Submission.from_json(submissionJSON);

    expect(submissionFromJSON).eql(submission1);
  });

  it("(de)serialize ProofReference", function () {
    const proofRef1 = submission1.computeProofReference(1)!;
    const proofRef2 = submission1.computeProofReference(2)!;

    const proofRefJSON = proofRef1.to_json();
    const proofRefFromJSON = ProofReference.from_json(proofRefJSON);

    expect(proofRefFromJSON).eql(proofRef1);
    expect(proofRefFromJSON).not.eql(proofRef2);
  });

  it("(de)serialize SubmissionProof", function () {
    const submissionProof1 = submission1.computeSubmissionProof(0, 1)!;
    const submissionProof2 = submission1.computeSubmissionProof(1, 1)!;

    const submissionProofJSON = submissionProof1.to_json();
    const submissionProofFromJSON =
      SubmissionProof.from_json(submissionProofJSON);

    expect(submissionProofFromJSON).eql(submissionProof1);
    expect(submissionProofFromJSON).not.eql(submissionProof2);
  });

  it("(de)serialize submission markers", function () {
    const submissions = [submission1, submission2, submission1];
    const submissionMarkers = computeUnpackedOffChainSubmissionmarkers(
      submissions,
      1,
      7
    );

    const submissionMarkersJSON = JSON.stringify(submissionMarkers);
    const submissionMarkersFromJSON = JSON.parse(submissionMarkersJSON);

    expect(submissionMarkers).eql(submissionMarkersFromJSON);
  });

  it("test SDK functions to compute submission markers", function () {
    expect(packOffChainSubmissionMarkers([])).eql(0n);

    const submissions = [submission1, submission2, submission1];
    const submissionMarkers1 = computeUnpackedOffChainSubmissionmarkers(
      submissions,
      1,
      7
    );
    const expectedSubmissionMarkers1 = [
      false,
      false,
      true,
      false,
      false,
      true,
      false,
    ];
    expect(submissionMarkers1).eql(expectedSubmissionMarkers1);
    expect(packOffChainSubmissionMarkers(expectedSubmissionMarkers1)).eql(36n);

    const submissionMarkers2 = computeUnpackedOffChainSubmissionmarkers(
      submissions,
      0,
      11
    );
    const expectedSubmissionMarkers2 = [
      false,
      false,
      false,
      true,
      false,
      false,
      true,
      false,
      false,
      false,
      true,
    ];
    expect(submissionMarkers2).eql(expectedSubmissionMarkers2);
    expect(packOffChainSubmissionMarkers(expectedSubmissionMarkers2)).eql(
      1096n
    );

    const submissionMarkers3 = computeUnpackedOffChainSubmissionmarkers(
      submissions,
      6,
      1
    );
    const expectedSubmissionMarkers3 = [true];
    expect(submissionMarkers3).eql(expectedSubmissionMarkers3);
    expect(packOffChainSubmissionMarkers(expectedSubmissionMarkers3)).eql(1n);
  });

  it("getCircuitIdsProofsAndInputs", function () {
    const returnedAll = submission1.getCircuitIdsProofsAndInputs(
      0,
      submission1.proofs.length
    );
    expect(returnedAll).eql(cidsProofsAndInputs);

    const returned12 = submission1.getCircuitIdsProofsAndInputs(1, 1);
    expect(returned12).eql(cidsProofsAndInputs.slice(1, 2));
  });

  it("getProofIds", function () {
    const proofIds = submission1.getProofIds();
    expect(proofIds.length).equals(4);

    const proofIds_1_2 = submission1.getProofIds(1, 2);
    expect(proofIds_1_2).eql([proofIds[1], proofIds[2]]);

    const proofIds_2 = submission1.getProofIds(2);
    expect(proofIds_2).eql([proofIds[2], proofIds[3]]);

    const proofIds__2 = submission1.getProofIds(undefined, 2);
    expect(proofIds__2).eql([proofIds[0], proofIds[1]]);
  });
});
