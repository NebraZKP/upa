import { expect } from "chai";
import {
  DUMMY_PROOF_CIRCUIT_ID,
  Groth16Proof,
  CircuitIdProofAndInputs,
} from "../src/sdk/application";
import { Submission } from "../src/sdk/submission";
import {
  SubmissionInterval,
  mergeSubmissionIntervals,
  splitSubmissionInterval,
} from "../src/sdk/submissionIntervals";
import { loadDummyProofData } from "../src/tool/config";
import { bigintToHex32 } from "../src/sdk/utils";

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

const cidsProofsAndInputs = [
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
  {
    circuitId: bigintToHex32(456n),
    proof: pf_b,
    inputs: [5n, 0n, 0n],
  },
  {
    circuitId: bigintToHex32(456n),
    proof: pf_b,
    inputs: [6n, 0n, 0n],
  },
].map(CircuitIdProofAndInputs.from_json);

const dummyProofData = loadDummyProofData();
expect(dummyProofData.circuitId).eql(DUMMY_PROOF_CIRCUIT_ID);

describe("SubmissionInterval", () => {
  const sub =
    // eslint-disable-next-line
    Submission.fromCircuitIdsProofsInputsAndDupIdx(cidsProofsAndInputs, 0);

  it("correctly splits full submission", () => {
    // [ a, b, c, d, e, f ]
    const siAll: SubmissionInterval = {
      submission: sub,
      startIdx: 0,
      numProofs: 6,
      data: undefined,
    };

    // [ a, b, c, d, e, f ]
    // 2 -> [ a, b, _, _, _, _ ], [ _, _, c, d, e, f ]
    expect(splitSubmissionInterval(siAll, 2)).eql([
      {
        submission: sub,
        startIdx: 0,
        numProofs: 2,
        data: undefined,
      },
      {
        submission: sub,
        startIdx: 2,
        numProofs: 4,
        data: undefined,
      },
    ]);

    // [ a, b, c, d, e, f ]
    // 3 -> [ a, b, c, _, _, _ ], [ _, _, _, d, e, f ]
    expect(splitSubmissionInterval(siAll, 3)).eql([
      {
        submission: sub,
        startIdx: 0,
        numProofs: 3,
        data: undefined,
      },
      {
        submission: sub,
        startIdx: 3,
        numProofs: 3,
        data: undefined,
      },
    ]);

    // [ a, b, c, d, e, f ]
    // 6 -> [ a, b, c, d, e, f ], undefined
    expect(splitSubmissionInterval(siAll, 6)).eql([siAll, undefined]);

    // [ a, b, c, d, e, f ]
    // 8 -> [ a, b, c, d, e, f ], undefined
    expect(splitSubmissionInterval(siAll, 8)).eql([siAll, undefined]);
  });

  // Splitting of submission tail: [ _, _, c, d, e, f ]
  it("correctly splits submission tail", () => {
    const siPartial: SubmissionInterval = {
      submission: sub,
      startIdx: 2,
      numProofs: 4,
      data: undefined,
    };

    // [ _, _, c, d, e, f ]
    // 2 -> [ _, _, c, d, _, _ ], [ _, _, _, _, e, f ]
    expect(splitSubmissionInterval(siPartial, 2)).eql([
      {
        submission: sub,
        startIdx: 2,
        numProofs: 2,
        data: undefined,
      },
      {
        submission: sub,
        startIdx: 4,
        numProofs: 2,
        data: undefined,
      },
    ]);

    // [ _, _, c, d, e, f ]
    // 3 -> [ _, _, c, d, e, _ ], [ _, _, _, _, _, f ]
    expect(splitSubmissionInterval(siPartial, 3)).eql([
      {
        submission: sub,
        startIdx: 2,
        numProofs: 3,
        data: undefined,
      },
      {
        submission: sub,
        startIdx: 5,
        numProofs: 1,
        data: undefined,
      },
    ]);

    // [ _, _, c, d, e, f ]
    // 4 -> [ _, _, c, d, e, f ], undefined
    // eslint-disable-next-line
    expect(splitSubmissionInterval(siPartial, 4)).eql([siPartial, undefined]);

    // [ _, _, c, d, e, f ]
    // 8 -> [ _, _, c, d, e, f ], undefined
    // eslint-disable-next-line
    expect(splitSubmissionInterval(siPartial, 8)).eql([siPartial, undefined]);
  });

  it("correctly splits submission mid-interval", () => {
    // [ _, b, c, d, e, _ ]
    const siPartial: SubmissionInterval = {
      submission: sub,
      startIdx: 1,
      numProofs: 4,
      data: undefined,
    };

    // [ _, b, c, d, e, _ ]
    // 2 -> [ _, b, c, _, _, _ ], [ _, _, _, d, e, _ ]
    expect(splitSubmissionInterval(siPartial, 2)).eql([
      {
        submission: sub,
        startIdx: 1,
        numProofs: 2,
        data: undefined,
      },
      {
        submission: sub,
        startIdx: 3,
        numProofs: 2,
        data: undefined,
      },
    ]);

    // [ _, _, c, d, e, f ]
    // 3 -> [ _, b, c, d, _, _ ], [ _, _, _, _, e, _ ]
    expect(splitSubmissionInterval(siPartial, 3)).eql([
      {
        submission: sub,
        startIdx: 1,
        numProofs: 3,
        data: undefined,
      },
      {
        submission: sub,
        startIdx: 4,
        numProofs: 1,
        data: undefined,
      },
    ]);

    // [ _, b, c, d, e, _ ]
    // 4 -> [ _, b, c, d, e, _ ], undefined
    // eslint-disable-next-line
    expect(splitSubmissionInterval(siPartial, 4)).eql([siPartial, undefined]);

    // [ _, b, c, d, e, _ ]
    // 5 -> [ _, b, c, d, e, _ ], undefined
    // eslint-disable-next-line
    expect(splitSubmissionInterval(siPartial, 5)).eql([siPartial, undefined]);
  });

  describe("correctly merges", () => {
    const sA = Submission.fromCircuitIdsProofsInputsAndDupIdx(
      [
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
      ].map(CircuitIdProofAndInputs.from_json),
      0
    );

    const sB = Submission.fromCircuitIdsProofsInputsAndDupIdx(
      [
        {
          circuitId: bigintToHex32(456n),
          proof: pf_b,
          inputs: [5n, 0n, 0n],
        },
        {
          circuitId: bigintToHex32(456n),
          proof: pf_b,
          inputs: [6n, 0n, 0n],
        },
        {
          circuitId: bigintToHex32(123n),
          proof: pf_b,
          inputs: [7n, 0n, 0n],
        },
      ].map(CircuitIdProofAndInputs.from_json),
      0
    );

    const sC = Submission.fromCircuitIdsProofsInputsAndDupIdx(
      [
        {
          circuitId: bigintToHex32(321n),
          proof: pf_b,
          inputs: [8n, 0n, 0n],
        },
        {
          circuitId: bigintToHex32(123n),
          proof: pf_b,
          inputs: [9n, 0n, 0n],
        },
      ].map(CircuitIdProofAndInputs.from_json),
      0
    );

    it("in trivial cases", () => {
      /// []
      /// -> []
      {
        expect(mergeSubmissionIntervals([])).eql([]);
      }

      // [
      //   { sid:A, entries: [ a, b, _, _ ] }
      // ]
      // -> (unchanged)
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 0,
            numProofs: 2,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ _, b, c, _ ] }
      // ]
      // -> (unchanged)
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 1,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 1,
            numProofs: 2,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ _, _, c, d ] }
      // ]
      // -> (unchanged)
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 2,
            numProofs: 2,
            data: undefined,
          },
        ]);
      }
    });

    it("in complex cases", () => {
      // [
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, _ ] },
      // ]
      // -> [{ sid:A, entries: [ a, b, c, _ ] }]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 2,
            numProofs: 2,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, _ ] },
      // ]
      // -> [{ sid:A, entries: [ a, b, c, _ ] }]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 0,
            numProofs: 4,
            data: undefined,
          },
        ]);
      }

      // [
      //   {sid:B},
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, d ] },
      //   {sid:C},
      // ]
      // -> [{sid:B}, { sid:A, entries: [ a, b, c, d ] }, {sid:C}]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sB,
              startIdx: 0,
              numProofs: 3,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sC,
              startIdx: 0,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sB,
            startIdx: 0,
            numProofs: 3,
            data: undefined,
          },
          {
            submission: sA,
            startIdx: 0,
            numProofs: 4,
            data: undefined,
          },
          {
            submission: sC,
            startIdx: 0,
            numProofs: 1,
            data: undefined,
          },
        ]);
      }

      // [
      //   {sid:B},
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, _ ] },
      // ]
      // -> [{sid:B}, { sid:A, entries: [ a, b, c, _ ] }]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sB,
              startIdx: 0,
              numProofs: 3,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sB,
            startIdx: 0,
            numProofs: 3,
            data: undefined,
          },
          {
            submission: sA,
            startIdx: 0,
            numProofs: 3,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, d ] },
      //   {sid:B},
      // ]
      // -> [{ sid:A, entries: [ a, b, c, d ] }, {sid:B}]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sB,
              startIdx: 0,
              numProofs: 3,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 0,
            numProofs: 4,
            data: undefined,
          },
          {
            submission: sB,
            startIdx: 0,
            numProofs: 3,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ _, b, c, _ ] },
      //   { sid:A, entries: [ _, _, _, d ] },
      // ]
      // -> [{ sid:A, entries: [ _, b, c, d ] }
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 1,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 3,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 1,
            numProofs: 3,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, _ ] },
      //   { sid:A, entries: [ _, _, _, d ] },
      // ]
      // -> [{ sid:A, entries: [ a, b, c, d ] }
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 1,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 3,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 0,
            numProofs: 4,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ _, b, c, _ ] },
      //   { sid:A, entries: [ _, _, _, d ] },
      //   { sid:B, entries: [ a, b, _ ] },
      //   { sid:B, entries: [ _, _, c ] ,
      // ]
      // -> [{ sid:A, entries: [ _, b, c, d ] },
      //          { sid:B, entries: [ a, b, c ] }]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 1,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 3,
              numProofs: 1,
              data: undefined,
            },
            {
              submission: sB,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sB,
              startIdx: 2,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sA,
            startIdx: 1,
            numProofs: 3,
            data: undefined,
          },
          {
            submission: sB,
            startIdx: 0,
            numProofs: 3,
            data: undefined,
          },
        ]);
      }

      // [
      //   {sid:B},
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, d ] },
      // ]
      // -> [{sid:B}, { sid:A, entries: [ a, b, c, d ] }]
      {
        expect(
          mergeSubmissionIntervals([
            {
              submission: sB,
              startIdx: 0,
              numProofs: 3,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).eql([
          {
            submission: sB,
            startIdx: 0,
            numProofs: 3,
            data: undefined,
          },
          {
            submission: sA,
            startIdx: 0,
            numProofs: 4,
            data: undefined,
          },
        ]);
      }

      // [
      //   { sid:A, entries: [ a, b, _, _ ] },
      //   { sid:A, entries: [ _, _, c, _ ] },
      //   {sid:B},
      // ]
      // -> (error)
      {
        expect(() =>
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 1,
              data: undefined,
            },
            {
              submission: sB,
              startIdx: 0,
              numProofs: 3,
              data: undefined,
            },
          ])
        ).to.throw();
      }

      // [
      //   {sid:B},
      //   { sid:A, entries: [ _, _, c, _ ] },
      // ]
      // -> (error)
      {
        expect(() =>
          mergeSubmissionIntervals([
            {
              submission: sB,
              startIdx: 0,
              numProofs: 3,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).to.throw();
      }

      // [
      //   [{ sid:A, entries: [ a, b, _, _ ] }],
      //   [{ sid:A, entrie: [ _, _, _, d ] }]
      // ]
      // -> (error)
      {
        expect(() =>
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 0,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 3,
              numProofs: 1,
              data: undefined,
            },
          ])
        ).to.throw();
      }

      // [
      //   [{ sid:A, entries: [ _, b, c, _ ] }],
      //   [{ sid:A, entries: [ _, _, c, d ] }],
      // ]
      // -> (error)
      {
        expect(() =>
          mergeSubmissionIntervals([
            {
              submission: sA,
              startIdx: 1,
              numProofs: 2,
              data: undefined,
            },
            {
              submission: sA,
              startIdx: 2,
              numProofs: 2,
              data: undefined,
            },
          ])
        ).to.throw();
      }
    });

    it("with dummy proof", () => {
      const dummySubmission = Submission.fromCircuitIdsProofsInputsAndDupIdx(
        [dummyProofData],
        0
      );
      // if the dummy proof appears at the end, merging should succeed.
      expect(
        mergeSubmissionIntervals([
          {
            submission: sA,
            startIdx: 0,
            numProofs: 2,
            data: undefined,
          },
          {
            submission: sA,
            startIdx: 2,
            numProofs: 2,
            data: undefined,
          },
          {
            submission: dummySubmission,
            startIdx: 0,
            numProofs: 1,
            data: undefined,
          },
        ])
      ).eqls([
        {
          submission: sA,
          startIdx: 0,
          numProofs: 4,
          data: undefined,
        },
        {
          submission: dummySubmission,
          startIdx: 0,
          numProofs: 1,
          data: undefined,
        },
      ]);
      // otherwise, it should throw
      expect(() =>
        mergeSubmissionIntervals([
          {
            submission: dummySubmission,
            startIdx: 0,
            numProofs: 1,
            data: undefined,
          },
          {
            submission: sA,
            startIdx: 0,
            numProofs: 2,
            data: undefined,
          },
        ])
      ).to.throw();
      expect(() =>
        mergeSubmissionIntervals([
          { submission: sB, startIdx: 0, numProofs: 3, data: undefined },
          {
            submission: dummySubmission,
            startIdx: 0,
            numProofs: 1,
            data: undefined,
          },
          {
            submission: sA,
            startIdx: 0,
            numProofs: 2,
            data: undefined,
          },
        ])
      ).to.throw();
    });

    it("mismatched data should throw", () => {
      expect(() =>
        mergeSubmissionIntervals([
          {
            submission: sA,
            startIdx: 0,
            numProofs: 2,
            data: 1n,
          },
          {
            submission: sA,
            startIdx: 2,
            numProofs: 2,
            data: 2n,
          },
        ])
      ).to.throw();
    });
  });
});
