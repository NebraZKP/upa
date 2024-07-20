import { expect } from "chai";
import { application } from "../src/sdk";
import { SnarkJSProof } from "../src/sdk/snarkjs";
import { GnarkProof } from "../src/sdk/gnark";

describe("Application", () => {
  // Sample snarkjs proof data from the demo-app.
  // eslint-disable-next-line
  const snarkjsProofData = {
    proof: {
      pi_a: [
        // eslint-disable-next-line
        "17744376663532097317485783491747860775914678513822928001932875741042914462904",
        // eslint-disable-next-line
        "11094770315232978073638548164398910587900468733763894156880072738084987419865",
        "1",
      ],
      pi_b: [
        [
          // eslint-disable-next-line
          "605206633930345541695663273400816523037437407926507669953314174314721503561",
          // eslint-disable-next-line
          "15625484640176526230536130091583840235150831606466440955050523683990973723264",
        ],
        [
          // eslint-disable-next-line
          "8846788807317690941528557528412121111448355240241260094197162224542284891820",
          // eslint-disable-next-line
          "16791610613411431006300402330693144962764699630402441713438537252601919981899",
        ],
        ["1", "0"],
      ],
      pi_c: [
        // eslint-disable-next-line
        "5833867748280713133669878270309873032973505621834726589591128740396310269504",
        // eslint-disable-next-line
        "1260394973503253533411972689781095642144990723677131064119173013755801805746",
        "1",
      ],
      protocol: "groth16",
      curve: "bn128",
    },
    publicSignals: ["23774", "13148", "47548"],
  };
  // eslint-enable

  const snarkjsProofExpect = new application.Groth16Proof(
    [
      "0x273af6169ad92751e3b20a67cc67c2ddf998960e41c0f456f2e12a28c8d58cb8",
      "0x18876adeeff085c8178690b518670f4719a7d16df94d5fa65c9b9e2b2c913cd9",
    ],
    [
      [
        "0x015688e9b0ab398daa2bf5af85f64025ab04fc5f1bb6f68033253ffba0eae949",
        "0x228bb5fd592018b905921baffe58158f4c3069d8f625a0faaafde83168f43280",
      ],
      [
        "0x138f1ae294508de4ce974a81e13b52a2c092a35785c428aac82103ec1371c6ac",
        "0x251fb6fdac11473f2e173bc97e217cb7ea5104cf004de544abe2e064b5d0494b",
      ],
    ],
    [
      "0x0ce5da25579a4983c5468454ac2639eaf7ca540612fc53714ecaa5cfa24d0e40",
      "0x02c95bb7e150b5900bb3474bcfa2ca0772b6524836b8ba1ff43227fc424ea3b2",
    ],
    [],
    []
  );

  // Sample Gnark proof data from Brevis.
  // eslint-disable-next-line
  const gnarkProofData = {
    Ar: {
      // eslint-disable-next-line
      X: "20934579367966291584717573903206788679461237936481123179626217764335308387002",
      // eslint-disable-next-line
      Y: "13046438475049311798772631343741920452364665104772658928190186786976466702696",
    },
    Krs: {
      // eslint-disable-next-line
      X: "8974860757117300533539990550905731397765624975552355113138317252585651892623",
      // eslint-disable-next-line
      Y: "2956869890815927214652007539578001333860389311197697598815622425718071817847",
    },
    Bs: {
      X: {
        // eslint-disable-next-line
        A0: "13049244466569935163499660017775593037177980681640549586904940521246701893755",
        // eslint-disable-next-line
        A1: "19277748768080823370993816218782843541323430215659841625539246015225864112516",
      },
      Y: {
        // eslint-disable-next-line
        A0: "12511003952503161048605070929765377465268932178922863011919714909708796669939",
        // eslint-disable-next-line
        A1: "17392438560285846847045393351128798746965523127411534249313761090383087790034",
      },
    },
    Commitments: [
      {
        // eslint-disable-next-line
        X: "7856551849401418337206312780272143792992617682304676811898920167160475106147",
        // eslint-disable-next-line
        Y: "7394615866234640375895482715703310589640913697951205795251091544235468188934",
      },
    ],
    CommitmentPok: {
      // eslint-disable-next-line
      X: "196304420420688550508108404419351471683380084412648767974803175549011629552",
      // eslint-disable-next-line
      Y: "8479199301402009399650245281152105753278547467527538789277936389007097830117",
    },
  };
  // eslint-enable

  const gnarkProofExpect = new application.Groth16Proof(
    [
      "0x2e488d5189825fa3055f8ea13e9e9067c06f6edea44e66581180ead49a3632ba",
      "0x1cd805c25cb7c84b9680b4ecbb0c9fdae831af7a0661d62d572f1bb8a72f9168",
    ],
    [
      [
        "0x1cd99c525f4bc718c97566af773f196c68d83efa8101ab421be0cf4875bfb87b",
        "0x2a9ed1b3050c88baaff2e403e36d3f808f68f10bfb7c2bd010f20b883823c984",
      ],
      [
        "0x1ba8fa301e765e16fd2b0edaa2b14d3593cb75acdcc7713281bc49fbef29aff3",
        "0x2673c578d528c6770550be95045dee595f060c7ed8d080df0206153306cde7d2",
      ],
    ],
    [
      "0x13d7975737f7e97624c21ff66fb319b5db204493f161558666db286f7b62f18f",
      "0x0689876fdba3d81a8dea689b7c2fd625f4987b7dc0d3d490e295e0ec22d8f677",
    ],
    [
      [
        "0x115ea6986e10cb68b2aa674e6037c82068df239ab0737e563c7b7a2ad3c13b63",
        "0x1059344a87b388c401c92a4c3a32ff81a6d488a952dfc662ec3f151cc33ced06",
      ],
    ],
    [
      [
        "0x006f1ab7a2e592276f1cd59d5642e0de559247e99a1e5ba4f6d587aed2f615f0",
        "0x12bf0e8604430e6adbad7d9b5098b2384abcf5d559b26bdd12ffdb692ff99ae5",
      ],
    ]
  );

  describe("Proof", () => {
    it("proof from snarkjs to proof", async function () {
      const snarkjs_proof = snarkjsProofData.proof as SnarkJSProof;
      const proof = application.Groth16Proof.from_snarkjs(snarkjs_proof);
      expect(proof).eql(snarkjsProofExpect);
    });

    it("proof from gnark to proof", async function () {
      const gnarkProof = gnarkProofData as GnarkProof;
      const proof = application.Groth16Proof.from_gnark(gnarkProof);
      expect(proof).eql(gnarkProofExpect);
    });
  });
});

// TODO Gnark version
