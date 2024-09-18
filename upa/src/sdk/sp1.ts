import {
  AppVkProofInputs,
  Groth16Proof,
  Groth16VerifyingKey,
} from "./application";

export type SP1ProofFixture = {
  // SP1 Program Verification Key
  vkey: string;
  // SP1 Public Values Digest
  publicValuesDigest: string;
  // SP1 Encoded Proof (first 4 bytes are verifier hash)
  proof: string;
};

// eslint-disable-next-line max-len
export const P = BigInt(
  "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
);

// Returns the negation of a in Fp
// In other words, x such that a + x = 0 mod p
// TS equivalent negate fn. from SP1's Groth16Verifier.sol
const negateFp = (a: bigint): bigint => {
  const aReduced = a % P;
  return (P - aReduced) % P;
};

// From SP1VerifierGroth16.sol
type SP1Groth16VerifyingKey = {
  ALPHA_X: bigint;
  ALPHA_Y: bigint;
  BETA_NEG_X_0: bigint;
  BETA_NEG_X_1: bigint;
  BETA_NEG_Y_0: bigint;
  BETA_NEG_Y_1: bigint;
  GAMMA_NEG_X_0: bigint;
  GAMMA_NEG_X_1: bigint;
  GAMMA_NEG_Y_0: bigint;
  GAMMA_NEG_Y_1: bigint;
  DELTA_NEG_X_0: bigint;
  DELTA_NEG_X_1: bigint;
  DELTA_NEG_Y_0: bigint;
  DELTA_NEG_Y_1: bigint;
  CONSTANT_X: bigint;
  CONSTANT_Y: bigint;
  PUB_0_X: bigint;
  PUB_0_Y: bigint;
  PUB_1_X: bigint;
  PUB_1_Y: bigint;
};

// Constants from v1.2.0
/* eslint-disable max-len */
const SP1_GROTH16_VK_V1_2_0 = {
  // Groth16 alpha point in G1
  ALPHA_X: BigInt(
    "16824748082761027289403020823817900376175197022851240418647484763478464123198"
  ),
  ALPHA_Y: BigInt(
    "11683994685964714260324343303943939682301299075504304862945838718548302000401"
  ),

  // Groth16 beta point in G2 in powers of i
  BETA_NEG_X_0: BigInt(
    "6012203653756052523353542340150469539265082406293136140411872887864191664305"
  ),
  BETA_NEG_X_1: BigInt(
    "6291636065550854379100787904950515357219288186946057578788825789245406766953"
  ),
  BETA_NEG_Y_0: BigInt(
    "8479861103528550966799853659352503798462730898093166661842402674702796622679"
  ),
  BETA_NEG_Y_1: BigInt(
    "1633523335605438695154599416411390033345510848756189876127962429956098742451"
  ),

  // Groth16 gamma point in G2 in powers of i
  GAMMA_NEG_X_0: BigInt(
    "4142835535619576684322245157901312250554378142114381564290468432742521314704"
  ),
  GAMMA_NEG_X_1: BigInt(
    "17842020501532861335251277735290851172413446056529606168368465340825902541810"
  ),
  GAMMA_NEG_Y_0: BigInt(
    "11320632725496471124352232673686498720611893913179832806771034178631284892116"
  ),
  GAMMA_NEG_Y_1: BigInt(
    "311895667756833756493099755182157054434816599621289498984920445818614464745"
  ),

  // Groth16 delta point in G2 in powers of i
  DELTA_NEG_X_0: BigInt(
    "1401586467118744686649898232509431431936958634904286407525795344840171509724"
  ),
  DELTA_NEG_X_1: BigInt(
    "20524563347740346853186643374142185321405370469810755613088256350493061219989"
  ),
  DELTA_NEG_Y_0: BigInt(
    "14665335796225261740324266854622393607627804871217389582109229884209518049091"
  ),
  DELTA_NEG_Y_1: BigInt(
    "4675922494502640538519101370992755143525716960516481658013166874162416756018"
  ),

  // Constant and public input points
  CONSTANT_X: BigInt(
    "8310411565601441527035131496852221148476487246063333349863921483414575409313"
  ),
  CONSTANT_Y: BigInt(
    "21343132819492496456805562863075138986248235983567056732949060829719030087739"
  ),
  PUB_0_X: BigInt(
    "9193066544127521442507379487110183725565203847410097866655781919341371314500"
  ),
  PUB_0_Y: BigInt(
    "1229953730407424098511641946145120096161248105904311204671469367759481075237"
  ),
  PUB_1_X: BigInt(
    "9302931036688912050769082570627051329799904248848128887752496390619992168298"
  ),
  PUB_1_Y: BigInt(
    "11368205644090635269179087945262736859378503013874730222437645132828283002424"
  ),
};
/* eslint-enable max-len */

export const sp1Versions = ["v1.2.0"];

export const sp1VersionToGroth16Vk = new Map<string, SP1Groth16VerifyingKey>();

sp1VersionToGroth16Vk.set("v1.2.0", SP1_GROTH16_VK_V1_2_0);

export const convertSp1ProofFixture = (
  fixture: SP1ProofFixture,
  version: string
) => {
  if (!sp1Versions.includes(version)) {
    throw new Error(`SP1 version ${version} not supported by UPA SDK`);
  }

  const groth16Vk = sp1VersionToGroth16Vk.get(version);

  if (!groth16Vk) {
    throw new Error(`SP1 version ${version} not supported by UPA SDK`);
  }

  const {
    ALPHA_X,
    ALPHA_Y,
    BETA_NEG_X_0,
    BETA_NEG_X_1,
    BETA_NEG_Y_0,
    BETA_NEG_Y_1,
    GAMMA_NEG_X_0,
    GAMMA_NEG_X_1,
    GAMMA_NEG_Y_0,
    GAMMA_NEG_Y_1,
    DELTA_NEG_X_0,
    DELTA_NEG_X_1,
    DELTA_NEG_Y_0,
    DELTA_NEG_Y_1,
    CONSTANT_X,
    CONSTANT_Y,
    PUB_0_X,
    PUB_0_Y,
    PUB_1_X,
    PUB_1_Y,
  } = groth16Vk;

  // Parse public inputs
  const PROGRAM_VKEY = BigInt(fixture.vkey);
  const PI_DIGEST = BigInt(fixture.publicValuesDigest);

  const UPA_INPUTS = [PROGRAM_VKEY, PI_DIGEST];

  // Parse proof
  // Remove 0x prefix
  const PROOF = fixture.proof.slice(2);

  let idx = 0;

  // First 4 bytes form the verifier hash
  // See SP1Groth16Verifier.sol for details
  // Currently unused in UPA SDK

  /* eslint-disable-next-line @typescript-eslint/no-unused-vars */
  const V_HASH = "0x" + PROOF.slice(idx, (idx += 8));

  const piA_X = "0x" + PROOF.slice(idx, (idx += 64));
  const piA_Y = "0x" + PROOF.slice(idx, (idx += 64));

  const PI_B_X_1 = "0x" + PROOF.slice(idx, (idx += 64));
  const PI_B_X_0 = "0x" + PROOF.slice(idx, (idx += 64));
  const PI_B_Y_1 = "0x" + PROOF.slice(idx, (idx += 64));
  const PI_B_Y_0 = "0x" + PROOF.slice(idx, (idx += 64));

  const PI_C_X = "0x" + PROOF.slice(idx, (idx += 64));
  const PI_C_Y = "0x" + PROOF.slice(idx, (idx += 64));

  const UPA_GROTH16_PROOF: Groth16Proof = new Groth16Proof(
    [piA_X, piA_Y],
    [
      [PI_B_X_0, PI_B_X_1],
      [PI_B_Y_0, PI_B_Y_1],
    ],
    [PI_C_X, PI_C_Y],
    [],
    []
  );

  // SP1 G2 VK Points in contract are negated
  // UPA G2 VK Points are not negated
  const UPA_GROTH16_VK: Groth16VerifyingKey = new Groth16VerifyingKey(
    [ALPHA_X.toString(), ALPHA_Y.toString()],
    [
      [BETA_NEG_X_0.toString(), BETA_NEG_X_1.toString()],
      [negateFp(BETA_NEG_Y_0).toString(), negateFp(BETA_NEG_Y_1).toString()],
    ],
    [
      [GAMMA_NEG_X_0.toString(), GAMMA_NEG_X_1.toString()],
      [negateFp(GAMMA_NEG_Y_0).toString(), negateFp(GAMMA_NEG_Y_1).toString()],
    ],
    [
      [DELTA_NEG_X_0.toString(), DELTA_NEG_X_1.toString()],
      [negateFp(DELTA_NEG_Y_0).toString(), negateFp(DELTA_NEG_Y_1).toString()],
    ],
    [
      [CONSTANT_X.toString(), CONSTANT_Y.toString()],
      [PUB_0_X.toString(), PUB_0_Y.toString()],
      [PUB_1_X.toString(), PUB_1_Y.toString()],
    ],
    [],
    []
  );

  const UPA_PROOF_VK_INPUTS: AppVkProofInputs = {
    proof: UPA_GROTH16_PROOF,
    vk: UPA_GROTH16_VK,
    inputs: UPA_INPUTS,
  };

  return UPA_PROOF_VK_INPUTS;
};
