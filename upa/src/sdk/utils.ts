import {
  BytesLike,
  BigNumberish,
  ContractFactory,
  Signer,
  getUint,
  isError,
  keccak256,
  hexlify,
} from "ethers";
import { Groth16VerifyingKey } from "./groth16";
import { strict as assert } from "assert";
import { G1Point, G2Point } from "./ecc";
import * as ethers from "ethers";
import { ZERO_BYTES32 } from "./submission";
import {
  computeMerkleRoot,
  evmInnerHashFn,
  evmLeafHashFn,
} from "./merkleUtils";
import { utils } from ".";

// Domain tags for the circuit id calculations.
// Reproduce the calculation with:
//
//   `cargo test -- domain --no-capture --include-ignored`
//
// in the repo root. See
// `upa_circuits::tests::hashing::domain_tags` test.

const CIRCUIT_ID_DOMAIN_TAG =
  "0x4fb2fda778fd224ee633116280b47f502b0d937ce78d390aa16f73d9007c65f2";
const CIRCUIT_ID_DOMAIN_TAG_WITH_COMMITMENT =
  "0xbe0523909703924017e523b64b54adc1091d895bc2cea0e312c4b2e63c813202";

const zeroes = "0".repeat(64);

/// Converts a bigint into 32 byte hex string (big endian)
export function bigintToHex32(b: bigint): string {
  const hex = b.toString(16);
  if (hex.length > 64) {
    throw "bigint too large to convert to 32 bytes";
  }

  return zeroes.slice(hex.length) + hex;
}

/// Converts a bigint into 32 bytes (big endian)
export function bigintToBytes32(b: bigint): Uint8Array {
  const hex = bigintToHex32(b);

  const u8 = new Uint8Array(32);
  for (let i = 0, j = 0; i < 32; i++, j += 2) {
    u8[i] = parseInt(hex.slice(j, j + 2), 16);
  }

  return u8;
}

/// Take a length 32 BytesLike and convert it to a correctly formatted string.
export function readBytes32(x: BytesLike): string {
  if (typeof x === "string") {
    if (x.length === 64) {
      return "0x" + x;
    } else if (x.length === 66) {
      assert(x.startsWith("0x"));
      return x;
    } else {
      throw `cannot convert ${x} to string`;
    }
  } else if (typeof x === "object") {
    assert(x.length == 32);
    const cid = hexlify(x);
    assert(cid.length == 64 + 2);
    assert(cid.startsWith("0x"));
    return cid;
  } else {
    throw `cannot convert ${x} (${typeof x}) to string`;
  }
}

export function bytes32IsWellFormed(bytes32: string): boolean {
  return (
    typeof bytes32 === "string" &&
    bytes32.length == 64 + 2 &&
    bytes32.startsWith("0x")
  );
}

// Read and deploy bytecode as a contract
export async function populateDeployBinaryContract(
  deployer: Signer,
  outer_verifier_hex: string,
  nonce?: number
): Promise<ethers.PreparedTransactionRequest> {
  const factory = new ContractFactory([], outer_verifier_hex, deployer);
  return await factory.getDeployTransaction({ nonce });
}

// Read and deploy bytecode as a contract
export async function deployBinaryContract(
  deployer: Signer,
  outer_verifier_hex: string,
  nonce?: number
): Promise<string> {
  const txReq = await populateDeployBinaryContract(
    deployer,
    outer_verifier_hex,
    nonce
  );
  const sentTx = await deployer.sendTransaction(txReq);
  const address = ethers.getCreateAddress(sentTx);
  await sentTx.wait();
  return address;
}

/// JSON.stringify handling bigints as (decimal) strings.  If forceDecimal is
/// true, strings of the form: "0x<hex-string>" are also converted to
/// decimals.
export function JSONstringify(
  obj: unknown,
  spacing?: number,
  forceDecimal: boolean = false
): string {
  if (forceDecimal) {
    return JSON.stringify(
      obj,
      (_key, value) => {
        if (typeof value === "bigint") {
          return value.toString(10);
        } else if (typeof value == "string" && value.startsWith("0x")) {
          return BigInt(value).toString(10);
        }
      },
      spacing
    );
  } else {
    return JSON.stringify(
      obj,
      (_key, value) => (typeof value === "bigint" ? value.toString(10) : value),
      spacing
    );
  }
}

// Helper function that performs retries and error handling for RPC calls.
// `requestFn` can be any operation that queries the attached node.
export async function requestWithRetry<T>(
  requestFn: () => Promise<T>,
  requestLabel: string,
  maxRetries: number = 5,
  timeoutMs?: number,
  contractInterface?: ethers.Interface,
  onFail?: () => void
): Promise<T> {
  const retryWaitMs = 10000;

  // maxRetries retries means a total of 1+maxRetries attempts.
  for (let retries = 0; retries <= maxRetries; retries++) {
    try {
      const promises: Promise<T>[] = [requestFn()];

      // Add timeout promise only if a timeout is provided
      if (timeoutMs) {
        promises.push(
          new Promise<T>((_, reject) =>
            setTimeout(
              () => reject(new Error(`Request timeout for ${requestLabel}`)),
              timeoutMs
            )
          )
        );
      }

      return await Promise.race(promises);
    } catch (error) {
      // If an interface was given, attempt to decode the error. If this was a
      // custom error, throw it without retrying (it will keep reverting).
      if (contractInterface) {
        // eslint-disable-next-line
        const data = (error as any)?.data?.data || (error as any)?.data;
        if (data) {
          throw utils.JSONstringify({
            error: error,
            msg: contractInterface.parseError(data),
          });
        }
      }

      if (
        isError(error, "UNKNOWN_ERROR") ||
        isError(error, "NETWORK_ERROR") ||
        isError(error, "CALL_EXCEPTION")
      ) {
        console.error(`Error message: ${error.message}`);
        if (error.info) {
          console.error(`Error info: ${JSON.stringify(error.info)}`);
        }
        console.log(
          `Known error: ${error.code} for ${requestLabel} ` +
            `(Retry ${retries}/${maxRetries})...`
        );
      } else {
        console.error(
          `Unknown error: ${error} for ${requestLabel} ` +
            `(Retry ${retries}/${maxRetries})...`
        );
      }

      if (retries < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, retryWaitMs));
      }
    }
  }

  if (onFail) {
    onFail();
  }

  throw new Error(`Max retries reached for ${requestLabel}.`);
}

export function computeCircuitId(vk: Groth16VerifyingKey): string {
  // Find the unique 32 byte hex representations and concatenate them.
  function g1_hex(g1: G1Point): string[] {
    return g1.map((x) => bigintToHex32(BigInt(x)));
  }

  function g2_hex(g2: G2Point): string[] {
    // Sightly cheating.  G2Points are actually a pair of Fq2 points, but the
    // types make it look like a pair of G1Points.
    return g2.flatMap(g1_hex);
  }

  const hasCommitment = vk.h1.length > 0;
  const domainTag = hasCommitment
    ? CIRCUIT_ID_DOMAIN_TAG_WITH_COMMITMENT
    : CIRCUIT_ID_DOMAIN_TAG;

  // Use the "0x" prefix from the domain tag
  const preimage =
    domainTag +
    [
      g1_hex(vk.alpha),
      g2_hex(vk.beta),
      g2_hex(vk.gamma),
      g2_hex(vk.delta),
      [bigintToHex32(BigInt(vk.s.length))],
      ...vk.s.map(g1_hex),
      ...vk.h1.map(g2_hex),
      ...vk.h2.map(g2_hex),
    ]
      .flat()
      .join("");

  return keccak256(preimage);
}

export function computeProofId(
  circuitId: string,
  appPublicInputs: BigNumberish[]
): string {
  assert(bytes32IsWellFormed(circuitId), `invalid CircuitId: ${circuitId}`);
  // Leverage the fact that circuitId starts with "0x"
  const pubInputs = appPublicInputs.map(BigInt);
  const data = [circuitId, ...pubInputs.map(bigintToHex32)].join("");
  return keccak256(data);
}

/// Given an array of proofIds in a submission, compute the submissionId.
export function computeSubmissionId(
  proofIds: string[]
): ethers.ethers.BytesLike {
  const depth = Math.ceil(Math.log2(proofIds.length));
  const paddedLength = 1 << depth;
  const paddedProofIds = proofIds.slice();
  while (paddedProofIds.length < paddedLength) {
    paddedProofIds.push(ZERO_BYTES32);
  }

  proofIds.forEach((pid) => assert(typeof pid === "string"));

  return computeMerkleRoot(evmLeafHashFn, evmInnerHashFn, paddedProofIds);
}

export function computeFinalDigest(proofIds: BytesLike[]): string {
  const proofIDsPreimage =
    "0x" +
    proofIds
      .map((x) => {
        if (x.length != 66 || !x.toString().startsWith("0x")) {
          throw "invalid proofId string";
        }
        return x.slice(2);
      })
      .join("");
  return keccak256(proofIDsPreimage);
}

export function digestAsFieldElements(finalDigest: string): bigint[] {
  assert(finalDigest.length == 66);
  assert(finalDigest.startsWith("0x"));
  const finalDigestHex = finalDigest.slice(2); // remove 0x
  const finalDigest_l = "0x" + "0".repeat(32) + finalDigestHex.slice(32);
  const finalDigest_r = "0x" + "0".repeat(32) + finalDigestHex.slice(0, 32);
  return [BigInt(finalDigest_l), BigInt(finalDigest_r)];
}

/// Parse as a number, or return undefined (if the string is empty or
/// undefined).  Throws for invalid strings.
export function parseNumberOrUndefined(
  number?: string,
  errorMessage?: string
): bigint | undefined {
  let result;
  try {
    result = number ? getUint(number) : undefined;
  } catch (error) {
    if (errorMessage) {
      console.log(errorMessage, error);
    } else {
      console.log(error);
    }
    throw error;
  }
  return result;
}

export function parseWeiOrUndefined(feeInWei?: string): bigint | undefined {
  return parseNumberOrUndefined(feeInWei, "Error while parsing the fee");
}

export function parseGweiOrUndefined(valueInGwei?: string): bigint | undefined {
  if (valueInGwei) {
    return ethers.parseUnits(valueInGwei, "gwei");
  }
  return undefined;
}

export function weiToEther(wei: bigint, numDecimalPlaces: number): number {
  const weiPerEther = 10n ** 18n;
  return (
    Number((wei * 10n ** BigInt(numDecimalPlaces)) / weiPerEther) /
    10 ** Number(numDecimalPlaces)
  );
}

/// Pauses execution for `s` miliseconds, then resumes.
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function versionStringToUint(versionString: string): bigint {
  const [major, minor, patch] = versionString.split(".").map(BigInt);
  assert(
    typeof major === "bigint" &&
      typeof minor === "bigint" &&
      typeof patch === "bigint",
    `badly formed version string: ${versionString}`
  );

  return patch + minor * 100n + major * 10000n;
}

export function versionUintToString(versionUint: bigint): string {
  const patch = versionUint % 100n;
  const minor = (versionUint / 100n) % 100n;
  const major = (versionUint / 10000n) % 100n;
  return `${major}.${minor}.${patch}`;
}
