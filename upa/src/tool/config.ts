import { Submission, utils } from "../sdk";
import * as log from "./log";
import {
  UpaInstanceDescriptor,
  UpaInstance,
  upaInstanceFromDescriptor,
  UpaConfig,
} from "../sdk/upa";
import {
  AppVkProofInputs,
  Groth16VerifyingKey,
  Groth16Proof,
  CircuitIdProofAndInputs,
} from "../sdk/application";
import { SnarkJSVKey } from "../sdk/snarkjs";
import * as ethers from "ethers";
import * as fs from "fs";
import * as path from "path";
import { strict as assert } from "assert";
import { GnarkInputs, GnarkProof, GnarkVerificationKey } from "../sdk/gnark";
import { computeCircuitId } from "../sdk/utils";

/// Load an instance descriptor file
export function loadInstance(instanceFile: string): UpaInstanceDescriptor {
  return JSON.parse(
    fs.readFileSync(instanceFile, "ascii")
  ) as UpaInstanceDescriptor;
}

/// Load an instance descriptor file and initialize and instance.  Optionally
/// connect to an ethers.Provider or etheres.Signer.
export function upaFromInstanceFile(
  instanceFile: string,
  provider: ethers.ContractRunner
): UpaInstance {
  const instanceDesc = loadInstance(instanceFile);
  return upaInstanceFromDescriptor(instanceDesc, provider);
}

/// Create a Signer from an encrypted keyfile.
export async function loadWallet(
  keyfile: string,
  password: string,
  provider?: ethers.Provider
): Promise<ethers.BaseWallet> {
  const keystoreStr = fs.readFileSync(keyfile, "ascii");
  let wallet = await ethers.Wallet.fromEncryptedJson(keystoreStr, password);
  if (provider) {
    wallet = wallet.connect(provider);
  }
  return wallet;
}

/// Read an address from a keyfile
export function readAddressFromKeyfile(keyfile: string): string {
  const keystoreObj = JSON.parse(fs.readFileSync(keyfile, "ascii"));
  return ethers.getAddress(keystoreObj.address);
}

/// Result of handling a transaction according to standard flags.
type HandleTxRequestResult = {
  // The populated Tx
  populatedTx: ethers.TransactionRequest;
  // Gas cost, if computed
  gas?: bigint;
  // The sent Tx, if available
  sentTx?: ethers.TransactionResponse;
};

/// Handle tx according to some standard flags, and process errors so they are
/// more human-readable.
export async function handleTxRequestInternal(
  wallet: ethers.Signer,
  txReq: ethers.PreparedTransactionRequest,
  estimateGas: boolean,
  dumpTx: boolean,
  wait: boolean,
  contractInterface?: ethers.Interface
): Promise<HandleTxRequestResult> {
  const doHandleTx = async () => {
    const populatedTx = await wallet.populateTransaction(txReq);
    const provider = wallet.provider;
    assert(provider);

    const result: HandleTxRequestResult = { populatedTx };

    if (estimateGas) {
      assert(!wait, "--estimate-gas should not be used with --wait");
      const gas = await provider.estimateGas(populatedTx);
      result.gas = gas;
      return result;
    }

    if (dumpTx) {
      return result;
    }

    const signedTx = await wallet.signTransaction(populatedTx);
    const tx = await provider.broadcastTransaction(signedTx);
    result.sentTx = tx;

    log.info(tx.hash);
    if (wait) {
      log.debug("waiting ...");
      await tx.wait();
    }

    return result;
  };

  return doHandleTx().catch((err) => {
    // If an interface was given, attempt to decode the error
    if (contractInterface) {
      // eslint-disable-next-line
      const data = (err as any)?.data?.data || (err as any)?.data;
      if (data) {
        throw utils.JSONstringify({
          error: err,
          msg: contractInterface.parseError(data),
        });
      }
    }

    throw err;
  });
}

/// Consistent handling of txs over multiple commands.  If estimateGas is
/// true, print the gas and exit.  Otherwise, if dumpTx is true, write out the
/// Tx JSON and exit, otherwise sign and send the tx, optionally waiting for
/// it to be accepted.
export async function handleTxRequest(
  wallet: ethers.Signer,
  txReq: ethers.PreparedTransactionRequest,
  estimateGas: boolean,
  dumpTx: boolean,
  wait: boolean,
  contractInterface?: ethers.Interface
): Promise<void> {
  const handleTxResult = await handleTxRequestInternal(
    wallet,
    txReq,
    estimateGas,
    dumpTx,
    wait,
    contractInterface
  );

  // TODO: this is not great for now as we are trying to replicate the
  // behaviour of handleTxRequestInternal, but this allows us to use this
  // high-level command for most txs, and the `Internal` version for commands
  // where we need to control exactly what is output.

  if (estimateGas) {
    assert(!dumpTx, "--dump-tx should not be used with --estimate-gas");
    assert(!wait, "--dump-tx should not be used with --wait");
    assert(handleTxResult.gas);
    console.log(`${handleTxResult.gas} gas`);
    return;
  }

  if (dumpTx) {
    assert(handleTxResult.populatedTx);
    console.log(utils.JSONstringify(handleTxResult.populatedTx));
    return;
  }

  assert(handleTxResult.sentTx);
  console.log(handleTxResult.sentTx.hash);
}

/// Load application VK
export function loadAppVK(filename: string): Groth16VerifyingKey {
  const json = fs.readFileSync(filename, "ascii");
  return Groth16VerifyingKey.from_json(JSON.parse(json) as object);
}

/// Load SnarkJS VK
export function loadSnarkjsVK(filename: string): SnarkJSVKey {
  return JSON.parse(fs.readFileSync(filename, "ascii")) as SnarkJSVKey;
}

///
export function loadGnarkVK(filename: string): GnarkVerificationKey {
  return JSON.parse(fs.readFileSync(filename, "ascii")) as GnarkVerificationKey;
}

///
export function loadGnarkProof(filename: string): GnarkProof {
  return JSON.parse(fs.readFileSync(filename, "ascii")) as GnarkProof;
}

export function loadGnarkInputs(filename: string): GnarkInputs {
  const inputsJSON = JSON.parse(fs.readFileSync(filename, "ascii"));
  const result = inputsJSON.map(BigInt);
  console.log(result);
  return result;
}

export function loadAppVkProofInputsFile(filename: string): AppVkProofInputs {
  const vkProofInputs: object = JSON.parse(fs.readFileSync(filename, "ascii"));
  return AppVkProofInputs.from_json(
    vkProofInputs,
    Groth16VerifyingKey.from_json,
    Groth16Proof.from_json
  );
}

export function loadAppVkProofInputsBatchFile(
  filename: string
): AppVkProofInputs[] {
  const proofsWithInputs: object[] = JSON.parse(
    fs.readFileSync(filename, "ascii")
  );
  return proofsWithInputs.map((o) =>
    AppVkProofInputs.from_json(
      o,
      Groth16VerifyingKey.from_json,
      Groth16Proof.from_json
    )
  );
}

/// Converts either of the JSON objects:
/// - A single object { vk, proof, inputs }
/// - A single object { circuitId, proof, inputs }
/// into a `CircuitIdProofAndInputs`
export function singleProofAsCircuitIdProofAndInputs(
  parsedJSON: object
): CircuitIdProofAndInputs {
  // Attempt to load as AppVkProofInputs
  const vkProofsAndInputs = parsedJSON as AppVkProofInputs;
  if (typeof vkProofsAndInputs.vk === "object") {
    return CircuitIdProofAndInputs.from_json({
      circuitId: computeCircuitId(vkProofsAndInputs.vk),
      proof: vkProofsAndInputs.proof,
      inputs: vkProofsAndInputs.inputs,
    });
  }

  // Attempt to load as CircuitIdProofAndInputs
  const circuitIdProofsAndInputs = parsedJSON as CircuitIdProofAndInputs;
  if (typeof circuitIdProofsAndInputs.circuitId === "string") {
    return CircuitIdProofAndInputs.from_json(parsedJSON);
  }

  throw Error("Incorrect single proof format.");
}

/// Loads the file formats:
/// - A single object { vk, proof, inputs }
/// - A single object { circuitId, proof, inputs }
/// into a `CircuitIdProofAndInputs`
export function loadSingleProofFileAsCircuitIdProofAndInputs(
  filename: string
): CircuitIdProofAndInputs {
  const parsedJSON: object = JSON.parse(fs.readFileSync(filename, "ascii"));
  return singleProofAsCircuitIdProofAndInputs(parsedJSON);
}

/// Converts either of the JSON formats:
/// - An array of { vk, proof, inputs }
/// - An array of { circuitId, proof, inputs }
/// into a `CircuitIdProofAndInputs[]`
export function proofArrayAsCircuitIdProofAndInputs(
  parsedJSON: object[]
): CircuitIdProofAndInputs[] {
  // Attempt to load as AppVkProofInputs[]
  const vkProofsAndInputs = parsedJSON as AppVkProofInputs[];
  if (typeof vkProofsAndInputs[0].vk === "object") {
    return vkProofsAndInputs.map((vpi) => {
      return CircuitIdProofAndInputs.from_json({
        circuitId: computeCircuitId(vpi.vk),
        proof: vpi.proof,
        inputs: vpi.inputs,
      });
    });
  }

  // Attempt to load as CircuitIdProofAndInputs[]
  const circuitIdProofsAndInputs = parsedJSON as CircuitIdProofAndInputs[];
  if (typeof circuitIdProofsAndInputs[0].circuitId === "string") {
    return parsedJSON.map((obj) => CircuitIdProofAndInputs.from_json(obj));
  }
  throw Error("Incorrect proof array format.");
}

/// Loads the JSON file formats:
/// - An array of { vk, proof, inputs }
/// - An array of { circuitId, proof, inputs }
/// - A single object { vk, proof, inputs }
/// - A single object { circuitId, proof, inputs }
/// into an array `CircuitIdProofAndInputs[]`, ready to submit to UPA.
///
/// Throws if the file format does not match one of the above formats.
export function loadProofFileAsCircuitIdProofAndInputsArray(
  filename: string
): CircuitIdProofAndInputs[] {
  const parsedJSON: object[] = JSON.parse(fs.readFileSync(filename, "ascii"));
  if (Array.isArray(parsedJSON)) {
    return proofArrayAsCircuitIdProofAndInputs(parsedJSON);
  } else {
    return [singleProofAsCircuitIdProofAndInputs(parsedJSON)];
  }
}

/// Load the UPA config file that was used to generate the circuits.
export function loadUpaConfig(upaConfigFile: string): UpaConfig {
  return JSON.parse(fs.readFileSync(upaConfigFile, "utf-8"));
}

export function findUpaDir(): string {
  let dir = __dirname;
  while (!fs.existsSync(path.join(dir, "dist", "package.json"))) {
    dir = path.dirname(dir);
    if (dir === path.dirname(dir)) {
      throw new Error("Project root not found");
    }
  }
  return dir;
}

export function loadDummyProofData(): CircuitIdProofAndInputs {
  const upaDir = findUpaDir();
  const dummyProofFile = `${upaDir}/test/dummy/dummy_proof.upa.json`;
  return loadSingleProofFileAsCircuitIdProofAndInputs(dummyProofFile);
}

export function loadDummyVK(): Groth16VerifyingKey {
  const upaDir = findUpaDir();
  const dummyVKFile = `${upaDir}/test/dummy/dummy_vk.upa.json`;
  return loadAppVK(dummyVKFile);
}

/// Load a Submission object from a file
export function loadSubmission(filename: string): Submission {
  return Submission.from_json(fs.readFileSync(filename, "ascii"));
}
