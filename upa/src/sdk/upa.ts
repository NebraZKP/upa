import * as pkg from "../../package.json";
import * as ethers from "ethers";
import {
  UpaVerifier,
  UpaProofReceiver,
  IUpaProofReceiver,
  UpaProofReceiver__factory,
  UpaVerifier__factory,
  TestUpgradedUpaVerifier,
  TestUpgradedUpaVerifier__factory,
} from "../../typechain-types";
import { Groth16Proof } from "./application";
import { PayableOverrides } from "../../typechain-types/common";
import { strict as assert } from "assert";
import { Submission } from "./submission";
import {
  SubmissionVerifiedEventGetter,
  getCallDataForVerifyAggregatedProofTx,
} from "./events";
import { events } from ".";
import {
  bigintToHex32,
  computeFinalDigest,
  digestAsFieldElements,
  versionStringToUint,
} from "./utils";

// Function lookup strings
export const isProofVerifiedSingle = "isProofVerified(bytes32,uint256[])";
export const isProofVerifiedMulti =
  "isProofVerified(bytes32,uint256[],(bytes32,bytes32[],uint16))";
export const isProofVerifiedByIdSingle = "isProofVerified(bytes32)";
export const isProofVerifiedbyIdMulti =
  "isProofVerified(bytes32,(bytes32,bytes32[],uint16))";
export const isSingleCircuitSubmissionVerified =
  "isSubmissionVerified(bytes32,uint256[][])";
export const isSubmissionVerified =
  "isSubmissionVerified(bytes32[],uint256[][])";
export const isSubmissionVerifiedById = "isSubmissionVerified(bytes32)";

/// Configuration used to generate the circuits.
export type UpaConfig = {
  max_num_app_public_inputs: number;
  inner_batch_size: number;
  outer_batch_size: number;
  bv_config: CircuitWithLimbsConfig;
  keccak_config: CircuitConfig;
  outer_config: CircuitWithLimbsConfig;
  output_submission_id: boolean;
};

/// Configuration for a circuit with limbs.
export type CircuitWithLimbsConfig = {
  degree_bits: number;
  lookup_bits: number;
  limb_bits: number;
  num_limbs: number;
};

/// Configuration for a circuit
export type CircuitConfig = {
  degree_bits: number;
  lookup_bits: number;
};

/**
 * Description of a single deployment.  Intended to be serializable as
 * JSON. This is a longer sentence.
 */
export type UpaInstanceDescriptor = {
  /// Address of the UPA verifier contract
  verifier: string;
  /// Deployment blockNumber (of the ProofReceiver)
  deploymentBlockNumber: number;
  /// Deployment tx ID
  deploymentTx: string;
  /// ChainId
  chainId: string;
};

/// Reference to a deployed instance
export type UpaInstance = {
  verifier: UpaVerifier;
  deploymentBlockNumber: number;
  deploymentTx: string;
  chainId: string;
};

/// Reference to a deployed instance (only for testing upgrade)
export type TestUpgradedUpaInstance = {
  verifier: TestUpgradedUpaVerifier;
  deploymentBlockNumber: number;
};

export async function upaInstanceFromDescriptor(
  instanceDescriptor: UpaInstanceDescriptor,
  provider: ethers.ContractRunner
): Promise<UpaInstance> {
  const verifierContract = UpaVerifier__factory.connect(
    instanceDescriptor.verifier
  );
  const verifier = verifierContract.connect(provider);
  const contractVersion = await verifier.version();
  const sdkVersion = versionStringToUint(pkg.version);
  if (contractVersion / 100n !== sdkVersion / 100n) {
    throw (
      `UPA contract version ${contractVersion} is incompatible with SDK ` +
      `version ${sdkVersion}`
    );
  }

  return {
    verifier,
    deploymentBlockNumber: instanceDescriptor.deploymentBlockNumber,
    deploymentTx: instanceDescriptor.deploymentTx,
    chainId: instanceDescriptor.chainId,
  };
}

// Only for testing upgrade
export function testUpaInstanceFromDescriptor(
  instanceDescriptor: UpaInstanceDescriptor,
  provider: ethers.ContractRunner
): TestUpgradedUpaInstance {
  const instance = {
    verifier: TestUpgradedUpaVerifier__factory.connect(
      instanceDescriptor.verifier
    ),
    proofReceiver: UpaProofReceiver__factory.connect(
      instanceDescriptor.verifier
    ),
  };

  return {
    verifier: instance.verifier.connect(provider),
    deploymentBlockNumber: instanceDescriptor.deploymentBlockNumber,
  };
}

/// Given a (possibly null) options struct, return one populated with at least
/// the submission fee required.  To determine submission fee, a gasPrice is
/// required, in which case it is taken from (in order): `options.gasPrice`,
/// `options.maxFeePerGas`, a `getFeeData` query to the provider.
export async function updateFeeOptions(
  proofReceiver: IUpaProofReceiver,
  numProofs: number,
  options?: PayableOverrides
): Promise<PayableOverrides> {
  // Copy the options struct if given, otherwise start with an empty one.
  if (!options) {
    options = {};
  } else {
    options = { ...options };
  }

  // Fill in the value entry if necessary.  This involves determining a
  // gasPrice if one was not specified (in which case, we record the price in
  // the returned options).

  if (options.value === undefined) {
    // Options struct to use for querying the fee.  May differ from options.
    let queryOptions = options;

    if (options.gasPrice) {
      // `gasPrice` is set.  Ensure that the ERC-1559 options are NOT also
      // set, and use `gasPrice`.
      assert(!options.maxFeePerGas, "maxFeePerGas conflicts with gasPrice");
      assert(
        !options.maxPriorityFeePerGas,
        "maxPriorityFeePerGas conflicts with gasPrice"
      );
    } else {
      // `gasPrice` is not given.  Use `maxFeePerGas` and
      // `maxPriorityFeePerGas`, populating them if not set.

      if (!options.maxFeePerGas || !options.maxPriorityFeePerGas) {
        const feeData = (await proofReceiver.runner?.provider?.getFeeData())!;
        options.maxFeePerGas = options.maxFeePerGas || feeData.maxFeePerGas;
        if (!options.maxPriorityFeePerGas) {
          // Use the maxPriorityFeePerGas from the feeData, unless it's
          // greater than the given maxFeePerGas.
          const optionsMaxFeePerGas = BigInt(options.maxFeePerGas!);
          const maxPriorityFeePerGas = BigInt(feeData.maxPriorityFeePerGas!);
          options.maxPriorityFeePerGas =
            options.maxPriorityFeePerGas ||
            (optionsMaxFeePerGas < maxPriorityFeePerGas
              ? optionsMaxFeePerGas
              : maxPriorityFeePerGas);
        }
      }

      // In the query to estimateFee, use `gasPrice` set to `maxFeePerGas`,
      // otherwise the node may run the query may with a lower price, and the
      // tx will later fail if a higher price is used.
      // Set `gasLimit` to a reasonable number, otherwise `estimateFee` may
      // fail due to using a far-too-large amount of supplied gas
      queryOptions = {
        ...options,
        gasPrice: options.maxFeePerGas,
        maxPriorityFeePerGas: undefined,
        maxFeePerGas: undefined,
        gasLimit: 100_000,
      };
    }

    options.value = await proofReceiver.estimateFee.staticCall(
      numProofs,
      queryOptions
    );
  }

  return options;
}

export async function populateSubmitProof(
  proofReceiver: IUpaProofReceiver,
  circuitId: ethers.BytesLike,
  proof: Groth16Proof,
  instance: ethers.BigNumberish[],
  options?: PayableOverrides
): Promise<ethers.ContractTransaction> {
  return proofReceiver.submit.populateTransaction(
    [circuitId],
    [proof.compress().solidity()],
    [instance],
    await updateFeeOptions(proofReceiver, 1, options)
  );
}

export async function submitProof(
  proofReceiver: IUpaProofReceiver,
  circuitId: ethers.BytesLike,
  proof: Groth16Proof,
  instance: ethers.BigNumberish[],
  options?: PayableOverrides
): Promise<ethers.ContractTransactionResponse> {
  return proofReceiver.submit(
    [circuitId],
    [proof.compress().solidity()],
    [instance],
    await updateFeeOptions(proofReceiver, 1, options)
  );
}

export async function populateSubmitProofs(
  proofReceiver: IUpaProofReceiver,
  circuitIds: ethers.BytesLike[],
  proofs: Groth16Proof[],
  instances: ethers.BigNumberish[][],
  options?: PayableOverrides
): Promise<ethers.ContractTransaction> {
  const numProofs = circuitIds.length;
  assert(proofs.length == numProofs);
  assert(instances.length == numProofs);
  return proofReceiver.submit.populateTransaction(
    circuitIds,
    proofs.map((pf) => pf.compress().solidity()),
    instances,
    await updateFeeOptions(proofReceiver, numProofs, options)
  );
}

export async function submitProofs(
  proofReceiver: IUpaProofReceiver,
  circuitIds: ethers.BytesLike[],
  proofs: Groth16Proof[],
  instances: ethers.BigNumberish[][],
  options?: PayableOverrides
): Promise<ethers.ContractTransactionResponse> {
  const numProofs = circuitIds.length;
  assert(proofs.length == numProofs);
  assert(instances.length == numProofs);
  options = await updateFeeOptions(proofReceiver, numProofs, options);

  return proofReceiver.submit(
    circuitIds,
    proofs.map((pf) => pf.compress().solidity()),
    instances,
    options
  );
}

/// Throws if the submission was malformed
export async function waitForSubmissionVerified(
  upaInstance: UpaInstance,
  txReceipt: ethers.TransactionReceipt,
  progress?: (v: number) => void
): Promise<void> {
  const provider = upaInstance.verifier.runner!.provider!;
  const submission = await Submission.fromTransactionReceipt(
    upaInstance.verifier,
    txReceipt
  );
  if (!submission) {
    throw "could not parse the submission from the chain";
  }

  const submissionId = submission.submissionId;
  const dupSubmissionIdx = submission.getDupSubmissionIdx();
  const submissionIdx = await upaInstance.verifier.getSubmissionIdx(
    submissionId,
    dupSubmissionIdx
  );

  // Poll from submittedBlock onwards
  let startBlock = txReceipt.blockNumber;
  const verifiedEventGetter = new SubmissionVerifiedEventGetter(
    upaInstance.verifier,
    submissionId
  );

  // Initialize progress indicator.
  const startVerifiedIdx =
    (await upaInstance.verifier.nextSubmissionIdxToVerify()) - 1n;
  const intervalId = setInterval(async () => {
    const curVerifiedIdx =
      (await upaInstance.verifier.nextSubmissionIdxToVerify()) - 1n;
    if (progress) {
      progress(
        Number(curVerifiedIdx - startVerifiedIdx) /
          Number(submissionIdx - startVerifiedIdx)
      );
    }
  }, 10000);

  let lastBlock = startBlock - 1;
  const maxBlocksPerQuery = 10;
  // Record the first block we see where `nextSubmissionIdxToVerify`
  // has incremented beyond `submissionIdx`. If we scan past this block and
  // have not seen a submissionVerified event, the submission was rejected.
  let proofMaybeRejectedBlock: number | null = null;

  for (;;) {
    const nextSubmissionIdxToVerify =
      await upaInstance.verifier.nextSubmissionIdxToVerify();
    const curBlock = await provider.getBlockNumber();
    if (!proofMaybeRejectedBlock && submissionIdx < nextSubmissionIdxToVerify) {
      proofMaybeRejectedBlock = curBlock;
    }

    // Look for this proof's `ProofVerifiedEvent` up to block `curBlock`.
    startBlock = lastBlock + 1;
    if (curBlock < startBlock) {
      await new Promise((r) => setTimeout(r, 1000));
      continue;
    }
    lastBlock = Math.min(curBlock, lastBlock + maxBlocksPerQuery - 1);
    const evs = await verifiedEventGetter.getFull(startBlock, lastBlock);
    for (const ev of evs) {
      if (ev.event.submissionId == submissionId) {
        clearInterval(intervalId);
        return;
      }
    }

    // Proof was rejected if there was a `proofMaybeRejectedBlock` and we have
    // scanned past it without seeing a `SubmissionVerifiedEvent`.
    if (proofMaybeRejectedBlock && proofMaybeRejectedBlock < lastBlock) {
      clearInterval(intervalId);
      throw new Error(`Submission was rejected. SubmissionId: ${submissionId}`);
    }
  }
}

/// Returns the last proofIdx that was aggregated by `verifyAggregatedProof`.
/// Note that this proofIdx corresponds to the last verified proof of the
/// current partially verified on-chain submission, which may be different
/// from the last fully verified submission's last proofIdx.
///
/// This function has a relatively high cost, involving many queries to the
/// attached node and manual scanning of events.
export async function lastAggregatedProofIdx(
  verifier: UpaVerifier,
  proofReceiver: UpaProofReceiver
): Promise<bigint> {
  // Get the height at which the last verified submission was submitted, and
  // scan that block for submission events.

  const lastVerifiedSubmissionHeight = Number(
    await verifier.lastVerifiedSubmissionHeight()
  );
  const endBlock = await verifier.runner!.provider!.getBlockNumber();
  const verifiedEventGetter = new events.SubmissionVerifiedEventGetter(
    verifier
  );
  const submissionVerifiedEvents = await verifiedEventGetter.getFull(
    lastVerifiedSubmissionHeight,
    endBlock
  );
  const numEvents = submissionVerifiedEvents.length;
  assert(
    numEvents !== 0,
    "There must be at least one submission verified event"
  );

  // Take the last `SubmissionVerified` event and find the
  // `verifyAggregatedProof` transaction. From this transaction's calldata,
  // extract the list of proofIds for this aggregated batch. The last proofId
  // is the last aggregated proof.

  const lastEvent =
    submissionVerifiedEvents[submissionVerifiedEvents.length - 1];

  const provider = proofReceiver.runner!.provider!;
  const lastEventTx = await provider.getTransaction(lastEvent.txHash);
  const { proofIds } = getCallDataForVerifyAggregatedProofTx(
    verifier,
    lastEventTx!
  );
  const lastAggregatedProofId = proofIds[proofIds.length - 1];

  // Find the proofIdx for the last aggregated proof by scanning the
  // `ProofSubmitted` events to find one matching its proofId.

  const proofSubmittedEventGetter = new events.ProofSubmittedEventGetter(
    proofReceiver
  );
  const proofSubmittedEventData = await proofSubmittedEventGetter.getFull(
    lastVerifiedSubmissionHeight,
    lastVerifiedSubmissionHeight
  );
  const isTheRightEvent = (event: events.ProofSubmittedEvent.OutputObject) =>
    event.proofId === lastAggregatedProofId;
  const proofSubmittedEvent = proofSubmittedEventData
    .map((eventdata) => eventdata.event)
    .filter(isTheRightEvent)[0];
  return proofSubmittedEvent.proofIdx;
}

/**
 * @param proofIDs expected to be encoded as "0x" followed by 64 chars
 * @returns Calldata with the correct `finalDigest` field elements
 * in the last two words and the first 12 words filled with padding.
 */
export function dummyProofData(proofIDs: string[]): ethers.BytesLike {
  // Compute digest and decompose into field elements, padded to 32 bytes so
  // they occupy the correct amount of space in the binary calldata hex.
  const finalDigest = computeFinalDigest(proofIDs);
  const [finalDigest_l, finalDigest_r] = digestAsFieldElements(finalDigest);

  // Create dummy calldata.  12 (non-zero) uint256 values, followed by the
  // field elements.
  let calldata = "0x";
  for (let i = 0; i < 12; i++) {
    calldata +=
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  }
  calldata += bigintToHex32(finalDigest_l);
  calldata += bigintToHex32(finalDigest_r);

  return calldata;
}
