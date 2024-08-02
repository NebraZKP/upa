import {
  TypedEventLog,
  TypedContractEvent,
  TypedDeferredTopicFilter,
} from "../../typechain-types/common";
import {
  ProofSubmittedEvent,
  VKRegisteredEvent,
  IUpaProofReceiver,
  Groth16CompressedProofStruct,
} from "../../typechain-types/contracts/IUpaProofReceiver";
import {
  IUpaVerifier,
  SubmissionVerifiedEvent,
} from "../../typechain-types/contracts/IUpaVerifier";
import * as ethers from "ethers";
import { strict as assert } from "assert";
import { bytes32IsWellFormed, readBytes32 } from "./utils";
import { UpaVerifier } from "../../typechain-types";
// eslint-disable-next-line
import { SubmissionProofStruct } from "../../typechain-types/contracts/UpaVerifier";

export { VKRegisteredEvent, ProofSubmittedEvent, SubmissionVerifiedEvent };

export type EventData<EventOutput> = {
  blockNumber: number;
  txHash: string;
  event: EventOutput;
};

/// Where a single transaction results in multiple events
export type EventSet<EventOutput> = {
  blockNumber: number;
  txHash: string;
  events: EventOutput[];
};

/// Base class to query the chain for specific events.
export abstract class EventGetterBase<
  Event extends TypedContractEvent,
  EventOutput
> {
  upa: ethers.BaseContract;
  filter: TypedDeferredTopicFilter<Event>;

  constructor(
    upa: ethers.BaseContract,
    filter: TypedDeferredTopicFilter<Event>
  ) {
    this.upa = upa;
    this.filter = filter;
  }

  // Get the event log with typechain wrapper
  public async get(
    startBlock: number,
    endBlock: number
  ): Promise<TypedEventLog<Event>[]> {
    return this.upa.queryFilter(this.filter, startBlock, endBlock) as Promise<
      TypedEventLog<Event>[]
    >;
  }

  // Get the parsed event data
  public async getFull(
    startBlock: number,
    endBlock: number
  ): Promise<EventData<EventOutput>[]> {
    const logs = await this.get(startBlock, endBlock);
    return logs.map((log) => {
      return {
        blockNumber: log.blockNumber,
        txHash: log.transactionHash,
        event: this.parseEvent(log),
      };
    });
  }

  // Get parsed events, grouped by transaction.
  public async getFullGroupedByTransaction(
    startBlock: number,
    endBlock: number
  ): Promise<EventSet<EventOutput>[]> {
    const logs = await this.get(startBlock, endBlock);
    if (logs.length === 0) {
      return [];
    }

    const output: EventSet<EventOutput>[] = [];
    let curSet: EventSet<EventOutput> = {
      txHash: logs[0].transactionHash,
      blockNumber: logs[0].blockNumber,
      events: [],
    };

    logs.forEach((log) => {
      const txHash = log.transactionHash;
      if (txHash !== curSet.txHash) {
        // New batch.  Push the current one and reset.
        assert(curSet.events.length != 0);
        output.push(curSet);

        curSet = {
          txHash,
          blockNumber: log.blockNumber,
          events: [],
        };
      } else {
        assert(log.blockNumber == curSet.blockNumber);
      }

      curSet.events.push(this.parseEvent(log));
    });

    // Should always be a curGroup left over.
    assert(curSet.events.length != 0);
    output.push(curSet);

    return output;
  }

  // TODO: There should be a generic way to write this.
  abstract parseEvent(ev: TypedEventLog<Event>): EventOutput;
}

/**
 * Extension of the ProofSubmittedEvent data, to include circuitId, proof and
 * public input data extracted from tx calldata.
 */
export type ProofSubmittedEventWithProofData =
  ProofSubmittedEvent.OutputObject & {
    readonly circuitId: string;
    readonly proof: Groth16CompressedProofStruct;
    readonly publicInputs: bigint[];
  };

/**
 * Specialized version of EventGetter for ProofSubmitted events.
 */
export class ProofSubmittedEventGetter extends EventGetterBase<
  ProofSubmittedEvent.Event,
  ProofSubmittedEvent.OutputObject
> {
  constructor(
    upa: IUpaProofReceiver,
    ...args: Partial<ProofSubmittedEvent.InputTuple>
  ) {
    super(upa, upa.filters.ProofSubmitted(...args));
  }

  parseEvent(
    ev: TypedEventLog<ProofSubmittedEvent.Event>
  ): ProofSubmittedEvent.OutputObject {
    const args = ev.args;
    return {
      proofId: args.proofId,
      submissionIdx: args.submissionIdx,
      proofIdx: args.proofIdx,
      dupSubmissionIdx: args.dupSubmissionIdx,
    };
  }

  /**
   * Given the ProofSubmitted events emitted from the contract, query the
   * calldata for each tx and extract all circuitId, proof and publicInput
   * data.
   */
  getProofDataForSubmittedEvents(
    eventSets: EventSet<ProofSubmittedEvent.OutputObject>[]
  ): Promise<EventSet<ProofSubmittedEventWithProofData>[]> {
    const eventSetsWithDataP: Promise<
      EventSet<ProofSubmittedEventWithProofData>
    >[] = eventSets.map(async (evSet) => {
      const txId = evSet.txHash;
      const tx = await this.upa.runner!.provider!.getTransaction(txId);
      const { circuitIds, proofs, publicInputs } = getCallDataForSubmitTx(
        this.upa as IUpaProofReceiver,
        tx!
      );
      assert(circuitIds.length === evSet.events.length);

      const eventsWithData: ProofSubmittedEventWithProofData[] =
        evSet.events.map((ev, i) => {
          return {
            circuitId: circuitIds[i],
            proofId: ev.proofId,
            submissionIdx: ev.submissionIdx,
            proofIdx: ev.proofIdx,
            dupSubmissionIdx: ev.dupSubmissionIdx,
            proof: proofs[i],
            publicInputs: publicInputs[i],
          };
        });

      return {
        blockNumber: evSet.blockNumber,
        txHash: evSet.txHash,
        events: eventsWithData,
      };
    });

    return Promise.all(eventSetsWithDataP);
  }
}

export function getCallDataForSubmitTx(
  proofReceiver: IUpaProofReceiver,
  tx: ethers.TransactionResponse
): {
  circuitIds: string[];
  proofs: Groth16CompressedProofStruct[];
  publicInputs: bigint[][];
} {
  const submitFragment = proofReceiver.getFunction("submit")!.fragment;
  const decoded = proofReceiver.interface.decodeFunctionData(
    submitFragment,
    tx.data
  );

  // The decoded data is dynamically indexed.  Extract everything to make it a
  // concrete struct.

  const circuitIds: string[] = decoded.circuitIds.map(readBytes32);
  const proofs: Groth16CompressedProofStruct[] = [...decoded.proofs];
  const publicInputs: bigint[][] = decoded.publicInputs.map(
    (pi: ethers.BigNumberish[]) => pi.map(BigInt)
  );

  assert(circuitIds.length === proofs.length);
  assert(circuitIds.length === publicInputs.length);
  assert(bytes32IsWellFormed(circuitIds[0]));
  assert("bigint" === typeof publicInputs[0][0]);

  return { circuitIds, proofs, publicInputs };
}

export function getCallDataForVerifyAggregatedProofTx(
  verifier: UpaVerifier,
  tx: ethers.TransactionResponse
): {
  proof: string;
  proofIds: string[];
  numOnchainProofs: bigint;
  submissionProofs: SubmissionProofStruct[];
  offChainSubmissionMarkers: bigint;
} {
  const submitFragment = verifier.getFunction(
    "verifyAggregatedProof"
  )!.fragment;
  const decoded = verifier.interface.decodeFunctionData(
    submitFragment,
    tx.data
  );

  // The decoded data is dynamically indexed.  Extract everything to make it a
  // concrete struct.

  const proof = decoded.proof;
  const proofIds: string[] = decoded.proofIds.map(readBytes32);
  const numOnchainProofs: bigint = BigInt(decoded.numOnchainProofs);
  const submissionProofs: SubmissionProofStruct[] =
    decoded.submissionProofs.map((proof: ethers.Result) => proof.toObject());
  const offChainSubmissionMarkers = BigInt(decoded.offChainSubmissionMarkers);

  assert(bytes32IsWellFormed(proofIds[0]));
  assert("bigint" === typeof numOnchainProofs);
  assert("bigint" === typeof offChainSubmissionMarkers);

  return {
    proof,
    proofIds,
    numOnchainProofs,
    submissionProofs,
    offChainSubmissionMarkers,
  };
}

/// Specialized version of EventGetter for ProofVerified events.
export class SubmissionVerifiedEventGetter extends EventGetterBase<
  SubmissionVerifiedEvent.Event,
  SubmissionVerifiedEvent.OutputObject
> {
  constructor(
    upa: IUpaVerifier,
    ...args: Partial<SubmissionVerifiedEvent.InputTuple>
  ) {
    super(upa, upa.filters.SubmissionVerified(...args));
  }

  parseEvent(
    ev: TypedEventLog<SubmissionVerifiedEvent.Event>
  ): SubmissionVerifiedEvent.OutputObject {
    const args = ev.args;
    return {
      submissionId: args.submissionId,
    };
  }
}

/**
 * Type for the VKRegistered event, which app VK is registered
 */
export type VKRegisteredEventOutput = VKRegisteredEvent.OutputObject;

/// Specialized version of EventGetter for ProofSubmitted events.
export class VKRegisteredEventGetter extends EventGetterBase<
  VKRegisteredEvent.Event,
  VKRegisteredEvent.OutputObject
> {
  constructor(upa: IUpaProofReceiver) {
    super(upa, upa.filters.VKRegistered());
  }

  parseEvent(
    ev: TypedEventLog<VKRegisteredEvent.Event>
  ): VKRegisteredEvent.OutputObject {
    const args = ev.args;
    return {
      circuitId: args.circuitId,
      vk: args.vk,
    };
  }
}
