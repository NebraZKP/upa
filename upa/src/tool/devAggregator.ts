import { command, option, number } from "cmd-ts";
import * as options from "./options";
import * as ethers from "ethers";
import { ProofSubmittedEventGetter } from "../sdk/events";
import * as config from "./config";
import { dummyProofData, UpaInstance } from "../sdk/upa";
import { strict as assert } from "assert";
import { NonPayableOverrides } from "../../typechain-types/common";
import * as log from "./log";
import { packOffChainSubmissionMarkers } from "../sdk/submission";
import {
  siProofIds,
  SubmissionInterval,
  splitSubmissionInterval,
  submissionIntervalsFromEvents,
} from "../sdk/submissionIntervals";
import { computeAggregatedProofParameters } from "../sdk/aggregatedProofParams";

export const devAggregator = command({
  name: "aggregator",
  args: {
    batchSize: option({
      type: number,
      long: "batch-size",
      defaultValue: () => 4,
      description: "Target batch size for aggregated proofs",
    }),
    latency: option({
      type: number,
      long: "latency",
      defaultValue: () => 5,
      description: "Time (sec) between aggregated batches",
    }),
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
  },
  description:
    "Listens for ProofSubmitted events, submits dev aggregated proofs",
  handler: async function ({
    batchSize,
    latency,
    endpoint,
    instance,
    keyfile,
    password,
  }): Promise<void> {
    log.info("Starting dev aggregator...");
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    let nonce = await wallet.getNonce();
    const upaInstance = await config.upaFromInstanceFile(instance, wallet);

    let lastBlockSeen =
      Number(await upaInstance.verifier.lastVerifiedSubmissionHeight()) - 1;
    const maxBlockPerQuery = 5;
    log.info(`Dev aggregator starting at block ${lastBlockSeen + 1}`);

    // Event getter
    const submittedEventGetter = new ProofSubmittedEventGetter(
      upaInstance.verifier
    );
    const submissionQueue: SubmissionInterval[] = [];

    // Submit a batch every `latency` seconds, even if only
    // partially full.
    setInterval(async () => {
      if (submissionQueue.length) {
        await submitBatchFromQueue();
      }
    }, 1000 * latency);

    async function submitBatchFromQueue() {
      assert(submissionQueue.length);
      const batch = pullBatchFromQueue();
      await submitBatch(batch, upaInstance, { nonce: nonce++ });
    }

    /**
     * Takes up to `batchSize` many proofs from the `submissionQueue`,
     * splitting `SubmissionInterval`s if needed. These proofs are
     * removed from `submissionQueue`.
     * @returns a `SubmissionInterval[]` representing the batch.
     */
    function pullBatchFromQueue(): SubmissionInterval[] {
      const batch: SubmissionInterval[] = [];
      let curBatchSize = 0;
      while (curBatchSize < batchSize && submissionQueue.length) {
        const numProofsRequired = batchSize - curBatchSize;
        const sizeNextInterval = submissionQueue[0].numProofs;
        // Add entire next submission interval to batch if there's room
        if (sizeNextInterval <= numProofsRequired) {
          batch.push(submissionQueue.shift()!);
          curBatchSize += sizeNextInterval;
        } else {
          // There wasn't room for all of this submission interval, so split it
          const [submissionInterval, remainderInterval] =
            splitSubmissionInterval(submissionQueue[0], numProofsRequired);
          batch.push(submissionInterval);
          assert(
            remainderInterval !== undefined,
            "expected non-empty remainderInterval"
          );
          submissionQueue[0] = remainderInterval;
          curBatchSize = batchSize;
        }
      }

      log.info(`Formed batch of size ${curBatchSize}`);
      return batch;
    }

    // The first time fetching events, check if part of a `Submission`
    // has already been verified.
    const checkVerified = true;

    // Loop for parsing new events and adding to submissionQueue
    for (;;) {
      // Get the latest block, and determine the range [startBlock, endBlock] of
      // blocks to check.

      const blockNum = await provider.getBlockNumber();
      const startBlock = lastBlockSeen + 1;
      const endBlock = Math.min(blockNum, lastBlockSeen + maxBlockPerQuery);

      // If no new blocks are present, sleep and retry.

      if (endBlock <= lastBlockSeen) {
        // Wait 1 sec
        await new Promise((resolve) => setTimeout(resolve, 1000));
        continue;
      }

      // Pull any events in the block interval [startBlock, endBlock] and add
      // them to the queue.

      const newEvents = await submittedEventGetter.getFullGroupedByTransaction(
        startBlock,
        endBlock
      );
      const newEventsWithData =
        await submittedEventGetter.getProofDataForSubmittedEvents(newEvents);

      const submissions: SubmissionInterval[] =
        await submissionIntervalsFromEvents(
          checkVerified,
          upaInstance,
          newEventsWithData
        );

      log.info(
        `  LOOP: blockNum: ${blockNum}, lastBlockSeen: ${lastBlockSeen}, ` +
          `maxBlockPerQuery: ${maxBlockPerQuery} endBlock: ${endBlock}\n` +
          `        in blocks [${startBlock}:${endBlock}]: ` +
          `${submissions.length} submissions`
      );

      submissions.map((si) => {
        log.info(`Queued submissionId: ${si.submission.submissionId}`);
      });
      submissionQueue.push(...submissions);

      lastBlockSeen = endBlock;
    }
  },
});

// TODO(#689): Include offchain submissions in dev aggregator
async function submitBatch(
  batch: SubmissionInterval[],
  upaInstance: UpaInstance,
  options?: NonPayableOverrides
) {
  // Compute the finalDigest
  const proofIds = batch.flatMap((si) => siProofIds(si));
  const calldata = dummyProofData(proofIds);
  const aggProofParams = computeAggregatedProofParameters(batch, []);

  // Submit aggregated proof
  await upaInstance.verifier.verifyAggregatedProof(
    calldata,
    aggProofParams.proofIds,
    aggProofParams.numOnChainProofs,
    aggProofParams.submissionProofs,
    packOffChainSubmissionMarkers(aggProofParams.offChainSubmissionMarkers),
    aggProofParams.dupSubmissionIdxs,
    options || {}
  );

  log.info(`Submitted aggregated proof for proofIds: ${proofIds}`);
}
