import {
  command,
  option,
  optional,
  string,
  number,
  flag,
  boolean,
} from "cmd-ts";
import {
  SubmissionVerifiedEvent,
  ProofSubmittedEvent,
  ProofSubmittedEventGetter,
  SubmissionVerifiedEventGetter,
} from "../sdk/events";
import { upaFromInstanceFile } from "./config";
import * as utils from "../sdk/utils";
import { endpoint, instance } from "./options";
import * as ethers from "ethers";
import { strict as assert } from "assert";
import * as fs from "fs";

export { ProofSubmittedEvent, SubmissionVerifiedEvent };

/// Number of blocks to compute rates over
const DEFAULT_BLOCK_DEPTH = 5;

/// Track events by block over some window and compute the rate per second.
class RateTracker {
  readonly provider: ethers.Provider;
  readonly blockDepth: number;
  readonly verbose: boolean;
  readonly counts: { blockNumber: number; count: number }[];
  earliestBlockSeen: number;
  lastBlockSeen: number;

  constructor(provider: ethers.Provider, blockDepth: number, verbose: boolean) {
    this.provider = provider;
    this.blockDepth = blockDepth;
    this.verbose = verbose;
    this.earliestBlockSeen = 0;
    this.lastBlockSeen = 0;
    this.counts = [];
  }

  public addEvent(blockNumber: number) {
    const counts = this.counts;
    const numBlocks = counts.length;
    if (numBlocks == 0) {
      counts.push({ blockNumber, count: 1 });
      return;
    }

    const latest = counts[numBlocks - 1];
    if (this.verbose) {
      console.log(`  RateTracker.addEvent: blockNumber: ${blockNumber}`);
    }
    assert(blockNumber >= latest.blockNumber);
    if (blockNumber > latest.blockNumber) {
      counts.push({ blockNumber, count: 1 });
    } else {
      latest.count++;
    }
  }

  public seenBlock(blockNumber: number) {
    const counts = this.counts;
    if (counts.length == 0) {
      counts.push({ blockNumber, count: 0 });
    }

    const latest = counts[this.counts.length - 1];
    assert(blockNumber >= latest.blockNumber);

    if (blockNumber > latest.blockNumber) {
      counts.push({ blockNumber, count: 0 });
    }

    this.removeOld();
  }

  public async getRate(): Promise<number> {
    const counts = this.counts;
    const numBlocks = counts.length;
    assert(numBlocks <= this.blockDepth);

    if (this.verbose) {
      console.log(`  RateTracker.addEvent: counts: ${JSON.stringify(counts)}`);
    }

    if (numBlocks < 2) {
      return 0.0;
    }

    const firstBlockNum = counts[0].blockNumber;
    const lastBlockNum = counts[numBlocks - 1].blockNumber;
    const firstBlockP = this.provider.getBlock(firstBlockNum);
    const lastBlockP = this.provider.getBlock(lastBlockNum);

    // Count proofs (skip first block) while waiting
    let count = 0;
    for (let i = 1; i < numBlocks; ++i) {
      count += counts[i].count;
    }

    const firstBlockTime = (await firstBlockP)!.timestamp;
    const lastBlockTime = (await lastBlockP)!.timestamp;

    const rate = count / (lastBlockTime - firstBlockTime);

    if (this.verbose) {
      console.log(
        `  RateTracker.getRate(): firstBlockTime: ${firstBlockTime} ` +
          `(${firstBlockNum})`
      );
      console.log(
        `  RateTracker.getRate(): lastBlockTime: ${lastBlockTime} ` +
          `(${lastBlockNum})`
      );
      console.log(`  RateTracker.getRate(): count: ${count}`);
    }
    return rate;
  }

  private removeOld() {
    const counts = this.counts;
    while (counts.length > this.blockDepth) {
      this.counts.shift();
    }

    assert(this.counts.length <= this.blockDepth);
  }
}

/// Record the number of events per block.
class EventCounter {
  readonly provider: ethers.Provider;
  readonly verbose: boolean;
  readonly counts: { blockNumber: number; count: number }[];

  constructor(provider: ethers.Provider, verbose: boolean = false) {
    this.provider = provider;
    this.verbose = verbose;
    this.counts = [];
  }

  public addEvent(blockNumber: number) {
    const counts = this.counts;
    const numBlocks = counts.length;
    if (numBlocks == 0) {
      counts.push({ blockNumber, count: 1 });
      return;
    }

    const latest = counts[numBlocks - 1];
    if (this.verbose) {
      console.log(`  EventCounter.addEvent: blockNumber: ${blockNumber}`);
    }
    assert(blockNumber >= latest.blockNumber);
    if (blockNumber > latest.blockNumber) {
      counts.push({ blockNumber, count: 1 });
    } else {
      latest.count++;
    }
  }

  public getCounts(): { blockNumber: number; count: number }[] {
    return this.counts;
  }
}

export const events = command({
  name: "events",
  args: {
    endpoint: endpoint(),
    instance: instance(),
    startBlock: option({
      type: optional(number),
      long: "start-block",
    }),
    endBlock: option({
      type: optional(number),
      long: "end-block",
    }),
    maxBlockPerQuery: option({
      type: number,
      long: "max-blocks-per-query",
      defaultValue: () => 2000,
    }),
    // TODO: add support - potentially non-trivial without streaming
    // outputFile: option({
    //   type: optional(string),
    //   long: "output-file",
    // }),
  },
  description: "Dump ProofVerified events across a block range",
  handler: async function ({
    endpoint,
    instance,
    startBlock,
    endBlock,
    maxBlockPerQuery,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const upa = await upaFromInstanceFile(instance, provider);

    // Event getters
    const verifiedEventGetter = new SubmissionVerifiedEventGetter(upa.verifier);

    // If startBlock is not given, pull blockDepth blocks (including the
    // newest block).
    startBlock = startBlock ? startBlock : 0;
    endBlock = endBlock
      ? endBlock
      : (await provider.getBlockNumber()) || startBlock;

    let curBlock = startBlock;
    // Main loop
    while (curBlock <= endBlock) {
      const lastBlock = Math.min(endBlock, curBlock + maxBlockPerQuery - 1);
      // console.log(`Blocks [${curBlock},${lastBlock}]`);
      const evs = await verifiedEventGetter.getFull(curBlock, lastBlock);
      console.log(utils.JSONstringify(evs));

      curBlock = lastBlock + 1;
    }
  },
});

export const eventCounts = command({
  name: "eventCounts",
  args: {
    endpoint: endpoint(),
    instance: instance(),
    startBlock: option({
      type: optional(number),
      long: "start-block",
    }),
    endBlock: option({
      type: optional(number),
      long: "end-block",
    }),
    maxBlockPerQuery: option({
      type: number,
      long: "max-blocks-per-query",
      defaultValue: () => 2000,
    }),
    outputFile: option({
      type: optional(string),
      long: "output-file",
    }),
  },
  description: "Dump per-block event counts over a block range",
  handler: async function ({
    endpoint,
    instance,
    startBlock,
    endBlock,
    maxBlockPerQuery,
    outputFile,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const upa = await upaFromInstanceFile(instance, provider);

    // Event getters
    const verifiedEventGetter = new SubmissionVerifiedEventGetter(upa.verifier);

    // If startBlock is not given, pull blockDepth blocks (including the
    // newest block).
    startBlock = startBlock ? startBlock : 0;
    endBlock = endBlock
      ? endBlock
      : (await provider.getBlockNumber()) || startBlock;

    const counter = new EventCounter(provider);
    let curBlock = startBlock;
    // Main loop
    while (curBlock <= endBlock) {
      const lastBlock = Math.min(endBlock, curBlock + maxBlockPerQuery - 1);
      console.log(`Blocks [${curBlock},${lastBlock}]`);
      const evs = await verifiedEventGetter.get(curBlock, lastBlock);
      evs.forEach((ev) => {
        counter.addEvent(ev.blockNumber);
      });

      curBlock = lastBlock + 1;
    }

    // Write the JSON file to disk
    if (outputFile) {
      fs.writeFileSync(outputFile, utils.JSONstringify(counter.getCounts()));
    } else {
      console.log(utils.JSONstringify(counter.getCounts()));
    }
  },
});

export const monitor = command({
  name: "monitor",
  args: {
    endpoint: endpoint(),
    instance: instance(),
    startBlock: option({
      type: optional(number),
      long: "start-block",
    }),
    maxBlockPerQuery: option({
      type: optional(number),
      long: "max-blocks-per-query",
    }),
    interval: option({
      type: number,
      long: "interval",
      defaultValue: () => 5.0,
      description: "Interval (in seconds) to query (default: 5.0)",
    }),
    blockDepth: option({
      type: number,
      long: "block-depth",
      defaultValue: () => DEFAULT_BLOCK_DEPTH,
      description:
        "Num blocks to compute rates over " +
        `(default: ${DEFAULT_BLOCK_DEPTH})`,
    }),
    verbose: flag({
      type: boolean,
      long: "verbose",
      short: "v",
      description: "Output extra information (primarily for debugging).",
    }),
  },
  description: "Monitor the UPA contract state",
  handler: async function ({
    endpoint,
    instance,
    startBlock,
    maxBlockPerQuery,
    interval,
    blockDepth,
    verbose,
  }): Promise<undefined> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const upa = await upaFromInstanceFile(instance, provider);

    // Event getters
    const submittedEventGetter = new ProofSubmittedEventGetter(upa.verifier);
    const verifiedEventGetter = new SubmissionVerifiedEventGetter(upa.verifier);
    maxBlockPerQuery = maxBlockPerQuery || 2000;

    // If startBlock is not given, pull blockDepth blocks (including the
    // newest block).
    let lastBlockSeen = startBlock
      ? startBlock - 1
      : (await provider.getBlockNumber()) - blockDepth;

    // Rate counters
    const submittedRateTracker = new RateTracker(provider, blockDepth, verbose);
    const verifiedRateTracker = new RateTracker(provider, blockDepth, verbose);

    async function showRate() {
      const submitRateP = submittedRateTracker.getRate();
      const verifyRateP = verifiedRateTracker.getRate();
      console.log(
        `RATE: (block ${lastBlockSeen}) submit: ${await submitRateP} ` +
          `proofs/s, verify: ${await verifyRateP} submissions/s`
      );
    }

    // Main loop
    for (;;) {
      const blockNum = await provider.getBlockNumber();
      const endBlock = Math.min(blockNum, lastBlockSeen + maxBlockPerQuery);

      if (verbose) {
        console.log(
          `  MAIN: blockNum: ${blockNum}, curBlock: ${endBlock}, ` +
            `lastBlock: ${startBlock}`
        );
      }

      if (endBlock > lastBlockSeen) {
        const startBlock = lastBlockSeen + 1;
        let proofSubmittedEvents: ProofSubmittedEvent.Log[];
        let submissionVerifiedEvents: SubmissionVerifiedEvent.Log[];

        // Pull any events
        try {
          [proofSubmittedEvents, submissionVerifiedEvents] = await Promise.all([
            submittedEventGetter.get(startBlock, endBlock),
            verifiedEventGetter.get(startBlock, endBlock),
          ]);
        } catch (e) {
          console.warn(`  MAIN: error getting events: ${e}`);
          await new Promise((r) => setTimeout(r, 1000));
          continue;
        }

        // TODO: Here we post events one-at-a-time to the counters.  If we
        // have only queried for a single block, we could just pass the number
        // of events to the counters.

        if (verbose) {
          console.log(`proofSubmittedEvents: ${proofSubmittedEvents}`);
          console.log(`submissionVerifiedEvents: ${submissionVerifiedEvents}`);
        }

        // Add events to the counters
        if (proofSubmittedEvents.length) {
          if (verbose) {
            console.log(
              `  MAIN: Submitted: ${proofSubmittedEvents.length} proofs in` +
                ` blocks ${startBlock}-${endBlock}`
            );
          }
          proofSubmittedEvents.forEach((ev) => {
            submittedRateTracker.addEvent(ev.blockNumber);
          });
        }

        if (submissionVerifiedEvents.length) {
          if (verbose) {
            console.log(
              `  MAIN: Verified: ${submissionVerifiedEvents.length} ` +
                `submissions in blocks ${startBlock}-${endBlock}`
            );
          }
          submissionVerifiedEvents.forEach((ev) => {
            verifiedRateTracker.addEvent(ev.blockNumber);
          });
        }

        submittedRateTracker.seenBlock(endBlock);
        verifiedRateTracker.seenBlock(endBlock);

        lastBlockSeen = endBlock;
      }

      await showRate();

      await new Promise((r) => setTimeout(r, interval * 1000));
    }
  },
});
