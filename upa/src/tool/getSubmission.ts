import { command, flag, positional, string } from "cmd-ts";
import * as options from "./options";
import * as ethers from "ethers";
import * as config from "./config";
import * as utils from "../sdk/utils";
import { Submission } from "../sdk";
import { EventSet, ProofSubmittedEventGetter } from "../sdk/events";
// eslint-disable-next-line
import { ProofSubmittedEvent } from "../../typechain-types/contracts/tests/TestUpgradedUpaVerifier";

export const getSubmission = command({
  name: "get-submission",
  args: {
    chainEndpoint: options.chainEndpoint(),
    instance: options.instance(),
    txId: positional({
      type: string,
      displayName: "tx-id",
      description: "Tx Id of the submission to retrieve",
    }),
    events: flag({
      long: "events",
      description: "Dump event data for the submission",
    }),
  },
  description: "Get the on-chain submission information associated with a Tx",
  handler: async function ({
    chainEndpoint,
    instance,
    txId,
    events,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const { verifier } = await config.upaFromInstanceFile(instance, provider);

    const txReceipt = await provider.getTransactionReceipt(txId);
    if (!txReceipt) {
      throw `Failed to get receipt for tx ${txId}`;
    }
    const submission = await Submission.fromTransactionReceipt(
      verifier,
      txReceipt
    );

    // If the events flag is given, dump the event data.
    if (events) {
      const evGetter = new ProofSubmittedEventGetter(verifier);
      const eventSet = evGetter.parseTransactionReceipt(txReceipt);
      // Put the event set on an `eventSet` attribute of the submission
      // object.
      (
        submission as unknown as {
          eventSet: EventSet<ProofSubmittedEvent.OutputObject>;
        }
      ).eventSet = eventSet;
    }

    console.log(utils.JSONstringify(submission));
  },
});
