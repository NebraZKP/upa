import { command, flag, boolean } from "cmd-ts";
import { upaFromInstanceFile } from "./config";
import { endpoint, instance } from "./options";
import { utils } from "../sdk";
import * as ethers from "ethers";
import { strict as assert } from "assert";
// eslint-disable-next-line
import { Groth16VKStructOutput } from "../../typechain-types/contracts/UpaProofReceiver";
import { UpaFixedGasFee__factory } from "../../typechain-types";

/// The json data output from this command.
type StateJSON = {
  blockNumber: number;
  upaContractVersion: bigint;
  nextSubmissionIdxToVerify: bigint;
  lastVerifiedSubmissionHeight: bigint;
  nextSubmissionIdx: bigint;
  numPendingSubmissions: bigint;
  circuitIds?: string[];
  verificationKeys?: { [cid: string]: Groth16VKStructOutput };
  allocatedFee: bigint;
  claimableFees: bigint;
  verifiedProofIdxForAllocatedFee?: bigint;
};

export const stats = command({
  name: "stats",
  args: {
    endpoint: endpoint(),
    instance: instance(),
    listCircuits: flag({
      type: boolean,
      long: "circuits",
      short: "c",
      defaultValue: () => false,
      description: "List the registered circuit IDs",
    }),
    showvks: flag({
      type: boolean,
      long: "show-vks",
      short: "s",
      defaultValue: () => false,
      description: "Include VK in circuit info",
    }),
  },
  description: "Query the UPA contract state",
  handler: async function ({
    endpoint,
    instance,
    listCircuits,
    showvks,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = await upaFromInstanceFile(instance, provider);

    const blockNumberP = provider.getBlockNumber();
    const contractVersionP = verifier.version();
    const nextSubmissionIdxP = verifier.getNextSubmissionIdx();
    const nextSubmissionIdxToVerifyP = verifier.nextSubmissionIdxToVerify();
    const lastVerifiedSubmissionHeightP =
      verifier.lastVerifiedSubmissionHeight();
    const { cids, vks } = await (async () => {
      if (!listCircuits && !showvks) {
        return { cids: undefined, vks: undefined };
      }

      const circuitIdsP = verifier.getCircuitIds();
      let cids: string[] | undefined = undefined;
      let vks: { [cid: string]: Groth16VKStructOutput } | undefined = undefined;

      if (showvks) {
        vks = {};
        await Promise.all(
          (
            await circuitIdsP
          ).map(async (cidO: ethers.BytesLike) => {
            const cid = utils.readBytes32(cidO);
            const vk = await verifier.getVK(cid);
            assert(vks); // to keep the compiler happy
            vks[cid] = vk;
          })
        );
      }

      if (listCircuits) {
        cids = (await circuitIdsP).map(utils.readBytes32);
      }

      return { vks, cids };
    })();
    const [allocatedFee, claimableFees] = await Promise.all([
      verifier.feeAllocated(),
      verifier.claimableFees(),
    ]);

    // If the fee model is the the UPA fixed fee contract,
    // we return the verified proof index for allocated fee
    const upaFee = UpaFixedGasFee__factory.connect(
      await verifier.getAddress()
    ).connect(provider);
    let verifiedProofIdxForAllocatedFee;
    try {
      verifiedProofIdxForAllocatedFee =
        await upaFee.verifiedSubmissionIdxForAllocatedFee();
    } catch {
      verifiedProofIdxForAllocatedFee = undefined;
    }

    const output: StateJSON = {
      blockNumber: await blockNumberP,
      upaContractVersion: await contractVersionP,
      nextSubmissionIdxToVerify: await nextSubmissionIdxToVerifyP,
      lastVerifiedSubmissionHeight: await lastVerifiedSubmissionHeightP,
      nextSubmissionIdx: await nextSubmissionIdxP,
      numPendingSubmissions:
        (await nextSubmissionIdxP) - (await nextSubmissionIdxToVerifyP),
      circuitIds: cids,
      verificationKeys: vks,
      allocatedFee,
      claimableFees,
      verifiedProofIdxForAllocatedFee,
    };

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(utils.JSONstringify(output, 2));
  },
});
