import { command } from "cmd-ts";
import * as options from "./options";
import * as config from "./config";
import * as ethers from "ethers";
import { utils } from "../sdk";
import { PayableOverrides } from "../../typechain-types/common";

export const claimAggregatorFee = command({
  name: "claim-aggregator-fee",
  args: {
    endpoint: options.endpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    wait: options.wait(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
  },
  description:
    "Claims the allocated aggregator fee in UPA's fee model contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    wait,
    estimateGas,
    dumpTx,
    maxFeePerGasGwei,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider
    );
    const { verifier: verifier } = await config.upaFromInstanceFile(
      instance,
      wallet
    );

    const optionsPayable: PayableOverrides = {
      maxFeePerGas: utils.parseGweiOrUndefined(maxFeePerGasGwei),
    };
    const txReq = await verifier.claimAggregatorFee.populateTransaction(
      optionsPayable
    );

    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      verifier.interface
    );
  },
});
