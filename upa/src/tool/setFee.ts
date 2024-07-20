import { command, option, string } from "cmd-ts";
import {
  instance,
  keyfile,
  endpoint,
  wait,
  password,
  getPassword,
  estimateGas,
  dumpTx,
  maxFeePerGasGwei,
} from "./options";
import { loadWallet, upaFromInstanceFile, handleTxRequest } from "./config";
import { PayableOverrides } from "../../typechain-types/common";
import * as ethers from "ethers";
import { parseNumberOrUndefined, parseGweiOrUndefined } from "../sdk/utils";

export const setFee = command({
  name: "set-fee",
  description:
    "Set the fixed fee per proof of the UpaFixedGasFee contract (in gas)",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    feeInGas: option({
      type: string,
      long: "fee",
      short: "f",
      description: "New fixed fee per proof (in gas)",
    }),
    wait: wait(),
    estimateGas: estimateGas(),
    dumpTx: dumpTx(),
    maxFeePerGasGwei: maxFeePerGasGwei(),
  },
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    feeInGas,
    wait,
    estimateGas,
    dumpTx,
    maxFeePerGasGwei,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = upaFromInstanceFile(instance, wallet);

    const fee = parseNumberOrUndefined(feeInGas, "Error parsing fee in gas");
    if (!fee) {
      throw "Undefined fee";
    }

    const optionsPayable: PayableOverrides = {
      maxFeePerGas: parseGweiOrUndefined(maxFeePerGasGwei),
    };
    const txReq = await upa.verifier.changeGasFee.populateTransaction(
      fee,
      optionsPayable
    );

    await handleTxRequest(wallet, txReq, estimateGas, dumpTx, wait);
  },
});
