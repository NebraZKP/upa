import { command } from "cmd-ts";
import {
  instance,
  keyfile,
  endpoint,
  wait,
  password,
  getPassword,
  estimateGas,
  dumpTx,
} from "./options";
import {
  handleTxRequestInternal,
  loadWallet,
  upaFromInstanceFile,
} from "./config";
import * as ethers from "ethers";
import assert from "assert";
import { utils } from "../sdk";

export const unpause = command({
  name: "unpause",
  description: "Unpause the UPA Proof Receiver contract (must be owner)",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    estimateGas: estimateGas(),
    dumpTx: dumpTx(),
    wait: wait(),
  },
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    estimateGas,
    dumpTx,
    wait,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = upaFromInstanceFile(instance, wallet);

    const txReq = await upa.verifier.unpause.populateTransaction();

    const { populatedTx, gas } = await handleTxRequestInternal(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      upa.verifier.interface
    );

    if (estimateGas) {
      assert(gas);
      console.log(`${gas} gas`);
    } else if (dumpTx) {
      assert(populatedTx);
      console.log(utils.JSONstringify(populatedTx));
    }
  },
});
