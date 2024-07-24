import { command } from "cmd-ts";
import {
  instance,
  keyfile,
  endpoint,
  wait,
  password,
  getPassword,
  vkFile,
  estimateGas,
  dumpTx,
} from "./options";
import {
  handleTxRequestInternal,
  loadAppVK,
  loadWallet,
  upaFromInstanceFile,
} from "./config";
import * as ethers from "ethers";
import assert from "assert";
import { utils } from "../sdk";

export const registervk = command({
  name: "registervk",
  description: "Register a verifying key with UPA",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    estimateGas: estimateGas(),
    dumpTx: dumpTx(),
    wait: wait(),
    vkFile: vkFile(),
  },
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    estimateGas,
    dumpTx,
    wait,
    vkFile,
  }): Promise<void> {
    const vk = loadAppVK(vkFile);
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = upaFromInstanceFile(instance, wallet);

    const txReq = await upa.verifier.registerVK.populateTransaction(
      vk.solidity()
    );
    const { populatedTx, gas, sentTx } = await handleTxRequestInternal(
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
    } else {
      // Deploy and output the resulting contract address to stdout.
      assert(sentTx);
      console.log(sentTx.hash);
    }
  },
});
