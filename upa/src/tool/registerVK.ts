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
  handleTxRequest,
  loadAppVK,
  loadWallet,
  upaFromInstanceFile,
} from "./config";
import * as ethers from "ethers";

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
    const upa = await upaFromInstanceFile(instance, wallet);

    const txReq = await upa.verifier.registerVK.populateTransaction(
      vk.solidity()
    );
    await handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      upa.verifier.interface
    );
  },
});
