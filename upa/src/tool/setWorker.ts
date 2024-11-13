import { command, positional, string } from "cmd-ts";
import {
  instance,
  keyfile,
  chainEndpoint,
  wait,
  password,
  getPassword,
  estimateGas,
  dumpTx,
} from "./options";
import { loadWallet, upaFromInstanceFile, handleTxRequest } from "./config";
import * as ethers from "ethers";

export const setWorker = command({
  name: "set-worker",
  description: "Set the worker address",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    address: positional({
      type: string,
      description: "Address of new worker",
    }),
    wait: wait(),
    estimateGas: estimateGas(),
    dumpTx: dumpTx(),
  },
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    instance,
    address,
    wait,
    estimateGas,
    dumpTx,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = await upaFromInstanceFile(instance, wallet);

    const txReq = await upa.verifier.setWorker.populateTransaction(address);

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
