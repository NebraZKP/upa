import { command, number, positional } from "cmd-ts";
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

export const setVersion = command({
  name: "set-version",
  description: "Set the contract version",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    version: positional({
      type: number,
      description: "Value of new contract version",
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
    version,
    wait,
    estimateGas,
    dumpTx,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = await upaFromInstanceFile(instance, wallet);

    const txReq = await upa.verifier.setVersion.populateTransaction(version);

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
