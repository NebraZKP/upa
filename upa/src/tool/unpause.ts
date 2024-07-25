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
import { handleTxRequest, loadWallet, upaFromInstanceFile } from "./config";
import * as ethers from "ethers";

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
