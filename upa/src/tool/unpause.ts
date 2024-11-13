import { command } from "cmd-ts";
import {
  instance,
  keyfile,
  chainEndpoint,
  wait,
  password,
  getPassword,
  estimateGas,
  dumpTx,
  from,
} from "./options";
import { handleTxRequest, loadWallet, upaFromInstanceFile } from "./config";
import * as ethers from "ethers";

export const unpause = command({
  name: "unpause",
  description: "Unpause the UPA Proof Receiver contract (must be owner)",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    estimateGas: estimateGas(),
    dumpTx: dumpTx(),
    fromAddress: from(),
    wait: wait(),
  },
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    instance,
    estimateGas,
    dumpTx,
    fromAddress,
    wait,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(
      keyfile,
      getPassword(password),
      provider,
      fromAddress
    );
    const upa = await upaFromInstanceFile(instance, wallet);

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
