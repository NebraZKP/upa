import { command } from "cmd-ts";
import {
  instance,
  keyfile,
  endpoint,
  wait,
  password,
  getPassword,
} from "./options";
import { loadWallet, upaFromInstanceFile } from "./config";
import * as log from "./log";
import * as ethers from "ethers";

export const unpause = command({
  name: "unpause",
  description: "Unpause the UPA Proof Receiver contract (must be owner)",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    wait: wait(),
  },
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    wait,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = upaFromInstanceFile(instance, wallet);

    const tx = await upa.verifier.unpause();
    log.info(tx.hash);
    console.log(tx.hash);

    if (wait) {
      await tx.wait();
    }
  },
});
