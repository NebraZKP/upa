import { command } from "cmd-ts";
import {
  instance,
  keyfile,
  endpoint,
  wait,
  password,
  getPassword,
  vkFile,
} from "./options";
import { loadAppVK, loadWallet, upaFromInstanceFile } from "./config";
import * as log from "./log";
import * as ethers from "ethers";

export const registervk = command({
  name: "registervk",
  description: "Register a verifying key with UPA",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    wait: wait(),
    vkFile: vkFile(),
  },
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    wait,
    vkFile,
  }): Promise<void> {
    const vk = loadAppVK(vkFile);
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const upa = upaFromInstanceFile(instance, wallet);

    const tx = await upa.verifier.registerVK(vk.solidity());
    log.info(tx.hash);
    console.log(tx.hash);

    if (wait) {
      await tx.wait();
    }
  },
});
