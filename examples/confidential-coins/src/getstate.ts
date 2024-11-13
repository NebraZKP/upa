import * as ethers from "ethers";
import { command } from "cmd-ts";
import { config, options } from "@nebrazkp/upa/tool";
const { keyfile, chainEndpoint, password } = options;
const { loadWallet } = config;
import {
  confidentialCoinsFromInstance,
  getOnChainBalances,
  instance,
  stringify,
} from "./utils";

export const getstate = command({
  name: "getstate",
  args: {
    keyfile: keyfile(),
    password: password(),
    chainEndpoint: chainEndpoint(),
    instance: instance(),
  },
  description: "Query your ConfidentialCoins balances.",
  handler: async function ({
    keyfile,
    password,
    chainEndpoint,
    instance,
  }): Promise<void> {
    let confidentialCoins = confidentialCoinsFromInstance(instance);
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    confidentialCoins = confidentialCoins.connect(wallet);

    const balances = await getOnChainBalances(confidentialCoins, wallet);

    console.log("---- ConfidentialCoins contract state ----");
    console.log(stringify(balances));
  },
});
