import * as ethers from "ethers";
import { command } from "cmd-ts";
import { config, options } from "@nebrazkp/upa/tool";
const { keyfile, endpoint, password } = options;
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
    endpoint: endpoint(),
    instance: instance(),
  },
  description: "Query your ConfidentialCoins balances.",
  handler: async function ({
    keyfile,
    password,
    endpoint,
    instance,
  }): Promise<void> {
    let confidentialCoins = confidentialCoinsFromInstance(instance);
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    confidentialCoins = confidentialCoins.connect(wallet);

    const balances = await getOnChainBalances(confidentialCoins, wallet);

    console.log("---- ConfidentialCoins contract state ----");
    console.log(stringify(balances));
  },
});
