import * as ethers from "ethers";
import { command, option, number } from "cmd-ts";
import { confidentialCoinsFromInstance } from "./utils";
import { options, config } from "@nebrazkp/upa/tool";
import { instance, circuitWasm, circuitZkey } from "./utils";
const { keyfile, chainEndpoint, password } = options;
const { loadWallet } = config;

export const initBalances = command({
  name: "init-balances",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    numProofs: option({
      type: number,
      long: "num",
      short: "n",
      defaultValue: () => 0,
      description: "The number of conversions to perform.",
    }),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
  },
  description: "Initializes ConfidentialCoins balances for a keyfile.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    instance,
  }): Promise<undefined> {
    let confidentialCoins = confidentialCoinsFromInstance(instance);
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    confidentialCoins = confidentialCoins.connect(wallet);

    console.log("Initializing balances to 1000");
    const initializeTx = await confidentialCoins.initializeBalances();
    await initializeTx.wait();
  },
});
