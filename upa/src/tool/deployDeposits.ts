import { handleTxRequestInternal, loadWallet } from "./config";
import { keyfile, endpoint, password, getPassword, instance } from "./options";
import { command, option, optional, positional, string } from "cmd-ts";
import * as ethers from "ethers";
import * as fs from "fs";
import * as options from "./options";
import * as utils from "../sdk/utils";
import { strict as assert } from "assert";
import { Deposits__factory } from "../../typechain-types";
import { config } from ".";

export const deployDeposits = command({
  name: "deploy-deposits",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    instance: instance(),
    password: password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    name: option({
      type: string,
      long: "name",
      description: "Name of the deposits contract (for EIP-712)",
    }),
    version: option({
      type: string,
      long: "version",
      description: "Version of the deposits contract (for EIP-712)",
    }),
    aggregator: option({
      type: optional(string),
      long: "aggregator",
      description: "Aggregator address (defaults to address of keyfile)",
    })
  },
  description: "Deploy an aggregator's deposits contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    name,
    version,
    aggregator,
    instance
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    
    aggregator = aggregator || await wallet.getAddress();
    // Sanity check address string
    aggregator = ethers.getAddress(aggregator);
    const upaDesc = await config.loadInstance(instance);
    
    const depositsFactory = new Deposits__factory(wallet);
    const deployTx = await depositsFactory.getDeployTransaction(name, version, aggregator, upaDesc.verifier);

    const { populatedTx, gas, sentTx } = await handleTxRequestInternal(
      wallet,
      deployTx,
      estimateGas,
      dumpTx,
      wait
    );

    if (estimateGas) {
      assert(gas);
      console.log(`${gas} gas`);
    } else if (dumpTx) {
      assert(populatedTx);
      console.log(utils.JSONstringify(populatedTx));
    } else {
      // Deploy and output the resulting contract address to stdout.
      assert(sentTx);
      const address = ethers.getCreateAddress(sentTx);
      console.log(address);
    }
  },
});
