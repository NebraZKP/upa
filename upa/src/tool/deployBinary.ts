import { handleTxRequestInternal, loadWallet } from "./config";
import { keyfile, endpoint, password, getPassword } from "./options";
import { command, positional, string } from "cmd-ts";
import * as ethers from "ethers";
import * as fs from "fs";
import * as options from "./options";
import * as utils from "../sdk/utils";
import { strict as assert } from "assert";

export const deployBinary = command({
  name: "deploy-binary",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    verifierBin: positional({
      type: string,
      description: "On-chain verifier binary file",
    }),
  },
  description: "Deploy a binary contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    verifierBin,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);

    // Load binary contract
    const contractHex = "0x" + fs.readFileSync(verifierBin, "utf-8").trim();

    const txReq = await utils.populateDeployBinaryContract(wallet, contractHex);

    const { populatedTx, gas, sentTx } = await handleTxRequestInternal(
      wallet,
      txReq,
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
