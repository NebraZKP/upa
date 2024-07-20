import { loadWallet } from "./config";
import { keyfile, endpoint, password, getPassword } from "./options";
import { command, positional, string } from "cmd-ts";
import * as ethers from "ethers";
import * as fs from "fs";
import * as utils from "../sdk/utils";

export const deployBinary = command({
  name: "deploy-binary",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    // TODO: Not clear how we could support these in a nice way, given that if
    // we need to call `ethers.getCreateAddress` on the `TransactionResponse`,
    // which significantly complicates the logic of handleTxRequest.
    //
    // wait: options.wait(),
    // estimateGas: options.estimateGas(),
    // dumpTx: options.dumpTx(),
    verifier_bin: positional({
      type: string,
      description: "On-chain verifier binary file",
    }),
  },
  description: "Deploy a binary contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    verifier_bin,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);

    // Load binary contract
    const contractHex = "0x" + fs.readFileSync(verifier_bin, "utf-8").trim();

    // Deploy and output the resulting contract address to stdout.
    const address = await utils.deployBinaryContract(wallet, contractHex);
    console.log(address);
  },
});
