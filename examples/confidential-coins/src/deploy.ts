import * as ethers from "ethers";
import { command } from "cmd-ts";
import * as fs from "fs";
import assert from "assert";
import {
  ConfidentialCoinsInstance,
  instance,
  upaInstance,
  vkFile,
} from "./utils";
import { options, config } from "@nebrazkp/upa/tool";
import { utils } from "@nebrazkp/upa/sdk";
import { ConfidentialCoins__factory } from "../typechain-types";
const { keyfile, endpoint, password } = options;
const { loadWallet, upaFromInstanceFile } = config;

export const deploy = command({
  name: "deploy",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance("Output file for instance information"),
    upaInstance: upaInstance(),
    vkFile: vkFile(),
  },
  description: "Deploy the ConfidentialCoins contract.",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    upaInstance,
    vkFile,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, password, provider);

    const upa = upaFromInstanceFile(upaInstance, provider);
    const vk = config.loadAppVK(vkFile);
    const circuitId = utils.computeCircuitId(vk);

    const confidentialCoinsFactory = new ConfidentialCoins__factory(wallet);
    const confidentialCoins = await confidentialCoinsFactory.deploy(
      upa.verifier,
      circuitId
    );
    await confidentialCoins.waitForDeployment();

    assert(circuitId == (await confidentialCoins.circuitId()));

    // Write the instance information to disk
    const instanceData: ConfidentialCoinsInstance = {
      confidentialCoins: await confidentialCoins.getAddress(),
      circuitId: circuitId.toString(),
    };
    fs.writeFileSync(instance, JSON.stringify(instanceData));

    console.log(`ConfidentialCoins contract deployed to address \
    ${instanceData.confidentialCoins}, circuitId is \
    ${instanceData.circuitId}`);
  },
});
