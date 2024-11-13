import * as ethers from "ethers";
import { command } from "cmd-ts";
import * as fs from "fs";
import assert from "assert";
import { demoAppInstance, upaInstance, DemoAppInstance, vkFile } from "./utils";
import { DemoApp__factory } from "../typechain-types";
import { options, config } from "@nebrazkp/upa/tool";
import { utils } from "@nebrazkp/upa/sdk";
const { keyfile, chainEndpoint, password } = options;
const { loadWallet, upaFromInstanceFile } = config;

export const deploy = command({
  name: "deploy",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    demoAppInstanceFile: demoAppInstance(
      "Output file for instance information"
    ),
    upaInstance: upaInstance(),
    vkFile: vkFile(),
  },
  description: "Deploy the DemoApp contract.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    upaInstance,
    vkFile,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, password, provider);

    const upa = await upaFromInstanceFile(upaInstance, provider);
    const vk = config.loadAppVK(vkFile);
    const circuitId = utils.computeCircuitId(vk);

    const DemoApp = new DemoApp__factory(wallet);
    const demoApp = await DemoApp.deploy(upa.verifier, circuitId);
    await demoApp.waitForDeployment();

    assert(circuitId == (await demoApp.circuitId()));

    // Write the instance information to disk
    const instanceData: DemoAppInstance = {
      demoApp: await demoApp.getAddress(),
      circuitId: circuitId.toString(),
      vk,
    };
    fs.writeFileSync(demoAppInstanceFile, JSON.stringify(instanceData));

    console.log(`DemoApp was deployed to address \
    ${instanceData.demoApp}, circuitId is \
    ${instanceData.circuitId}`);
  },
});
