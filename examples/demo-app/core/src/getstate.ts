import * as ethers from "ethers";
import { command } from "cmd-ts";
import { options } from "@nebrazkp/upa/tool";
const { chainEndpoint } = options;
import { demoAppFromInstance, demoAppInstance } from "./utils";

export const getstate = command({
  name: "getstate",
  args: {
    chainEndpoint: chainEndpoint(),
    demoAppInstanceFile: demoAppInstance(),
  },
  description: "Query the DemoApp contract state.",
  handler: async function ({
    chainEndpoint,
    demoAppInstanceFile,
  }): Promise<void> {
    let demoApp = demoAppFromInstance(demoAppInstanceFile);
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    demoApp = demoApp.connect(provider);

    const proofsVerified = await demoApp.proofsVerified();
    const jsonData = { proofsVerified: proofsVerified.toString() };
    console.log(JSON.stringify(jsonData));
  },
});
