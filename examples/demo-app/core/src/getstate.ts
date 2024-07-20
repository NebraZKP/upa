import * as ethers from "ethers";
import { command } from "cmd-ts";
import { options } from "@nebrazkp/upa/tool";
const { endpoint } = options;
import { demoAppFromInstance, demoAppInstance } from "./utils";

export const getstate = command({
  name: "getstate",
  args: {
    endpoint: endpoint(),
    demoAppInstanceFile: demoAppInstance(),
  },
  description: "Query the DemoApp contract state.",
  handler: async function ({ endpoint, demoAppInstanceFile }): Promise<void> {
    let demoApp = demoAppFromInstance(demoAppInstanceFile);
    const provider = new ethers.JsonRpcProvider(endpoint);
    demoApp = demoApp.connect(provider);

    const proofsVerified = await demoApp.proofsVerified();
    const jsonData = { proofsVerified: proofsVerified.toString() };
    console.log(JSON.stringify(jsonData));
  },
});
