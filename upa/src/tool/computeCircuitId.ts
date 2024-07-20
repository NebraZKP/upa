import { command, positional, string } from "cmd-ts";
import { loadAppVK } from "./config";
import { utils } from "../sdk";

export const computecircuitid = command({
  name: "compute-circuit-id",
  args: {
    vkFile: positional({
      type: string,
      displayName: "vk-file",
      description: "JSON VK file for the circuit",
    }),
  },
  description: "Use the UPA contract to compute the circuitId of a given VK",
  handler: function ({ vkFile }): void {
    const vk = loadAppVK(vkFile);
    const circuitId = utils.computeCircuitId(vk);

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(circuitId);
  },
});
