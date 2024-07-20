import { boolean, command, flag, string, option } from "cmd-ts";
import { loadSnarkjsVK, loadGnarkVK } from "./config";
import { Groth16VerifyingKey } from "../sdk/application";
import * as fs from "fs";

export const convertvkSnarkJs = command({
  name: "convert-vk-snark-js",
  args: {
    snarkjsVkFile: option({
      type: string,
      long: "snarkjs-vk",
      description:
        "The verifying key output by SnarkJS, to be converted into\
       a UPA VK",
    }),
    upaVkFile: option({
      type: string,
      long: "vk-file",
      description: "The destination for output UPA verifying key",
    }),
  },
  description: "Convert Groth16 verifying key from SnarkJS to UPA format",
  handler: async function ({ snarkjsVkFile, upaVkFile }): Promise<void> {
    const snarkjsVk = loadSnarkjsVK(snarkjsVkFile);

    const upaVk = Groth16VerifyingKey.from_snarkjs(snarkjsVk);

    fs.writeFileSync(upaVkFile, JSON.stringify(upaVk));
  },
});

export const convertvkGnark = command({
  name: "convert-vk-gnark",
  args: {
    gnarkVkFile: option({
      type: string,
      long: "gnark-vk",
      description:
        "The verifying key output by Gnark, to be converted into\
       a UPA VK",
    }),
    hasCommitment: flag({
      type: boolean,
      long: "has-commitment",
      description:
        "Whether this VK belongs to a circuit that uses LegoSnark commitments",
    }),
    upaVkFile: option({
      type: string,
      long: "vk-file",
      description: "The destination for output UPA verifying key",
    }),
  },
  description: "Convert Groth16 verifying key from Gnark to UPA format",
  handler: async function ({
    gnarkVkFile,
    hasCommitment,
    upaVkFile,
  }): Promise<void> {
    const gnarkVk = loadGnarkVK(gnarkVkFile);

    const upaVk = Groth16VerifyingKey.from_gnark(gnarkVk, hasCommitment);

    fs.writeFileSync(upaVkFile, JSON.stringify(upaVk));
  },
});
