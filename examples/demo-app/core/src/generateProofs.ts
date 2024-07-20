import { command, option, number } from "cmd-ts";
import {
  circuitWasm,
  circuitZkey,
  proofOutputFile,
  generateProof,
  demoAppInstance,
  loadDemoAppInstance,
} from "./utils";
import * as fs from "fs";

export const generateProofs = command({
  name: "generate-proofs",
  args: {
    numProofs: option({
      type: number,
      long: "num",
      short: "n",
      defaultValue: () => 1,
      description: "The number of proofs to generate.",
    }),
    demoAppInstanceFile: demoAppInstance(),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
    proofOutputFile: proofOutputFile(),
  },
  description: "Generate a number of demo-app proofs and write them to file.",
  handler: async function ({
    numProofs,
    demoAppInstanceFile,
    circuitWasm,
    circuitZkey,
    proofOutputFile,
  }): Promise<undefined> {
    const startTimeMilliseconds = Date.now();

    const demoAppInstance = loadDemoAppInstance(demoAppInstanceFile);
    const circuitId = demoAppInstance.circuitId;

    const cidProofsPIs = [];

    for (let i = 0; i < numProofs; i++) {
      const [proof, inputs] = await generateProof(circuitWasm, circuitZkey);
      cidProofsPIs.push({ circuitId, proof, inputs });

      console.log(`Generated proof ${i}.`);
    }

    const endTimeMilliseconds = Date.now(); // Record the end time
    const elapsedTimeSeconds =
      (endTimeMilliseconds - startTimeMilliseconds) / 1000;

    console.log(
      `Generated ${numProofs} proofs in ${elapsedTimeSeconds} seconds.`
    );

    fs.writeFileSync(proofOutputFile, JSON.stringify(cidProofsPIs, null, 2));

    console.log(`Generated proofs written to file ${proofOutputFile}.`);
  },
});
