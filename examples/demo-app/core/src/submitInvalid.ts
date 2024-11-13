import * as ethers from "ethers";
import { ContractTransactionReceipt } from "ethers";
import { command, option, number } from "cmd-ts";
const snarkjs = require("snarkjs");
import { generateRandomProofInputs, upaInstance } from "./utils";
import { demoAppInstance, loadDemoAppInstance } from "./utils";
import { Groth16Proof, application, utils, UpaClient } from "@nebrazkp/upa/sdk";
import { options, config } from "@nebrazkp/upa/tool";
const { keyfile, chainEndpoint, password } = options;
const { loadWallet, loadInstance } = config;
import { circuitWasm, circuitZkey } from "./utils";
import { Sema, RateLimit } from "async-sema";

export const submitInvalid = command({
  name: "submit",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    demoAppInstanceFile: demoAppInstance(),
    upaInstance: upaInstance(),
    numProofs: option({
      type: number,
      long: "num",
      short: "n",
      defaultValue: () => 0,
      description: "The number of proofs to send. If 0, send unlimited proofs.",
    }),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
    submitRate: option({
      type: number,
      long: "submit-rate",
      defaultValue: () => 1,
      description: "The maximum submission rate per second.",
    }),
  },
  description:
    "Send a number of invalid demo-app proofs to UPA to be verified.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    upaInstance,
    numProofs,
    circuitWasm,
    circuitZkey,
    submitRate,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    const upaClient = await UpaClient.init(wallet, loadInstance(upaInstance));

    const demoAppInstance = loadDemoAppInstance(demoAppInstanceFile);
    const circuitId = demoAppInstance.circuitId;

    const maxConcurrency = 5;
    const sema = new Sema(maxConcurrency);

    const submitTxPromises: Promise<void>[] = [];
    const waitTxPromises: Promise<ContractTransactionReceipt | null>[] = [];

    const initialNonce = await wallet.getNonce();

    const startTimeMilliseconds = Date.now();

    const rateLimiter = RateLimit(submitRate, { uniformDistribution: true });

    // Loops indefinitely if numProofs was set to 0.
    for (let i = 0; i < numProofs || numProofs == 0; i++) {
      const proofData = await snarkjs.groth16.fullProve(
        generateRandomProofInputs(),
        circuitWasm,
        circuitZkey
      );

      const proof = Groth16Proof.from_snarkjs(proofData.proof);

      let publicInputs: bigint[] = proofData.publicSignals.map(BigInt);

      publicInputs = publicInputs.map((input) => {
        let inputBigInt = BigInt(input);
        inputBigInt += BigInt(1);
        return inputBigInt;
      });

      const submitTxFn = async () => {
        const circuitIdProofAndInputs: application.CircuitIdProofAndInputs[] = [
          { circuitId, proof, inputs: publicInputs },
        ];
        return await upaClient.submitProofs(circuitIdProofAndInputs, {
          nonce: initialNonce + i,
        });
      };

      // Wrap `submitTxFn` with retry logic and aquire/release of `sema`.
      const submitTxPromise = async () => {
        try {
          await sema.acquire();
          await rateLimiter();

          const submissionHandle = await utils.requestWithRetry(
            submitTxFn,
            `${i}` /* proofLabel*/
          );
          console.log(`Successfully submitted tx for invalid proof ${i}`);
          waitTxPromises.push(submissionHandle.txResponse.wait());
        } finally {
          sema.release();
        }
      };

      console.log(`Queueing tx submit for invalid proof ${i}.`);
      submitTxPromises.push(submitTxPromise());
    }

    await Promise.all(submitTxPromises);
    await Promise.all(waitTxPromises);

    const endTimeMilliseconds = Date.now(); // Record the end time
    const elapsedTimeSeconds =
      (endTimeMilliseconds - startTimeMilliseconds) / 1000;

    console.log(
      `All ${numProofs} invalid proofs submitted in
      ${elapsedTimeSeconds} seconds.`
    );
  },
});
