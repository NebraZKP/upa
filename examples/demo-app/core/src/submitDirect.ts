import * as ethers from "ethers";
import { ContractTransactionReceipt } from "ethers";
import { command, option, number } from "cmd-ts";
const snarkjs = require("snarkjs");
import { generateRandomProofInputs } from "./utils";
import { Sema, RateLimit } from "async-sema";
import { Groth16Proof, utils } from "@nebrazkp/upa/sdk";
import { options, config } from "@nebrazkp/upa/tool";
import {
  demoAppFromInstance,
  demoAppInstance,
  circuitWasm,
  circuitZkey,
} from "./utils";
const { keyfile, chainEndpoint, password } = options;
const { loadWallet } = config;

export const submitDirect = command({
  name: "submit-direct",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    demoAppInstanceFile: demoAppInstance(),
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
  description: "Send a number of proofs to DemoApp's verifier.",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    demoAppInstanceFile,
    numProofs,
    circuitWasm,
    circuitZkey,
    submitRate,
  }): Promise<undefined> {
    let demoApp = demoAppFromInstance(demoAppInstanceFile);
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    demoApp = demoApp.connect(wallet);

    const maxConcurrency = 1;
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

      const calldataBlob = await snarkjs.groth16.exportSolidityCallData(
        proofData.proof,
        proofData.publicSignals
      );

      const calldataJSON = JSON.parse("[" + calldataBlob + "]");

      const proof = new Groth16Proof(
        calldataJSON[0],
        calldataJSON[1],
        calldataJSON[2],
        [],
        []
      );
      const publicSignals = calldataJSON[3];

      const submitTxFn = async () => {
        return await demoApp.submitSolutionDirect(
          proof.pi_a,
          proof.pi_b,
          proof.pi_c,
          publicSignals,
          { nonce: initialNonce + i }
        );
      };

      // Wrap `submitTxFn` with retry logic and aquire/release of `sema`.
      const submitTxPromise = async () => {
        try {
          await sema.acquire();
          await rateLimiter();

          const submitProofTx = await utils.requestWithRetry(
            submitTxFn,
            `${i}` /* proofLabel*/
          );
          console.log(`Successfully submitted tx for proof ${i}`);
          waitTxPromises.push(submitProofTx.wait());
        } finally {
          sema.release();
        }
      };

      console.log(`Queueing tx submit for proof ${i}.`);
      submitTxPromises.push(submitTxPromise());
    }

    await Promise.all(submitTxPromises);

    const txReceipts = await Promise.all(waitTxPromises);

    const endTimeMilliseconds = Date.now(); // Record the end time
    const elapsedTimeSeconds =
      (endTimeMilliseconds - startTimeMilliseconds) / 1000;

    console.log(
      `All ${numProofs} proofs submitted and verified in ` +
        `${elapsedTimeSeconds} seconds.`
    );

    const totalGasUsed = txReceipts.reduce(
      (total, receipt) => total + receipt!.gasUsed,
      0n
    );

    const totalWeiUsed = txReceipts.reduce(
      (total, receipt) => total + receipt!.fee,
      0n
    );

    const totalEthUsed = utils.weiToEther(totalWeiUsed, 6 /*numDecimalPlaces*/);

    console.table({
      "Gas used for submitting proofs and solutions to demo-app": {
        "Cost (gas)": `${totalGasUsed}`,
        "Cost (ETH)": `${totalEthUsed}`,
      },
    });
  },
});
