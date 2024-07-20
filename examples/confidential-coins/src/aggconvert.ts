import * as ethers from "ethers";
import { command, option, number } from "cmd-ts";
const snarkjs = require("snarkjs");
import {
  CircuitInputs,
  Coin,
  balancesUninitialized,
  confidentialCoinsFromInstance,
  generateRandomCoinPair,
  getBalance,
  getOnChainBalances,
  loadConfidentialCoinsInstance,
  stringify,
  toyHash,
  upaInstance,
  updateBalances,
} from "./utils";
import {
  CircuitIdProofAndInputs,
  Groth16Proof,
  UpaClient,
  utils,
} from "@nebrazkp/upa/sdk";
import { options, config } from "@nebrazkp/upa/tool";
import { instance, circuitWasm, circuitZkey } from "./utils";
import { ConfidentialCoins } from "../typechain-types/contracts";
const { keyfile, endpoint, password } = options;
const { loadWallet, loadInstance } = config;

export const aggConvert = command({
  name: "agg-convert",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
    upaInstance: upaInstance(),
    numProofs: option({
      type: number,
      long: "num",
      short: "n",
      defaultValue: () => 1,
      description: "The number of conversions to perform in one tx.",
    }),
    circuitWasm: circuitWasm(),
    circuitZkey: circuitZkey(),
  },
  description: "Perform many conversions using UPA to aggregate the proofs",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    upaInstance,
    numProofs,
    circuitWasm,
    circuitZkey,
  }): Promise<undefined> {
    let confidentialCoins = confidentialCoinsFromInstance(instance);
    const circuitId = loadConfidentialCoinsInstance(instance).circuitId;
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    confidentialCoins = confidentialCoins.connect(wallet);

    // TODO (#670): Add flag to reset balance before executing transactions.
    // Get current balances. If all zero, initialize balances.
    let currentBalances = await getOnChainBalances(confidentialCoins, wallet);
    if (balancesUninitialized(currentBalances)) {
      console.log("Initializing balances to 1000");
      const initializeTx = await confidentialCoins.initializeBalances();
      await initializeTx.wait();
      currentBalances = await getOnChainBalances(confidentialCoins, wallet);
    }

    // On-chain calldata used to compute public inputs.
    const convertTxSequence: ConfidentialCoins.ConvertTxStruct[] = [];

    // Data used to prepare a multi-proof submission to UPA.
    const circuitIdProofAndInputs: CircuitIdProofAndInputs[] = [];

    console.log("generating tx sequence");

    // Generate a random sequence of n transactions.
    // TODO (#670): Allow sequence to be passed in from file.
    for (let i = 0; i < numProofs || numProofs == 0; i++) {
      // Randomly choose source coin, target coin and transfer amount.
      const [sourceCoin, targetCoin] = generateRandomCoinPair();

      // Choose a transfer amount under the current source coin balance
      const oldSourceCoinBalance = getBalance(sourceCoin, currentBalances);
      const oldSourceCoinBalanceHash = toyHash(oldSourceCoinBalance);
      const transferAmount = BigInt(
        Math.floor(Math.random() * Number(oldSourceCoinBalance))
      );
      const transferAmountHash = toyHash(transferAmount);

      // Compute new sourceCoin balance and its hash.
      const newSourceCoinBalance = oldSourceCoinBalance - transferAmount;
      const newSourceCoinBalanceHash = toyHash(newSourceCoinBalance);

      // Compute new targetCoin balance and its hash
      const oldTargetCoinBalance = getBalance(targetCoin, currentBalances);
      const oldTargetCoinBalanceHash = toyHash(oldTargetCoinBalance);
      const newTargetCoinBalance = oldTargetCoinBalance + transferAmount;
      const newTargetCoinBalanceHash = toyHash(newTargetCoinBalance);

      const convertTx: ConfidentialCoins.ConvertTxStruct = {
        sourceCoin,
        targetCoin,
        newSourceCoinBalanceHash,
        newTargetCoinBalanceHash,
        transferAmountHash,
      };
      convertTxSequence.push(convertTx);
      console.log(
        `Convert ${transferAmount} ${Coin[sourceCoin]} ---> ` +
          `${Coin[targetCoin]}`
      );

      // Generate zk proof of tx validity and add to proof sequence.
      const circuitInputs: CircuitInputs = {
        oldSourceCoinBalance,
        oldSourceCoinBalanceHash,
        newSourceCoinBalance,
        newSourceCoinBalanceHash,
        oldTargetCoinBalance,
        oldTargetCoinBalanceHash,
        newTargetCoinBalance,
        newTargetCoinBalanceHash,
        transferAmount,
        transferAmountHash,
      };

      const proofData = await snarkjs.groth16.fullProve(
        circuitInputs,
        circuitWasm,
        circuitZkey
      );
      const proof = Groth16Proof.from_snarkjs(proofData.proof);
      const inputs: bigint[] = proofData.publicSignals.map(BigInt);

      circuitIdProofAndInputs.push({ circuitId, proof, inputs });

      currentBalances = updateBalances(
        currentBalances,
        sourceCoin,
        targetCoin,
        newSourceCoinBalance,
        newSourceCoinBalanceHash,
        newTargetCoinBalance,
        newTargetCoinBalanceHash
      );
    }

    // Initialize a `UpaClient` for submitting proofs to the UPA.
    const upaClient = new UpaClient(wallet, loadInstance(upaInstance));

    const submissionHandle = await upaClient.submitProofs(
      circuitIdProofAndInputs
    );

    // Wait for an off-chain prover to send an aggregated proof to the UPA
    // contract showing that our submitted `circuitIdProofAndInputs` was valid.
    const submitProofsToUpaTxReceipt =
      await upaClient.waitForSubmissionVerified(submissionHandle);
    const totalWeiUsedSubmittingProofs =
      submitProofsToUpaTxReceipt.fee + submissionHandle.txResponse.value;
    const totalEthUsedSubmittingProofs = utils.weiToEther(
      totalWeiUsedSubmittingProofs,
      6 /*numDecimalPlaces*/
    );

    // Submit the sequence of transactions to the contract. The app contract
    // will check that UPA has verified and aggregated all the proofs in the
    // submission. If so, the transaction sequence is valid and the app
    // contract may commit the result of the transaction sequence.
    const submitTxResponse =
      await confidentialCoins.aggregatedSubmitTransactions(convertTxSequence);
    const submitTxReceipt = await submitTxResponse.wait();
    const totalWeiUsedSubmittingConvert = submitTxReceipt!.fee;
    const totalEthUsedSubmittingConvert = utils.weiToEther(
      totalWeiUsedSubmittingConvert,
      6 /*numDecimalPlaces*/
    );

    const newBalances = await getOnChainBalances(confidentialCoins, wallet);
    console.log(
      `Balances updated. New on-chain balances are:\n${stringify(newBalances)}`
    );

    console.log("Gas Cost Summary:");
    console.table({
      "Submit proof to UPA": {
        "Cost (gas)": `${submitProofsToUpaTxReceipt!.gasUsed}`,
        "Cost (ETH)": `${totalEthUsedSubmittingProofs}`,
      },
      "Submit convert sequence to app contract": {
        "Cost (gas)": `${submitTxReceipt!.gasUsed}`,
        "Cost (ETH)": `${totalEthUsedSubmittingConvert}`,
      },
      Total: {
        "Cost (gas)": `${
          submitProofsToUpaTxReceipt!.gasUsed + submitTxReceipt!.gasUsed
        }`,
        "Cost (ETH)": `${
          totalEthUsedSubmittingProofs + totalEthUsedSubmittingConvert
        }`,
      },
    });
  },
});
