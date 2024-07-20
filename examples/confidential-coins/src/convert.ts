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
  stringify,
  toyHash,
  updateBalances,
} from "./utils";
import { Groth16Proof, utils } from "@nebrazkp/upa/sdk";
import { options, config } from "@nebrazkp/upa/tool";
import { instance, circuitWasm, circuitZkey } from "./utils";
import { ConfidentialCoins } from "../typechain-types/contracts";
import { ProofStruct } from "../typechain-types/contracts/ConfidentialCoins";
const { keyfile, endpoint, password } = options;
const { loadWallet } = config;

export const convert = command({
  name: "convert",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance(),
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
  description: "Perform many conversions, checking individual validity proofs",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    instance,
    numProofs,
    circuitWasm,
    circuitZkey,
  }): Promise<undefined> {
    let confidentialCoins = confidentialCoinsFromInstance(instance);
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, password, provider);
    confidentialCoins = confidentialCoins.connect(wallet);

    // TODO: Add flag to reset balance before executing transactions.
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

    // The i-th proof attests to the validity of the i-th convertTx
    const proofSequence: ProofStruct[] = [];

    console.log("Generating tx sequence");

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
      proofSequence.push(proof.solidity());

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

    // Submit the sequence of transactions and validity proofs to the contract.
    // The contract will verify each proof individually and then commit the
    // result of the transaction sequence.
    const submitTxResponse = await confidentialCoins.submitTransactions(
      convertTxSequence,
      proofSequence
    );
    const submitTxReceipt = await submitTxResponse.wait();
    const totalWeiUsed = submitTxReceipt!.fee;
    const totalEthUsed = utils.weiToEther(totalWeiUsed, 6 /*numDecimalPlaces*/);

    const newBalances = await getOnChainBalances(confidentialCoins, wallet);
    console.log(
      `Balances updated. New on-chain balances are:\n${stringify(newBalances)}`
    );

    console.table({
      "Submit convert sequence and proofs to confidential-coins": {
        "Cost without UPA (gas)": `${submitTxReceipt!.gasUsed}`,
        "Cost without UPA (ETH)": `${totalEthUsed}`,
      },
    });
  },
});
