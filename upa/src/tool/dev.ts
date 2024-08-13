import {
  subcommands,
  command,
  string,
  option,
  positional,
  optional,
  flag,
  boolean,
} from "cmd-ts";
import {
  loadAppVkProofInputsFile,
  loadWallet,
  readAddressFromKeyfile,
} from "./config";
import { endpoint, keyfile, password, getPassword } from "./options";
import * as log from "./log";
import * as ethers from "ethers";
import * as fs from "fs";
import { execSync } from "child_process";
import { devAggregator } from "./devAggregator";
import { options } from ".";
import { Groth16Verifier } from "../sdk";
import { getLogger } from "./log";

export const ethkeygen = command({
  name: "ethkeygen",
  args: {
    keyfile: keyfile("Keyfile to write to"),
    password: password(),
  },
  description: "Generate an ethereum key and save to an encrypted keyfile",
  handler: async function ({ keyfile, password }): Promise<void> {
    if (fs.existsSync(keyfile)) {
      throw "refusing to overwrite file: " + keyfile;
    }

    const wallet = ethers.Wallet.createRandom();
    const keystore = await wallet.encrypt(getPassword(password));
    log.debug("generated keyfile: " + keystore);
    fs.writeFileSync(keyfile, keystore);

    const keystoreParsed = JSON.parse(keystore);
    const address = ethers.getAddress(keystoreParsed.address);
    console.log(address);
  },
});

export const send = command({
  name: "send",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    destination: option({
      type: string,
      long: "dest",
      short: "d",
      description: "Destination address",
    }),
    amount: option({
      type: string,
      long: "amount",
      short: "a",
      description: "ETH amount to send",
    }),
  },
  description: "Send ETH",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    destination,
    amount,
  }) {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const value = ethers.parseUnits(amount);
    const tx = await wallet.sendTransaction({
      to: destination,
      from: await wallet.getAddress(),
      value,
    });
    console.log(tx.hash);
  },
});

export const balance = command({
  name: "balance",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(undefined, false),
    address: positional({
      type: optional(string),
      description: "Address to check (DEFAULT: address from keyfile)",
    }),
  },
  description: "Get the balance for an address (or keyfile)",
  handler: async function ({ endpoint, keyfile, address }) {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const addr = (() => {
      if (address) {
        return ethers.getAddress(address);
      }

      if (!keyfile) {
        console.error("no address or keyfile given");
        process.exit(1);
      }

      return readAddressFromKeyfile(keyfile);
    })();

    const balanceWei = await provider.getBalance(addr);
    const balanceEth = ethers.formatEther(balanceWei);
    console.log(balanceEth);
  },
});

const fund = command({
  name: "fund",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile("keyfile for account to fund", false),
    address: positional({
      type: optional(string),
      description: "Address to fund (if keyfile not given)",
    }),
    amount: option({
      type: string,
      long: "amount",
      short: "a",
      defaultValue: () => "1.0",
      description: "ETH amount to fund (default: 1.0 ETH)",
    }),
  },
  description: "Send a single ETH from a hosted address",
  handler: async function ({
    endpoint,
    address,
    keyfile,
    amount,
  }): Promise<undefined> {
    // If address is given use it, otherwise fallback to keyfile.  (Note,
    // keyfile may be set via env variables, even though the user intention is
    // to fund a specific address, hence we don't assert that only one may be
    // set.)
    const addr = await (async () => {
      if (address) {
        return ethers.getAddress(address);
      }

      if (!keyfile) {
        console.error("no address or keyfile given");
        process.exit(1);
      }

      return readAddressFromKeyfile(keyfile);
    })();

    const provider = new ethers.JsonRpcProvider(endpoint);
    const signer = await provider.getSigner(0);
    const value = ethers.parseUnits(amount);
    const result = await signer.sendTransaction({
      to: addr,
      value,
    });
    log.debug("result: " + JSON.stringify(result));
    await result.wait();
  },
});

const trace = command({
  name: "trace",
  args: {
    endpoint: endpoint(),
    traceFile: option({
      type: string,
      long: "trace-file",
      short: "t",
      defaultValue: () => "trace.json",
      description: "File to dump a trace to (default: trace.json)",
    }),
    txHash: positional({
      type: string,
      displayName: "tx-hash",
      description: "Hash of the tx to trace",
    }),
  },
  description: "Dump a trace of the given tx",
  handler: async function ({ endpoint, traceFile, txHash }) {
    const cmd =
      `curl -s -X POST ${endpoint} -H "Content-Type:application-json" ` +
      `--data '{"method":"debug_traceTransaction","params":["${txHash}"],` +
      `"id":1,"jsonrpc":"2.0"}' > ${traceFile}`;
    console.log("cmd: " + cmd);
    execSync(cmd);
  },
});

const getReceipt = command({
  name: "get-receipt",
  args: {
    endpoint: endpoint(),
    txHash: positional({
      type: string,
      displayName: "tx-hash",
      description: "Get the receipt for a given tx.",
    }),
  },
  description: "Get the gas cost for a given tx",
  handler: async function ({ endpoint, txHash }) {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const receipt = await provider.getTransactionReceipt(txHash);
    console.log(JSON.stringify(receipt));
  },
});

const gasPrice = command({
  name: "gas-price",
  args: {
    endpoint: endpoint(),
  },
  description: "Get the gas price estimates from the node",
  handler: async function ({ endpoint }) {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const feeData = await provider.getFeeData();
    console.log(JSON.stringify(feeData));
  },
});

const intervalMining = command({
  name: "interval-mining",
  args: {
    endpoint: endpoint(),
    interval: positional({
      type: optional(string),
      displayName: "interval-ms",
      description: "Mining interval (ms).  0 = disable interval mining.",
    }),
  },
  description:
    "If interval > 0, disable autoMine and use interval mining.\n" +
    "If interval == 0, enable autoMine and disable interval mining.",
  handler: async function ({ endpoint, interval }) {
    const intervalMS = parseInt(interval || "1000");
    const autoMine = intervalMS == 0;
    const provider = new ethers.JsonRpcProvider(endpoint);
    await provider.send("evm_setAutomine", [autoMine]);
    await provider.send("evm_setIntervalMining", [intervalMS]);
  },
});

const getBlockBaseFee = command({
  name: "get-block-base-fee",
  args: {
    endpoint: endpoint(),
  },
  description: "Return the base fee per gas of the latest block, in Gwei",
  handler: async function ({ endpoint }) {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const block = await provider.getBlock("latest");
    const feeWei = block?.baseFeePerGas;
    const feeGwei = ethers.formatUnits(feeWei!, "gwei");
    console.log(feeGwei);
  },
});

const setBlockBaseFee = command({
  name: "set-block-base-fee",
  args: {
    endpoint: endpoint(),
    feeGwei: positional({
      type: string,
      displayName: "base-fee-in-gwei",
      description: "Base fee in gwei of the next block",
    }),
  },
  description: "Set block base fee per gas of the next block",
  handler: async function ({ endpoint, feeGwei }) {
    const baseFeeWei = ethers.parseUnits(feeGwei, "gwei").toString();
    const provider = new ethers.JsonRpcProvider(endpoint);
    await provider.send("hardhat_setNextBlockBaseFeePerGas", [baseFeeWei]);
  },
});

const describe = command({
  name: "describe",
  args: {},
  description: "Print a description string, primarily for testing",
  handler: function () {
    console.log(
      "UPA tool - command-line utility for interacting with NEBRA UPA"
    );
  },
});

const groth16Verify = command({
  name: "groth16-verify",
  description: "Verify a groth16 proof",
  args: {
    proofFile: options.proofFile(),
    doLog: flag({
      type: boolean,
      long: "log",
      short: "l",
      description: "Log groth16 verification",
    }),
  },
  handler: async function ({ proofFile, doLog }): Promise<void> {
    const { vk, proof, inputs } = loadAppVkProofInputsFile(proofFile);
    const processedInputs = inputs.map((input) => {
      if (typeof input === "number") {
        return BigInt(input);
      } else {
        return input;
      }
    });
    const groth16Verifier = await Groth16Verifier.initialize();
    const logger = doLog ? getLogger() : undefined;
    const verified = await groth16Verifier.verifyGroth16Proof(
      vk,
      proof,
      processedInputs,
      logger
    );

    if (!verified.result) {
      log.info(`Verification error: ${verified.error!}`);
    }

    // write 1/0 to stdout and use exit status to indicate validity
    console.log(verified ? "1" : "0");
    process.exit(verified ? 0 : 1);
  },
});

export const dev = subcommands({
  name: "dev",
  description: "Utilities for local development",
  cmds: {
    ethkeygen,
    fund,
    trace,
    "interval-mining": intervalMining,
    "get-receipt": getReceipt,
    send,
    balance,
    "gas-price": gasPrice,
    describe,
    "set-block-base-fee": setBlockBaseFee,
    "get-block-base-fee": getBlockBaseFee,
    aggregator: devAggregator,
    "groth16-verify": groth16Verify,
  },
});
