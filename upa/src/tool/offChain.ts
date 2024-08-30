import {
  subcommands,
  command,
  string,
  option,
  optional,
  positional,
} from "cmd-ts";
import * as log from "./log";
import {
  loadWallet,
  loadAppVkProofInputsBatchFile,
  readAddressFromKeyfile,
} from "./config";
import {
  password,
  getPassword,
  keyfile,
  vkProofInputsBatchFilePositional,
  submissionEndpoint,
  endpoint,
} from "./options";
import {
  computeCircuitId,
  computeProofId,
  computeSubmissionId,
  JSONstringify,
} from "../sdk/utils";
import {
  getSignedResponseData,
  OffChainClient,
  OffChainSubmissionResponse,
  signOffChainSubmissionRequest,
  UnsignedOffChainSubmissionRequest,
} from "../sdk/offChainClient";
import { ethers } from "ethers";
import { Deposits__factory } from "../../typechain-types";
import fs from "fs";
import { config, options } from ".";

function depositContract() {
  return option({
    type: string,
    long: "deposit-contract",
    description:
      "Aggregator's deposit contract (DEPOSIT_CONTRACT or query server)",
    defaultValue: () => {
      const val = process.env.DEPOSIT_CONTRACT;
      if (val) {
        return val;
      }

      throw "deposit contract not specified";
    },
  });
}

export const submit = command({
  name: "submit",
  args: {
    endpoint: endpoint(),
    submissionEndpoint: submissionEndpoint(),
    keyfile: keyfile(),
    password: password(),
    proofsFile: vkProofInputsBatchFilePositional(),
    depositContract: depositContract(),
    nonceString: option({
      type: optional(string),
      long: "nonce",
      description: "Submitter nonce (default: query server)",
    }),
    feeGweiString: option({
      type: optional(string),
      long: "fee-gwei",
      description: "Total submission fee, in gwei (default: query server)",
    }),
    expirationBlockString: option({
      type: optional(string),
      long: "fee-per-proof",
      description: "Submission expiry block number (default: query server)",
    }),
  },
  description: "Submit a set of proofs to an off-chain aggregator",
  handler: async function ({
    endpoint,
    submissionEndpoint,
    keyfile,
    password,
    proofsFile,
    depositContract,
    nonceString,
    feeGweiString,
    expirationBlockString,
  }): Promise<void> {
    const vksProofsInputs = loadAppVkProofInputsBatchFile(proofsFile);
    const proofIds = vksProofsInputs.map((vpi) => {
      const circuitId = computeCircuitId(vpi.vk);
      return computeProofId(circuitId, vpi.inputs);
    });
    const submissionId = computeSubmissionId(proofIds);

    // Create the submission client and load the wallet
    const client = await OffChainClient.init(submissionEndpoint);
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);

    // Check that the deposit contract is as expected.  Don't just trust the
    // aggregator.
    const aggDepositContract = client.getDepositContract();
    if (depositContract !== aggDepositContract) {
      throw `aggregator claims deposit contract ${aggDepositContract}`;
    }

    // Load submitter state. (A custom client can keep track of nonce, etc and
    // potentially avoid querying at each submission.)
    const address = await wallet.getAddress();
    const submitterState = await client.getSubmitterState(address);
    const submissionParameters = await client.getSubmissionParameters();

    // Use submitter state to fill in nonce, fee, expirationBlock if not given
    const nonce = nonceString
      ? BigInt(nonceString)
      : submitterState.lastNonce + 1n;

    // If not specified explicitly, expiration block is given by the current
    // block number + expected latency.
    const expirationBlock = expirationBlockString
      ? Number(expirationBlockString)
      : (await provider.getBlockNumber()) +
        submissionParameters.expectedLatency;

    // If not given explicitly, set a fee of 'minFeePerProof * numProofs'.
    const submissionFee = feeGweiString
      ? ethers.parseUnits(feeGweiString, "gwei")
      : BigInt(vksProofsInputs.length) * submissionParameters.minFeePerProof;
    log.info(`feePerProof: ${submissionParameters.minFeePerProof}`);
    log.info(`numProofs: ${vksProofsInputs.length}`);
    log.info(`submissionFee: ${submissionFee}`);

    const totalFee = submitterState.totalFee + submissionFee;

    // Prepare an UnsignedOffChainSubmissionRequest
    const unsignedSubmission = new UnsignedOffChainSubmissionRequest(
      vksProofsInputs,
      submissionId,
      submissionFee,
      expirationBlock,
      address,
      nonce,
      totalFee
    );

    // Sign the request
    const submission = await signOffChainSubmissionRequest(
      unsignedSubmission,
      wallet,
      depositContract
    );
    log.debug(`submission: ${JSONstringify(submission)}`);
    const response = await client.submit(submission);
    response as unknown;

    console.log(JSONstringify(response));
  },
});

export const deposit = command({
  name: "deposit",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    depositContract: depositContract(),
    amountEth: option({
      type: string,
      long: "amount-eth",
      description: "Amount to deposit, in ETH",
    }),
  },
  description: "Deposit ETH into an aggregator's deposits contract",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    depositContract,
    amountEth,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const deposits = Deposits__factory.connect(depositContract);
    const amountWei = ethers.parseEther(amountEth);
    const txReq = await deposits.deposit.populateTransaction({
      value: amountWei,
    });
    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      deposits.interface
    );
  },
});

export const refundFee = command({
  name: "refund-fee",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    depositContract: option({
      type: string,
      long: "deposit-contract",
      description: "Address of the aggregator's deposit contract",
    }),
    signedResponseFile: option({
      type: string,
      long: "signed-response",
      description: "File containing a signed aggregator response.",
    }),
  },
  description: "Refund a submission not aggregated within agreed expiry time",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    depositContract,
    signedResponseFile,
  }): Promise<void> {
    const parsedJSON: object[] = JSON.parse(
      fs.readFileSync(signedResponseFile, "ascii")
    );
    const signedResponse = OffChainSubmissionResponse.from_json(parsedJSON);
    const aggregationAgreement = getSignedResponseData(signedResponse);

    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const deposits = Deposits__factory.connect(depositContract);
    const txReq = await deposits.refundFees.populateTransaction(
      aggregationAgreement,
      signedResponse.signature
    );
    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      deposits.interface
    );
  },
});

export const initiateWithdrawal = command({
  name: "init-withdrawal",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    depositContract: depositContract(),
  },
  description: "Initiate a withdrawal",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    depositContract,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const deposits = Deposits__factory.connect(depositContract);
    const txReq = await deposits.initiateWithdrawal.populateTransaction();
    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      deposits.interface
    );
  },
});

export const withdraw = command({
  name: "withdraw",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    wait: options.wait(),
    depositContract: depositContract(),
    amountEth: option({
      type: string,
      long: "amount-eth",
      description: "Amount to withdraw, in ETH",
    }),
  },
  description: "Withdraw deposit. Must `init-withdrawal` before notice period",
  handler: async function ({
    endpoint,
    keyfile,
    password,
    estimateGas,
    dumpTx,
    wait,
    depositContract,
    amountEth,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const wallet = await loadWallet(keyfile, getPassword(password), provider);
    const deposits = Deposits__factory.connect(depositContract);
    const amountWei = ethers.parseEther(amountEth);
    const txReq = await deposits.withdraw.populateTransaction(amountWei);
    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      deposits.interface
    );
  },
});

export const getParameters = command({
  name: "get-parameters",
  args: {
    endpoint: submissionEndpoint(),
  },
  description: "Get the current parameters for an off-chain aggregator",
  handler: async function ({ endpoint }): Promise<void> {
    const client = await OffChainClient.init(endpoint);
    const submissionParameters = await client.getSubmissionParameters();
    console.log(JSONstringify(submissionParameters));
  },
});

export const getState = command({
  name: "get-state",
  args: {
    endpoint: submissionEndpoint(),
    keyfile: keyfile(),
  },
  description: "Get the submitter state held by an off-chain aggregator",
  handler: async function ({ endpoint, keyfile }): Promise<void> {
    // Create the client, read the address and make the query.
    const client = await OffChainClient.init(endpoint);
    const address = readAddressFromKeyfile(keyfile);
    const submitterState = await client.getSubmitterState(address);
    console.log(JSONstringify(submitterState));
  },
});

export const balance = command({
  name: "balance",
  args: {
    endpoint: endpoint(),
    depositContract: depositContract(),
    keyfile: keyfile(undefined, false),
    address: positional({
      type: optional(string),
      description: "Address to query (DEFAULT: address from keyfile)",
    }),
  },
  description: "View the balance of an address",
  handler: async function ({
    endpoint,
    address,
    keyfile,
    depositContract,
  }): Promise<void> {
    address = config.addressFromParamOrKeyfile(address, keyfile);

    const provider = new ethers.JsonRpcProvider(endpoint);
    const deposits =
      Deposits__factory.connect(depositContract).connect(provider);
    const balance = await deposits.balance(address);

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(balance);
  },
});

export const pendingWithdrawalInitializedAtBlock = command({
  name: "withdraw-init-block",
  args: {
    endpoint: endpoint(),
    address: option({
      type: string,
      long: "address",
      description: "Address whose withdraw init block we are viewing",
    }),
    depositContract: depositContract(),
  },
  description: "View the block at which a withdrawal was initiated",
  handler: async function ({
    endpoint,
    address,
    depositContract,
  }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const deposits =
      Deposits__factory.connect(depositContract).connect(provider);
    const withdrawalInitBlock =
      await deposits.pendingWithdrawalInitializedAtBlock(address);

    // Print this to stdout, NOT the log, so it can be consumed by scripts.
    console.log(withdrawalInitBlock);
  },
});

export const offChain = subcommands({
  name: "off-chain",
  description: "Utilities for off-chain submission",
  cmds: {
    submit,
    deposit,
    "init-withdrawal": initiateWithdrawal,
    withdraw,
    balance,
    "withdraw-init-block": pendingWithdrawalInitializedAtBlock,
    "refund-fee": refundFee,
    "get-state": getState,
    "get-parameters": getParameters,
  },
});
