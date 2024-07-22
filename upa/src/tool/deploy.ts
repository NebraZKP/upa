import { loadUpaConfig, loadWallet } from "./config";
import {
  instance,
  keyfile,
  endpoint,
  password,
  getPassword,
  upaConfigFile,
} from "./options";
import {
  command,
  string,
  option,
  optional,
  boolean,
  flag,
  number,
} from "cmd-ts";
import { IGroth16Verifier__factory } from "../../typechain-types";
import * as options from "./options";
import * as ethers from "ethers";
import * as fs from "fs";
import { parseNumberOrUndefined, sleep } from "../sdk/utils";
import * as utils from "../sdk/utils";
import {
  IGroth16Verifier,
  UpaVerifier__factory,
  Groth16Verifier__factory,
} from "../../typechain-types";
import { strict as assert } from "assert";
import { UpaInstanceDescriptor } from "../sdk/upa";
import { spawn } from "child_process";

// Only import if the env var HARDHAT_CONFIG is set.
// eslint-disable-next-line
let importUpgrades: () => any;
if (process.env.HARDHAT_CONFIG) {
  importUpgrades = function importUpgrade() {
    return require("hardhat").upgrades;
  };
} else {
  importUpgrades = function importUpgrade() {
    return undefined;
  };
}
const upgrades = importUpgrades();

type DeployArgs = {
  endpoint: string;
  keyfile: string;
  password: string;
  verifier_bin: string;
  instance: string;
  upaConfigFile: string;
  useTestConfig: boolean;
  maxRetries: number;
  owner?: string;
  worker?: string;
  feeRecipient?: string;
  feeInGas?: string;
  aggregatorCollateralInWei?: string;
  groth16VerifierAddress?: string;
  fixedReimbursementInWei?: string;
};

const deployHandler = async function (args: DeployArgs): Promise<void> {
  // We only want to import from `upgrades` when we are deploying. This is
  // because with this import, we must also set the env var HARDHAT_CONFIG.
  // (See https://github.com/NomicFoundation/hardhat/issues/2669)
  // So when we run this function, if HARDHAT_CONFIG is not yet set then we
  // set up a config file and point to it with HARDHAT_CONFIG. Then we run
  // this function again as a child process. On the second run, `upgrades`
  // will be imported and the deployment logic will run.
  if (upgrades === undefined) {
    setupEnvAndRepeatCommand();
    return;
  }

  // Deployment logic below
  const {
    endpoint,
    keyfile,
    password,
    verifier_bin,
    instance,
    upaConfigFile,
    useTestConfig,
    owner,
    worker,
    feeRecipient,
    feeInGas,
    aggregatorCollateralInWei,
    groth16VerifierAddress,
    fixedReimbursementInWei,
    maxRetries,
  } = args;

  const provider = new ethers.JsonRpcProvider(endpoint);
  const wallet = await loadWallet(keyfile, getPassword(password), provider);
  const fixedFeePerProof = parseNumberOrUndefined(
    feeInGas,
    "Error while parsing the fee"
  );
  const collateral = parseNumberOrUndefined(
    aggregatorCollateralInWei,
    "Error while parsing the aggregator collateral"
  );
  const fixedReimbursement = parseNumberOrUndefined(
    fixedReimbursementInWei,
    "Error while parsing the fixed reimbursement"
  );

  const groth16Verifier = groth16VerifierAddress
    ? IGroth16Verifier__factory.connect(groth16VerifierAddress)
    : undefined;

  const maxNumInputs = useTestConfig
    ? TEST_MAX_NUM_INPUTS
    : loadUpaConfig(upaConfigFile).max_num_app_public_inputs;

  // Load binary contract
  const contract_hex = "0x" + fs.readFileSync(verifier_bin, "utf-8").trim();
  const upaInstance = await deployUpa(
    wallet,
    contract_hex,
    maxNumInputs,
    maxRetries,
    groth16Verifier,
    owner,
    worker,
    feeRecipient,
    fixedFeePerProof,
    collateral,
    fixedReimbursement
  );
  fs.writeFileSync(instance, JSON.stringify(upaInstance));
};

export const deploy = command({
  name: "deploy",
  args: {
    endpoint: endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance("Output file for instance information"),
    upaConfigFile: upaConfigFile(),
    useTestConfig: flag({
      type: boolean,
      long: "use-test-config",
      description: "Use a default UPA config for testing",
    }),
    verifier_bin: option({
      type: string,
      long: "verifier",
      short: "v",
      description: "On-chain verifier binary",
    }),
    owner: option({
      type: optional(string),
      long: "owner",
      short: "o",
      description: "Owner address (defaults to address of keyfile)",
    }),
    worker: option({
      type: optional(string),
      long: "worker",
      short: "w",
      description: "Worker address (defaults to address of owner)",
    }),
    feeRecipient: option({
      type: optional(string),
      long: "fee-recipient",
      description: "Fee recipient address (defaults to address of worker)",
    }),
    groth16VerifierAddress: option({
      type: optional(string),
      long: "groth16",
      short: "g16",
      description: "Groth16 verifier address",
    }),
    proofReceiverAddress: option({
      type: optional(string),
      long: "proof-receiver",
      short: "receiver",
      description: "Proof receiver contract address",
    }),
    feeModelAddress: option({
      type: optional(string),
      long: "fee-model",
      description: "Fee model contract address",
    }),
    feeInGas: options.feeInGas(),
    aggregatorCollateralInWei: options.aggregatorCollateralInWei(),
    fixedReimbursementInWei: option({
      type: optional(string),
      long: "fixed-reimbursement",
      description: "Fixed reimbursement for censorship claims, in Wei",
    }),
    maxRetries: option({
      type: number,
      long: "retries",
      defaultValue: () => 1,
      description: "The number of times to retry verifier deployment",
    }),
  },
  description: "Deploy the UPA contracts for a given configuration",
  handler: deployHandler,
});

/// Max number of public inputs for the test config.
const TEST_MAX_NUM_INPUTS = 16;

/// Default fee in gas.
const DEFAULT_FEE_IN_GAS = 30000n;

/// Default collateral for aggregators to cover censorship claims
const DEFAULT_AGGREGATOR_COLLATERAL = 10000000000000000n; // 0.01 eth

/// Default fixed reimbursement for censorship claims
const DEFAULT_FIXED_REIMBURSEMENT = 0n;

/// Block time in seconds
const BLOCK_TIME = 12;

/// Default number of blocks to wait for the signer nonce
/// to be updated
const DEFAULT_NUMBER_OF_BLOCKS_SIGNER_NONCE = 6;

/// Deploys the UPA contract, with all dependencies.  `verifier_bin_file`
/// points to the hex representation of the verifier byte code (as output by
/// solidity). The address of `signer` is used by default for `owner` and
/// `worker` if they are not given.
export async function deployUpa(
  signer: ethers.Signer,
  outer_verifier_hex: string,
  maxNumInputs: number,
  maxRetries: number,
  groth16Verifier?: IGroth16Verifier,
  owner?: string,
  worker?: string,
  feeRecipient?: string,
  feeInGas?: bigint,
  aggregatorCollateral?: bigint,
  fixedReimbursement?: bigint
): Promise<UpaInstanceDescriptor> {
  const addrP = signer.getAddress();
  const nonceP = signer.getNonce();
  feeInGas = feeInGas || DEFAULT_FEE_IN_GAS;
  aggregatorCollateral = aggregatorCollateral || DEFAULT_AGGREGATOR_COLLATERAL;
  fixedReimbursement = fixedReimbursement || DEFAULT_FIXED_REIMBURSEMENT;
  const addr = await addrP;
  owner = owner || addr;
  worker = worker || owner;
  feeRecipient = feeRecipient || worker;
  let nonce = await nonceP;

  // Sanity check address strings
  owner = ethers.getAddress(owner);
  worker = ethers.getAddress(worker);
  feeRecipient = ethers.getAddress(feeRecipient);

  // Deploy the Aggregated proof Verifier from binary
  const binVerifierAddr = await utils.deployBinaryContract(
    signer,
    outer_verifier_hex,
    nonce++
  );

  // Determine groth16Verifier
  const groth16VerifierAddr = await (async () => {
    if (groth16Verifier) {
      return await groth16Verifier.getAddress();
    }

    const groth16Nonce = nonce++;
    const groth16VerifierFactory = new Groth16Verifier__factory(signer);
    const universalGroth16Verifier = await groth16VerifierFactory.deploy({
      nonce: groth16Nonce,
    });
    await universalGroth16Verifier.waitForDeployment();
    return universalGroth16Verifier.getAddress();
  })();

  // Wait for the chain to catch up to the signer's nonce
  // before attempting to deploy UPA
  let counter = 0;
  while ((await signer.getNonce()) !== nonce) {
    await sleep(BLOCK_TIME * 1000);
    counter++;
    if (counter >= DEFAULT_NUMBER_OF_BLOCKS_SIGNER_NONCE) {
      throw "Unable to update nonce";
    }
  }

  // Deploy UPA
  const UpaVerifierFactory = new UpaVerifier__factory(signer);

  const deployFn = async () =>
    upgrades.deployProxy(
      UpaVerifierFactory,
      [
        owner,
        worker,
        feeRecipient,
        binVerifierAddr,
        groth16VerifierAddr,
        fixedReimbursement,
        feeInGas,
        aggregatorCollateral,
        maxNumInputs,
      ],
      {
        kind: "uups",
        unsafeAllowLinkedLibraries: true,
      }
    );

  const upaVerifier: ethers.Contract = await utils.requestWithRetry(
    deployFn,
    "UPA contract upgrade",
    maxRetries
  );

  await upaVerifier.waitForDeployment();
  const upaVerifierAddr = await upaVerifier.getAddress();
  const deployTxResponse = upaVerifier.deploymentTransaction()!;
  const deploymentTx = (await deployTxResponse.wait())!;
  const deploymentBlockNumber: number = deploymentTx.blockNumber;
  assert(
    deploymentBlockNumber,
    `failed getting deployBlockNumber: ${deploymentTx} ${deploymentBlockNumber}`
  );

  // Top up the aggregator collateral
  const topUpCollateralTx = await signer.sendTransaction({
    to: upaVerifierAddr,
    value: aggregatorCollateral,
  });
  await topUpCollateralTx.wait();

  // Return the instance data
  return {
    verifier: upaVerifierAddr,
    deploymentBlockNumber,
    deploymentTx: deploymentTx.hash,
  };
}

// Only used with OpenZeppelin's upgradeable contracts library.
// Work-around code that generates the hardhat config file and sets the env var
// HARDHAT_CONFIG as needed to deploy or upgrade. Then runs the `upa` command
// again as a child process.
export async function setupEnvAndRepeatCommand() {
  const upaDir = `${__dirname}/../../..`;

  // Config file that is generated when no HARDHAT_CONFIG is specified.
  const GENERATED_HARDHAT_CONFIG = `${upaDir}/upa_deployment.hardhat.config.js`;

  // Write upa_deployment.hardhat.config.js using the RPC_ENDPOINT env var.
  // We make sure to set this RPC_ENDPOINT as the default network, as
  // OpenZeppelin checks that the contract was deployed using this default.
  const rpcEndpoint = process.env.RPC_ENDPOINT;
  if (!rpcEndpoint) {
    throw new Error("RPC_ENDPOINT environment variable is not set");
  }

  // Needed for locating the validations.json file generated by OpenZeppelin
  const cacheDir = `${upaDir}/cache`;

  const configContent = `
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
require("@openzeppelin/hardhat-upgrades");
const config = {
  defaultNetwork: "localhost",
  networks: {
    hardhat: {},
    localhost: {
      url: "${rpcEndpoint}",
    },
  },
  paths: {
    cache: "${cacheDir}",
  },
};
exports.default = config;
`;
  fs.writeFileSync(GENERATED_HARDHAT_CONFIG, configContent);

  process.env.HARDHAT_CONFIG = GENERATED_HARDHAT_CONFIG;

  // Now spawn the child process, passing in the same arguments.
  const childProcess = spawn("upa", process.argv.slice(2));

  childProcess.stdout.on("data", (data) => {
    console.log(`stdout: ${data}`);
  });

  childProcess.stderr.on("data", (data) => {
    console.error(`stderr: ${data}`);
  });

  await new Promise<void>((resolve, reject) => {
    childProcess.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`Child process exited with code ${code}`));
      } else {
        resolve();
      }
    });
    childProcess.on("error", (err) => {
      reject(err);
    });
  });
}
