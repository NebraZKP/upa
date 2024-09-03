import * as pkg from "../../package.json";
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
import { parseNumberOrUndefined } from "../sdk/utils";
import * as utils from "../sdk/utils";
import {
  IGroth16Verifier,
  UpaVerifier__factory,
  Groth16Verifier__factory,
} from "../../typechain-types";
import { strict as assert } from "assert";
import { UpaInstanceDescriptor } from "../sdk/upa";
import { spawn } from "child_process";
// eslint-disable-next-line
import { getInitializerData } from "@openzeppelin/hardhat-upgrades/dist/utils/initializer-data";
// eslint-disable-next-line
import ERC1967Proxy from "@openzeppelin/upgrades-core/artifacts/@openzeppelin/contracts-v5/proxy/ERC1967/ERC1967Proxy.sol/ERC1967Proxy.json";

export const UPA_DEPLOY_SALT =
  "NEBRA UPA! Salt-n-Pepa and Heavy D up in the limousine";

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

type DeployPrepareData = {
  implAddress: string;
  deployProxyTxData: string;
  createXDeploySalt: string;
  aggregatorCollateral: bigint;
};

type DeployArgs = {
  endpoint: string;
  keyfile: string;
  password: string;
  verifierBin?: string;
  instance: string;
  upaConfigFile: string;
  useTestConfig: boolean;
  maxRetries: number;
  prepare: boolean;
  owner?: string;
  worker?: string;
  feeRecipient?: string;
  feeInGas?: string;
  aggregatorCollateralInWei?: string;
  groth16VerifierAddress?: string;
  fixedReimbursementInWei?: string;
  sidVerifierBin?: string;
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
    verifierBin,
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
    sidVerifierBin,
    maxRetries,
    prepare,
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
  const contract_hex = verifierBin
    ? "0x" + fs.readFileSync(verifierBin, "utf-8").trim()
    : undefined;
  const sid_contract_hex = sidVerifierBin
    ? "0x" + fs.readFileSync(sidVerifierBin, "utf-8").trim()
    : undefined;
  const upaInstance = await deployUpa(
    wallet,
    maxNumInputs,
    maxRetries,
    prepare,
    groth16Verifier,
    owner,
    worker,
    feeRecipient,
    fixedFeePerProof,
    collateral,
    fixedReimbursement,
    contract_hex,
    sid_contract_hex
  );
  if (!prepare) {
    fs.writeFileSync(instance, JSON.stringify(upaInstance));
  } else {
    const {
      implAddress,
      deployProxyTxData,
      createXDeploySalt,
      aggregatorCollateral,
    } = upaInstance as DeployPrepareData;

    console.log(`UpaVerifier impl has been deployed to ${implAddress}`);

    console.log(`deployProxyTx (pass this into CreateX initcode arg):`);
    console.log(deployProxyTxData);

    console.log("createXDeploySalt");
    console.log(createXDeploySalt);

    console.log(
      `Verifier needs to be sent ${aggregatorCollateral} Wei as` +
        ` aggregator collateral.`
    );
  }
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
    verifierBin: option({
      type: optional(string),
      long: "verifier",
      description: "On-chain verifier binary",
    }),
    sidVerifierBin: option({
      type: optional(string),
      long: "sid-verifier",
      description: "Submission-id on-chain verifier binary",
    }),
    owner: option({
      type: optional(string),
      long: "owner",
      description: "Owner address (defaults to address of keyfile)",
    }),
    worker: option({
      type: optional(string),
      long: "worker",
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
      description: "Groth16 verifier address",
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
    prepare: flag({
      type: boolean,
      long: "prepare",
      description: "Only deploy the implementation contract, not the proxy",
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

export async function deployUpaDependencies(
  signer: ethers.Signer,
  nonce: number,
  groth16Verifier?: IGroth16Verifier,
  outerVerifierHex?: string,
  sidVerifierHex?: string
) {
  assert(
    outerVerifierHex || sidVerifierHex,
    "At least one outer verifier must be provided"
  );
  // Deploy the Aggregated proof Verifier from binary
  const binVerifierAddr = outerVerifierHex
    ? await utils.deployBinaryContract(signer, outerVerifierHex, nonce++)
    : undefined;

  const sidVerifierAddr = sidVerifierHex
    ? await utils.deployBinaryContract(signer, sidVerifierHex, nonce++)
    : undefined;

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

  return {
    binVerifierAddr,
    sidVerifierAddr,
    groth16VerifierAddr,
    newNonce: nonce,
  };
}

/// Deploys the UPA contract, with all dependencies.  `verifierBinFile`
/// points to the hex representation of the verifier byte code (as output by
/// solidity). The address of `signer` is used by default for `owner` and
/// `worker` if they are not given.
export async function deployUpa(
  signer: ethers.Signer,
  maxNumInputs: number,
  maxRetries: number,
  prepare: boolean,
  groth16Verifier?: IGroth16Verifier,
  owner?: string,
  worker?: string,
  feeRecipient?: string,
  feeInGas?: bigint,
  aggregatorCollateral?: bigint,
  fixedReimbursement?: bigint,
  outerVerifierHex?: string,
  sidVerifierHex?: string,
  versionString?: string,
  noOpenZeppelin?: boolean
): Promise<UpaInstanceDescriptor | DeployPrepareData> {
  // Decode version string
  if (!versionString) {
    versionString = pkg.version;
  }
  assert(versionString);
  const versionNum = utils.versionStringToUint(versionString);
  console.log(`Deploying UPA Version ${versionString}`);

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

  const chainId = (await signer.provider?.getNetwork())?.chainId;
  assert(chainId, "failed to get chainId");

  // Sanity check address strings
  owner = ethers.getAddress(owner);
  worker = ethers.getAddress(worker);
  feeRecipient = ethers.getAddress(feeRecipient);

  const { binVerifierAddr, sidVerifierAddr, groth16VerifierAddr, newNonce } =
    await deployUpaDependencies(
      signer,
      nonce,
      groth16Verifier,
      outerVerifierHex,
      sidVerifierHex
    );
  nonce = newNonce;

  // Deploy the UPA implementation contract.
  const UpaVerifierFactory = new UpaVerifier__factory(signer);
  const deployArgs = [
    owner,
    worker,
    feeRecipient,
    binVerifierAddr || ethers.ZeroAddress,
    groth16VerifierAddr,
    fixedReimbursement,
    feeInGas,
    aggregatorCollateral,
    maxNumInputs,
    sidVerifierAddr || ethers.ZeroAddress,
    versionNum,
  ];
  const deployImplNonce = nonce;

  const deployImpl = async () => {
    if (noOpenZeppelin) {
      const verifier = await UpaVerifierFactory.deploy();
      return verifier.getAddress();
    } else {
      return upgrades.deployImplementation(UpaVerifierFactory, deployArgs, {
        kind: "uups",
        unsafeAllowLinkedLibraries: true,
        nonce: deployImplNonce,
      });
    }
  };

  const implAddress: string = await utils.requestWithRetry(
    deployImpl,
    "UPA contract deployment",
    maxRetries,
    undefined /*timeoutMs*/,
    UpaVerifierFactory.interface
  );

  await UpaVerifierFactory.attach(implAddress).waitForDeployment();

  // console.log(`UpaVerifier impl has been deployed to ${implAddress}`);

  // The nonce won't have incremented if the impl already existed. Re-query it.
  nonce = await signer.getNonce();

  const initializerData = getInitializerData(
    UpaVerifierFactory.interface,
    deployArgs
  );

  const ProxyFactory = new ethers.ContractFactory(
    ERC1967Proxy.abi,
    ERC1967Proxy.bytecode
  );

  // Only populate the transaction with the nonce if we will deploy the proxy
  // contract in this function.
  const deployProxyNonce = prepare ? undefined : nonce++;
  const deployProxyTx = await ProxyFactory.getDeployTransaction(
    implAddress,
    initializerData,
    { nonce: deployProxyNonce }
  );

  // Dump information needed to create the proxy contract.
  if (prepare) {
    const createXDeploySalt = computeCreateXDeploySalt(UPA_DEPLOY_SALT);
    return {
      implAddress,
      deployProxyTxData: deployProxyTx.data,
      createXDeploySalt,
      aggregatorCollateral,
    };
  }

  // Deploy the proxy contract
  const deployProxy = async () => {
    const txResp = await signer.sendTransaction(deployProxyTx);
    return txResp.wait();
  };

  const deploymentTx = await utils.requestWithRetry(
    deployProxy,
    "UPA contract deployment",
    maxRetries,
    undefined /*timeoutMs*/,
    UpaVerifierFactory.interface
  );

  assert(deploymentTx);
  const upaVerifierAddr = deploymentTx.contractAddress!;
  const deploymentBlockNumber: number = deploymentTx.blockNumber;
  assert(
    deploymentBlockNumber,
    `failed getting deployBlockNumber:` +
      ` ${deploymentTx} ${deploymentBlockNumber}`
  );

  // Top up the aggregator collateral
  const topUpCollateralTx = await signer.sendTransaction({
    to: upaVerifierAddr,
    value: aggregatorCollateral,
    nonce: nonce++,
  });
  await topUpCollateralTx.wait();

  // Return the instance data
  return {
    verifier: upaVerifierAddr,
    deploymentBlockNumber,
    deploymentTx: deploymentTx.hash,
    chainId: chainId.toString(),
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
    process.stdout.write(`child[stdout]: ${data}`);
  });
  childProcess.stderr.on("data", (data) => {
    process.stderr.write(`child[stderr]: ${data}`);
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

// We set the first 20 bytes to be equal to the multi-sig address. CreateX
// uses this for permissioned deploy protection. (See the `_guard`
// function in ComputeCreateXDeployAddress.sol. The 21st byte is `00` to turn
// off cross-chain redeploy protection. The last 11 bytes are free for us to
// set.
export function computeCreateXDeploySalt(salt: string) {
  const multiSig = "0xb463603469Bf31f189E3F6625baf8378880Df14e";
  const saltSuffix = ethers.keccak256(ethers.toUtf8Bytes(salt)).slice(2, 24);
  const createXDeploySalt = multiSig + "00" + saltSuffix;
  return createXDeploySalt;
}
