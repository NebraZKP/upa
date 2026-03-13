import { loadWallet } from "./config";
import {
  instance,
  keyfile,
  chainEndpoint,
  password,
  getPassword,
} from "./options";
import { command, string, option, optional, number } from "cmd-ts";
import * as ethers from "ethers";
import * as fs from "fs";
import * as utils from "../sdk/utils";
import { SimpleVerifier__factory } from "../../typechain-types";
import { strict as assert } from "assert";
import { UpaInstanceDescriptor } from "../sdk/upa";

type DeployPrepareData = {
  implAddress: string;
  deployProxyTxData: string;
  createXDeploySalt: string;
  aggregatorCollateral: bigint;
};

type DeployArgs = {
  chainEndpoint: string;
  keyfile: string;
  password: string;
  verifierBin?: string;
  instance: string;
  maxRetries: number;
  owner?: string;
};

const deployHandler = async function (args: DeployArgs): Promise<void> {
  const {
    chainEndpoint,
    keyfile,
    password,
    verifierBin,
    instance,
    maxRetries,
    owner,
  } = args;

  const provider = new ethers.JsonRpcProvider(chainEndpoint);
  const wallet = await loadWallet(keyfile, getPassword(password), provider);

  // Load binary contract
  const contract_hex = verifierBin
    ? "0x" + fs.readFileSync(verifierBin, "utf-8").trim()
    : undefined;
  const upaInstance = await deploySimpleContract(
    wallet,
    maxRetries,
    owner,
    contract_hex
  );
  fs.writeFileSync(instance, JSON.stringify(upaInstance));
};

export const deploySimple = command({
  name: "deploy-simple",
  args: {
    chainEndpoint: chainEndpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: instance("Output file for instance information"),
    verifierBin: option({
      type: optional(string),
      long: "verifier",
      description: "On-chain verifier binary",
    }),
    maxRetries: option({
      type: number,
      long: "retries",
      defaultValue: () => 1,
      description: "The number of times to retry verifier deployment",
    }),
    owner: option({
      type: optional(string),
      long: "owner",
      description: "Owner address (defaults to address of keyfile)",
    }),
  },
  description: "Deploy the UPA contracts for a given configuration",
  handler: deployHandler,
});

/// Deploys the UPA contract, with all dependencies.  `verifierBinFile`
/// points to the hex representation of the verifier byte code (as output by
/// solidity). The address of `signer` is used by default for `owner` and
/// `worker` if they are not given.
export async function deploySimpleContract(
  signer: ethers.Signer,
  maxRetries: number,
  owner?: string,
  outerVerifierHex?: string
): Promise<UpaInstanceDescriptor | DeployPrepareData> {
  // Decode version string

  const addrP = signer.getAddress();
  const nonceP = signer.getNonce();
  const addr = await addrP;
  owner = owner || addr;
  let nonce = await nonceP;

  const chainId = (await signer.provider?.getNetwork())?.chainId;
  assert(chainId, "failed to get chainId");

  // Sanity check address strings
  owner = ethers.getAddress(owner);
  assert(owner, "owner address");

  const binVerifierAddr = outerVerifierHex
    ? await utils.deployBinaryContract(signer, outerVerifierHex, nonce++)
    : undefined;
  assert(binVerifierAddr);

  // TODO: support passing in the address of an existing verifier

  // Deploy the UPA implementation contract.
  const SimpleVerifierFactory = new SimpleVerifier__factory(signer);

  const deployImpl = async () => {
    // TODO: expand contract contructor to accept an owner as well
    const verifier = await SimpleVerifierFactory.deploy(binVerifierAddr, owner);
    await verifier.waitForDeployment();
    const tx = await verifier.deploymentTransaction()?.wait();
    assert(tx, "tx");
    assert(tx.blockNumber, "block number");
    return { address: await verifier.getAddress(), tx };
  };

  const { address, tx } = await utils.requestWithRetry(
    deployImpl,
    "UPA contract deployment",
    maxRetries,
    undefined /*timeoutMs*/,
    SimpleVerifierFactory.interface
  );

  const deploymentBlockNumber = tx.blockNumber;
  assert(typeof deploymentBlockNumber === "number");
  const deploymentTx = tx.hash;

  // Wait for deployment to complete.
  await SimpleVerifierFactory.attach(address).waitForDeployment();

  // Return the instance data
  return {
    verifier: address,
    deploymentBlockNumber,
    deploymentTx,
    chainId: chainId.toString(),
  };
}
