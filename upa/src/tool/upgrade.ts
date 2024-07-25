import { ContractFactory, ethers } from "ethers";
import { UpaInstanceDescriptor } from "../sdk/upa";
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
import { options } from ".";
import { command, number, option } from "cmd-ts";
import { loadInstance, loadWallet } from "./config";
import { getPassword, keyfile, password } from "./options";
import { setupEnvAndRepeatCommand } from "./deploy";
// eslint-disable-next-line
import { UpaVerifier__factory } from "../../typechain-types/factories/contracts/UpaVerifier__factory";
import { requestWithRetry } from "../sdk/utils";

type UpgradeArgs = {
  endpoint: string;
  keyfile: string;
  password: string;
  instance: string;
  maxRetries: number;
};

const upgradeHandler = async function (args: UpgradeArgs): Promise<void> {
  // When we import OpenZeppelin's `upgrades` library, we must also set the
  // env var HARDHAT_CONFIG.
  // (See https://github.com/NomicFoundation/hardhat/issues/2669)
  // So when we run this function, if HARDHAT_CONFIG is not yet set then we
  // set up a config file and point to it with HARDHAT_CONFIG. Then we run
  // this function again as a child process. On the second run, `upgrades`
  // will be imported and the deployment logic will run.
  if (upgrades === undefined) {
    setupEnvAndRepeatCommand();
    return;
  }

  // Upgrade logic below
  const { endpoint, keyfile, password, instance, maxRetries } = args;

  const provider = new ethers.JsonRpcProvider(endpoint);
  const wallet = await loadWallet(keyfile, getPassword(password), provider);
  const upaDesc = loadInstance(instance);

  const newUpaVerifierFactory = new UpaVerifier__factory(wallet);
  await upgradeVerifierContract(upaDesc, newUpaVerifierFactory, maxRetries);
};

export const upgrade = command({
  name: "upgrade",
  args: {
    endpoint: options.endpoint(),
    keyfile: keyfile(),
    password: password(),
    instance: options.instance(),
    maxRetries: option({
      type: number,
      long: "retries",
      defaultValue: () => 1,
      description: "The number of times to retry verifier upgrade",
    }),
  },
  description: "Upgrade the UPA verifier contract. Keyfile must be the owner",
  handler: upgradeHandler,
});

export async function upgradeVerifierContract<T extends ContractFactory>(
  oldUpaVerifierDescriptor: UpaInstanceDescriptor,
  newUpaVerifierFactory: T,
  maxRetries: number
): Promise<void> {
  const upaVerifierV1Address = oldUpaVerifierDescriptor.verifier;

  // The signer doing this upgrade comes from `UpaVerifierV2Factory`.
  const upgradeFn = async () =>
    upgrades.upgradeProxy(upaVerifierV1Address, newUpaVerifierFactory, {
      redeployImplementation: "always",
      unsafeAllowLinkedLibraries: true,
    });

  const verifier: ethers.Contract = await requestWithRetry(
    upgradeFn,
    "UPA contract upgrade",
    maxRetries,
    undefined /*timeoutMs*/,
    newUpaVerifierFactory.interface
  );

  const deployedVerifier = await verifier.waitForDeployment();
  const address = await deployedVerifier.getAddress();
  console.log(`Upgraded UpaVerifier impl has been deployed to ${address}`);

  return;
}
