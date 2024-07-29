import * as pkg from "../../package.json";
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
import { boolean, command, flag, number, option } from "cmd-ts";
import { loadInstance, loadWallet } from "./config";
import { getPassword, keyfile, password } from "./options";
import { setupEnvAndRepeatCommand } from "./deploy";
// eslint-disable-next-line
import { UpaVerifier__factory } from "../../typechain-types/factories/contracts/UpaVerifier__factory";
import { requestWithRetry } from "../sdk/utils";
import assert from "assert";
import { utils } from "../sdk";

type UpgradeArgs = {
  endpoint: string;
  keyfile: string;
  password: string;
  instance: string;
  maxRetries: number;
  prepare: boolean;
  versionString?: string;
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
  const { endpoint, keyfile, password, instance, maxRetries, prepare } = args;

  const provider = new ethers.JsonRpcProvider(endpoint);
  const wallet = await loadWallet(keyfile, getPassword(password), provider);
  const upaDesc = loadInstance(instance);

  const newUpaVerifierFactory = new UpaVerifier__factory(wallet);
  await upgradeVerifierContract(
    upaDesc,
    newUpaVerifierFactory,
    maxRetries,
    prepare,
    args.versionString
  );
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
    prepare: flag({
      type: boolean,
      long: "prepare",
      description: "Only deploy the implementation contract",
    }),
  },
  description: "Upgrade the UPA verifier contract. Keyfile must be the owner",
  handler: upgradeHandler,
});

// Upgrade the verifier contract and then execute `call` on it.
export async function upgradeVerifierContract<T extends ContractFactory>(
  oldUpaVerifierDescriptor: UpaInstanceDescriptor,
  newUpaVerifierFactory: T,
  maxRetries: number,
  prepare: boolean,
  versionString?: string
): Promise<void> {
  // Decode version string
  if (!versionString) {
    versionString = pkg.version;
  }
  assert(versionString);
  const versionNum = utils.versionStringToUint(versionString);

  // Write call that sets the version of the contract.
  const setVersionFragment =
    newUpaVerifierFactory.interface.getFunction("setVersion")!;
  // Encoding for OpenZeppelin `upgradeProxy` method
  const call = { fn: setVersionFragment, args: [versionNum] };
  // Encoding for proxy contract's `upgradeToAndCall` method
  const encodedCall = newUpaVerifierFactory.interface.encodeFunctionData(
    call.fn,
    call.args
  );

  const proxyAddress = oldUpaVerifierDescriptor.verifier;
  // The signer doing this upgrade comes from `UpaVerifierV2Factory`.
  const upgradeFn = async () => {
    if (prepare) {
      const newImplAddress: string = await upgrades.prepareUpgrade(
        proxyAddress,
        newUpaVerifierFactory,
        {
          redeployImplementation: "always",
          unsafeAllowLinkedLibraries: true,
        }
      );

      console.log(
        `Upgraded UpaVerifier impl has been deployed to ${newImplAddress}`
      );
      const verifier = UpaVerifier__factory.connect(proxyAddress);

      const txReq = await verifier.upgradeToAndCall.populateTransaction(
        newImplAddress,
        encodedCall,
        {} /*overrides*/
      );
      console.log("Tx for updating the proxy contract:");
      console.log(utils.JSONstringify(txReq.data));
    } else {
      const verifier: ethers.Contract = await upgrades.upgradeProxy(
        proxyAddress,
        newUpaVerifierFactory,
        {
          redeployImplementation: "always",
          unsafeAllowLinkedLibraries: true,
          call,
        }
      );
      await verifier.waitForDeployment();
      const newImplAddress = await verifier.getAddress();
      console.log(`UpaVerifier at ${newImplAddress} has been upgraded`);
    }
  };

  await requestWithRetry(
    upgradeFn,
    "UPA contract upgrade",
    maxRetries,
    undefined /*timeoutMs*/,
    newUpaVerifierFactory.interface
  );

  return;
}
