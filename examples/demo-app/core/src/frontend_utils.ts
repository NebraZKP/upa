import { ethers } from "ethers";
import { DemoApp, DemoApp__factory } from "../typechain-types";

export function demoAppFromDescriptor(
  address: string,
  signer: ethers.ContractRunner
): DemoApp {
  return DemoApp__factory.connect(address, signer);
}
