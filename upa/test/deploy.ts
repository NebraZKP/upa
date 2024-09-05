import { ethers } from "hardhat";
import { Signer } from "ethers";
import {
  UpaInstanceDescriptor,
  upaInstanceFromDescriptor,
  UpaInstance,
} from "../src/sdk/upa";
import * as fs from "fs";
import { deployUpa } from "../src/tool/deploy";
import { strict as assert } from "assert";

export type DeployResult = {
  upa: UpaInstance;
  upaDesc: UpaInstanceDescriptor;
  owner: Signer;
  worker: Signer;
  feeRecipient: Signer;
  user1: Signer;
  user2: Signer;
};

export async function deployUpaWithVerifier(
  verifier?: string,
  maxNumPublicInputs?: number,
  version?: string,
  noOpenZeppelin: boolean = true
): Promise<DeployResult> {
  const [deployer, owner, worker, feeRecipient, user1, user2] =
    await ethers.getSigners();

  maxNumPublicInputs = maxNumPublicInputs || 16;

  verifier = verifier || "test/data/outer_2_2.verifier.bin";
  const contract_hex = "0x" + fs.readFileSync(verifier, "utf-8").trim();

  const upaDesc = (await deployUpa(
    deployer,
    maxNumPublicInputs,
    3 /*maxRetries*/,
    false /*prepare*/,
    undefined /*groth16Verifier*/,
    owner.address,
    worker.address,
    feeRecipient.address /* feeRecipient */,
    undefined /* feeInGas */,
    undefined /* aggregatorCollateral */,
    undefined /* fixedReimbursement */,
    contract_hex,
    undefined /* sid verifier hex */,
    version,
    noOpenZeppelin
  )) as UpaInstanceDescriptor;
  assert(upaDesc);
  const upa = await upaInstanceFromDescriptor(upaDesc, owner);

  return { upa, upaDesc, owner, worker, feeRecipient, user1, user2 };
}

export async function deployUpaDummyVerifier(version?: string) {
  return deployUpaWithVerifier("test/data/test.bin", undefined, version);
}

export async function deployAndUpgradeUpa() {
  return deployUpaWithVerifier(undefined, undefined, undefined, false);
}
