import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import {
  JSONstringify,
  computeCircuitId,
  computeProofId,
  readBytes32,
} from "../src/sdk/utils";
import { loadAppVK } from "../src/tool/config";
import { readFileSync } from "fs";
import { Signer, ContractTransactionResponse } from "ethers";
import {
  CircuitIdProofAndInputs,
  Groth16VerifyingKey,
} from "../src/sdk/application";
import { CompressedGroth16Proof } from "../src/sdk/groth16";
import {
  dummyProofData,
  submitProof,
  isProofVerifiedSingle,
  isProofVerifiedMulti,
  submitProofs,
  UpaInstanceDescriptor,
  upaInstanceFromDescriptor,
  UpaInstance,
  isSubmissionVerified,
  isSubmissionVerifiedById,
  isSingleCircuitSubmissionVerified,
  isProofVerifiedByIdSingle,
  isProofVerifiedbyIdMulti,
  updateFeeOptions,
} from "../src/sdk/upa";
import {
  computeMerkleRoot,
  evmInnerHashFn,
  evmLeafHashFn,
} from "../src/sdk/merkleUtils";
import {
  SubmissionDescriptor,
  Submission,
  ZERO_BYTES32,
} from "../src/sdk/submission";
import {
  packDupSubmissionIdxs,
  packOffChainSubmissionMarkers,
} from "../src/sdk/aggregatedProofParams";
import { UpaFixedGasFee__factory } from "../typechain-types";
import { SubmissionProof } from "../src/sdk/submission";
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
  version?: string
): Promise<DeployResult> {
  const [deployer, owner, worker, feeRecipient, user1, user2] =
    await ethers.getSigners();

  maxNumPublicInputs = maxNumPublicInputs || 16;

  verifier = verifier || "test/data/outer_2_2.verifier.bin";
  const contract_hex = "0x" + fs.readFileSync(verifier, "utf-8").trim();

  const upaDesc = await deployUpa(
    deployer,
    contract_hex,
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
    version
  );
  assert(upaDesc);
  const upa = await upaInstanceFromDescriptor(upaDesc, owner);

  return { upa, upaDesc, owner, worker, feeRecipient, user1, user2 };
}

export async function deployUpaDummyVerifier(version?: string) {
  return deployUpaWithVerifier("test/data/test.bin", undefined, version);
}

export async function deployAndUpgradeUpa() {
  const { upa, upaDesc, owner, worker, user1, user2 } =
    await deployUpaWithVerifier();

  return {
    upa,
    upaDesc,
    owner,
    worker,
    user1,
    user2,
  };
}
