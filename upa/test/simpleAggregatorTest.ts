import { expect } from "chai";
import { ethers } from "hardhat";
import { deployUpaDummyVerifier } from "./deploy";
import { readFileSync } from "fs";
import { computeProofId, computeCircuitId } from "../src/sdk/utils";
import path = require("path");
import { dummyProofData } from "../src/sdk/upa";

describe("SimpleAggregator", async () => {
  it("deploy", async () => {
    // deploys simple verifier and query unverified proof id with contract
    const dummyVerifier = await deployUpaDummyVerifier();
    const [owner] = await ethers.getSigners();

    const MyContract = await ethers.getContractFactory("SimpleVerifier");
    const contract = await MyContract.deploy(
      dummyVerifier.upa.verifier.target,
      owner
    );

    const circuitId = "0x" + "ab".repeat(32);
    const publicInputs = [1, 2, 3];

    // querying contract with unverified proof id

    const verified = await contract.getFunction(
      "isProofVerified(bytes32,uint256[])"
    )(circuitId, publicInputs);
    console.log("result:", verified);
    expect(verified).to.be.false;
  });

  it("accepts aggregated proofs", async () => {
    // submit aggregated proof to contract and query Pids

    const dummyVerifier = await deployUpaDummyVerifier();
    const [owner] = await ethers.getSigners();

    const MyContract = await ethers.getContractFactory("SimpleVerifier");
    const contract = await MyContract.deploy(
      dummyVerifier.upa.verifier.target,
      owner
    );

    const vkPath = path.join(
      __dirname,
      "../../circuits/src/tests/data/universal_batch_verifier_4_proofs.json"
    );
    const vkJson = JSON.parse(readFileSync(vkPath, "utf-8"));

    const circuitIds = [];
    const publicIps = [];
    const proofIds = [];

    for (let i = 0; i < 4; i++) {
      circuitIds.push(computeCircuitId(vkJson[i].vk));
      publicIps.push(await vkJson[i].inputs);
      proofIds.push(computeProofId(circuitIds[i], publicIps[i]));
    }

    // generating and verifying a dummy proof

    const dummyProof = dummyProofData(proofIds);

    await contract.verifyAggregatedProof(proofIds, dummyProof);

    // querying contract with proof ids

    const proofVerified = [];

    for (let i = 0; i < 4; i++) {
      proofVerified.push(
        await contract.getFunction("isProofVerified(bytes32,uint256[])")(
          circuitIds[i],
          publicIps[i]
        )
      );
      console.log(proofVerified[i]);
      expect(proofVerified[i]).to.be.true;
    }
  });
});
