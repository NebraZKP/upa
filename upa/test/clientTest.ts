import {
  loadFixture,
  mine,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ethers } from "hardhat";
import {
  deployUpaDummyVerifier,
  pf_a,
  pf_b,
  pf_c,
  pf_d,
  pf_e,
  pf_f,
  pi_a,
  pi_b,
  pi_c,
  pi_d,
  pi_e,
  pi_f,
} from "./upaTests";
import { UpaClient, SubmissionHandle } from "../src/sdk/client";
import { UpaInstance, dummyProofData, updateFeeOptions, upaInstanceFromDescriptor } from "../src/sdk/upa";
import { loadAppVK, upaFromInstanceFile } from "../src/tool/config";
import { CircuitIdProofAndInputs } from "../src/sdk/application";
import { Signer } from "ethers";
import { expect } from "chai";
import { PayableOverrides } from "../typechain-types/common";
import { packOffChainSubmissionMarkers } from "../src/sdk/submission";
import { computeCircuitId } from "../src/sdk/utils";
type DeployAndRegisterResult = {
  worker: Signer;
  upa: UpaInstance;
  upaClient: UpaClient;
  cid_a: string;
};

type DeployAndSubmitResult = {
  worker: Signer;
  upa: UpaInstance;
  upaClient: UpaClient;
  submissionHandle_1: SubmissionHandle;
  submissionHandle_2: SubmissionHandle;
  submissionHandle_3: SubmissionHandle;
  cid_a: string;
};

async function deployAndRegister(): Promise<DeployAndRegisterResult> {
  const vk = loadAppVK("../circuits/src/tests/data/vk.json");
  const deployResult = await deployUpaDummyVerifier();
  const { upa, upaDesc, worker } = deployResult;
  const upaClient = await UpaClient.init(worker, upaDesc);
  const { verifier } = upa;
  await verifier.registerVK(vk);
  const cid_a = computeCircuitId(vk);

  return {
    worker,
    upa,
    upaClient,
    cid_a,
  };
}

async function deployAndSubmit(): Promise<DeployAndSubmitResult> {
  const { worker, upa, upaClient, cid_a } = await deployAndRegister();

  /// Submit 3 submissions (all against cid_a):
  ///   1: [ pf_a ]
  ///   2: [ pf_b, pf_c, pf_d ]  (Merkle depth 2, not full)
  ///   3: [ pf_e, pf_f ]        (Merkle depth 2, full)
  const cidProofAndInputs_1: CircuitIdProofAndInputs[] = [
    { circuitId: cid_a, proof: pf_a, inputs: pi_a },
  ];
  const cidProofAndInputs_2: CircuitIdProofAndInputs[] = [
    { circuitId: cid_a, proof: pf_b, inputs: pi_b },
    { circuitId: cid_a, proof: pf_c, inputs: pi_c },
    { circuitId: cid_a, proof: pf_d, inputs: pi_d },
  ];
  const cidProofAndInputs_3: CircuitIdProofAndInputs[] = [
    { circuitId: cid_a, proof: pf_e, inputs: pi_e },
    { circuitId: cid_a, proof: pf_f, inputs: pi_f },
  ];

  const submissionHandle_1 = await upaClient.submitProofs(cidProofAndInputs_1);

  const submissionHandle_2 = await upaClient.submitProofs(cidProofAndInputs_2);

  // Submit 3
  const submissionHandle_3 = await upaClient.submitProofs(cidProofAndInputs_3);

  return {
    worker,
    upa,
    upaClient,
    submissionHandle_1,
    submissionHandle_2,
    submissionHandle_3,
    cid_a,
  };
}

// UpaClient tests
describe("UPA Client", async () => {
  it.only("Fails to initialize if contract version is out of date", async() => {
    let thrown = false;
    try {
      await deployUpaDummyVerifier("0.3.0");
    } catch (e) {
      thrown = true;
    }
    expect(thrown).to.be.true;
  });

  it("Throws error if submission was skipped", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const {
      worker,
      upa,
      upaClient,
      submissionHandle_1,
      submissionHandle_2,
      submissionHandle_3,
    } = deployResult;

    //   agg1: [ pf_a ]
    //   agg3: [ pf_e, pf_f ]
    //   - skipped all proofs in submission 2
    const agg1 = submissionHandle_1.submission.proofIds;
    const calldata1 = dummyProofData(agg1);
    const agg3 = submissionHandle_3.submission.proofIds;
    const calldata3 = dummyProofData(agg3);
    // submission proof for pf_e, pf_f
    const pf3 = submissionHandle_3.submission.computeSubmissionProof(0, 2)!;

    const { verifier } = upa;
    await verifier
      .connect(worker)
      .verifyAggregatedProof(
        calldata1,
        agg1,
        agg1.length,
        [],
        packOffChainSubmissionMarkers([])
      );

    await verifier
      .connect(worker)
      .verifyAggregatedProof(
        calldata3,
        agg3,
        agg3.length,
        [pf3.solidity()],
        packOffChainSubmissionMarkers([])
      );

    await upaClient.waitForSubmissionVerified(submissionHandle_1);
    await upaClient.waitForSubmissionVerified(submissionHandle_3);

    // Mine blocks while we wait for the second submission to throw
    const intervalId = setInterval(async () => {
      await mine();
    }, 1000);

    try {
      // Should throw an error because this submission was skipped.
      await upaClient.waitForSubmissionVerified(submissionHandle_2);
      throw new Error(
        "Expected waitForSubmissionVerified to throw an error, but it didn't."
      );
    } catch (error) {
      // eslint-disable-next-line
      expect((error as any).message).to.contain("Submission was rejected");
    } finally {
      clearInterval(intervalId);
    }
  });

  it("computes fees correctly", async () => {
    const { upaClient, cid_a } = await loadFixture(deployAndRegister);
    const verifier = upaClient.upaInstance.verifier;
    const pf_a_c = pf_a.compress().solidity();

    async function testOptions(options: PayableOverrides) {
      expect(BigInt(options.value!)).above(0n);
      await verifier.submit.staticCall([cid_a], [pf_a_c], [pi_a], options);
    }

    await testOptions(await updateFeeOptions(verifier, 1, {}));
    await testOptions(await updateFeeOptions(verifier, 1, { gasPrice: 123 }));
    await testOptions(
      await updateFeeOptions(verifier, 1, { maxPriorityFeePerGas: 123 })
    );
    await testOptions(
      await updateFeeOptions(verifier, 1, {
        maxFeePerGas: 123,
      })
    );
    await testOptions(
      await updateFeeOptions(verifier, 1, {
        maxFeePerGas: 321,
        maxPriorityFeePerGas: 123,
      })
    );
  });
});
