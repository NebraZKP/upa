import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
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
import { UpaClient } from "../src/sdk/client";
import { UpaInstance } from "../src/sdk/upa";
import { loadAppVK } from "../src/tool/config";
import { AppVkProofInputs } from "../src/sdk/application";
import { keccak256, Signer, verifyTypedData } from "ethers";
import { expect } from "chai";
import { Deposits, Deposits__factory } from "../typechain-types";
import {
  getEIP712Domain,
  getEIP712RequestType,
  getSignedRequestData,
  signOffChainSubmissionRequest,
  UnsignedOffChainSubmissionRequest,
} from "../src/sdk/offChainClient";

type DeployAndSubmitResult = {
  worker: Signer;
  upa: UpaInstance;
  upaClient: UpaClient;
  vkProofAndInputs_1: AppVkProofInputs[];
  vkProofAndInputs_2: AppVkProofInputs[];
  vkProofAndInputs_3: AppVkProofInputs[];
  deposits: Deposits;
};

const TEST_FEE_CONTRACT_NAME = "Offchain NEBRA UPA Aggregator";
const TEST_FEE_CONTRACT_VERSION = "1";

async function deployAndSubmit(): Promise<DeployAndSubmitResult> {
  const vk = loadAppVK("../circuits/src/tests/data/vk.json");
  const deployResult = await deployUpaDummyVerifier();
  const { upa, upaDesc, worker } = deployResult;
  const upaClient = await UpaClient.init(worker, upaDesc);
  const { verifier } = upa;
  await verifier.registerVK(vk);

  /// Prepare 3 submissions (all against vk):
  ///   1: [ pf_a ]
  ///   2: [ pf_b, pf_c, pf_d ]
  ///   3: [ pf_e, pf_f ]
  const vkProofAndInputs_1: AppVkProofInputs[] = [
    { vk, proof: pf_a, inputs: pi_a },
  ];
  const vkProofAndInputs_2: AppVkProofInputs[] = [
    { vk, proof: pf_b, inputs: pi_b },
    { vk, proof: pf_c, inputs: pi_c },
    { vk, proof: pf_d, inputs: pi_d },
  ];
  const vkProofAndInputs_3: AppVkProofInputs[] = [
    { vk, proof: pf_e, inputs: pi_e },
    { vk, proof: pf_f, inputs: pi_f },
  ];

  // Deploy an off-chain fee contract
  const depositsFactory = new Deposits__factory(worker);
  const deposits = await depositsFactory.deploy(
    TEST_FEE_CONTRACT_NAME,
    TEST_FEE_CONTRACT_VERSION
  );
  await deposits.waitForDeployment();

  return {
    worker,
    upa,
    upaClient,
    vkProofAndInputs_1,
    vkProofAndInputs_2,
    vkProofAndInputs_3,
    deposits,
  };
}

describe("Off-chain submission fees", async () => {
  it("Sign a submission request and verify the signature", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const { worker, vkProofAndInputs_1, deposits } = deployResult;

    const depositsAddress = await deposits.getAddress();

    // dummy submissionId
    // TODO: compute from vkProofsAndInputs automatically from the client

    // Prepare an unsigned offChainSubmissionRequest
    const offChainSubmissionRequest: UnsignedOffChainSubmissionRequest = {
      proofs: vkProofAndInputs_1,
      submissionId: keccak256("0x1234"),
      submitterId: await worker.getAddress(),
      expirationBlockNumber: 100000n,
      submitterNonce: 0n,
      fee: 0n,
      totalFee: 0n,
    };

    // Sign the request
    const signedRequest = await signOffChainSubmissionRequest(
      offChainSubmissionRequest,
      worker,
      depositsAddress
    );

    const signedRequestData = getSignedRequestData(signedRequest);
    const domain = await getEIP712Domain(worker, depositsAddress);
    const types = getEIP712RequestType();

    // Verify the signature using ethers
    const ethersRecoveredSigner = verifyTypedData(
      domain,
      types,
      signedRequestData,
      signedRequest.signature!
    );
    expect(ethersRecoveredSigner).eql(await worker.getAddress());

    // Verify the signature in the fee contract
    const contractRecoveredSigner = await deposits.recoverRequestSigner(
      signedRequestData,
      signedRequest.signature
    );
    expect(contractRecoveredSigner).eql(await worker.getAddress());
  });
});
