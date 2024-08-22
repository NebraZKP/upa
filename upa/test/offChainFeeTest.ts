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
import {
  UpaClient,
  UnsignedOffChainSubmissionRequest,
  signOffChainSubmissionRequest,
  getEIP712Domain,
  getEIP712RequestType,
  getSignedRequestData,
} from "../src/sdk/client";
import { UpaInstance } from "../src/sdk/upa";
import { loadAppVK } from "../src/tool/config";
import { CircuitIdProofAndInputs } from "../src/sdk/application";
import { Signer, verifyTypedData } from "ethers";
import { expect } from "chai";
import { computeCircuitId } from "../src/sdk/utils";
import { UpaOffChainFee, UpaOffChainFee__factory } from "../typechain-types";
import { SubmissionDescriptor } from "../src/sdk";
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
  submission_1: SubmissionDescriptor;
  submission_2: SubmissionDescriptor;
  submission_3: SubmissionDescriptor;
  cid_a: string;
  upaOffChainFee: UpaOffChainFee;
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

const TEST_FEE_CONTRACT_NAME = "Offchain NEBRA UPA Aggregator";
const TEST_FEE_CONTRACT_VERSION = "1";

async function deployAndSubmit(): Promise<DeployAndSubmitResult> {
  const { worker, upa, upaClient, cid_a } = await deployAndRegister();

  /// Prepare 3 submissions (all against cid_a):
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

  const submission_1 =
    SubmissionDescriptor.fromCircuitIdsProofsAndInputs(cidProofAndInputs_1);
  const submission_2 =
    SubmissionDescriptor.fromCircuitIdsProofsAndInputs(cidProofAndInputs_2);
  const submission_3 =
    SubmissionDescriptor.fromCircuitIdsProofsAndInputs(cidProofAndInputs_3);

  // Deploy an off-chain fee contract
  const UpaOffChainFeeFactory = new UpaOffChainFee__factory(worker);
  const upaOffChainFee = await UpaOffChainFeeFactory.deploy(
    TEST_FEE_CONTRACT_NAME,
    TEST_FEE_CONTRACT_VERSION
  );
  await upaOffChainFee.waitForDeployment();

  return {
    worker,
    upa,
    upaClient,
    submission_1,
    submission_2,
    submission_3,
    cid_a,
    upaOffChainFee,
  };
}

describe.only("Off-chain submission fees", async () => {
  it("Sign a submission request and verify the signature", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const { worker, submission_1, upaOffChainFee } = deployResult;

    const upaOffChainFeeAddress = await upaOffChainFee.getAddress();

    // Prepare an unsigned offChainSubmissionRequest
    const offChainSubmissionRequest: UnsignedOffChainSubmissionRequest = {
      circuitIdProofAndInputs: submission_1.getCircuitIdsProofsAndInputs(),
      submissionId: submission_1.getSubmissionId(),
      expirationBlockNumber: 100000n,
      submitterNonce: 0n,
      fee: 0n,
      totalFee: 0n,
    };

    // Sign the request
    const signedRequest = await signOffChainSubmissionRequest(
      offChainSubmissionRequest,
      worker,
      upaOffChainFeeAddress
    );

    const signedRequestData = getSignedRequestData(signedRequest);
    const domain = await getEIP712Domain(worker, upaOffChainFeeAddress);
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
    const contractRecoveredSigner = await upaOffChainFee.recoverRequestSigner(
      signedRequestData,
      signedRequest.signature
    );
    expect(contractRecoveredSigner).eql(await worker.getAddress());
  });
});
