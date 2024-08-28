import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import {
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
import { deployUpaDummyVerifier } from "./deploy";
import { UpaClient } from "../src/sdk/client";
import { dummyProofData, UpaInstance } from "../src/sdk/upa";
import { loadAppVK } from "../src/tool/config";
import { AppVkProofInputs } from "../src/sdk/application";
import { keccak256, Signer, verifyTypedData, WeiPerEther } from "ethers";
import { expect } from "chai";
import { Deposits, Deposits__factory } from "../typechain-types";
import {
  getEIP712Domain,
  getEIP712RequestType,
  getEIP712ResponseType,
  getSignedRequestData,
  getSignedResponseData,
  signOffChainSubmissionRequest,
  signOffChainSubmissionResponse,
  UnsignedOffChainSubmissionRequest,
  UnsignedOffChainSubmissionResponse,
} from "../src/sdk/offChainClient";
import {
  vkProofsInputsToProofIds,
  vkProofsInputsToSubmissionId,
} from "../src/sdk/utils";
// eslint-disable-next-line
import { packOffChainSubmissionMarkers } from "../src/sdk/aggregatedProofParams";
import { mine } from "@nomicfoundation/hardhat-network-helpers";

type DeployAndSubmitResult = {
  worker: Signer;
  upa: UpaInstance;
  upaClient: UpaClient;
  vkProofAndInputs_1: AppVkProofInputs[];
  vkProofAndInputs_2: AppVkProofInputs[];
  vkProofAndInputs_3: AppVkProofInputs[];
  deposits: Deposits;
  user: Signer;
};

const TEST_FEE_CONTRACT_NAME = "Offchain NEBRA UPA Aggregator";
const TEST_FEE_CONTRACT_VERSION = "1";

async function deployAndSubmit(): Promise<DeployAndSubmitResult> {
  const vk = loadAppVK("../circuits/src/tests/data/vk.json");
  const deployResult = await deployUpaDummyVerifier();
  const { upa, upaDesc, worker, user1 } = deployResult;
  const upaClient = await UpaClient.init(worker, upaDesc);
  const { verifier } = upa;
  await verifier.registerVK(vk);

  /// Prepare 3 submissions (all against vk):
  ///   1: [ pf_a ]
  ///   2: [ pf_b, pf_c, pf_d ]
  ///   3: [ pf_e, pf_f ]
  const vkProofAndInputs_1: AppVkProofInputs[] = [
    new AppVkProofInputs(vk, pf_a, pi_a),
  ];
  const vkProofAndInputs_2: AppVkProofInputs[] = [
    new AppVkProofInputs(vk, pf_b, pi_b),
    new AppVkProofInputs(vk, pf_c, pi_c),
    new AppVkProofInputs(vk, pf_d, pi_d),
  ];
  const vkProofAndInputs_3: AppVkProofInputs[] = [
    new AppVkProofInputs(vk, pf_e, pi_e),
    new AppVkProofInputs(vk, pf_f, pi_f),
  ];

  // Deploy an off-chain fee contract
  const depositsFactory = new Deposits__factory(worker);
  const deposits = await depositsFactory.deploy(
    TEST_FEE_CONTRACT_NAME,
    TEST_FEE_CONTRACT_VERSION,
    await worker.getAddress(),
    await verifier.getAddress()
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
    user: user1,
  };
}

describe("Off-chain submission fees", async () => {
  it("Sign submission request/response and verify the signature", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const { worker, vkProofAndInputs_1, deposits, user } = deployResult;
    const depositsAddress = await deposits.getAddress();

    // Prepare an unsignedOffChainSubmissionRequest
    const offChainSubmissionRequest: UnsignedOffChainSubmissionRequest = {
      proofs: vkProofAndInputs_1,
      submissionId: keccak256("0x1234"),
      submitterAddress: await user.getAddress(),
      expirationBlockNumber: 100000,
      submitterNonce: 0n,
      fee: 0n,
      totalFee: 0n,
    };

    // Sign the request
    const signedRequest = await signOffChainSubmissionRequest(
      offChainSubmissionRequest,
      user,
      depositsAddress
    );

    const signedRequestData = getSignedRequestData(signedRequest);
    const domain = await getEIP712Domain(worker, depositsAddress);
    const requestTypes = getEIP712RequestType();

    // Verify the signature using ethers
    const ethersRecoveredRequestSigner = verifyTypedData(
      domain,
      requestTypes,
      signedRequestData,
      signedRequest.signature!
    );
    expect(ethersRecoveredRequestSigner).eql(await user.getAddress());

    // Verify the signature in the fee contract
    const contractRecoveredRequestSigner = await deposits.recoverRequestSigner(
      signedRequestData,
      signedRequest.signature
    );
    expect(contractRecoveredRequestSigner).eql(await user.getAddress());

    // Prepare an unsignedOffChainSubmissionResponse
    const offChainSubmissionResponse: UnsignedOffChainSubmissionResponse = {
      submissionId: vkProofsInputsToSubmissionId(vkProofAndInputs_1),
      submitterAddress: await worker.getAddress(),
      expirationBlockNumber: 100000,
      submitterNonce: 0n,
      fee: 0n,
      totalFee: 0n,
    };

    // Sign the response
    const signedResponse = await signOffChainSubmissionResponse(
      offChainSubmissionResponse,
      worker,
      depositsAddress
    );

    const signedResponseData = getSignedResponseData(signedResponse);
    const repsonseTypes = getEIP712ResponseType();

    // Verify the signature using ethers
    const ethersRecoveredResponseSigner = verifyTypedData(
      domain,
      repsonseTypes,
      signedResponseData,
      signedResponse.signature!
    );
    expect(ethersRecoveredResponseSigner).eql(await worker.getAddress());

    // Verify the signature in the fee contract
    const contractRecoveredResponseSigner =
      await deposits.recoverResponseSigner(
        signedResponseData,
        signedResponse.signature
      );
    expect(contractRecoveredResponseSigner).eql(await worker.getAddress());
  });

  it("Off-chain submissions aggregated within deadline", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const { worker, vkProofAndInputs_1, deposits, user, upa } = deployResult;
    const depositsAddress = await deposits.getAddress();
    const initialDeposit = WeiPerEther; // 1 ETH
    await deposits.connect(user).deposit({ value: initialDeposit });
    expect(await deposits.viewBalance(user.getAddress())).eql(initialDeposit);
    const provider = worker.provider!;
    const currentBlockNumber = await provider.getBlockNumber();

    // Prepare an unsignedOffChainSubmissionRequest
    const feeAmount = WeiPerEther / 100n; // 0.01 ETH
    const offChainSubmissionRequest: UnsignedOffChainSubmissionRequest = {
      proofs: vkProofAndInputs_1,
      submissionId: vkProofsInputsToSubmissionId(vkProofAndInputs_1),
      submitterAddress: await user.getAddress(),
      expirationBlockNumber: currentBlockNumber + 10,
      submitterNonce: 0n,
      fee: feeAmount,
      totalFee: feeAmount,
    };

    // Sign the request
    const signedRequest = await signOffChainSubmissionRequest(
      offChainSubmissionRequest,
      user,
      depositsAddress
    );
    const signedRequestData = getSignedRequestData(signedRequest);

    // Verify this submission in the UPA contract within the deadline
    const proofIds = vkProofsInputsToProofIds(vkProofAndInputs_1);
    await upa.verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        0,
        [],
        packOffChainSubmissionMarkers([true]),
        0
      );

    // Attempt to claim with the wrong signature. Should fail.
    const badSignedRequest = await signOffChainSubmissionRequest(
      offChainSubmissionRequest,
      worker,
      depositsAddress
    );

    await expect(
      deposits
        .connect(worker)
        .claimFees(signedRequestData, badSignedRequest.signature)
    ).to.be.revertedWithCustomError(deposits, "BadSignature");

    // Claim fees using the correctly signed request
    const workerBalanceBefore = await provider.getBalance(
      await worker.getAddress()
    );
    await deposits
      .connect(worker)
      .claimFees(signedRequestData, signedRequest.signature);
    expect(await deposits.viewBalance(user.getAddress())).eql(
      initialDeposit - feeAmount
    );
    const workerBalanceAfter = await provider.getBalance(
      await worker.getAddress()
    );
    // The worker's ETH should increase by the fee amount minus a small
    // amount for the gas fee of the claim.
    expect(workerBalanceAfter - workerBalanceBefore).greaterThan(
      (feeAmount * 99n) / 100n
    );
    expect(workerBalanceAfter - workerBalanceBefore).lessThan(feeAmount);

    // Claiming again should fail
    await expect(
      deposits
        .connect(worker)
        .claimFees(signedRequestData, signedRequest.signature)
    ).to.be.revertedWithCustomError(deposits, "AlreadyClaimed");
  });

  it("Off-chain submission missed deadline", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const { worker, vkProofAndInputs_1, deposits, user, upa } = deployResult;
    const depositsAddress = await deposits.getAddress();
    const initialDeposit = WeiPerEther; // 1 ETH
    await deposits.connect(user).deposit({ value: initialDeposit });
    expect(await deposits.viewBalance(user.getAddress())).eql(initialDeposit);
    const provider = worker.provider!;
    const currentBlockNumber = await provider.getBlockNumber();

    // Prepare an unsignedOffChainSubmissionResponse
    const feeAmount = WeiPerEther / 100n; // 0.01 ETH
    const offChainSubmissionResponse: UnsignedOffChainSubmissionResponse = {
      submissionId: vkProofsInputsToSubmissionId(vkProofAndInputs_1),
      submitterAddress: await user.getAddress(),
      expirationBlockNumber: currentBlockNumber + 10,
      submitterNonce: 0n,
      fee: feeAmount,
      totalFee: feeAmount,
    };

    // Sign the response as the aggregator
    const signedResponse = await signOffChainSubmissionResponse(
      offChainSubmissionResponse,
      worker,
      depositsAddress
    );
    const signedResponseData = getSignedResponseData(signedResponse);

    // Increment 11 blocks so that we miss the block deadline
    await mine(11);

    // Verify this submission in the UPA contract
    const proofIds = vkProofsInputsToProofIds(vkProofAndInputs_1);
    await upa.verifier
      .connect(worker)
      .verifyAggregatedProof(
        dummyProofData(proofIds),
        proofIds,
        0,
        [],
        packOffChainSubmissionMarkers([true]),
        0
      );

    // Attempt to refund with the wrong signature. Should fail.
    const badSignedResponse = await signOffChainSubmissionResponse(
      offChainSubmissionResponse,
      user,
      depositsAddress
    );

    await expect(
      deposits
        .connect(worker)
        .refundFees(signedResponseData, badSignedResponse.signature)
    ).to.be.revertedWithCustomError(deposits, "BadSignature");

    const depositsBefore = await deposits.viewBalance(user.getAddress());
    // Claim refund using the correctly signed request
    await deposits
      .connect(worker)
      .refundFees(signedResponseData, signedResponse.signature);
    const depositsAfter = await deposits.viewBalance(user.getAddress());

    // The balance should have increased by a bit more than the fee (as gas is
    // also refunded)
    expect(depositsAfter - depositsBefore).greaterThan(feeAmount);

    // Claiming again should fail
    await expect(
      deposits
        .connect(worker)
        .refundFees(signedResponseData, signedResponse.signature)
    ).to.be.revertedWithCustomError(deposits, "AlreadyRefunded");
  });

  it("User withdraws balance before/after notice", async () => {
    const deployResult = await loadFixture(deployAndSubmit);
    const { worker, deposits, user } = deployResult;
    const initialDeposit = WeiPerEther; // 1 ETH
    await deposits.connect(user).deposit({ value: initialDeposit });
    expect(await deposits.viewBalance(user.getAddress())).eql(initialDeposit);
    const provider = worker.provider!;

    // Attempt to withdraw before initiating a withdrawal
    await expect(
      deposits.connect(user).withdraw(initialDeposit)
    ).to.be.revertedWithCustomError(deposits, "NoPendingWithdrawal");

    // Initiate a withdrawal
    await deposits.connect(user).initiateWithdrawal();

    // View which block initiated the withdrawal
    const withdrawInitBlock =
      await deposits.viewPendingWithdrawalInitializedAtBlock(user.getAddress());

    expect(withdrawInitBlock > 0).is.true;

    // Attempt to withdraw before the notice period is done
    const NOTICE_PERIOD = await deposits.WITHDRAWAL_NOTICE_BLOCKS();
    await mine(NOTICE_PERIOD / 2n);
    await expect(
      deposits.connect(user).withdraw(initialDeposit)
    ).to.be.revertedWithCustomError(deposits, "InsufficientNotice");

    // Increment so that we are past the notice period
    await mine(NOTICE_PERIOD / 2n);
    // In case we rounded down when halving the notice period.
    await mine(1);

    // Attempt to withdraw more than user's balance
    await expect(
      deposits.connect(user).withdraw(initialDeposit + 1n)
    ).to.be.revertedWithCustomError(deposits, "InsufficientBalance");

    // Withdraw the user's balance.
    const userBalanceBefore = await provider.getBalance(user.getAddress());
    await deposits.connect(user).withdraw(initialDeposit);
    const userBalanceAfter = await provider.getBalance(user.getAddress());

    // The user balance should increase by the initial deposit minus a small
    // amount for the gas fee of the claim.
    expect(userBalanceAfter - userBalanceBefore).greaterThan(
      (initialDeposit * 99n) / 100n
    );
    expect(userBalanceAfter - userBalanceBefore).lessThan(initialDeposit);
  });

  it("Sequence of submissions, fee claims, refunds", async () => {
    // TODO: Test interleaved fee claims/refunds with several submissions.
  });
});
