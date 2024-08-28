import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { deployUpaDummyVerifier } from "./deploy";
import { loadAppVK } from "../src/tool/config";
import { Groth16Proof } from "../src/sdk/application";
import { updateFeeOptions } from "../src/sdk/upa";

// eslint-disable-next-line
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

// Dummy proofs and PIs
export const pf_a = new Groth16Proof(
  ["1", "2"],
  [
    ["3", "4"],
    ["5", "6"],
  ],
  ["7", "8"],
  [],
  []
);
export const pi_a = [11n, 12n, 13n];

describe("UPA Test Pausability (Kill Switch)", async () => {
  const vk = loadAppVK("../../circuits/src/tests/data/vk.json");
  it("Only owner can pause/unpause contract", async () => {
    const { upa, user1 } = await loadFixture(deployUpaDummyVerifier);
    const { verifier } = upa;

    // Check user1 cannot pause/unpause while contract is unpaused
    await expect(verifier.connect(user1).pause()).reverted;
    await expect(verifier.connect(user1).unpause()).reverted;

    // Check owner cna pause the contract
    const pauseTx = await verifier.pause();
    const pauseReceipt = await pauseTx.wait();
    expect(pauseReceipt?.status).to.equal(1);

    // Check user1 cannot unpause while contract is paused
    await expect(verifier.connect(user1).pause()).reverted;
    await expect(verifier.connect(user1).unpause()).reverted;

    // Check owner can unpause the contract
    const unpauseTx = await verifier.unpause();
    const unpauseReceipt = await unpauseTx.wait();
    expect(unpauseReceipt?.status).to.equal(1);

    // Pause the contract
    await verifier.pause();

    // Register vk should fail
    await expect(verifier.registerVK(vk)).reverted;

    // Unpause the contract
    await verifier.unpause();

    // Register vk should succeed
    const registerVkTx = await verifier.registerVK(vk);
    const registerVkReceipt = await registerVkTx.wait();
    expect(registerVkReceipt?.status).to.equal(1);

    const circuitIds = await verifier.getCircuitIds();

    // Pause the contract
    await verifier.pause();

    // Submit proof should fail

    // (submit proof data)
    const options = await updateFeeOptions(verifier, 1, undefined);
    // Submit proof for cid[0]
    await expect(
      verifier.submit(
        [circuitIds[0]],
        [pf_a.compress().solidity()],
        [pi_a],
        options
      )
    ).reverted;

    // Unpause the contract
    await verifier.unpause();

    // Submit proof should succeed
    const submitTx = await verifier.submit(
      [circuitIds[0]],
      [pf_a.compress().solidity()],
      [pi_a],
      options
    );

    const submitTxReceipt = await submitTx.wait();
    expect(submitTxReceipt?.status).to.equal(1);
  });

  it("Pause/Unpause registerVk", async () => {
    const { upa } = await loadFixture(deployUpaDummyVerifier);
    const { verifier } = upa;
    // Pause the contract
    await verifier.pause();

    // Register vk should fail
    await expect(verifier.registerVK(vk)).reverted;

    // Unpause the contract
    await verifier.unpause();

    // Register vk should succeed
    const registerVkTx = await verifier.registerVK(vk);
    const registerVkReceipt = await registerVkTx.wait();
    expect(registerVkReceipt?.status).to.equal(1);
  });

  it("Pause/Unpause submitProof", async () => {
    const { upa } = await loadFixture(deployUpaDummyVerifier);
    const { verifier } = upa;

    // Register vk should succeed
    const registerVkTx = await verifier.registerVK(vk);
    const registerVkReceipt = await registerVkTx.wait();
    expect(registerVkReceipt?.status).to.equal(1);

    const circuitIds = await verifier.getCircuitIds();

    // Pause the contract
    await verifier.pause();

    // Submit proof should fail

    // (submit proof data)
    const options = await updateFeeOptions(verifier, 1, undefined);
    // Submit proof for cid[0]
    await expect(
      verifier.submit(
        [circuitIds[0]],
        [pf_a.compress().solidity()],
        [pi_a],
        options
      )
    ).reverted;

    // Unpause the contract
    await verifier.unpause();

    // Submit proof should succeed
    const submitTx = await verifier.submit(
      [circuitIds[0]],
      [pf_a.compress().solidity()],
      [pi_a],
      options
    );

    const submitTxReceipt = await submitTx.wait();
    expect(submitTxReceipt?.status).to.equal(1);
  });
});
