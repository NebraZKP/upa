import { command, positional, string, number } from "cmd-ts";
import * as config from "./config";
import * as options from "./options";
import * as ethers from "ethers";

export const getAggregatedProofVerifier = command({
  name: "aggregated-proof-verifier",
  args: {
    chainEndpoint: options.chainEndpoint(),
    instance: options.instance(),
  },
  description: "Get the current aggregated proof verifier address",
  handler: async function ({ chainEndpoint, instance }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const { verifier } = await config.upaFromInstanceFile(instance, provider);
    console.log(await verifier.outerVerifier());
  },
});

export const setAggregatedProofVerifier = command({
  name: "set-aggregated-proof-verifier",
  args: {
    chainEndpoint: options.chainEndpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    wait: options.wait(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    fromAddress: options.from(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    address: positional({
      type: string,
      description: "Address of new aggregated proof verifier",
    }),
    maxNumPublicInputs: positional({
      type: number,
      description: "Max num public inputs",
    }),
  },
  description: "Set the aggregated proof verifier",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    instance,
    wait,
    estimateGas,
    dumpTx,
    fromAddress,
    address,
    maxNumPublicInputs,
  }): Promise<void> {
    const newVerifier: string = ethers.getAddress(address);

    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider,
      fromAddress
    );
    const { verifier } = await config.upaFromInstanceFile(instance, wallet);

    const txReq = await verifier.setOuterVerifier.populateTransaction(
      newVerifier,
      maxNumPublicInputs
    );

    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      verifier.interface
    );
  },
});

export const setSidAggregatedProofVerifier = command({
  name: "set-sid-aggregated-proof-verifier",
  args: {
    chainEndpoint: options.chainEndpoint(),
    keyfile: options.keyfile(),
    password: options.password(),
    instance: options.instance(),
    wait: options.wait(),
    estimateGas: options.estimateGas(),
    dumpTx: options.dumpTx(),
    fromAddress: options.from(),
    maxFeePerGasGwei: options.maxFeePerGasGwei(),
    address: positional({
      type: string,
      description: "Address of new sid aggregated proof verifier",
    }),
  },
  description:
    "Set the sid aggregated proof verifier, which outputs submissionId",
  handler: async function ({
    chainEndpoint,
    keyfile,
    password,
    instance,
    wait,
    estimateGas,
    dumpTx,
    fromAddress,
    address,
  }): Promise<void> {
    const newVerifier: string = ethers.getAddress(address);

    const provider = new ethers.JsonRpcProvider(chainEndpoint);
    const wallet = await config.loadWallet(
      keyfile,
      options.getPassword(password),
      provider,
      fromAddress
    );
    const { verifier } = await config.upaFromInstanceFile(instance, wallet);

    const txReq = await verifier.setSidOuterVerifier.populateTransaction(
      newVerifier
    );

    await config.handleTxRequest(
      wallet,
      txReq,
      estimateGas,
      dumpTx,
      wait,
      verifier.interface
    );
  },
});
