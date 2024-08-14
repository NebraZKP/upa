import { command, positional, string, number } from "cmd-ts";
import * as config from "./config";
import * as options from "./options";
import * as ethers from "ethers";

export const getAggregatedProofVerifier = command({
  name: "aggregated-proof-verifier",
  args: {
    endpoint: options.endpoint(),
    instance: options.instance(),
  },
  description: "Get the current aggregated proof verifier address",
  handler: async function ({ endpoint, instance }): Promise<void> {
    const provider = new ethers.JsonRpcProvider(endpoint);
    const { verifier } = await config.upaFromInstanceFile(instance, provider);
    console.log(await verifier.outerVerifier());
  },
});

export const setAggregatedProofVerifier = command({
  name: "set-aggregated-proof-verifier",
  args: {
    endpoint: options.endpoint(),
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
    endpoint,
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

    const provider = new ethers.JsonRpcProvider(endpoint);
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
