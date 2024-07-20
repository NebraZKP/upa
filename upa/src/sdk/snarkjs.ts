/// Declarations for snarkjs types

const snarkjs_impl = require("snarkjs");

export type SnarkJSG1 = [string, string, string];

export type SnarkJSG2 = [[string, string], [string, string], [string, string]];

/// The vkey format output from snarkjs
export type SnarkJSVKey = {
  vk_alpha_1: SnarkJSG1;
  vk_beta_2: SnarkJSG2;
  vk_gamma_2: SnarkJSG2;
  vk_delta_2: SnarkJSG2;
  IC: SnarkJSG1[];
  nPublic: number;
  curve: string;
  protocol: string;
};

/// Proof emitted from snarkjs.fullProve
export type SnarkJSProof = {
  pi_a: SnarkJSG1;
  pi_b: SnarkJSG2;
  pi_c: SnarkJSG1;
  protocol: string;
  curve: string;
};

/// Output from the fullProve function.
export type SnarkJSProveOutput = {
  proof: SnarkJSProof;
  publicSignals: string[];
};

export type SignalValueType = string | number | bigint | SignalValueType[];

export interface ProveInputSignals {
  [signal: string]: SignalValueType;
}

export const groth16 = {
  fullProve: (
    input: ProveInputSignals,
    wasmFile: string,
    zkeyFileName: string,
    // eslint-disable-next-line
    logger?: any
  ): Promise<SnarkJSProveOutput> => {
    return snarkjs_impl.groth16.fullProve(
      input,
      wasmFile,
      zkeyFileName,
      logger
    );
  },

  verify: (
    vk: SnarkJSVKey,
    publicSignals: (string | bigint)[],
    proof: SnarkJSProof,
    // eslint-disable-next-line
    logger?: any
  ): Promise<boolean> => {
    return snarkjs_impl.groth16.verify(vk, publicSignals, proof, logger);
  },
};
