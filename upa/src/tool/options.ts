import { string, option, boolean, flag, optional } from "cmd-ts";
import { ArgParser } from "cmd-ts/dist/cjs/argparser";
import { Descriptive, ProvidesHelp } from "cmd-ts/dist/cjs/helpdoc";
import "dotenv/config";
import * as readlineSync from "readline-sync";

export type Option = ReturnType<typeof option>;
export type Flag = ReturnType<typeof flag>;
export type OptionalOption = ArgParser<string | undefined> &
  ProvidesHelp &
  Partial<Descriptive>;

export function keyfile(
  description?: string | undefined,
  required: boolean = true
): Option {
  const defaultValue = () => {
    const value = process.env.KEYFILE;
    if (!value && required) {
      // Caught by the CLI framework
      throw "Keyfile not specified";
    }

    return value || "";
  };
  return option({
    type: string,
    long: "keyfile",
    short: "k",
    defaultValue,
    description:
      description || "Keyfile to sign tx (defaults to KEYFILE env var)",
  });
}

// Pass the output into `getPassword`.
export function password(description?: string | undefined): Option {
  return option({
    type: string,
    long: "password",
    short: "p",
    defaultValue: () => process.env.KEYFILE_PASSWORD || "",
    description:
      description ||
      "Password for keyfile (defaults to KEYFILE_PASSWORD env var)",
  });
}

export function getPassword(password?: string): string {
  if (password) {
    // If password is provided as a command line argument, use it
    return password;
  }

  // If KEYFILE_PASSWORD is defined in environment variables, use it
  const envPassword = process.env.KEYFILE_PASSWORD;
  if (envPassword || envPassword == "") {
    return envPassword;
  }

  // Securely prompt user for their password (hides their input)
  const stdinPassword = readlineSync.question(
    "Enter your keyfile password (empty if unencrypted): ",
    {
      hideEchoBack: true,
    }
  );

  return stdinPassword;
}

export function endpoint(): Option {
  return option({
    type: string,
    long: "endpoint",
    short: "e",
    defaultValue: () => process.env.RPC_ENDPOINT || "http://127.0.0.1:8545/",
    description: "RPC endpoint to connect to (defaults to ENDPOINT env var)",
  });
}

export function instance(description?: string | undefined): Option {
  return option({
    type: string,
    long: "instance",
    short: "i",
    defaultValue: () => "upa.instance",
    description: description || "UPA instance file",
  });
}

export function upaConfigFile(): Option {
  return option({
    type: string,
    long: "config",
    defaultValue: () => "upa_config.json",
    description: "Location of UPA config json file",
  });
}

export function proofFile(): Option {
  return option({
    type: string,
    long: "proof-file",
    short: "p",
    description:
      'Proof and public inputs JSON file: {"proof": {..}, "inputs": [..]}',
  });
}

export function vkProofInputsFile(): Option {
  return option({
    type: string,
    long: "proof-file",
    short: "p",
    description:
      'VK, proof, inputs file: {"vk": {..}, "proof": {..}, "inputs": [..]}',
  });
}

export function vkFile(): Option {
  return option({
    type: string,
    long: "vk-file",
    short: "v",
    description: "Verifying key file",
  });
}

/// A JSON file in one of the formats:
/// - An array of { vk, proof, inputs }
/// - An array of { circuitId, proof, inputs }
/// - A single object { vk, proof, inputs }
/// - A single object { circuitId, proof, inputs }
export function proofsFile(): Option {
  return option({
    type: string,
    long: "proofs-file",
    short: "p",
    description: "Proofs file (containing a list of proofs)",
  });
}

export function circuitId(): Option {
  return option({
    type: string,
    long: "circuit-id",
    short: "c",
    description: "Circuit Id",
  });
}

export function wait(): Flag {
  return flag({
    type: boolean,
    long: "wait",
    short: "w",
    defaultValue: () => false,
    description: "Wait for the transaction to complete",
  });
}

export function estimateGas(): Flag {
  return flag({
    type: boolean,
    long: "estimate-gas",
    short: "g",
    defaultValue: () => false,
    description: "Estimate gas only.  Do not send the tx.",
  });
}

export function dumpTx(): Flag {
  return flag({
    type: boolean,
    long: "dump-tx",
    short: "d",
    defaultValue: () => false,
    description: "Dump the tx request.  Do not send.",
  });
}

export function maxFeePerGasGwei(): Option {
  return option({
    type: string,
    long: "max-fee-per-gas",
    defaultValue: () => {
      return process.env.MAX_FEE_PER_GAS_GWEI || "";
    },
    description: "Maximum fee per gas(Gwei) (or env var MAX_FEE_PER_GAS_GWEI)",
  });
}

export function feeInGas(): OptionalOption {
  return option({
    type: optional(string),
    long: "fee-in-gas",
    description: "Fixed fee per proof in gas",
  });
}

export function overrideUpaFeeGwei(): OptionalOption {
  return option({
    type: optional(string),
    long: "override-upa-fee",
    description: "Override computed UPA fee (in Gwei)",
  });
}

export function aggregatorCollateralInWei(): OptionalOption {
  return option({
    type: optional(string),
    long: "collateral",
    description: "Aggregator collateral in Wei",
  });
}

export function submissionFile(description?: string | undefined): Option {
  return option({
    type: string,
    long: "submission-file",
    short: "s",
    defaultValue: () => "",
    description: description || "Submission file",
  });
}

export function proofReferenceFile(description?: string | undefined): Option {
  return option({
    type: string,
    long: "proof-ref-file",
    short: "r",
    defaultValue: () => "",
    description: description || "Proof reference file",
  });
}

export function owner_keyfile(
  description?: string | undefined
): OptionalOption {
  return option({
    type: optional(string),
    long: "owner-keyfile",
    short: "owner-k",
    description: description || "Owner keyfile",
  });
}

// Pass the output into `getPassword`.
export function owner_password(
  description?: string | undefined
): OptionalOption {
  return option({
    type: optional(string),
    long: "owner-password",
    short: "owner-p",
    description: description || "Owner password",
  });
}
