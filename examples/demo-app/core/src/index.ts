#!/usr/bin/env node

import { subcommands, run } from "cmd-ts";
import { batchFiller } from "./batchFiller";
import { deploy } from "./deploy";
import { submitDirect } from "./submitDirect";
import { getstate } from "./getstate";
import { multiSubmit } from "./multiSubmit";
import { submit } from "./submit";
import { submitInvalid } from "./submitInvalid";
import { generateProofs } from "./generateProofs";
import { submitProofsFromFile } from "./submitProofsFromFile";
import { submitSolutionsFromFile } from "./submitSolutionsFromFile";
import { submitOffchain } from "./submitOffchain";

const root = subcommands({
  name: "demo-app",
  cmds: {
    deploy,
    submit: submit,
    "generate-proofs": generateProofs,
    "submit-proofs-from-file": submitProofsFromFile,
    "submit-solutions-from-file": submitSolutionsFromFile,
    "submit-invalid": submitInvalid,
    "multi-submit": multiSubmit,
    "submit-direct": submitDirect,
    "submit-offchain": submitOffchain,
    "get-state": getstate,
    "batch-filler": batchFiller,
  },
});

process.on("unhandledRejection", (reason, promise) => {
  console.log(
    "[unhandledRejection] Unhandled rejection at ",
    promise,
    `reason: ${reason}`
  );
  process.exit(1);
});

process.on("uncaughtException", (err) => {
  console.log(`[uncaughtException] Uncaught Exception: ${err.message}`);
  process.exit(1);
});

run(root, process.argv.slice(2))
  .then(() => {
    process.exit();
  })
  .catch((error) => {
    console.error("demo-app error: ", error);
    process.exit(1);
  });
