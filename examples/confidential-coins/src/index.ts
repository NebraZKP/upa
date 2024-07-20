#!/usr/bin/env node

import { subcommands, run } from "cmd-ts";
import { deploy } from "./deploy";
import { aggConvert } from "./aggconvert";
import { getstate } from "./getstate";
import { convert } from "./convert";
import { initBalances } from "./initbalance";

const root = subcommands({
  name: "confidential-coins",
  cmds: {
    deploy,
    convert,
    "agg-convert": aggConvert,
    "get-state": getstate,
    "init-balances": initBalances,
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
    console.error("confidential-coins error: ", error);
    process.exit(1);
  });
