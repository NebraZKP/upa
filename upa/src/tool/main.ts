#!/usr/bin/env node
// -*- typescript -*-

import { subcommands, run } from "cmd-ts";
import { challenge } from "./challenge";
import { dev } from "./dev";
import { compute } from "./compute";
import { convert } from "./convert";
import { registervk } from "./registerVK";
import { submitProofs } from "./submitProofs";
import { version } from "./version";
import { aggregator } from "./aggregator";
import { owner } from "./owner";
import { query } from "./query";

const root = subcommands({
  name: "upa",
  cmds: {
    registervk,
    "submit-proofs": submitProofs,
    challenge,
    version,
    compute,
    query,
    convert,
    dev,
    owner,
    aggregator,
  },
});

run(root, process.argv.slice(2));
