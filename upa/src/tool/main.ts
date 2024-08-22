#!/usr/bin/env node
// -*- typescript -*-

import { subcommands, run } from "cmd-ts";
import { challenge } from "./challenge";
import { getSubmission } from "./getSubmission";
import { dev } from "./dev";
import { compute } from "./compute";
import { convert } from "./convert";
import { registervk } from "./registerVK";
import { submitProofs } from "./submitProofs";
import { version } from "./version";
import { aggregator } from "./aggregator";
import { owner } from "./owner";
import { query } from "./query";
import { offChain } from "./offChain";

const root = subcommands({
  name: "upa",
  cmds: {
    registervk,
    "submit-proofs": submitProofs,
    "get-submission": getSubmission,
    challenge,
    version,
    compute,
    query,
    convert,
    dev,
    owner,
    aggregator,
    "off-chain": offChain,
  },
});

run(root, process.argv.slice(2));
