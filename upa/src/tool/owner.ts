import { subcommands } from "cmd-ts";
import { deploy } from "./deploy";
import { setFee } from "./setFee";
import { upgrade } from "./upgrade";
import { unpause } from "./unpause";
import { pause } from "./pause";
import { deployBinary } from "./deployBinary";
import { setAggregatedProofVerifier } from "./aggregatedProofVerifier";

export const owner = subcommands({
  name: "owner",
  description: "Commands used by the owner of the UPA contract",
  cmds: {
    deploy,
    "set-fee": setFee,
    upgrade,
    pause,
    unpause,
    "deploy-binary": deployBinary,
    "set-aggregated-proof-verifier": setAggregatedProofVerifier,
  },
});
