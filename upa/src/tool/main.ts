#!/usr/bin/env node
// -*- typescript -*-

import { subcommands, run } from "cmd-ts";
import { challenge } from "./challenge";
import { deploy } from "./deploy";
import { dev } from "./dev";
import { computecircuitid } from "./computeCircuitId";
import { devAggregator } from "./devAggregator";
import { registervk } from "./registerVK";
import { stats, statsUI } from "./stats";
import { submitProofs } from "./submitProofs";
import { submitAggregatedProof } from "./submitAggregatedProof";
import { computeFinalDigest } from "./computeFinalDigest";
import { convertProofGnark, convertProofSnarkjs } from "./convertProof";
import { convertvkGnark, convertvkSnarkJs } from "./convertVK";
import { monitor, events, eventCounts } from "./monitor";
import { genstandardjsoninput } from "./genStandardJsonInput";
import { computeProofId, computeProofIds } from "./computeProofId";
import { isVerified } from "./isVerified";
import { allocateAggregatorFee } from "./allocateAggregatorFee";
import { claimAggregatorFee } from "./claimAggregatorFee";
import { submissionFromTx } from "./submissionFromTx";
import { computeProofRef } from "./computeProofRef";
import { computeSubmissionProof } from "./computeSubmissionProof";
import { groth16Verify } from "./groth16Verify";
import { upgrade } from "./upgrade";
import { pause } from "./pause";
import { unpause } from "./unpause";
import { computeSubmissionMarkers } from "./computeSubmissionMarkers";
import { setFee } from "./setFee";
import { getConfig } from "./getConfig";
import { convertVkProofsAndInputsFile } from "./convertVKProofsInputs";
import { verifierByteCode } from "./verifierByteCode";
import {
  getAggregatedProofVerifier,
  getMaxNumPublicInputs,
  setAggregatedProofVerifier,
} from "./aggregatedProofVerifier";
import { deployBinary } from "./deployBinary";
import { version } from "./version";

const root = subcommands({
  name: "upa",
  cmds: {
    "allocate-aggregator-fee": allocateAggregatorFee,
    "claim-aggregator-fee": claimAggregatorFee,
    challenge,
    dev,
    deploy,
    registervk,
    "convert-proof-snarkjs": convertProofSnarkjs,
    "convert-proof-gnark": convertProofGnark,
    "convert-vk-gnark": convertvkGnark,
    "convert-vk-snarkjs": convertvkSnarkJs,
    "convert-vk-proofs-inputs": convertVkProofsAndInputsFile,
    stats,
    "stats-ui": statsUI,
    "submit-proofs": submitProofs,
    genstandardjsoninput,
    "compute-circuit-id": computecircuitid,
    "submit-aggregated-proof": submitAggregatedProof,
    "compute-final-digest": computeFinalDigest,
    monitor,
    events,
    "event-counts": eventCounts,
    "compute-proof-id": computeProofId,
    "compute-proof-ids": computeProofIds,
    "is-verified": isVerified,
    "submission-from-tx": submissionFromTx,
    "compute-proof-ref": computeProofRef,
    "compute-submission-proof": computeSubmissionProof,
    "compute-submission-markers": computeSubmissionMarkers,
    "dev-aggregator": devAggregator,
    "groth16-verify": groth16Verify,
    "set-fee": setFee,
    upgrade,
    pause,
    unpause,
    "get-config": getConfig,
    "get-verifier-bytecode": verifierByteCode,
    "deploy-binary": deployBinary,
    "get-aggregated-proof-verifier": getAggregatedProofVerifier,
    "get-max-num-public-inputs": getMaxNumPublicInputs,
    "set-aggregated-proof-verifier": setAggregatedProofVerifier,
    version,
  },
});

run(root, process.argv.slice(2));
