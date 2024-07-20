## Context

In the wider protocol, the role of the UPA contracts is to:
- Accept on-chain submissions from "Submitters" (any party), where each
  submission contains one or more Groth16 proofs,
- Accept aggregated proofs from on-chain submissions from an specific
  aggregator (who is untrusted, but permitted to submit aggregated proofs).
  If the aggregated proof attests to the validity of some sequence of some
  previously submitted Groth16 proofs, the contract state is updated to record
  this.
- Accept queries from applications and return a result indicating whether a
  given proof has been shown to be valid or not
  - (note, a negative response indicates that the proof has not been shown to
    be valid, not necessarily that it is invalid)
- Ensure that fees:
  - are paid by Submitters at submission time
  - can be reclaimed by the Submitter if the Aggregator fails to provide
    evidence that a valid Groth16 proof, previously submitted to the contract,
    is indeed valid, OR
  - can be claimed by the Aggregator after proving the validity of proofs in
    a submission

## Files for audit

- EllipticCurveUtils.sol
  - Based on external code, including (audited) Tornado cash contract.  See
    file for links.
- Groth16Verifier.sol
- Merkle.sol
- Uint16VectorLib.sol
- UpaFeeBase.sol
- UpaFixedGasFee.sol
- UpaInternalLib.sol
- UpaLib.sol
- UpaProofReceiver.sol
- UpaVerifier.sol

## Out of scope, but included for reference

- IGroth16Verifier.sol
- IUpaProofReceiver.sol
- IUpaVerifier.sol

## Contract behaviour (for Audit)

The behaviour of the contracts should follow that described in the spec.

Assumptions:
- the proof system used to show validity of N Groth16 proofs via an aggregated
  proof is complete and sound.

### Valid submissions

- For submissions containing only valid Groth16 proofs (for statements with N
  or fewer public inputs),
  - the contacts correctly accept the submission only if the submitter has
    paid the correct fee
  - an honest aggregator must be able to
    - convince the contract to update its state to indicate that each proof in
      the submission is valid
    - claim the submisson fee
    - prevent any other party from (re)claiming the paid fee
  - an aggregator (malicious or otherwise) who *does not* provide evidence to
    the contract of the validity of a proof in the submission:
    - should be able to prevent the submitter from later reclaiming the
      associated fee paid.

(*) The meaning of *not* providing evidence that a proof P is valid: to submit
evidence for proofs in later submissions, before submitting evidence for P.

### Invalid submissions

- For submissions containing 1 or more invalid proofs:
  - no party (malicious or otherwise) should be able to convince the
    contract to mark the invalid proofs as valid.
  - note, there is no guarantee that other (valid) proofs in the set will be
    marked valid (i.e. in this case the aggregator is permitted to censor
    the proofs)
