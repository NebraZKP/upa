---
title: NEBRA UPA v1.1.0 Protocol Specification
author: Nebra Labs
date: 2024
papersize: a4
geometry: margin=2cm
header-includes: |
  \newcommand{\domaintag}{\mathsf{DT}}
  \newcommand{\computeCircuitId}{\mathsf{compute\_circuit\_id}}
  \newcommand{\cid}{\mathsf{circuitId}}
  \newcommand{\pid}{\mathsf{proofId}}
  \newcommand{\pidx}{\mathsf{proofIndex}}
  \newcommand{\sid}{\mathsf{submissionId}}
  \newcommand{\sidx}{\mathsf{submissionIndex}}
  \newcommand{\pdigest}{\mathsf{proofDigest}}
  \newcommand{\poseidon}{\text{poseidon}}
  \newcommand{\keccak}{\mathsf{keccak}}
  \newcommand{\PI}{\mathsf{PI}}
  \newcommand{\vk}{\mathsf{VK}}
  \newcommand{\pk}{\mathsf{PK}}
  \newcommand{\VK}{\mathsf{VK}}
  \newcommand{\isnark}{\mathsf{SNARK_{\text{bv}}}}
  \newcommand{\ipi}{\pi_{\text{bv}}}
  \newcommand{\ivk}{\vk^{\text{bv}}}
  \newcommand{\ipk}{\pk^{\text{bv}}}
  \newcommand{\app}{\text{app}}
  \newcommand{\snark}{\textsf{SNARK}}
  \newcommand{\Verify}{\textsf{Verify}}
  \newcommand{\sv}{\textsf{SuccinctVerify}}
  \newcommand{\BV}{\text{BV}}
  \newcommand{\truncate}{\text{truncate}}
  \newcommand{\outercircuit}{\text{outer}}
---

# Overview

*Application developers* register VKs for their circuits with the UPA contract.  Eack VK is assigned a *circuit id* $\cid$ (the poseidon hash of the VK) and shared with off-chain aggregators (via events).

*Application Clients* submit proofs and PIs to the UPA contract as tuples $(\pi, \PI, \cid)$, where `proof` is expected to be a proof that $\PI$ is an instance of the circuit with *circuit id* $\cid$.

A single call to the contract submits an *ordered list* $(\pi_i, \PI_i, \cid_i)_{i=0}^{n-1}$ (of any size $n$ up to some implementation-defined maximum $N$) of these tuples.  This ordered list of tuples is referred to as a *Submission*. Submissions of more than 1 proof allow the client to amortize the cost of submitting proofs.  Note that there is no requirement for the $\cid_i$s to match, namely, a single *Submission* may contain proofs for multiple application circuits.

Each tuple in the submission is assigned:

- $\pid$ - a unique *proof id* (equal to the Keccak hash of the circuit ID and PIs), and
- $\pidx$ - a *proof index* (a simple incrementing counter).

The submission is assigned:

- a *Submission Id* $\sid$, computed as the Merkle root of the list of $\pid_i$s, padded to the nearest power of 2 with `bytes32(0)`.
- a *submission index* $\sidx$, a simple incrementing counter of submissions, used later for censorship resistance.

Note that:

- for submissions that consist of a single proof, $\pid_0 == \sid$, and the submitted proof can be referenced by $\pid_0$, whereas
- for submissions of multiple proofs, each proof is referred to by $\sid$ and an index (or *location*) of the proof within the submission.  Where required, a Merkle proof can be used to show that a proof with $\pid_i$ is indeed at the given index within the submission $\sid$.

The proof and public input data is not stored on-chain, but is emitted as Events for *Aggregators* to monitor and receive.  The contract stores information about the submission (including $\sidx$, $n$ and some further metadata), indexed by the submission Id.

*Aggregators* aggregate *batches* of proofs with *increasing* proof index values.  In the case where invalid proofs have been submitted, aggregators may skip *only* invalid proofs.  Aggregators that skip valid proofs will be punished (see below).

As aggregated batches of proofs are received and verified by the UPA contract, the corresponding proof ids are marked as verified.  Note that, for proofs that are part of a multi-proof submission, the contract records the fact that the proof at location $i$ of submission $\sid$ was verified.

An application client can then submit a transaction to the application circuit (optionally with some `ProofReference` metadata), and the application circuit can verify the existence of an associated ZKP as follows:

- Application contract computes the public inputs for the proof, exactly as it would in the absence of UPA
- Application contract passes the public inputs $\PI$, the circuit Id $\cid$, and any metadata to the UPA contract.
- The UPA contract computes $\pid = \keccak(\cid, \PI)$ from the public inputs.
  - If the proof was submitted by itself, $\pid$ is equal to the submission ID, and the contract can immediately check whether a valid proof has been seen as part of an aggregated proof.
  - If the proof was part of a multi-proof submission, the metadata includes the $\sid$, index $i$ of the proof within the submission $\sid$, and a Merkle proof that $\pid$ is indeed the $i$-th leaf of the submission.  After checking this Merkle proof, the contract can immediately verify that proof $i$ of submission $\sid$ has been seen as part of an aggregated proof batch.
- The UPA contract returns 1 if it has a record of a valid proof for $(\cid, \pid$), and 0 otherwise.

## Protocol

### Circuit registration

The application developer submits a transaction calling the `registerVK` method on the UPA contract, passing the verification key $\VK$.

The circuitId $\cid$ for the circuit is computed as
$$
  \cid = \computeCircuitId( \vk ) = \poseidon(\domaintag_{\mathsf{cid}} || \vk)
$$
where $\domaintag_{\mathsf{cid}}$ denotes a domain tag derived from a string describing the context, such as ``Saturn v1.0.0 CircuitId'' (See the Universal Batch Verifier specification for details.)

(We assume $\vk$ is serialized using [SnarkJS](https://github.com/iden3/snarkjs) or following the exactly the same protocol of SnarkJS).

$\VK$ is stored on the contract (for censorship resistance), indexed by $\cid$, and aggregators (who are assumed to be monitoring the contract) are notified via an event.

> NOTE: The poseidon hash is expensive to compute in the EVM, but this operation is only performed once at registration time.  This $\cid$ will be used to reference the circuit for future operations.

### Proof submission

The *App Client* creates the parameters for its smart contract as normal, including one or more proofs $\pi_i$ and public inputs $\PI_i$.  It then passes these, along with the relevant (pre-registered) circuit Ids $\cid_i$, to the `submit` method on the UPA contract, paying the aggregation fee in ether:
```solidity
contract Upa
{
    ...
    function submit(
            uint256[] calldata circuitId,
            Proof[] calldata proof,
            uint256[][] calldata publicInputs)
        external
        payable;
    ...
}
```

The `Upa.submit` method:

- computes $\pid_i = \keccak(\cid_i, \PI_i)$ for $i = 0, \ldots, n-1$.
- computes a `proofDigest` $\pdigest_i$ for each proof, as $\keccak(\pi_i)$
- computes the submission Id $\sid$ as the Merkle root of the list $(\pid_i)_{i=0}^{n-1}$ (padded as required to the nearest power of 2)
- computes the `digestRoot` as the Merkle root of the list $(\pdigest_i)_{i=0}^{n-1}$ (again padded as required to the nearest power of 2)
- rejects the tx if an entry for $\sid$ already exists
- assigns a $\sidx$ to the submission (using a single incrementing counter)
- assigns a $\pidx_i$ to each $(\pi_i, \PI_i)$ (using a single incrementing counter)
- emits an event for each proof, including $(\cid_i, \pi_i, \PI_i, \pidx_i)$
- updates contract state to record the fact that a submission with id $\sid$ has been made, recording `digestRoot`, $\sidx$, $n$ and the block number at submission time.



Note: Proof data itself does not appear in the input data used to compute `proofId`.  This is because, when the proof is verified by the application, the application does not have access to (and does not require) any proof data.  Thereby, the application is in fact verifying the *existence* of some proof for the given circuit and public inputs.

Note: Application authors must ensure that the public inputs to their ZKPs contain some random or unpredictable elements (and in general this will already be the case for sound protocols, in order to prevent replay attacks).  If the set of public inputs can be predicted by a malicious party, that malicious party can submit an invalid proof for the public inputs, preventing submission of further (valid) proofs for that same set of public inputs.

### Aggregated proof submission

*Aggregators* submit aggregated proofs to the `Upa.verifyAggregatedProof` method, proving validity of a set of previously submitted application proofs.  In return, they can claim batch submission fees.
```solidity!
function verifyAggregatedProof(
        bytes calldata proof,
        bytes32[] calldata proofIds,
        SubmissionProof[] calldata submissionProofs)
    external;
```

> `submissionProof` is an array of 0 or more proofs, each showing that some of the entries in `proofIds` belong to a specific multi-proof submission.  These are required as we do not have a map from `proofId` to `submissionId` or `submissionIdx`.  See the algorithm below for details.

The UPA contract:

- checks that `proof` is valid for `proofIds`
- for each $\pid$ in `proofIds`,
  - check that $\pid$ has been submitted to the contract, and that proofs appear in the aggregated batch in the order of submission (see below)
  - mark $\pid$ as valid (see below)
  - emit an event indicating that $\pid$ has been verified

Specifically, the algorithm for verifying submission (in the correct order) of `proofIds`, and marking them as verified, is as follows.

**State:** the contract holds

- a dynamic array `uint16[] numVerifiedInSubmission` of counters, where the $i$-th entry corresponds to the number of proofs that have been verified (in order) of the submission with $\sidx == i$
- the submission index `nextSubmissionIdxToVerify` of the next submission from which proofs are expected.

Given a list of `proofIds` and `submissionProofs`, the contract verified that `proofIds` appear in submissions as follows:

- For each $\pid$ in `proofIds`:
  - Attempt to lookup the submission data (see "Proof Submission") for a submission with Id $\pid$. If such a submission exists:
    - The proof was submitted as a single-proof submission.  The contract extracts the $\sidx$ from the submission data and ensures that $\sidx$ is greater than or equal to `nextSubmissionIdxToVerify`.  If not, reject the transaction.
    - The entry `numVerifiedInSubmission[` $\sidx$ `]` should logically be 0 (this can be sanity checked by the contract).  Set this entry to 1
    - update `nextSubmissionIdxToVerify` in contract state
  - Otherwise (if no submission data was found for $\sid = \pid$)
    - the proof is expected to be part of a multi-proof submission with $\sidx \geq$ `nextSubmissionIdxToVerify`.
      - Note that if a previous aggregated proof verified some subset, but not all, of the entries in the submission, `nextSubmissionIdxToVerify` would still refer to the partially verified submission at this stage.  In this case, `numVerifiedInSubmission[` $\sidx$ `]` should contain the number of entries already verified.
    - Take the next entry in `submissionProofs`.  This includes the following information:
      - the $\sid$ for the submission to be verified
      - a Merkle "interval" proof for a contiguous set of entries from that submission.
 - Determine the number `m` of entries in `proofIds`, including the current $\pid$, that belong to this submission, as follows:
      - Let `numProofIdsRemaining` be the number of entries (including $\pid$) still unchecked in `proofIds`.
      - Look up the submission data for $\sid$, in particular $\sidx$ and $n$.
      - Let `numUnverifiedFromSubmission = `$n$` - numVerifiedInSubmission[` $\sidx$ `]`.
      - The number `m` of entries from `proofIds` to consider as part of $\sid$ is given by `Min(numUnverifiedFromSubmission, numProofIdsRemaining)`.
    - Use the submission Id $\sid$ and the Merkle "interval" proof from the submission proof, to check that the `m` next entries from `proofIds` (including $\pid$) indeed belong to the submission $\sid$.  Reject the transaction if this check fails.
    - Increment the entry `numVerifiedInSubmission[` $\sidx$ `]` by `m`, indicating that `m` more proofs from the submission have been verified.
    - update `nextSubmissionIdxToVerify` in contract state, if all proofs from this submission have been verified

> See the `UpaVerifier.sol` file for the code corresponding to the above algorithm

### Proof verification by the application

The application client now creates the transaction calling the application's smart contract to perform the business logic.  Since the proof has already been submitted to the UPA, the proof is not required in this transaction.  If the proof was submitted as part of a multi-entry submission, the client must compute and send a `ProofReference` structure, indicating which submission the proof belongs to, and its "location" (or index) within it.

The application contract computes the public inputs, exactly as it otherwise would under normal operation, and queries the UPA contract (using the proofRef if given) to confirm the existence of a corresponding verified proof.

For proofs from single-entry submissions, the UPA provides the entry point:
```solidity!
function isVerified(
        uint256 circuitId,
        uint256[] calldata publicInputs)
    external
    view
    returns (bool);
```

For proofs from multi-entry submissions:
```solidity!
function isVerified(
        uint256 circuitId,
        uint256[] calldata publicInputs,
        ProofReference calldata proofRef)
    external
    view
    returns (bool);
```

The UPA contract:

- computes $\pid$ from the public inputs
- (using the `ProofReference` if necessary) confirms that $\pid$ belongs to a submission $\sid$ and reads the submission index $\sidx$.
- given $\sidx$ and the index `i` of the proof within the submission (taken from the `ProofReference`, or implicitly `0` for the single-entry submission case), the existence of a verified proof is given by the boolean value: `numVerifiedInSubmission[`$\sidx$`] > i`

## Censorship resistance

A censorship event is considered to have occured for a submission with Id $\sid$ (with submission index $\sidx$, consisting of $n$ entries) if all of the following are satisfied:

- a submission with Id $\sid$ has been made, and **all** proofs in the submission are valid for the corresponding public inputs and circuit Ids
- some of the entries in $\sid$ remain unverified, namely
  - `numVerifiedInSubmission[`$\sidx$`] < `$n$
- one or more proofs from submission with index greater than $\sidx$ (the submission index of the submission with id $\sid$) have been included in an aggregated batch.  Namely, there exists $j > \sidx$ s.t. `numVerifiedInSubmission[`$j$`] > 0` (or alternatively `nextSubmissionIdxToVerify` $> \sidx$)

Note that, if one or more entries in a submission are invalid, aggregators are not obliged to verify any proofs from that submission.


Censorship by an *Aggregator* can be proven by a *claimant*, by calling the method:

```solidity!
function challenge(
    uint256 circuitId,
    Proof calldata proof,
    uint256[] calldata publicInputs,
    bytes32 submissionId,
    bytes32[] proofIdMerkleProof,
    bytes32[] proofDigestMerkleProof,
) external;
```

providing:

- the **valid** tuple $(\cid, \pi, \PI)$, or `circuitId`, `proof` and `publicInputs`, the claimed next unverified entry in the submission
- $\sid$ or `submissionId`
- A Merkle proof that $\pid_i$ (computed from $\cid_i$ and $\PI_i$) belongs to the submission (at the "next index" - see below)
- A Merkle proof that $\pi_i$ belongs to the submission's `proofDigest` entry (at the "next index" - see below)

Here "next index" is determined by the `numVerifiedInSubmission` entry for this submission. That is, proofs that have been skipped by the aggregators must be provided in the order that they occur in the submission.

On receipt of a transaction calling this method, the contract:

- checks that the conditions above hold and that the provided proof has indeed been skipped
- checks the claimant is the original submitter
- looks up the verification key $\vk$ using $\cid$ and performs the full proof verification for $(\vk, \pi, \PI)$.  The transaction is rejected if the proof is not valid.
- increments the stored count `numVerifiedInSubmission[`$\sidx$`]`

The aggregator is punished only when all proofs in the submission have been shown to be valid.  As such, after the above, the contract:

- checks the condition `numVerifiedInSubmission[`$\sidx$`] == n` (where `n` is the number of proofs in the original submission $\sid$).
- if this final condition holds then validity of all proofs in the submission has been shown and the aggregator is punished.

Note: `proofDigest` is used here to prevent malicious clients from submitting invalid proofs, forcing aggregators to skip their proofs, and then later provide valid proofs for the same public inputs. This would otherwise be an attack vector since `proofId` is not dependent on the proof data.

> TODO: the above assumes a single aggregator.  For multiple aggregators, we must record extra information in order to determine which aggregator skipped a valid proof.
> We may need to introduce some time interval during which claims can be made (e.g. claims must be made before the proof index increases more than 2^12, say).  Similarly, if penalties are to be paid from stake, aggregators should have an "unbonding period" of at least this interval.


## Circuit Statements

Batches of $n$ application proofs are verified in a *batch verify* circuit using [batched Groth16 verification](https://hackmd.io/ll9PUdzSSO2nUvfNn5Y_0g).

A *keccak circuit* computes all $\pid$s of application proofs appearing in the *batch verify* proof, along with a *final digest* (the keccak hash of these $\pid$s, used to reduce the public input size of the outer circuit below).

A collection of $N$ *batch verify* proofs along with the *keccak* proof for their $\pid$s and *final digest* is verified in an *outer* circuit.

On-chain verification of an outer circuit proof thereby attests to the validity of $n \times N$ application proofs with given $\pid$s.

- $n$ - inner batch size.  Application proofs per *batch verify* circuit.
- $N$ - outer batch size.  Number of *batch verify* circuits per outer proof.
- $L$ - the maximum number of public inputs for an application circuit.

### Batch Verify Circuit: Groth16 batch verifier

The batch verify circuit corresponds to the following relation:

- *Public inputs*:
  - $(\ell_i, \cid_i, \overline{\PI}_i)_{i=1}^n$ where
      - $\PI_i = (x_{i,j})_{j=1}^{\ell_i}$ is the public inputs to the $i$-th proof
      - $\overline{\PI}_i = \PI_i | \{0\}_{j=\ell_i + 1}^{L}$ is $\PI_i$ after zero-padded to extend it to length $L$

- *Witness values*:
  - $\overline{\vk_i}$ - application verification keys, each padded to length $L$
  - $(\pi_i)_{i=1}^n$ - application proofs

- *Equivalent Statement*:
  - $\cid_i = \computeCircuitId(\truncate(\ell_i, \overline{\vk_i}))$
  - $\overline{\PI}_i = \truncate(\ell_i, \overline{\PI_i}) | \{0\}_{j=\ell_i + 1}^{L}$
  - `Groth16.Verify`$(\overline{\vk_i}, \pi_i, \overline{\PI_i}) = 1$ for $i=1,\ldots,n$ ([batched G16](https://hackmd.io/PZmhPljxRZm_IA7FC4Gu7A))
  - where
      - $\truncate(\ell, \overline{\vk})$ is the truncation of the size $L$ verification key $\overline{\VK}$ to a verification key of size $\ell$, and
      - $\truncate(\ell, \overline{\PI})$ is the truncation of the public inputs to an array of size $\ell$

### Keccak Circuit: ProofIDs and Final Digest

Computes the $\pid$ for each entry in each application proof in one or more verify circuit proofs.

- *Public inputs*:
  - $c^*, (\ell_i, \cid_i, \overline{\PI}_i)_{i=1}^{n \times N}$ where
      - $\PI_i = (x_{i,j})_{j=1}^{\ell_i}$ is the public inputs to the $i$-th proof
      - $\overline{\PI}_i = \PI_i | \{0\}_{j=\ell_i + 1}^{L}$ is $\PI_i$ after zero-padded to extend it to length $L$
    - $c^* = (c^*_1, c^*_2)$ (32 byte *final digest*, represented by two field elements)
- *Witness values*: (none)
- *Statement*:
    - $c_i = \keccak(\cid_i || \truncate(\ell_i, \overline{\PI_i}))$
    - $c^* = \keccak(c_1 || c_2 || \ldots || c_{n \times N})$

### Outer Circuit: Recursive verification of Batch Verifier and Keccak circuits

This circuit checks the validity of $N$ *batch verify* proofs ${\ipi}^{(j)}, j = 1, \ldots N$ as well as a single corresponding *keccak* proof $\pi_{keccak}$.

- *Public Inputs*:
    - $c^*$ - 32-byte *final digest*, encoded as $(c_1, c_2) \in \mathbb{F}_r^2$
    - $(L, R) \in \mathbb{G}_1^2$ - overall KZG accumulator, encoded in $(\mathbb{F}_r)^{12}$
      where $12$ comes from $4 \times$ `num_limbs`.
- *Witness values*:
    - $(\ell_{j,i}, \cid_{j,i}, \overline{\PI}_{j,i}, \pid_{j,i})$ for $i=1,\ldots, n$, $j=1, \ldots, N$, the number of public inputs, the circuit ID, padded public inputs and proof ID for the $i$-th application proof in the $j$-th BV proof.
    - $(\ipi^{(j)})$ for $j=1, \ldots, N$ BV proofs
    - $\pi_{\keccak}$ the keccak proof for public inputs
        - $c^*$, and
        - $(\ell_{1,1}, \cid_{1,1}, \overline{\PI}_{1,1}), (\ell_{1,2}, \cid_{1,2}, \overline{\PI}_{1,2}), \ldots , (\ell_{1,n}, \cid_{1,n}, \overline{\PI}_{1,n}),$
        - $(\ell_{2,1}, \cid_{2,1}, \overline{\PI}_{2,1}), (\ell_{2,2}, \cid_{2,2}, \overline{\PI}_{2,2}), \ldots , (\ell_{2,n}, \cid_{2,n}, \overline{\PI}_{2,n}),$
        - $\cdots$
        - $(\ell_{N,1}, \cid_{N,1}, \overline{\PI}_{N,1}), (\ell_{N,2}, \cid_{2,N}, \overline{\PI}_{N,2}), \ldots , (\ell_{N,n}, \cid_{N,n}, \overline{\PI}_{N,n}),$
- *"Equivalent Statement"*: (actual statement is shown as multiple sub-statements, given below)
    - For each $j=1,\ldots, N$, $\ipi^{(j)}$ is a valid proof of the *batch verify* circuit, for public inputs $(\ell_{j,i}, \cid_{j,i}, \overline{\PI}_{j,i})_{i=1}^n$, namely:
      $$\snark_{\BV}.\Verify \left( \ipi^{(j)}, (\ell_{j,i}, \cid_{j,i}, \overline{\PI}_{j,i})_{i=1}^n, \vk_{\BV} \right) = 1$$
    - Keccak proof is valid, and therefore $c^{*}$ is the *final digest* for all application PIs and vk hashes, namely:
      $$\snark_{\keccak}.\Verify \left(\pi_\keccak, c^*,(\ell_{j,i}, \cid_{j,i}, \overline{\PI_{j,i}})_{\substack{i=1,\ldots, n \\ j=1,\ldots,  N}}, \vk_\keccak \right)=1$$

- Actual Statement:
    - "Succinct" Plonk verification ($\sv$) namely "GWC Steps 1-11" using Shplonk, without final pairing:
      $$\begin{gathered}
      (L_j, R_j) = \sv \left( \ipi^{(j)}, (\ell_{j,i}, \cid_{j,i}, \overline{\PI_{j,i}})_{i=1}^n, \vk_{\BV} \right) ~\text{ for } j=1,\ldots N \\
      (L_{N+1}, R_{N+1}) = \sv \left( \pi_\keccak, c^*,(\ell_{j,i}, \cid_{j,i}, \overline{\PI_{j,i}})_{\substack{i=1,\ldots, n \\ j=1,\ldots,  N}}, \vk_\keccak \right) \\
      (L, R) = \sum_{j=1}^{N+1} r^j (L_j, R_j)
      \end{gathered}$$
      for random challenge scalar $r$.
- Verification: given $(\pi_{\text{outer}}, L, R, c^*)$, the on-chain verifier performs the following:
    - $(L_\outercircuit, R_\outercircuit) := \sv(\pi_\outercircuit, L, R, c^*, \vk_\outercircuit)$
    - for random challenge scalar $r'$, check that $e(L + r' L_\outercircuit, [\tau]_2) \stackrel{?}{=} e(R + r' R_\outercircuit, [1]_2)$


Note:

- The same witness values $\overline{\PI}_{i,j}$ are used in the *outer* circuit to verify $\ipi^{(j)}$ and $\pi_{keccak}$, implying that $c^*$ is indeed the commitment to all application public inputs and circuit IDs.
- The outer circuit does not include the final pairing checks, therefore its statement is not that the BV/Keccak proofs are *valid*, but rather that they have been correctly accumulated into a single KZG accumulator $(L,R)$. Checking that $e(L + r' L_\outercircuit, [\tau]_2) \stackrel{?}{=} e(R + r' R_\outercircuit, [1]_2)$, for random scalar $r'$, therefore implies their validity.
