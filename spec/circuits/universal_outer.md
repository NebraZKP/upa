# Universal Outer Circuit Specification

## Overview
The Universal Outer (a.k.a. outer) circuit is one of the three circuits which constitute the Universal Proof Aggregator (UPA), together with the Universal Batch Verifier (UBV) circuit and the variable length keccak circuit.

The outer circuit will take an outer batch of $`B_O`$ UBV Halo2 proofs with inner batch size $`B_I`$ and a keccak Halo2 proof and check:
- The keccak instance matches the UBV instances in the sense described in Copy Constraints (below).
- All the UBV proofs are valid.
- The keccak proof is valid.

## Conventions and Terminology

- $`e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T`$ denotes pairing on the BN254 elliptic curve
- $`g_1 \in \mathbb{G}_1`$ and $`g_2 \in \mathbb{G}_2`$ denote the respective generators.
- $`\mathbb{F}_r`$ denotes the scalar field of BN254.
- $`\mathbb{F}_p`$ denotes the base field of BN254.
- We use $`k = 1, \dots, M`$ to index $`\mathsf{keccak}`$ related variables.
- We use $`i = 1, \dots, B_I`$ and $`j = 1, \dots, B_O`$ to index $`\mathsf{UBV}`$ related variables.

## Configuration
The universal outer circuit is determined by the following parameters:

- `ubv_config`: The configuration of the UBV circuit whose proofs we're aggregating. It consists of:
    - `degree_bits`, `lookup_bits`, `limb_bits`, `num_limbs`.
    - `max_num_public_inputs`: The maximum number of public inputs allowed per application proof.
    - `inner_batch_size`: The number of Groth16 proofs aggregated. This is $`B_I`$.
- `outer_batch_size`: The number of UBV proofs to be aggregated. This is $`B_O`$
- `degree_bits`: The $`\log_2`$ of the number of rows.
- `lookup_bits`: The $`\log_2`$ of the number of rows allocated for lookup tables. Usually `degree_bits-1`.
- `limb_bits`: The bit size of limbs to represent an $`\mathbb{F}_p`$ element.
- `num_limbs`: The number of limbs to represent an $`\mathbb{F}_p`$ element.

## Inputs
The inputs to this circuit are:
- UBV circuit verifying key $`\mathsf{vk}_\mathsf{UBV}`$, generated with `ubv_config`.
- Keccak circuit verifying key $`\mathsf{vk}_\mathsf{keccak}`$.
- $`B_O`$ UBV instances and proofs $`\left\{ \{vk_i^j, n_i^j, \ell_i^j, \textsf{comm}_i^j, m_i^j, \overline{P}_i^j   \}_{i=1}^{B_I}, \pi^j_\mathsf{UBV} \right\}_{j=1}^{B_O}`$.
- one keccak instance and proof $`\left( \{vk_k, n_k, \ell_k, \textsf{comm}_k, m_k, \overline{P}_k \}_{k=1}^M \cup \{F_1, F_2\}, \pi_\mathsf{keccak}\ \right)`$.

where $`M = B_I * B_O`$.

## Detailed description

### Snark verifier
We use [snark-verifier](https://github.com/axiom-crypto/snark-verifier)'s `AggregationCircuit`. This circuit takes in a vector of so-called `SNARK`s, which consist of an augmented (i.e. with some metadata) verification key, a proof and an instance of a circuit.

The `AggregationCircuit` then runs steps 1-11 of the [Plonk verification algorithm](https://eprint.iacr.org/2019/953.pdf) (but using the Shplonk KZG multiopening scheme). That is, everything except for the pairing check on each `SNARK`. Then it does a random linear combination of the resulting $`\mathbb{G}_1`$ points, returning a pair $`h_1, h_2 \in \mathbb{G}_1`$. This last pair passing the pairing check is equivalent to all proofs being valid against their respective instances.

The `AggregationCircuit` interface gives access to the cells holding the instances of the `SNARK`s. By default, these are private witnesses to the `AggregationCircuit`. One may impose extra constraints on them or expose these as instances of the `AggregationCircuit` itself. In our case, we copy constrain the instances of the UBV `SNARK`s to match the corresponding instances of the Keccak `SNARK` and expose the final Keccak digest as a public input to the `AggregationCircuit`.

### Copy constraints
We impose the following copy constraints on the inputs (recall the indexing convention) for all $`i, j`$:
- $`vk_{(j-1)B_I + i} = vk_i^j`$ for all $`i, j`$, which is enforced element-wise ($`vk`$ is a concatenation of non-native limb decompositions of $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$ points).
- $`n_{(j-1)B_I + i} = n_i^j`$ for all $`i, j`$.
- $`\ell_{(j-1)B_I + i} = \ell_i^j`$ for all $`i, j`$.
- $`\textsf{comm}_{(j-1)B_I + i} = \textsf{comm}_i^j`$
- $`m_{(j-1)B_I + i} = m_i^j`$, which is enforced element-wise ($`m`$ is a non-native limb decomposition of a $`\mathbb{G}_1`$ point).
- $`\overline{P}_{(j-1)B_I + i} = \overline{P}_i^j`$, which is enforced element-wise ($`\overline{P}`$ is a vector of length `max_num_public_inputs` defined in the `ubv_config`).

### Expose instance
We expose the final keccak digest (see the keccak spec) $`\{ F_1, F_2 \}`$ as further public inputs.

## Instance

This circuit's instance consists of $$\{h_1, h_2, F_1, F_2 \},$$ where $`h_1, h_2`$ are the $`\mathbb{G}_1`$ points returned by `AggregationCircuit`. Note that the $`\mathbb{G}_1`$ points will be represented by 6 $`\mathbb{F}_r`$ elements each (two $`\mathbb{F}_p`$ coordinates per curve point times three limbs per $`\mathbb{F}_p`$ element).

## Statement
A batch of $`B_O`$ UBV proofs has been aggregated with a keccak proof, and their instances coincide. The accumulated pairing check points are $`h_1`$ and $`h_2`$ and the final keccak digest of the public inputs with their circuitIDs is given by $`\{F_1, F_2\}`$ (see the keccak circuit spec for more details).

### Note
To verify the validity of the statement, one must:
- perform a pairing check on $`h_1, h_2`$.
- verify the outer proof $`\Pi`$ generated by this circuit (which attests that $`h_1`$ and $`h_2`$ have been computed correctly).

Both pairings can be done in one go using a random linear combination.
