# Universal Batch Verifier Specification

## Overview

The Universal Batch Verifier (UBV) circuit is one of the three circuits which constitute the Universal Proof Aggregator (UPA), together with the Variable Length Keccak circuit and the Outer circuit.

In the following, $`vk`$ will denote a Groth16 verifying key (resulting from a circuit's trusted setup), $`\pi`$ a Groth16 proof and $`P`$ the public inputs.

The UBV circuit verifies that a set $`\{ (vk_i, \pi_i, P_i) \}_{i = 1}^{B}`$ of tuples: Groth16 verification key, Groth16 proof and public inputs, are all valid.  That is, `Groth16.Verify` $`( $vk_i, \pi_i, P_i ) ` = 1$ for each $`i = 1, \ldots, B`$.

### LegoSNARK Extension
The UBV circuit supports [LegoSNARK](https://eprint.iacr.org/2019/142)'s "commit-and-prove" extension to the original Groth16 proof system, meaning that  $`\pi`$ may contain a Pedersen commitment to certain witness values. Specifically, UBV supports up to 1 commitment to *private* witness values. Multiple Pedersen commitments and commitments to public witness values are *not* supported.

In this case $`\pi`$ includes points $`(m, pok) \in \mathbb{G}_1 \times \mathbb{G}_1`$ and $`vk`$ includes points $`(h_1, h_2) \in \mathbb{G}_2 \times \mathbb{G}_2`$. Here $`m`$ is a Pedersen commitment to private witness values and $`pok`$ is an accompanying proof of knowledge. The proof of knowledge is valid iff
```math
e(m, h_1) e(pok, h_2) = 1
```

The LegoSNARK extension modifies the original Groth16 proving system as follows:
- The verifier checks that $`e(m, h_1) e(pok, h_2) = 1`$
- The verifier derives an additional public input point $`p`$ from $`m`$ using a curve-to-field hash function (specified below)
- The verifier adds $`m`$ to the usual Groth16 public input term (see Step 4 below)

## Conventions and Terminology

- $`e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T`$ denotes the pairing over the BN254 elliptic curve.
- $`g_1 \in \mathbb{G}_1`$ and $`g_2 \in \mathbb{G}_2`$ denote the respective generators.
- $`\mathbb{F}_r`$ denotes the scalar field of BN254
- $`\mathbb{F}_p`$ denotes the base field of BN254

## Configuration

The Universal Batch Verifier (UBV) circuit is determined by the following parameters:
- `degree_bits`: The $\log_2$ of the number of rows.
- `lookup_bits`: The $\log_2$ of the number of rows allocated for lookup tables. Usually `degree_bits-1`.
- `limb_bits`: The bit size of limbs to represent an $F_p$ element.
- `num_limbs`: The number of limbs to represent an $F_p$ element.
- `batch_size`: The number of Groth16 proofs to be verified. This is $B$ in the statement.
- `num_public_inputs`: The maximum number of public inputs allowed in one application proof instance. We call this $L$.

## Inputs

This is the information required to generate a witness to the circuit. See `SafeCircuit::CircuitInputs` in the code.

Let $`\{ (vk_i, \pi_i, P_i) \}_{i = 1}^{B}`$ be a batch of Groth16 proofs that the prover wants to show are valid. Let $`\ell_i`$ be the number of public inputs to the circuit for $vk_i$, so that $`P_i = (P_{1i}, \ldots, P_{\ell_i i})`$. In the original Groth16 proof system,
- $`vk_i`$ denotes the verification key. It consists of:
    - $`\alpha_i \in \mathbb{G}_1`$
    - $`\beta_i \in \mathbb{G}_2`$
    - $`\gamma_i \in \mathbb{G}_2`$
    - $`\delta_i \in \mathbb{G}_2`$
    - $`s_i = (s_{0i}, s_{1i}, \dots, s_{\ell_i i}) \in \mathbb{G}_1^{i+1}`$
- $`\pi_i = (A_i, B_i, C_i) \in \mathbb{G}_1 \times \mathbb{G}_2 \times \mathbb{G}_1`$ denotes the proof
- $`P_i \in \mathbb{F}_r^{\ell_i}`$ denotes the instance to the $i$-th Groth16 circuit, where $`\ell_i \leq L`$.

In the LegoSNARK extension (with 1 Pedersen commitment to private witness values), we have the following additional inputs:
- $`vk_i`$ contains
    - An additional term $`s_{\ell_i + 1} \in \mathbb{G}_1`$
    - A Pedersen verifying key $`(h_1, h_2) \in \mathbb{G}_2 \times \mathbb{G}_2`$
- $`\pi_i`$ contains
    - A Pedersen commitment $`m \in \mathbb{G}_1`$
    - A Pedersen proof of knowledge $`pok \in \mathbb{G}_1`$

Note that because the LegoSNARK extension introduces a new public input value derived from $`m`$, circuits using this extension must have $`\ell_i + 1 \leq L`$.

We emphasize that the LegoSNARK extension is optional. Therefore these additional input data may not be present, in which case the preprocessing step below will insert "padding" data that trivially satisfy the pairing check $`e(m,h_1)e(pok,h_2)=1`$. The UBV circuit ensures that these padding data do not affect the result of ordinary Groth16 verification.

### Preprocessing
Before feeding the inputs to the circuit, they undergo some preprocessing. The circuit doesn't do this preprocessing but it checks it has been done correctly. For each input $`(vk_i, \pi_i, P_i)`$, we construct a batch entry as follows:
- Detect whether the optional LegoSNARK extension is being used: Let $`n_i = 1`$ if $`vk_i`$ contains a Pedersen verifying key and let $`n_i = 0`$ otherwise. Check also that $`\pi_i`$ contains a Pedersen commitment iff $n_i=1$.

#### VK Padding:
- Pad the verification key's public input terms with the generator:
```math
s_i \longrightarrow \overline{s}_i = (s_{ji})_{j=0}^{\ell_i + n_i} || (g_1)_{j=\ell_i + n_i + 1}^L
```
- If $n_i = 0$, pad the verification key with a trivial Pedersen commitment verifying key $`h_1 = h_2 = g_2`$.

The preprocessed verifying key $`\overline{vk}_i`$ is then
- If $n_i = 0$ (ordinary Groth16):
```math
vk_i \longrightarrow \overline{vk}_i = (\alpha_i, \beta_i, \gamma_i, \delta_i, \overline{s}_i, g_2, g_2)
```
- If $n_i = 1$ (LegoSNARK extension):
```math
vk_i \longrightarrow \overline{vk}_i = (\alpha_i, \beta_i, \gamma_i, \delta_i, \overline{s}_i, h_1, h_2)
```
#### Proof padding:
- If $n_i = 0$: pad with trivial Pedersen commitment $`\overline{m}=g_1`$ and proof of knowledge $`\overline{pok}=-g_1`$
```math
\pi_i \longrightarrow \overline{\pi_i} = (A_i, B_i, C_i, \overline{m}, \overline{pok})
```
- If $n_i = 1$: No padding required: $`\overline{\pi_i} = \pi_i`$

#### Public Input padding:
- Pad the public input with zeroes:
```math
P_i \longrightarrow \overline{P}_i = (P_{ji})_{j=1}^{\ell_i} || (0)_{j = \ell_i+1}^L
```
- Cast the public input length as an $`\mathbb{F}_r`$ element (we continue to denote it by $`\ell_i`$ without confusion).
#### Commitment hash computation:
Hash the Pedersen commitment point $`\overline{\pi_i}.m`$. The curve-to-field hash function used is:
- Decompose $`m`$ into bytes: concatenate the 32-byte big-endian representations of the $`x`$ and $`y`$ coordinates of the affine representation of $`m`$ to obtain a 64-byte representation of $`m`$.
- Compute the 32-byte Keccak digest of the byte representation of $`m`$.
- Interpret these bytes as the big-endian byte representation of a 256-bit integer.
- Reduce modulo $`r`$ to obtain an $`\mathbb{F}_r`$ element $`\textsf{comm}_i`$.

When $n_i=1$, this commitment hash is treated as another public input. The commitment hash is computed even when $`n_i=0`$ using the padding value $`\overline{\pi_i}.m=g_1`$, though in this case the result will not be used:
- If $n_i=1$, we set $`P_{\ell_i +1, i} = \textsf{comm}_i`$.
- If $n_i=0$, leave $`P_{\ell_i +1, i} = 0`$.

The commitment hash computation is the only preprocessing step whose correctness is not enforced by UBV circuit constraints. Instead it is performed in a separate Keccak circuit and a final layer of recursion (Universal Outer Circuit) constrains the commitment hash computed at this preprocessing step to the corresponding output from the Keccak circuit.

The UBV circuit *does* enforce the correct assignment of $`P_{\ell_i +1, i}`$, according to the value of $n_i$. (See Step 1c below.)

#### Circuit Inputs
After preprocessing, the $i$-th batch entry is given by $`BE_i = (\ell_i, n_i, \overline{vk}_i, \overline{\pi_i}, \overline{P}_i, \textsf{comm}_i)`$, and the inputs to the circuit consist of the set of all batch entries $`\{BE_i\}_{i=1}^B`$.

## Components

### First $\ell$ bits bitmask
- Input: a natural number $`N \in \mathbb{N}`$ and a length $`\ell \leq N`$. We consider $`\ell \in \mathbb{F}_r`$.
- A vector of bytes (aka bitmask): $`\mathfrak{b} = (b_0, \dots, b_{N-1})`$ such that:
    - $`b_k = 1`$ for $`k = 0, 1, \dots, \ell-1`$.
    - $`b_k = 0`$ for $`k = \ell, \ell+1, \dots, N-1`$.
- Description:
    - Initialize $`e = 1 \in \mathbb{F}_r`$.
    - Iterate over $`i \in \{0, 1, \dots, N \}`$.
    - For each $`i`$:
        - Let $`e = e - \textrm{is\_equal}(i, \ell)`$.
        - $`b_i = e`$

### $\ell$-th bit bitmask
- Input: a natural number $`N \in \mathbb{N}`$ and a length $`\ell \leq N`$. We consider $`\ell \in \mathbb{F}_r`$.
- A vector of bytes (aka bitmask): $`\mathfrak{b} = (b_0, \dots, b_{N-1})`$ such that:
    - $`b_k = 1`$ for $`k = \ell`$.
    - $`b_k = 0`$ for $`k \not= \ell`$.
- Description:
    - Iterate over $`i \in \{0, 1, \dots, N \}`$.
    - For each $i$:
        - Assign $`i \in \mathbb{F}_r`$ as a witness.
        - $`b_k = \textrm{is\_equal}(i, \ell)`$

## Detailed description


### Step 1: Check the entries

#### Step 1a: Check the padding
Assert that $n_i \in \{0,1\}$.
##### Public Input Padding
For $`i = 1, \dots, B`$, the circuit asserts that
$$\overline{P}_{ji} = 0$$
for $`j = \ell_i + n_i + 1, \dots, L`$. It does the computation in two steps:
- First, we enforce that $\ell_i + n_i \leq L$ and compute a first $`\ell_i + n_i `$ bits bitmask $`\mathfrak{b}_i`$ from $`\ell_i + n_i`$, which has ones in the first $`\ell_i + n_i`$ positions and zeroes everywhere else.
- Second, for $`j = 1, \dots, L`$:
    - assert $`(1-b_j)*\overline{P}_j = 0`$, where $`b_j`$ denotes the $j$-th bit in $`\mathfrak{b}_i`$.

##### VK Padding
The circuit asserts that $`\overline{s_{ji}} = g_1`$ for $`j = \ell_i + n_i + 1, \dots, L`$:
- First, compute a bitstring $`\textrm{is\_gen}_i`$ as
```math
\textrm{is\_gen}_{ji} = (\overline{s}_{ji} == g_1), \quad j=1, \dots, L,
```
which indicates whether a given element in the padded $`\overline{vk_i}`$ is the $`\mathbb{G}_1`$ generator or not.
- Second, for $`j = 1, \dots, L`$: assert $`(1-b_j)*(1-\textrm{is\_gen}_{ji}) = 0`$.

To check the correct padding of the Pedersen verifying key, the circuit computes boolean values `h_1_is_padding` := $`(\overline{vk_i}.h_1 == g_2)`$ and `h_2_is_padding` := $`(\overline{vk_i}.h_2 == g_2)`$ and asserts
```
n_i \lor ( h_1_is_padding \land h_2_is_padding )
```
In other words, $`n_i = 0`$ implies that the Pedersen verifying key in $`\overline{vk_i}`$ is padding.

##### Proof Padding
Similar to the padding check on the Pedersen verifying key, the circuit computes boolean values `m_is_padding` := $`(\overline{\pi_i}.m == g_1)`$ and `pok_is_padding` := $`(\overline{\pi_i}.pok == -g_1)`$ and asserts
```
n_i \lor ( m_is_padding \land pok_is_padding )
```
In other words, $`n_i = 0`$ implies that the Pedersen commitment and proof of knowledge in $`\overline{\pi_i}`$ are padding.

#### Step 1b: Check the proof and verifying key points
For $`i = 1, \dots, B`$, the circuit asserts that the proof points in $`\pi_i`$ lie on the right curves, i.e., $`A_i, C_i, m, pok \in \mathbb{G}_1`$ and $`B_i \in \mathbb{G}_2`$. It does so by checking the curve equations on their $X$ and $Y$ coordinates:
```math
Y^2 = X^3 + b
```
where $`b = 3`$ for $`\mathbb{G}_1`$ and
```math
\begin{align}
b &= 19485874751759354771024239261021720505790618469301721065564631296452457478373 \\ &+ 266929791119991161246907387137283842545076965332900288569378510910307636690 u
\end{align}
```
for $`\mathbb{G}_2`$. Here $u$ is the root of the irreducible polynomial $X^2 + 1 \in \mathbb{F}_p[X]$.

The circuit does the same for the verifying key $`\overline{vk}_i`$ points, i.e., asserts that $`\alpha_i, \overline{s}_{ij} \in \mathbb{G}_1`$ and $`\beta_i, \gamma_i, \delta_i, h_1, h_2 \in \mathbb{G}_2`$

#### Step 1c: Constrain commitment hash
The commitment hash was computed out-of-circuit during the Preprocessing phase. It should affect the circuit's computation only when $`n_i=1`$, in which case it is treated as the $`\ell_i+1`$ th public input term. If $`n_i=0`$ then this term should be 0.

The UBV circuit enforces this condition as follows:
- Compute an [$`\ell_i`$-th bit bitmask](#th-bit-bitmask) $`\mathfrak{b}`$ from $\ell_i+1$ which has a 1 in the $`\ell_i`$-th index (starting from 0) and zeroes everywhere else.
- Compute the inner product of $`\mathfrak{b}`$ with the public input vector. This returns the value of the public input vector at index $`\ell_i`$.
- Constrain this to equal $`n_i \times \textsf{comm}_i`$.

### Step 2: Compute VK Hash
For $`i = 1, \dots, B`$, the circuit computes the Poseidon hash of the padded verification key
$$\mathsf{vkHash}_i = \mathsf{poseidon}(\overline{vk}_i),$$
where $`\mathsf{poseidon}`$ denotes the hash function constructed by applying the duplex sponge construction (with $`\textrm{RATE} = 2`$) to the Poseidon permutation (with 8 full rounds and 57 partial rounds).

To compute $`\mathsf{vkHash}`$:
- Absorb $`\alpha_i || \beta_i || \gamma_i || \delta_i || \overline{s} || h_1 || h_2`$ (represented in their non-native limb decompositions)
- Squeeze

Note that we absorb the padded versions of $`vk.s`$ and $`vk.h_i`$.

### Step 3: Compute challenge points
We compute challenge points $`c, t \in \mathbb{F}_r`$ in the following way:

Let $`\mathsf{poseidon}`$ denote a Poseidon hasher with the same parameters as in Step 2, initialized instead with the domain tag "UPA Challenge". For each $`i = 1, ... B`$, absorb $`\mathsf{vkHash}_i || \pi_i || \overline{P}_i`$.

Squeeze once to obtain $c$ and once more to obtain $t$.


### Step 4: Compute the public input pairs
The circuit computes the public input terms $S_i$ for $i=1, \ldots, B$, namely
```math
S_i = \left( \overline{s}_{0i} + \sum_{j=1}^{L} \overline{P}_{ji} \overline{s}_{ji} \right) + n_i \cdot m_i \in \mathbb{G}_1.
```
and returns pairs
```math
\{ (S_i, \gamma_i) \}_{i=1}^B
```

### Step 5: Compute the other pairs
For $`i = 1, \dots, B`$, scales:
- $`A_i \rightarrow \tilde{A}_i = -c^{i-1} A_i`$
- $`C_i \rightarrow \tilde{C}_i = c^{i-1} C_i`$
- $`S_i \rightarrow \tilde{S}_i = c^{i-1} S_i`$
- $`\alpha_i \rightarrow \tilde{\alpha}_i = c^{i-1} \alpha_i`$
- $`m_i \rightarrow \tilde{m}_i = c^{i-1}t \cdot m_i`$
- $`pok_i \rightarrow \tilde{pok}_i = c^{i-1}t \cdot pok_i`$

and returns the pairs $`(\tilde{A}_i, B_i)`$, $`(\tilde{C}_i, g_2)`$, $`(\tilde{S}_i, \gamma_i)`$, $`(\tilde{\alpha}_i, \beta_i)`$, $`(\tilde{m}_i, h_{1,i})`$, $`(\tilde{pok}_i, h_{2,i})`$.

### Step 6: Compute the pairing
Given pairs $`\{ (\tilde{A}_i, B_i), (\tilde{C}_i, \delta_i), (S_i, \gamma_i), (\tilde{\alpha}_i, \beta_i), (\tilde{m}_i, h_{1,i}), (\tilde{pok}_i, h_{2,i}) \}_{i=1}^B`$, compute the pairing
```math
\prod_{i=1}^B e(\tilde{A}_i, B_i) e(\tilde{C_i}, \delta_i) e(\tilde{S}_i, \gamma_i) e(\tilde{\alpha}_i, \beta_i) e(\tilde{m}_i, h_{1,i}) e(\tilde{pok}_i, h_{2,i}).
```
The pairing computation is split into two phases:
- multi Miller loop of all pairs
- final exponentiation

### Step 7: Check final result
Asserts the output of the computation above equals the identity in $`\mathbb{G}_T`$.

Note that the pairs $`(\tilde{m}_i, h_{1,i}), (\tilde{pok}_i, h_{2,i})`$ have been scaled by the factor $`c^{i-1}t`$, making them independent of the pairs scaled by the factor $`c^{i-1}`$. Therefore the above pairing check passing implies that (e.w.n.p.)
```math
\begin{aligned} \prod_{i=1}^B e(\tilde{A}_i, B_i) e(\tilde{C_i}, \delta_i) e(\tilde{S}_i, \gamma_i) e(\tilde{\alpha}_i, \beta_i) &= 1 \\ \prod_{i=1}^B e(\tilde{m}_i, h_{1,i}) e(\tilde{pok}_i, h_{2,i}) &= 1 \end{aligned}
```

## Instance

This circuit's instance consists of
```math
\{ (vk_i, n_i, \ell_i, \mathsf{comm}_i, m_i, \overline{P}_i) \}_{i=1}^B.
```
In other words,

```
  [
    // Instance for application proof 1
    num_public_inputs_1,
    padded_vk_1_limb_decomposition,
    has_commitment_1,
    commitment_hash_1,
    commitment_1_limb_decomposition,
    public_inputs_1_1,
    public_inputs_1_2,
    ...
    public_inputs_1_L

    ...

    // Instance for application proof B
    num_public_inputs_B,
    padded_vk_B_limb_decomposition,
    has_commitment_B,
    commitment_hash_B,
    commitment_B_limb_decomposition,
    public_inputs_B_1,
    public_inputs_B_2,
    ...
    public_inputs_B_L
  ]
```
where
- `padded_vk_i_limb_decomposition` denotes the concatenation of the limb decompositions of $`vk.\alpha, vk.\beta, vk.\gamma, vk.\delta, vk.\overline{s}[0], \ldots vk.\overline{s}[L], vk.h_1, vk.h_2`$
- `has_commitment_i` equals 1 if the $i$ th circuit uses the LegoSNARK commitment and equals 0 otherwise
- `num_public_inputs_i` = $`\ell_i`$ (num public inputs for i-th circuit)
- `commitment_hash_i` = the result of hashing commitment point $`m_i`$ to $`\mathbb{F}_r`$
- `commitment_i_limb_decomposition` denotes the decomposition of $`m_i`$ into non-native limbs. (When $`n_i=0`$ then $`m_i`$ is the padding value $`g_1`$)
- `public_input_i_j` = $`\overline{P}_{ji}`$

## Equivalent Statement

The above circuit is equivalent (up to soundness) to the following:

For $`i = 1, \dots, B`$, there exists a verification key $`vk_i`$, public inputs $P_i$, and a proof $`\pi_i`$ such that either:
- Ordinary Groth16 case ($`n_i=0`$):
    - $`vk_i`$ has $`s_i`$ of length $`\ell_i+1`$
    - $`\mathsf{Groth16}.\mathsf{verify}(vk_i, \pi_i, P_i) = \mathsf{true}`$, where $`P_i \in \mathbb{F}_r^{\ell_i}`$ denotes the first $`\ell_i`$ elements of $`\overline{P}_i \in \mathbb{F}_r^{L}`$
    - $`\overline{P}_{ji} = 0`$ for $`j > \ell_i`$
- LegoSNARK extension case $`\mathsf{Groth16LSE}`$ ($`n_i=1`$):
    - $`vk_i`$ has $`s_i`$ of length $`\ell_i+2`$
    - $`\overline{P_i}[\ell_i] =`$ `commitment_hash_i` (using 0-indexing)
    - $`\mathsf{Groth16LSE}.\mathsf{verify}(vk_i, \pi_i, P_i) = \mathsf{true}`$, where $`P_i \in \mathbb{F}_r^{\ell_i}`$ denotes the first $`\ell_i+1`$ elements of $`\overline{P}_i \in \mathbb{F}_r^{L}`$
    - $`\overline{P}_{ji} = 0`$ for $`j > \ell_i+1`$

As mentioned in the Preprocessing section, the UBV circuit *does not* enforce that `commitment_hash_i` equals the hash-to-curve of $`m_i`$. Instead it exposes `commitment_hash_i` and $`m_i`$ (in the form of a limb decomposition) as public inputs. The verifier of the UBV circuit must check that `commitment_hash_i` $`=H(m_i)`$. In the UPA, this computation occurs in the Keccak circuit and the Outer circuit copy-constrains the Keccak/UBV circuit instances.
