// SPDX-License-Identifier: MIT
/*
    UPA is Nebra's first generation proof aggregation engine
                                         _.oo.
                 _.u[[/;:,.         .odMMMMMM'
              .o888UU[[[/;:-.  .o@P^    MMM^
             oN88888UU[[[/;::-.        dP^
            dNMMNN888UU[[[/;:--.   .o@P^
           ,MMMMMMN888UU[[/;::-. o@^
           NNMMMNN888UU[[[/~.o@P^
           888888888UU[[[/o@^-..
          oI8888UU[[[/o@P^:--..
       .@^  YUU[[[/o@^;::---..
     oMP     ^/o@P^;:::---..
  .dMMM    .o@^ ^;::---...
 dMMMMMMM@^`       `^^^^
YMMMUP^
 ^^
*/
pragma solidity 0.8.26;

import "./IGroth16Verifier.sol";

// Contract receiving proofs to be aggregated.  Application clients should
// interact with the contract using this interface.
interface IUpaProofReceiver {
    /// Emitted when an application VK is registered.
    event VKRegistered(bytes32 indexed circuitId, Groth16VK vk);

    /// Emitted when an application proof is submitted to the receiver
    /// contract.
    event ProofSubmitted(
        bytes32 indexed proofId,
        uint64 submissionIdx,
        uint64 proofIdx
    );

    /// Returns the maximum number of proofs that can be submitted at once.  0
    /// indicates that the contract itself does not impose a limit.
    // solhint-disable-next-line
    function MAX_NUM_PROOFS_PER_SUBMISSION() external view returns (uint16);

    /// Returns the maximum number of public inputs per proof allowed.
    ///
    /// Note for proofs with a gnark commitment point the actual number
    /// allowed is `maxNumPublicInputs() - 1`.
    function maxNumPublicInputs() external view returns (uint8);

    /// Register a circuit.  A circuit must be registered before proofs for it
    /// can be submitted.
    function registerVK(
        Groth16VK calldata vk
    ) external returns (bytes32 circuitId);

    /// Submit proofs `proofs[i]`, claiming that each entry in
    /// `publicInputs[i]` is a valid instance for the circuit with the
    /// corresponding `circuitIds[i]`.
    function submit(
        bytes32[] calldata circuitIds,
        Groth16CompressedProof[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external payable returns (bytes32 submissionId);

    /// Returns the estimated fee to aggregate `numProofs`.  This is intended
    /// to give clients a prediction of the fee (e.g. for displaying and / or
    /// creating submission transactions).  Note that the implementation may
    /// use the current gas price to determine the fee, so when calling this
    /// directly to estimate fees, the caller must use the same gas price as
    /// will be used in the final `submit` transaction.
    function estimateFee(
        uint16 numProofs
    ) external view returns (uint256 feeWei);
}
