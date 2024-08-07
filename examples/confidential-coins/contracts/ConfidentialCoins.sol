//SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "./CircuitVerifier.sol";
import "@nebrazkp/upa/contracts/IUpaVerifier.sol";
import "@nebrazkp/upa/contracts/UpaLib.sol";

/// The plain groth16 proof created by snarkjs.  Only used when not using the
/// UPA.
struct Proof {
    uint256[2] pA;
    uint256[2][2] pB;
    uint256[2] pC;
}

contract ConfidentialCoins is Groth16Verifier {
    // Address of the deployed UPA verifier contract
    IUpaVerifier public upaVerifier;

    // Identifier for this app
    bytes32 public circuitId;

    // Mapping of Ethereum addresses to hashed balances
    mapping(address => mapping(Coin => uint256)) public userBalanceHashes;

    enum Coin {
        USDT,
        USDC,
        DAI
    }

    // A transaction converting from `sourceCoin` to `targetCoin`
    struct ConvertTx {
        Coin sourceCoin;
        Coin targetCoin;
        uint256 newSourceCoinBalanceHash;
        uint256 newTargetCoinBalanceHash;
        uint256 transferAmountHash;
    }

    constructor(IUpaVerifier _upaVerifier, bytes32 _circuitId) {
        upaVerifier = _upaVerifier;
        circuitId = _circuitId;
    }

    // Submit a series of transactions, each with its own zk proof of validity.
    function submitTransactions(
        ConvertTx[] calldata convertTxSequence,
        Proof[] calldata proofSequence
    ) public {
        require(
            convertTxSequence.length == proofSequence.length,
            "len mismatch"
        );

        // Assemble public inputs then verify the proof that this tx is valid.
        mapping(Coin => uint256)
            storage currentBalanceHashes = userBalanceHashes[msg.sender];

        for (uint256 i = 0; i < convertTxSequence.length; i++) {
            ConvertTx calldata convertTx = convertTxSequence[i];

            uint256 sourceCoinBalanceHash = currentBalanceHashes[
                convertTx.sourceCoin
            ];
            uint256 targetCoinBalanceHash = currentBalanceHashes[
                convertTx.targetCoin
            ];

            uint256[5] memory publicInputs = [
                sourceCoinBalanceHash,
                convertTx.newSourceCoinBalanceHash,
                targetCoinBalanceHash,
                convertTx.newTargetCoinBalanceHash,
                convertTx.transferAmountHash
            ];

            Proof calldata proof = proofSequence[i];

            require(
                this.verifyProof(proof.pA, proof.pB, proof.pC, publicInputs),
                "Proof was not correct"
            );

            // Update the current balance hashes according to the transaction.
            //
            // For simplicity we accumulate updates in storage instead of
            // memory.
            currentBalanceHashes[convertTx.sourceCoin] = convertTx
                .newSourceCoinBalanceHash;
            currentBalanceHashes[convertTx.targetCoin] = convertTx
                .newTargetCoinBalanceHash;
        }
    }

    // Submit a series of transactions that have been proven valid by UPA.
    function aggregatedSubmitTransactions(
        ConvertTx[] calldata convertTxSequence
    ) public {
        // Assemble public inputs and then check that the sequence was proven
        // to be valid.
        uint256[][] memory publicInputsArray = new uint256[][](
            convertTxSequence.length
        );

        // Accumulate updates in storage instead of memory for simplicity
        mapping(Coin => uint256)
            storage currentBalanceHashes = userBalanceHashes[msg.sender];

        for (uint256 i = 0; i < convertTxSequence.length; i++) {
            ConvertTx calldata convertTx = convertTxSequence[i];

            uint256 sourceCoinBalanceHash = currentBalanceHashes[
                convertTx.sourceCoin
            ];
            uint256 targetCoinBalanceHash = currentBalanceHashes[
                convertTx.targetCoin
            ];

            publicInputsArray[i] = new uint256[](5);
            publicInputsArray[i][0] = sourceCoinBalanceHash;
            publicInputsArray[i][1] = convertTx.newSourceCoinBalanceHash;
            publicInputsArray[i][2] = targetCoinBalanceHash;
            publicInputsArray[i][3] = convertTx.newTargetCoinBalanceHash;
            publicInputsArray[i][4] = convertTx.transferAmountHash;

            // Update the current balance hashes according to the transaction.
            //
            // For simplicity we accumulate updates in storage instead of
            // memory.
            currentBalanceHashes[convertTx.sourceCoin] = convertTx
                .newSourceCoinBalanceHash;
            currentBalanceHashes[convertTx.targetCoin] = convertTx
                .newTargetCoinBalanceHash;
        }

        bytes32 submissionId = UpaLib.computeSubmissionId(
            circuitId,
            publicInputsArray
        );

        require(
            upaVerifier.isSubmissionVerified(submissionId),
            "Sequence not verified"
        );
    }

    // Sets sender's balance to 1000 for each coin.
    function initializeBalances() public {
        userBalanceHashes[msg.sender][Coin.USDT] = 1236468;
        userBalanceHashes[msg.sender][Coin.USDC] = 1236468;
        userBalanceHashes[msg.sender][Coin.DAI] = 1236468;
    }
}
