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

/*
    This contract is for testing upgrades. It adds a storage variable
    `testVar` and new functions `setTestVar`, `testNumber`, `setOuterVerifier`.
*/

pragma solidity 0.8.26;

import "./ITestUpgradedUpaVerifier.sol";
import "../UpaVerifier.sol";

// Inherits Initializable, UUPSUpgradeable, OwnableUpgradeable from UpaVerifier,
// as well as `initialize` function.
contract TestUpgradedUpaVerifier is ITestUpgradedUpaVerifier, UpaVerifier {
    // Renamed to  avoid name-collision with `VerifierStorage` in the parent
    // `UpaVerifier` contract.
    // For the same reason, omits the `@custom:storage-location` annotation.
    struct UpgradedVerifierStorage {
        address worker;
        address outerVerifier;
        IGroth16Verifier groth16Verifier;
        uint64 nextSubmissionIdxToVerify;
        uint64 lastVerifiedSubmissionHeight;
        mapping(bytes32 => uint256) openChallengeRefundAmounts;
        uint256 fixedReimbursement;
        uint256 fixedReimbursementPerProof;
        Uint16VectorLib.Uint16Vector numVerifiedInSubmission;
        /// Introduce new storage variable
        bool testVar;
    }

    // Uses the same storage location as the old contract. Renamed so it does
    // not get flagged as shadowing the `VERIFIER_STORAGE_LOCATION` variable
    // in `UpaVerifier`.
    // keccak256(abi.encode(uint256(keccak256("VerifierStorage")) - 1)) &
    // ~bytes32(uint256(0xff));
    bytes32 private constant UPGRADED_VERIFIER_STORAGE_LOCATION =
        0x4D7AE96A4105CE9C745382B9DE6F32626723345414218A3198E7DEF859C90A00;

    // Renamed to  avoid name-collision with `VerifierStorage` in the parent
    // `UpaVerifier` contract.
    function _getUpgradedVerifierStorage()
        private
        pure
        returns (UpgradedVerifierStorage storage $)
    {
        assembly {
            $.slot := UPGRADED_VERIFIER_STORAGE_LOCATION
        }
    }

    // Add new method interacting with new storage variable
    function testVar() external view returns (bool) {
        return _getUpgradedVerifierStorage().testVar;
    }

    // Add new method interacting with new storage variable
    function setTestVar(
        bool newValue
    ) external override(ITestUpgradedUpaVerifier) {
        _getUpgradedVerifierStorage().testVar = newValue;
    }

    // Add new method returning a constant.
    function testNumber()
        external
        pure
        override(ITestUpgradedUpaVerifier)
        returns (uint256)
    {
        return 123456;
    }
}
