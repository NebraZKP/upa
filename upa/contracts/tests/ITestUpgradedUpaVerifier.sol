// SPDX-License-Identifier: UNLICENSED
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

import "../IUpaVerifier.sol";

// Mock upgraded contract.  Extends the current UPAVerifier to test upgrading.
interface ITestUpgradedUpaVerifier is IUpaVerifier {
    function setTestVar(bool newValue) external;

    // Check new function returns the right constant.
    function testNumber() external pure returns (uint256);
}
