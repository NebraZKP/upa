// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../Uint16VectorLib.sol";

/// Specifically for testing the Uint16VectorLib functionality.
contract Uint16VectorLibTest {
    Uint16VectorLib.Uint16Vector private uint16Vector;

    function getUint16(uint64 idx) public view returns (uint16) {
        return Uint16VectorLib.getUint16(uint16Vector, idx);
    }

    function setUint16(uint64 idx, uint16 value) public {
        Uint16VectorLib.setUint16(uint16Vector, idx, value);
    }
}
