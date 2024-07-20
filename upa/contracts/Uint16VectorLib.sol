// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

library Uint16VectorLib {
    /// A vector of uint16's supporting auto-resizing / 0-padding when
    /// indexing beyond the current bounds.
    struct Uint16Vector {
        uint16[] entries;
    }

    function getUint16(
        Uint16Vector storage vector,
        uint64 idx
    ) internal view returns (uint16 out) {
        if (idx < vector.entries.length) {
            return vector.entries[idx];
        }
        return 0;
    }

    function setUint16(
        Uint16Vector storage vector,
        uint64 idx,
        uint16 value
    ) internal {
        if (idx >= vector.entries.length) {
            // Attempting to assign to length gives the (reasonable) error:
            //
            //   Member "length" is read-only and cannot be used to resize
            //   arrays.
            //
            // An assigning at an index >= length gives the runtime error:
            //
            //   Array accessed at an out-of-bounds or negative index
            //
            // Instead of extending the array by pushing 0s (which is probably
            // cheap in terms of SSTORE cost, but involves an unknown number
            // of iterations), we set the array length explicitly.

            // Equivalent to: vector.entries.length = idx + 1;
            assembly {
                sstore(vector.slot, add(idx, 1))
            }

            // For debugging:
            //   require(vector.entries.length == idx+1, "vector length");
        }
        vector.entries[idx] = value;
    }
}
