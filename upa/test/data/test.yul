object "test" {
    // Deployment
    code {
        function allocate(size) -> ptr {
            ptr := mload(0x40)
            if eq(ptr, 0) { ptr := 0x60 }
            mstore(0x40, add(ptr, size))
        }
        let size := datasize("Runtime")
        let offset := allocate(size)
        datacopy(offset, dataoffset("Runtime"), size)
        return(offset, size)
    }

    /// Entry point to test code which simply returns uint(19), unless it is
    /// passed call-data with a leading 0, in which case it reverts.  NOTE:
    /// this contract also serves as a dummy proof verifier, which always
    /// behaves as if the proof and instance is valid.
    object "Runtime" {
        code {
          if eq(calldataload(0x00),0) { revert(0, 0) }
          mstore(0x00, 19)
          return(0, 0x20)
        }
    }
}
