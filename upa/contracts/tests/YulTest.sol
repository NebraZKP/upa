/// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract YulTest {
    function callYul(
        address contractAddress,
        bytes calldata data
    ) public returns (bytes memory) {
        (bool success, bytes memory ret) = contractAddress.call(data);
        require(success, "yul code failed");
        return ret;
    }
}
