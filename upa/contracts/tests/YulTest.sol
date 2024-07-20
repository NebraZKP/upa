/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

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
