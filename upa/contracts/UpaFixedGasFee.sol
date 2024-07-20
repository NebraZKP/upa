// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./UpaFeeBase.sol";

abstract contract UpaFixedGasFee is
    Initializable,
    IUpaProofReceiver,
    UpaFeeBase
{
    /// Fixed fee per proof, in gas.
    uint256 public fixedGasFeePerProof;

    /// Prevents initializing the implementation contract outside of the
    /// upgradeable proxy.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // solhint-disable-next-line
    function __upaFixedGasFee_init(
        address _owner,
        uint256 _fixedGasFeePerProof,
        uint256 _aggregatorCollateral
    ) public onlyInitializing {
        fixedGasFeePerProof = _fixedGasFeePerProof;

        __upaFeeBase_init(_owner, _aggregatorCollateral);
    }

    function estimateFee(
        uint16 numProofs
    ) public view override returns (uint256 feeWei) {
        require(tx.gasprice > 0, "tx.gasprice must be non-zero");
        return numProofs * fixedGasFeePerProof * tx.gasprice;
    }

    /// Changes the `fixedFeePerProof` to `newFee`.
    function changeGasFee(uint256 newGasFee) external onlyOwner {
        fixedGasFeePerProof = newGasFee;
    }
}
