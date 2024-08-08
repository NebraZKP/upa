// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./UpaFeeBase.sol";

abstract contract UpaFixedGasFee is
    Initializable,
    IUpaProofReceiver,
    UpaFeeBase
{
    /// @custom:storage-location erc7201:FixedGasFeeStorage
    struct FixedGasFeeStorage {
        uint256 fixedGasFeePerProof;
    }

    /// Prevents initializing the implementation contract outside of the
    /// upgradeable proxy.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // keccak256(abi.encode(uint256(keccak256("FixedGasFeeStorage")) - 1)) &
    // ~bytes32(uint256(0xff));
    bytes32 private constant UPA_FIXED_GAS_FEE_STORAGE_LOCATION =
        0x6249b4b7734a2294928e4340fdb532178539b90e8e76c79881e107dd2f477700;

    function _getFixedGasFeeStorage()
        private
        pure
        returns (FixedGasFeeStorage storage $)
    {
        assembly {
            $.slot := UPA_FIXED_GAS_FEE_STORAGE_LOCATION
        }
    }

    // solhint-disable-next-line
    function __upaFixedGasFee_init(
        address _owner,
        uint256 _fixedGasFeePerProof,
        uint256 _aggregatorCollateral
    ) public onlyInitializing {
        FixedGasFeeStorage storage s = _getFixedGasFeeStorage();
        s.fixedGasFeePerProof = _fixedGasFeePerProof;

        __upaFeeBase_init(_owner, _aggregatorCollateral);
    }

    function fixedGasFeePerProof() external view returns (uint256) {
        return _getFixedGasFeeStorage().fixedGasFeePerProof;
    }

    function estimateFee(
        uint16 numProofs
    ) public view override returns (uint256 feeWei) {
        require(tx.gasprice > 0, "tx.gasprice must be non-zero");
        FixedGasFeeStorage storage s = _getFixedGasFeeStorage();
        return numProofs * s.fixedGasFeePerProof * tx.gasprice;
    }

    /// Changes the `fixedFeePerProof` to `newFee`.
    function changeGasFee(uint256 newGasFee) external onlyOwner {
        FixedGasFeeStorage storage s = _getFixedGasFeeStorage();
        s.fixedGasFeePerProof = newGasFee;
    }
}
