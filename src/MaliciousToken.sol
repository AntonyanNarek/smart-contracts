// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MaliciousToken
 * @notice ERC-20 токен с callback-хуком при transfer (имитация ERC-777).
 * @dev Используется только для тестирования reentrancy-защиты.
 *      В transfer() вызывает onTokenReceived() у получателя, что даёт
 *      возможность атакующему контракту провести повторный вход.
 */
interface IMaliciousReceiver {
    function onTokenReceived() external;
}

contract MaliciousToken is ERC20 {
    uint8 private _decimals;
    address public callbackReceiver; // адрес, у которого вызывается hook
    bool public callbackEnabled;

    constructor(string memory name, string memory symbol, uint8 decimals_)
        ERC20(name, symbol)
    {
        _decimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setCallback(address receiver, bool enabled) external {
        callbackReceiver = receiver;
        callbackEnabled = enabled;
    }

    /// @dev Переопределяем _update — это хук в OZ ERC20 v5.
    ///      Срабатывает на каждый transfer/transferFrom.
    function _update(address from, address to, uint256 value) internal override {
        super._update(from, to, value);

        // Если callback активен и переводим к нему — вызываем hook
        if (callbackEnabled && to == callbackReceiver && to != address(0)) {
            IMaliciousReceiver(to).onTokenReceived();
        }
    }
}
