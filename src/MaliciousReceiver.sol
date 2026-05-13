// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {SecureVault} from "./SecureVault.sol";
import {MaliciousToken} from "./MaliciousToken.sol";

/**
 * @title MaliciousReceiver
 * @notice Атакующий контракт для тестирования reentrancy-защиты.
 * @dev При получении токенов через transfer() пытается рекурсивно вызвать claim().
 */
contract MaliciousReceiver {
    SecureVault    public immutable vault;
    MaliciousToken public immutable token;

    bool public armed;
    bool public reenterAttempted;

    constructor(SecureVault _vault, MaliciousToken _token) {
        vault = _vault;
        token = _token;
    }

    function attackSetup() external {
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1_000e6, address(this), 0);
    }

    function requestWithdraw() external {
        uint256 shares = vault.sharesOf(address(this));
        vault.requestWithdraw(shares, 0);
    }

    function armAttack() external {
        armed = true;
        // Включаем callback в токене на наш адрес
        token.setCallback(address(this), true);
    }

    function executeAttack() external {
        vault.claim(address(this));
    }

    /// @notice Hook, который токен вызывает при transfer на этот адрес
    function onTokenReceived() external {
        if (armed && !reenterAttempted) {
            reenterAttempted = true;
            // Пытаемся повторно войти в claim() — должен сработать nonReentrant
            vault.claim(address(this));
        }
    }
}


