// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/**
 * @title MockChainlinkOracle
 * (@notice Имитация Chainlink AggregatorV3 для тестов.
 *         Позволяет вручную устанавливать цену, время и состояние раундов.
 */
contract MockChainlinkOracle {
    int256 public answer;
    uint256 public updatedAt;
    uint80 public roundId = 1;
    uint80 public answeredInRound = 1;
    uint8 private _decimals = 8;

    /// @notice Устанавливает цену и автоматически обновляет updatedAt = now
    function setPrice(int256 _price) external {
        answer = _price;
        updatedAt = block.timestamp;
    }

    /// @notice Устанавливает произвольное updatedAt (для теста stale price)
    function setUpdatedAt(uint256 _ts) external {
        updatedAt = _ts;
    }

    /// @notice Установка round mismatch (для теста некорректного раунда)
    function setRounds(uint80 _roundId, uint80 _answered) external {
        roundId = _roundId;
        answeredInRound = _answered;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    ) {
        return (roundId, answer, updatedAt, updatedAt, answeredInRound);
    }
}


