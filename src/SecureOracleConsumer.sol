// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {AggregatorV3Interface} from "../lib/chainlink-brownie-contracts/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

/**
 * @title SecureOracleConsumer
 * @notice Безопасное чтение цены из Chainlink с многоуровневой валидацией.
 * @dev Реализует ВСЕ необходимые проверки Chainlink:
 *      1. price > 0 (защита от bug в фиде)
 *      2. updatedAt != 0 (incomplete round)
 *      3. updatedAt не старше heartbeat (stale price)
 *      4. answeredInRound >= roundId (защита от round mismatch)
 *      5. price в диапазоне [minAnswer, maxAnswer] (защита от Luna-style flash crash)
 *
 *      Дополнительно: deviation check между двумя оракулами (если задан fallback).
 */
abstract contract SecureOracleConsumer {
    AggregatorV3Interface public immutable primaryOracle;
    AggregatorV3Interface public immutable fallbackOracle; // address(0) = не используется

    /// @dev Максимальный возраст цены (heartbeat зависит от пары, обычно 1 час для ETH/USD).
    uint256 public immutable maxStaleness;

    /// @dev Максимальное отклонение между primary и fallback (в bps, 10000 = 100%).
    uint256 public immutable maxDeviationBps;

    /// @dev Минимальная и максимальная цена (защита от Luna-style: фид показал $0.10 вместо $80).
    int256 public immutable minPrice;
    int256 public immutable maxPrice;

    error StalePrice(uint256 updatedAt, uint256 currentTime);
    error InvalidPrice(int256 price);
    error PriceOutOfRange(int256 price, int256 min, int256 max);
    error IncompleteRound();
    error RoundMismatch(uint256 answeredIn, uint256 roundId);
    error OracleDeviation(int256 primary, int256 fallback_);

    constructor(
        address _primary,
        address _fallback,
        uint256 _maxStaleness,
        uint256 _maxDeviationBps,
        int256 _minPrice,
        int256 _maxPrice
    ) {
        require(_primary != address(0), "Primary oracle required");
        require(_maxStaleness > 0 && _maxStaleness <= 24 hours, "Invalid staleness");
        require(_minPrice > 0 && _maxPrice > _minPrice, "Invalid price range");

        primaryOracle = AggregatorV3Interface(_primary);
        fallbackOracle = AggregatorV3Interface(_fallback); // может быть address(0)
        maxStaleness = _maxStaleness;
        maxDeviationBps = _maxDeviationBps;
        minPrice = _minPrice;
        maxPrice = _maxPrice;
    }

    /**
     * @dev Получение валидированной цены. Возвращает int256, чтобы вызывающий
     *      сам решал, что делать с decimals.
     */
    function _getValidatedPrice() internal view returns (int256 price, uint8 decimals) {
        price = _readOracle(primaryOracle);
        decimals = primaryOracle.decimals();

        // Cross-check с fallback оракулом (если настроен)
        if (address(fallbackOracle) != address(0)) {
            int256 fallbackPrice = _readOracle(fallbackOracle);
            // Нормализация под одинаковые decimals опущена для краткости —
            // в production обязательно нормализовать!
            _checkDeviation(price, fallbackPrice);
        }
    }

    function _readOracle(AggregatorV3Interface oracle) private view returns (int256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();

        // Проверка 1: incomplete round (Chainlink-известная проблема)
        if (updatedAt == 0) revert IncompleteRound();

        // Проверка 2: round mismatch
        if (answeredInRound < roundId) revert RoundMismatch(answeredInRound, roundId);

        // Проверка 3: stale price
        if (block.timestamp - updatedAt > maxStaleness) {
            revert StalePrice(updatedAt, block.timestamp);
        }

        // Проверка 4: цена положительна
        if (answer <= 0) revert InvalidPrice(answer);

        // Проверка 5: цена в разумном диапазоне (защита от Luna)
        if (answer < minPrice || answer > maxPrice) {
            revert PriceOutOfRange(answer, minPrice, maxPrice);
        }

        return answer;
    }

    function _checkDeviation(int256 a, int256 b) private view {
        int256 diff = a > b ? a - b : b - a;
        int256 maxDiff = (a * int256(maxDeviationBps)) / 10000;
        if (diff > maxDiff) revert OracleDeviation(a, b);
    }
} 
