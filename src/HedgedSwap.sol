// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SecureOracleConsumer} from "./SecureOracleConsumer.sol";

/**
 * @title HedgedSwap
 * @notice Атомарный обмен с защитой от манипуляции ценой через TWAP-оракул.
 * @dev Закрывает риски:
 *      R3 - манипуляция оракулом (TWAP + cross-check + price bounds)
 *      Front-running - через deadline + minAmountOut + commit-reveal (опционально)
 *      Flash-loan атаки - проверкой block.number (одна сделка на блок на пользователя)
 */
contract HedgedSwap is SecureOracleConsumer, ReentrancyGuard, AccessControl, Pausable {
    using SafeERC20 for IERC20;
    using Math for uint256;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    IERC20 public immutable tokenIn;
    IERC20 public immutable tokenOut;

    uint8 public immutable tokenInDecimals;
    uint8 public immutable tokenOutDecimals;

    /// @dev Защита от same-block flash-loan атак.
    mapping(address => uint256) public lastSwapBlock;

    /// @dev Глобальный лимит на объём свопа (защита от истощения ликвидности).
    uint256 public maxSwapAmount;

    event Swapped(
        address indexed user,
        uint256 amountIn,
        uint256 amountOut,
        int256 oraclePrice
    );
    event MaxSwapAmountUpdated(uint256 newMax);

    error DeadlineExpired(uint256 deadline, uint256 currentTime);
    error SameBlockSwap();
    error AmountTooLarge(uint256 amount, uint256 max);
    error ZeroAmount();
    error SlippageExceeded(uint256 minOut, uint256 actualOut);
    error InsufficientLiquidity();

    constructor(
        IERC20 _tokenIn,
        IERC20 _tokenOut,
        uint8 _tokenInDecimals,
        uint8 _tokenOutDecimals,
        address _primaryOracle,
        address _fallbackOracle,
        uint256 _maxStaleness,
        uint256 _maxDeviationBps,
        int256 _minPrice,
        int256 _maxPrice,
        address _admin
    )
        SecureOracleConsumer(
            _primaryOracle,
            _fallbackOracle,
            _maxStaleness,
            _maxDeviationBps,
            _minPrice,
            _maxPrice
        )
    {
        require(address(_tokenIn) != address(0) && address(_tokenOut) != address(0), "Zero token");
        require(address(_tokenIn) != address(_tokenOut), "Same token");
        require(_admin != address(0), "Zero admin");

        tokenIn = _tokenIn;
        tokenOut = _tokenOut;
        tokenInDecimals = _tokenInDecimals;
        tokenOutDecimals = _tokenOutDecimals;

        maxSwapAmount = type(uint256).max; // по умолчанию без лимита, ADMIN ставит реальный

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
    }

    /**
     * @notice Обмен tokenIn → tokenOut по защищённой цене.
     * @param amountIn Количество входного токена.
     * @param minAmountOut Минимум, который пользователь согласен получить (slippage protection).
     * @param deadline UNIX-время, после которого транзакция невалидна.
     */
    function swap(uint256 amountIn, uint256 minAmountOut, uint256 deadline)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 amountOut)
    {
        // 1. Базовые проверки
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        if (amountIn == 0) revert ZeroAmount();
        if (amountIn > maxSwapAmount) revert AmountTooLarge(amountIn, maxSwapAmount);

        // 2. Защита от flash-loan: один свап на блок на адрес.
        // Атакующий не может в одной транзакции и манипулировать ценой, и свопнуть.
        if (lastSwapBlock[msg.sender] == block.number) revert SameBlockSwap();
        lastSwapBlock[msg.sender] = block.number;

        // 3. Получаем валидированную цену
        (int256 price, uint8 priceDecimals) = _getValidatedPrice();

        // 4. Считаем amountOut с правильной нормализацией decimals
        amountOut = _calculateAmountOut(amountIn, uint256(price), priceDecimals);

        // 5. Slippage check
        if (amountOut < minAmountOut) revert SlippageExceeded(minAmountOut, amountOut);

        // 6. Проверка ликвидности
        if (tokenOut.balanceOf(address(this)) < amountOut) revert InsufficientLiquidity();

        // 7. EFFECTS-INTERACTIONS
        tokenIn.safeTransferFrom(msg.sender, address(this), amountIn);
        tokenOut.safeTransfer(msg.sender, amountOut);

        emit Swapped(msg.sender, amountIn, amountOut, price);
    }

    /**
    * @dev Корректная нормализация decimals.
    *      amountOut = amountIn × 10^outDec × 10^priceDec / (price × 10^inDec)
    *
    *      Пример: 1000 USDC (6 dec) при цене ETH = $2000 (8 dec)
    *      → 1e9 × 1e18 × 1e8 / (2e11 × 1e6) = 5e17 wei = 0.5 WETH ✓
    */
    function _calculateAmountOut(uint256 amountIn, uint256 price, uint8 priceDecimals)
        internal
        view
        returns (uint256)
    {
        return amountIn.mulDiv(
            (10 ** tokenOutDecimals) * (10 ** priceDecimals),
            price * (10 ** tokenInDecimals),
            Math.Rounding.Floor
        );
    }

    // ============ ADMIN ============

    function setMaxSwapAmount(uint256 newMax) external onlyRole(ADMIN_ROLE) {
        maxSwapAmount = newMax;
        emit MaxSwapAmountUpdated(newMax);
    }

    function pause() external onlyRole(ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }
}