// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title SecureVault
 * @notice Защищённый пул ликвидности с ERC-4626-совместимой логикой shares.
 * @dev Закрывает риски:
 *      R1 - inflation attack / нарушение инварианта (virtual offset, как в OZ ERC4626)
 *      R2 - reentrancy (CEI + nonReentrant + SafeERC20)
 *      R5 - rounding errors (mulDiv с правильным направлением округления)
 *      Pull-over-Push для вывода средств (защита от force-feed и DoS).
 *
 *      Инвариант: shares конвертируются в assets через формулу с виртуальным сдвигом,
 *      что делает inflation-атаку экономически невыгодной (атакующему нужно
 *      «пожертвовать» 10**DECIMALS_OFFSET долей).
 */
contract SecureVault is ReentrancyGuard, AccessControl, Pausable {
    using SafeERC20 for IERC20;
    using Math for uint256;

    // ============ РОЛИ ============
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant ADMIN_ROLE   = keccak256("ADMIN_ROLE");

    // ============ КОНСТАНТЫ ============
    /// @dev Виртуальный сдвиг — ключ к защите от inflation-attack (см. OZ ERC4626).
    /// Атакующий не может «надуть» цену доли, не потеряв 10**8 = 100 000 000 wei первого депозита.
    uint8 private constant DECIMALS_OFFSET = 8;

    /// @dev Минимальная сумма депозита защищает от dust-атак и потери точности.
    uint256 public constant MIN_DEPOSIT = 1e6;

    /// @dev Период задержки для экстренного вывода (на случай заморозки контракта).
    uint256 public constant EMERGENCY_DELAY = 7 days;

    // ============ СОСТОЯНИЕ ============
    IERC20 public immutable asset;

    uint256 private _totalShares;
    uint256 private _totalAssets;

    mapping(address => uint256) private _shares;
    mapping(address => uint256) private _pendingWithdrawals;

    /// @dev Дата активации экстренного режима (0 = не активен).
    uint256 public emergencyShutdownAt;

    // ============ СОБЫТИЯ ============
    event Deposit(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event WithdrawRequested(address indexed owner, uint256 shares, uint256 assets);
    event WithdrawClaimed(address indexed receiver, uint256 assets);
    event EmergencyShutdownTriggered(uint256 activeAt);
    event EmergencyShutdownCancelled();

    // ============ ОШИБКИ (gas-эффективнее require) ============
    error ZeroAmount();
    error AmountBelowMinimum(uint256 provided, uint256 required);
    error InsufficientShares(uint256 requested, uint256 available);
    error NothingToClaim();
    error ZeroAddress();
    error SlippageExceeded(uint256 expected, uint256 actual);
    error EmergencyNotActive();
    error EmergencyAlreadyActive();

    // ============ КОНСТРУКТОР ============
    constructor(IERC20 _asset, address _admin, address _guardian) {
        if (address(_asset) == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();
        if (_guardian == address(0)) revert ZeroAddress();

        asset = _asset;

        // ВАЖНО: DEFAULT_ADMIN_ROLE даём именно через _grantRole, не через msg.sender.
        // Это позволяет деплоить через factory без угроз делегирования.
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _guardian);
    }

    // ============ КОНВЕРТАЦИЯ (с virtual offset) ============

    /**
     * @dev Конвертация assets → shares с защитой от inflation-attack.
     *      Формула: shares = assets * (totalShares + 10**OFFSET) / (totalAssets + 1)
     *      Округление вниз (в пользу протокола) — у атакующего теряется dust.
     */
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets.mulDiv(
            _totalShares + 10 ** DECIMALS_OFFSET,
            _totalAssets + 1,
            Math.Rounding.Floor
        );
    }

    /**
     * @dev Конвертация shares → assets.
     *      Округление вниз (в пользу протокола, не в пользу выводящего).
     */
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return shares.mulDiv(
            _totalAssets + 1,
            _totalShares + 10 ** DECIMALS_OFFSET,
            Math.Rounding.Floor
        );
    }

    // ============ DEPOSIT ============

    /**
     * @notice Депозит активов в обмен на доли.
     * @param assets Количество активов.
     * @param receiver Получатель долей (может отличаться от msg.sender).
     * @param minSharesOut Минимально допустимое количество shares (защита от front-running).
     * @return shares Количество выпущенных долей.
     */
    function deposit(uint256 assets, address receiver, uint256 minSharesOut)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 shares)
    {
        if (receiver == address(0)) revert ZeroAddress();
        if (assets < MIN_DEPOSIT) revert AmountBelowMinimum(assets, MIN_DEPOSIT);

        // CHECKS: рассчитываем shares ДО приёма средств
        shares = convertToShares(assets);
        if (shares == 0) revert ZeroAmount();
        if (shares < minSharesOut) revert SlippageExceeded(minSharesOut, shares);

        // EFFECTS: обновляем состояние ДО внешнего вызова
        _totalAssets += assets;
        _totalShares += shares;
        _shares[receiver] += shares;

        // INTERACTIONS: SafeERC20 защищает от non-standard ERC20 (USDT и т.п.)
        asset.safeTransferFrom(msg.sender, address(this), assets);

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // ============ WITHDRAW (Pull-over-Push, 2 шага) ============

    /**
     * @notice Шаг 1: запрос на вывод. Доли сжигаются, средства резервируются.
     * @dev Защита от force-feed: даже если внешний вызов в claim() упадёт,
     *      shares уже сожжены, средства зарезервированы.
     */
    function requestWithdraw(uint256 shares, uint256 minAssetsOut)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 assets)
    {
        uint256 userShares = _shares[msg.sender];
        if (shares == 0) revert ZeroAmount();
        if (shares > userShares) revert InsufficientShares(shares, userShares);

        // CHECKS
        assets = convertToAssets(shares);
        if (assets == 0) revert ZeroAmount();
        if (assets < minAssetsOut) revert SlippageExceeded(minAssetsOut, assets);

        // EFFECTS
        _shares[msg.sender] = userShares - shares;
        _totalShares -= shares;
        _totalAssets -= assets;
        _pendingWithdrawals[msg.sender] += assets;

        emit WithdrawRequested(msg.sender, shares, assets);
    }

    /**
     * @notice Шаг 2: получение зарезервированных средств.
     * @dev Pull-pattern: контракт никогда не «толкает» средства, пользователь сам забирает.
     *      Это защищает от:
     *      - DoS через падающий receive() атакующего
     *      - Газовых атак (атакующий не может заставить контракт платить много gas)
     */
    function claim(address receiver) external nonReentrant returns (uint256 amount) {
        if (receiver == address(0)) revert ZeroAddress();

        amount = _pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToClaim();

        // EFFECTS first!
        _pendingWithdrawals[msg.sender] = 0;

        // INTERACTIONS
        asset.safeTransfer(receiver, amount);

        emit WithdrawClaimed(receiver, amount);
    }

    // ============ ЭКСТРЕННЫЙ РЕЖИМ ============

    /**
     * @notice GUARDIAN запускает экстренную остановку (например, при обнаружении эксплойта).
     * @dev После EMERGENCY_DELAY пользователи смогут выводить средства даже на паузе.
     */
    function triggerEmergencyShutdown() external onlyRole(GUARDIAN_ROLE) {
        if (emergencyShutdownAt != 0) revert EmergencyAlreadyActive();
        emergencyShutdownAt = block.timestamp + EMERGENCY_DELAY;
        _pause();
        emit EmergencyShutdownTriggered(emergencyShutdownAt);
    }

    function cancelEmergencyShutdown() external onlyRole(ADMIN_ROLE) {
        if (emergencyShutdownAt == 0) revert EmergencyNotActive();
        emergencyShutdownAt = 0;
        _unpause();
        emit EmergencyShutdownCancelled();
    }

    /**
     * @notice Экстренный вывод — работает даже на паузе после EMERGENCY_DELAY.
     * @dev Это критично: если admin-ключи скомпрометированы, пользователи всё равно
     *      смогут вывести деньги через 7 дней.
     */
    function emergencyClaim() external nonReentrant returns (uint256 amount) {
        if (emergencyShutdownAt == 0 || block.timestamp < emergencyShutdownAt) {
            revert EmergencyNotActive();
        }

        // Сначала конвертируем оставшиеся shares
        uint256 userShares = _shares[msg.sender];
        if (userShares > 0) {
            uint256 assets = convertToAssets(userShares);
            _shares[msg.sender] = 0;
            _totalShares -= userShares;
            _totalAssets -= assets;
            _pendingWithdrawals[msg.sender] += assets;
        }

        amount = _pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToClaim();
        _pendingWithdrawals[msg.sender] = 0;

        asset.safeTransfer(msg.sender, amount);
        emit WithdrawClaimed(msg.sender, amount);
    }

    // ============ VIEW ============

    function totalAssets() external view returns (uint256) { return _totalAssets; }
    function totalShares() external view returns (uint256) { return _totalShares; }
    function sharesOf(address user) external view returns (uint256) { return _shares[user]; }
    function pendingOf(address user) external view returns (uint256) { return _pendingWithdrawals[user]; }
}