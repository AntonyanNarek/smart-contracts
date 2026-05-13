// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test, console2} from "forge-std/Test.sol";
import {HedgedSwap}            from "../src/HedgedSwap.sol";
import {SecureOracleConsumer}  from "../src/SecureOracleConsumer.sol";
import {MockERC20}             from "../src/MockERC20.sol";
import {MockChainlinkOracle}   from "../src/MockChainlinkOracle.sol";

contract HedgedSwapTest is Test {
    HedgedSwap          public swap;
    MockERC20           public usdc;
    MockERC20           public weth;
    MockChainlinkOracle public oracle;

    address admin = makeAddr("admin");
    address alice = makeAddr("Alice");
    address bob   = makeAddr("bob");

    int256  constant ETH_PRICE      = 2000e8;       // $2000 в 8 dec
    uint256 constant MAX_STALENESS  = 1 hours;
    int256  constant MIN_PRICE      = 100e8;        // $100
    int256  constant MAX_PRICE      = 100_000e8;    // $100k

    function setUp() public {
        // ВАЖНО: переводим время в "сегодняшний день", иначе block.timestamp = 1
        // и арифметика с вычитанием времени даёт underflow.
        vm.warp(1_700_000_000);  // ≈ 14 ноября 2023

        usdc   = new MockERC20("USDC", "USDC", 6);
        weth   = new MockERC20("WETH", "WETH", 18);
        oracle = new MockChainlinkOracle();

        // Цена ETH = $2000, updatedAt = block.timestamp (свежая)
        oracle.setPrice(ETH_PRICE);

        swap = new HedgedSwap(
            usdc,
            weth,
            6,
            18,
            address(oracle),
            address(0),
            MAX_STALENESS,
            200,
            MIN_PRICE,
            MAX_PRICE,
            admin
        );

        weth.mint(address(swap), 100e18);
        usdc.mint(alice, 10_000e6);
        usdc.mint(bob,   10_000e6);
    }

    /* ════════════════════════════════════════════════════════════════
       T-02: БАЗОВЫЙ SWAP (positive path)
       ──────────────────────────────────────────────────────────────── */
    function test_T02_BasicSwap_Works() public {
        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        uint256 amountOut = swap.swap(
            1_000e6,
            0.49 ether,
            block.timestamp + 60
        );
        vm.stopPrank();

        assertEq(amountOut, 0.5 ether, "Expected exactly 0.5 WETH");
        assertEq(weth.balanceOf(alice), 0.5 ether);
        assertEq(usdc.balanceOf(alice), 9_000e6);
    }

    /* ════════════════════════════════════════════════════════════════
       T-05: STALE ORACLE
       ──────────────────────────────────────────────────────────────── */
    function test_T05_StalePrice_Reverts() public {
        // Устанавливаем updatedAt на 2 часа назад (порог = 1 час)
        oracle.setUpdatedAt(block.timestamp - 2 hours);

        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        vm.expectRevert();
        swap.swap(1_000e6, 0, block.timestamp + 60);
        vm.stopPrank();
    }

    /* ════════════════════════════════════════════════════════════════
       T-05.2: PRICE OUT OF RANGE
       ──────────────────────────────────────────────────────────────── */
    function test_T05_PriceOutOfRange_Reverts() public {
        oracle.setPrice(50e8);   // $50 — ниже minPrice ($100)

        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        vm.expectRevert();
        swap.swap(1_000e6, 0, block.timestamp + 60);
        vm.stopPrank();
    }

    /* ════════════════════════════════════════════════════════════════
       T-05.3: NEGATIVE PRICE
       ──────────────────────────────────────────────────────────────── */
    function test_T05_NegativePrice_Reverts() public {
        oracle.setPrice(-1);

        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        vm.expectRevert();
        swap.swap(1_000e6, 0, block.timestamp + 60);
        vm.stopPrank();
    }

    /* ════════════════════════════════════════════════════════════════
       T-05.4: ROUND MISMATCH
       ──────────────────────────────────────────────────────────────── */


function test_T05_RoundMismatch_Reverts() public {
        oracle.setRounds(10, 5);

        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        vm.expectRevert();
        swap.swap(1_000e6, 0, block.timestamp + 60);
        vm.stopPrank();
    }

    /* ════════════════════════════════════════════════════════════════
       T-06: FLASH-LOAN SAME-BLOCK
       ──────────────────────────────────────────────────────────────── */
    function test_T06_SameBlockSwap_Reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(swap), 5_000e6);

        // Первый swap проходит
        swap.swap(1_000e6, 0, block.timestamp + 60);

        // Второй в том же блоке — revert
        vm.expectRevert(HedgedSwap.SameBlockSwap.selector);
        swap.swap(1_000e6, 0, block.timestamp + 60);
        vm.stopPrank();

        // В следующем блоке — снова можно
        vm.roll(block.number + 1);
        vm.prank(alice);
        swap.swap(1_000e6, 0, block.timestamp + 60);
    }

    /* ════════════════════════════════════════════════════════════════
       T-08: SLIPPAGE
       ──────────────────────────────────────────────────────────────── */
    function test_T08_SlippageProtection_Works() public {
        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        vm.expectRevert();
        swap.swap(1_000e6, 0.6 ether, block.timestamp + 60);
        vm.stopPrank();
    }

    /* ════════════════════════════════════════════════════════════════
       T-08.2: DEADLINE
       ──────────────────────────────────────────────────────────────── */
    function test_T08_DeadlineExpired_Reverts() public {
        vm.startPrank(alice);
        usdc.approve(address(swap), 1_000e6);

        vm.expectRevert();
        swap.swap(1_000e6, 0, block.timestamp - 1);
        vm.stopPrank();
    }

    /* ════════════════════════════════════════════════════════════════
       FUZZ: проверка инварианта формулы
       ──────────────────────────────────────────────────────────────── */
    function testFuzz_SwapAmountConsistency(uint256 amountIn) public {
        // Ограничиваем диапазон, чтобы:
        // - amountIn >= 1e6 (1 USDC) — есть смысл свопать
        // - amountIn <= 100_000e6 (100k USDC) — хватает ликвидности
        //   100k USDC при $2000 → 50 WETH (есть 100 WETH)
        amountIn = bound(amountIn, 1e6, 100_000e6);

        // Гарантируем баланс и approve у alice
        usdc.mint(alice, amountIn);

        vm.startPrank(alice);
        usdc.approve(address(swap), amountIn);
        uint256 out = swap.swap(amountIn, 0, block.timestamp + 60);
        vm.stopPrank();

        // Инвариант: out = amountIn × 5×10⁸ при ETH=$2000
        // amountIn(6dec) × 5e8 = WETH(18dec) при цене 1/2000
        uint256 expected = amountIn * 5e8;
        assertEq(out, expected, "Swap formula broken");
    }
}