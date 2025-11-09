// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title KipuBank - Multi-token vault with USD cap (Option A withdraw rule)
/// @notice ETH represented as address(0). Uses Chainlink ETH/USD feed to value amounts in USD (6 decimals).
/// @dev SafeERC20, ReentrancyGuard and AccessControl used.

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import {
    AggregatorV3Interface
} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";

contract KipuBank is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20Metadata;

    /// Roles
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;
    address public constant USDC_ADDRESS =
        0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    /// Errors
    error ZeroAmount();
    error DepositExceedsBankCap(uint256 capUsd6, uint256 attemptedUsd6);
    error InsufficientBalance(
        address token,
        address user,
        uint256 available,
        uint256 required
    );
    error WithdrawExceedsPerTx(
        address token,
        uint256 limitUsd6,
        uint256 attemptedUsd6
    );
    error NativeTransferFailed(address to, uint256 amount);
    error InvalidPriceFeed();
    error UnsupportedToken();

    error SlippageTooHigh(uint256 estimatedUsdc, uint256 minOut);

    IUniswapV2Router02 public immutable i_uniswapRouter;
    IUniswapV2Factory public immutable i_uniswapFactory;
    /// Events
    event Deposit(
        address indexed token,
        address indexed user,
        uint256 amount,
        uint256 usdValue6
    );
    event Withdrawal(
        address indexed token,
        address indexed user,
        uint256 amount,
        uint256 usdValue6
    );
    event BankCapUpdated(uint256 oldUsd6, uint256 newUsd6);
    event ChainlinkFeedUpdated(address oldFeed, address newFeed);
    event MaxWithdrawUsd6Updated(uint256 oldUsd6, uint256 newUsd6);

    /// Constants / immutables
    uint8 public constant USDC_DECIMALS = 6; // internal USD base
    address public constant NATIVE_TOKEN = address(0);

    /// Chainlink ETH/USD feed (can be updated by admin)
    AggregatorV3Interface public i_ethUsdPriceFeed;

    /// State
    uint256 public immutable s_bankCapUsd6; // immutable bank cap in USD6 units
    uint256 public s_totalUsdStored6; // current total value in USD6
    uint256 public s_maxWithdrawUsd6; // global withdraw limit in USD6 (0 -> disabled)

    // I only need to track eth balances, and usdc balances
    mapping(address => mapping(address => uint256)) private s_balances;

    /// Counters
    uint256 public s_totalDeposits;
    uint256 public s_totalWithdrawals;

    /// Constructor
    /// @param admin admin address to grant DEFAULT_ADMIN_ROLE
    /// @param ethUsdPriceFeed Chainlink ETH/USD aggregator address
    /// @param bankCapUsd6 bank cap expressed in USD with 6 decimals (USDC-style)
    /// @param maxWithdrawUsd6 max withdraw per tx in USD6 (0 = no limit)
    constructor(
        address admin,
        address ethUsdPriceFeed,
        uint256 bankCapUsd6,
        uint256 maxWithdrawUsd6
    ) {
        _grantRole(ADMIN_ROLE, admin);
        i_ethUsdPriceFeed = AggregatorV3Interface(ethUsdPriceFeed);
        s_bankCapUsd6 = bankCapUsd6;
        s_maxWithdrawUsd6 = maxWithdrawUsd6;
        // mainnet address: 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
        // sepoila address: 0xeE567Fe1712Faf6149d80dA1E6934E354124CfE3
        i_uniswapRouter = IUniswapV2Router02(
            0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
        ); // Uniswap V2 Router
        // mainnet address: 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f
        // sepoila address: 0xF62c03E08ada871A0bEb309762E260a7a6a880E6
        i_uniswapFactory = IUniswapV2Factory(
            0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f
        ); // Uniswap V2 Factory.
        s_totalUsdStored6 = 0;
        s_totalDeposits = 0;
        s_totalWithdrawals = 0;
    }

    // -----------------------------
    // Admin
    // -----------------------------

    /// @notice Update Chainlink ETH/USD feed (admin)
    function setChainlinkFeed(address newFeed) external onlyRole(ADMIN_ROLE) {
        address old = address(i_ethUsdPriceFeed);
        i_ethUsdPriceFeed = AggregatorV3Interface(newFeed);
        emit ChainlinkFeedUpdated(old, newFeed);
    }

    /// @notice Update global max withdraw in USD6
    function setMaxWithdrawUsd6(
        uint256 newMaxUsd6
    ) external onlyRole(ADMIN_ROLE) {
        uint256 old = s_maxWithdrawUsd6;
        s_maxWithdrawUsd6 = newMaxUsd6;
        emit MaxWithdrawUsd6Updated(old, newMaxUsd6);
    }

    // -----------------------------
    // Deposits
    // -----------------------------

    function _depositETH(address sender, uint256 amount) internal {
        if (amount == 0) revert ZeroAmount();

        uint256 usd6 = _toUsd6(NATIVE_TOKEN, amount);
        uint256 newTotalUsd6 = s_totalUsdStored6 + usd6;

        if (newTotalUsd6 > s_bankCapUsd6)
            revert DepositExceedsBankCap(s_bankCapUsd6, newTotalUsd6);

        s_balances[NATIVE_TOKEN][sender] += amount;
        s_totalUsdStored6 = newTotalUsd6;

        unchecked {
            s_totalDeposits++;
        }

        emit Deposit(NATIVE_TOKEN, sender, amount, usd6);
    }

    function _depositUSDC(address sender, uint256 amount) internal {
        if (amount == 0) revert ZeroAmount();

        uint256 usd6 = amount; // USDC is already in 6 decimals
        uint256 newTotalUsd6 = s_totalUsdStored6 + usd6;

        if (newTotalUsd6 > s_bankCapUsd6)
            revert DepositExceedsBankCap(s_bankCapUsd6, newTotalUsd6);

        s_balances[USDC_ADDRESS][sender] += amount; // USDC token address
        s_totalUsdStored6 = newTotalUsd6;

        unchecked {
            s_totalDeposits++;
        }

        emit Deposit(USDC_ADDRESS, sender, amount, usd6);
    }

    /// @notice Deposit native ETH into sender vault
    function depositETH() external payable nonReentrant {
        _depositETH(msg.sender, msg.value);
    }

    function depositUSDC() external payable nonReentrant {
        _depositUSDC(msg.sender, msg.value);
    }

    function _getPathForTokenToUsd6(
        address token
    ) internal view returns (address[] memory) {
        address[] memory path;

        address pairAddress = i_uniswapFactory.getPair(token, USDC_ADDRESS);
        if (pairAddress == address(0)) {
            pairAddress = i_uniswapFactory.getPair(
                token,
                i_uniswapRouter.WETH()
            );
            if (pairAddress == address(0)) revert UnsupportedToken();
            path = new address[](3);
            path[0] = token;
            path[1] = i_uniswapRouter.WETH();
            path[2] = USDC_ADDRESS;
            return path;
        }
        path = new address[](2);
        path[0] = token;
        path[1] = USDC_ADDRESS;
        return path;
    }
    /// @notice Deposit ERC20 token into sender vault (token must implement decimals())
    /// @notice Deposit ERC20 token into sender vault (token must implement decimals())
    /// @dev Compute USD value and check cap BEFORE pulling tokens to avoid returning them.
    function depositToken(
        address token,
        uint256 amount,
        uint256 minOut
    ) external nonReentrant {
        if (amount == 0) revert ZeroAmount();

        if (token == NATIVE_TOKEN) {
            _depositETH(msg.sender, amount);
            return;
        }
        if (token == USDC_ADDRESS) {
            _depositUSDC(msg.sender, amount);
            return;
        }

        address[] memory path = _getPathForTokenToUsd6(token);

        // Estimate output
        uint256[] memory amountsOut = i_uniswapRouter.getAmountsOut(
            amount,
            path
        );
        uint256 expectedOut = amountsOut[amountsOut.length - 1];

        if (expectedOut < minOut) revert SlippageTooHigh(expectedOut, minOut);

        uint256 newTotalUsd6 = s_totalUsdStored6 + expectedOut;
        if (newTotalUsd6 > s_bankCapUsd6)
            revert DepositExceedsBankCap(s_bankCapUsd6, newTotalUsd6);

        // Pull tokens and approve router
        IERC20Metadata(token).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );
        IERC20Metadata(token).safeIncreaseAllowance(
            address(i_uniswapRouter),
            amount
        );

        // Swap to USDC
        uint[] memory amounts = i_uniswapRouter.swapExactTokensForTokens(
            amount,
            minOut,
            path,
            address(this),
            block.timestamp
        );

        uint256 usdcReceived = amounts[amounts.length - 1];

        // Update balances
        uint256 newTotalUsd6Final = s_totalUsdStored6 + usdcReceived;
        if (newTotalUsd6Final > s_bankCapUsd6)
            revert DepositExceedsBankCap(s_bankCapUsd6, newTotalUsd6Final);

        s_balances[USDC_ADDRESS][msg.sender] += usdcReceived;
        s_totalUsdStored6 = newTotalUsd6Final;
        unchecked {
            s_totalDeposits++;
        }

        emit Deposit(token, msg.sender, amount, usdcReceived);
    }

    /// @notice Withdraw native ETH
    function withdrawETH(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 userBal = s_balances[NATIVE_TOKEN][msg.sender];
        if (userBal < amount)
            revert InsufficientBalance(
                NATIVE_TOKEN,
                msg.sender,
                userBal,
                amount
            );

        uint256 usd6 = _toUsd6(NATIVE_TOKEN, amount);
        if (s_maxWithdrawUsd6 > 0 && usd6 > s_maxWithdrawUsd6)
            revert WithdrawExceedsPerTx(NATIVE_TOKEN, s_maxWithdrawUsd6, usd6);

        // effects
        s_balances[NATIVE_TOKEN][msg.sender] = userBal - amount;
        s_totalUsdStored6 = s_totalUsdStored6 - usd6;
        unchecked {
            s_totalWithdrawals++;
        }

        // interaction
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) revert NativeTransferFailed(msg.sender, amount);

        emit Withdrawal(NATIVE_TOKEN, msg.sender, amount, usd6);
    }

    function withdrawUSDC(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 userBal = s_balances[USDC_ADDRESS][msg.sender];
        if (userBal < amount)
            revert InsufficientBalance(
                USDC_ADDRESS,
                msg.sender,
                userBal,
                amount
            );

        uint256 usd6 = amount; // USDC is already in 6 decimals
        if (s_maxWithdrawUsd6 > 0 && usd6 > s_maxWithdrawUsd6)
            revert WithdrawExceedsPerTx(USDC_ADDRESS, s_maxWithdrawUsd6, usd6);

        // effects
        s_balances[USDC_ADDRESS][msg.sender] = userBal - amount;
        s_totalUsdStored6 = s_totalUsdStored6 - usd6;
        unchecked {
            s_totalWithdrawals++;
        }

        // interaction
        IERC20Metadata(USDC_ADDRESS).safeTransfer(msg.sender, amount);

        emit Withdrawal(USDC_ADDRESS, msg.sender, amount, usd6);
    }

    /// @notice Withdraw ERC20 token
    function withdrawToken(
        address token,
        uint256 amount
    ) external nonReentrant {
        if (token == NATIVE_TOKEN) revert();
        if (amount == 0) revert ZeroAmount();

        uint256 userBal = s_balances[token][msg.sender];
        if (userBal < amount)
            revert InsufficientBalance(token, msg.sender, userBal, amount);

        uint256 usd6 = _toUsd6(token, amount);
        if (s_maxWithdrawUsd6 > 0 && usd6 > s_maxWithdrawUsd6)
            revert WithdrawExceedsPerTx(token, s_maxWithdrawUsd6, usd6);

        // effects
        s_balances[token][msg.sender] = userBal - amount;
        s_totalUsdStored6 = s_totalUsdStored6 - usd6;
        unchecked {
            s_totalWithdrawals++;
        }

        // interaction
        IERC20Metadata(token).safeTransfer(msg.sender, amount);

        emit Withdrawal(token, msg.sender, amount, usd6);
    }

    // -----------------------------
    // Views
    // -----------------------------

    function getTokenBalance(
        address token,
        address user
    ) external view returns (uint256) {
        return s_balances[token][user];
    }

    function getContractTokenBalance(
        address token
    ) external view returns (uint256) {
        if (token == NATIVE_TOKEN) return address(this).balance;
        return IERC20Metadata(token).balanceOf(address(this));
    }

    function getBankCapUsd6() external view returns (uint256) {
        return s_bankCapUsd6;
    }

    // -----------------------------
    // Internal helper: convert amount -> USD6 using ETH/USD feed
    // -----------------------------
    /// @dev Converts token amount to USD with 6 decimals (USDC style).
    ///      Note: This function uses the ETH/USD feed. It assumes token is valued relative to ETH.
    function _toUsd6(
        address token,
        uint256 amount
    ) internal view returns (uint256) {
        // read ETH/USD price
        (, int256 priceInt, , , ) = i_ethUsdPriceFeed.latestRoundData();
        if (priceInt <= 0) revert InvalidPriceFeed();
        uint256 price = uint256(priceInt);
        uint8 priceDecimals = i_ethUsdPriceFeed.decimals();

        uint8 tokenDecimals = token == NATIVE_TOKEN
            ? 18
            : IERC20Metadata(token).decimals();

        // usd6 = amount * price * 10^USDC_DECIMALS / (10^tokenDecimals * 10^priceDecimals)
        // Avoid intermediate truncation: promote exponents to uint256
        uint256 scaled = amount * price; // amount * price
        uint256 denom = (10 ** uint256(tokenDecimals)) *
            (10 ** uint256(priceDecimals));
        uint256 usd6 = (scaled * (10 ** uint256(USDC_DECIMALS))) / denom;
        return usd6;
    }
    function getTotalUsdStored6() external view returns (uint256) {
        return s_totalUsdStored6;
    }
    function getMaxWithdrawUsd6() external view returns (uint256) {
        return s_maxWithdrawUsd6;
    }
    // -----------------------------
    // Fallback / receive
    // -----------------------------
    // Force explicit deposit function usage to keep accounting correct.
    receive() external payable {
        _depositETH(msg.sender, msg.value);
    }

    fallback() external payable {
        _depositETH(msg.sender, msg.value);
    }
}
