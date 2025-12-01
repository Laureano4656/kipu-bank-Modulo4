// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title KipuBank - Multi-token vault with USD cap (Option A withdraw rule)
/// @notice ETH is represented as address(0). The system uses a Chainlink ETH/USD feed to value amounts in USD (6 decimals).
/// @dev Implements AccessControl, ReentrancyGuard, and SafeERC20. WARNING: Contains logic issues regarding volatile asset accounting.

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

    /// @dev The address of the USDC token on the target network.
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
    /// @notice The maximum total value allowed in the bank, denominated in USD (6 decimals).
    uint256 public immutable s_bankCapUsd6;

    /// @notice Current total value stored in the bank in USD6.
    /// @dev Tracks historical deposits minus historical withdrawals, prone to drift with price volatility.
    uint256 public s_totalUsdStored6;

    /// @notice Global withdrawal limit per transaction in USD6 (0 means disabled).
    uint256 public s_maxWithdrawUsd6;

    struct UserBalances {
        uint256 ethAmount; // Saldo en ETH nativo
        uint256 usdcAmount; // Saldo en USDC (incluye depósitos directos y swaps)
    }

    /// @dev Mapping of user address to their balance struct (ETH and USDC).
    mapping(address => UserBalances) private s_balances;

    /// Counters
    uint256 public s_totalDeposits;
    uint256 public s_totalWithdrawals;

    /// @notice Contract constructor setting up roles, limits, and external interfaces.
    /// @param admin The address to be granted the DEFAULT_ADMIN_ROLE.
    /// @param ethUsdPriceFeed The address of the Chainlink ETH/USD aggregator.
    /// @param bankCapUsd6 The bank capacity cap expressed in USD with 6 decimals.
    /// @param maxWithdrawUsd6 The maximum withdrawal amount per transaction in USD6 (0 = no limit).
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

    /// @notice Updates the Chainlink ETH/USD price feed address.
    /// @dev Only callable by accounts with ADMIN_ROLE.
    /// @param newFeed The address of the new Chainlink AggregatorV3Interface.
    function setChainlinkFeed(address newFeed) external onlyRole(ADMIN_ROLE) {
        address old = address(i_ethUsdPriceFeed);
        i_ethUsdPriceFeed = AggregatorV3Interface(newFeed);
        emit ChainlinkFeedUpdated(old, newFeed);
    }

    /// @notice Updates the global maximum withdrawal amount per transaction.
    /// @dev Only callable by accounts with ADMIN_ROLE.
    /// @param newMaxUsd6 The new maximum withdrawal limit in USD6.
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

    /// @notice Internal helper to handle native ETH deposits.
    /// @dev Calculates USD value, enforces bank cap, updates struct, and emits event.
    /// @param sender The address of the depositor.
    /// @param amount The amount of ETH (in wei) being deposited.
    function _depositETH(address sender, uint256 amount) internal {
        if (amount == 0) revert ZeroAmount();

        uint256 currentTvlUsd6 = _calculateCurrentTVL();
        if (currentTvlUsd6 > s_bankCapUsd6)
            revert DepositExceedsBankCap(s_bankCapUsd6, currentTvlUsd6);

        s_balances[sender].ethAmount += amount;
        s_totalUsdStored6 = currentTvlUsd6;
        unchecked {
            s_totalDeposits++;
        }
        uint256 usd6 = _ethToUsd6(amount);
        emit Deposit(NATIVE_TOKEN, sender, amount, usd6);
    }

    /// @notice Internal helper to handle USDC deposits.
    /// @dev Enforces bank cap, updates struct, and emits event. Assumes USDC has 6 decimals.
    /// @param sender The address of the depositor.
    /// @param amount The amount of USDC being deposited.
    function _depositUSDC(address sender, uint256 amount) internal {
        if (amount == 0) revert ZeroAmount();

        uint256 usd6 = amount; // USDC is already in 6 decimals
        uint256 newTotalUsd6 = s_totalUsdStored6 + usd6;

        if (newTotalUsd6 > s_bankCapUsd6)
            revert DepositExceedsBankCap(s_bankCapUsd6, newTotalUsd6);

        s_balances[sender].usdcAmount += amount; // USDC token address
        s_totalUsdStored6 = newTotalUsd6;

        unchecked {
            s_totalDeposits++;
        }

        emit Deposit(USDC_ADDRESS, sender, amount, usd6);
    }

    /// @notice Allows a user to deposit native ETH.
    /// @dev Wrapper for _depositETH.
    function depositETH() external payable nonReentrant {
        _depositETH(msg.sender, msg.value);
    }

    /// @notice Allows a user to deposit USDC.
    /// @dev User must have approved the contract to spend the USDC amount. Wrapper for _depositUSDC.
    function depositUSDC() external payable nonReentrant {
        _depositUSDC(msg.sender, msg.value);
    }

    /// @notice Determines the Uniswap path for swapping a given token to USDC.
    /// @dev Checks if a direct pair exists; if not, routes through WETH.
    /// @param token The address of the input token.
    /// @return The array of addresses representing the swap path.
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

    /// @notice Deposits an ERC20 token, swaps it to USDC, and credits the user's USDC balance.
    /// @dev Calculates expected USDC out to check bank cap *before* and *after* execution.
    /// @param token The address of the ERC20 token to deposit.
    /// @param amount The amount of the token to deposit.
    /// @param minOut The minimum amount of USDC to receive (slippage protection).
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

        s_balances[msg.sender].usdcAmount += usdcReceived;
        s_totalUsdStored6 = newTotalUsd6Final;
        unchecked {
            s_totalDeposits++;
        }

        emit Deposit(token, msg.sender, amount, usdcReceived);
    }

    /// @notice Withdraws native ETH from the user's balance.
    /// @dev Updates the global USD counter based on CURRENT ETH price, which may cause underflows.
    /// @param amount The amount of ETH (in wei) to withdraw.
    function withdrawETH(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 userBal = s_balances[msg.sender].ethAmount;
        if (userBal < amount)
            revert InsufficientBalance(
                NATIVE_TOKEN,
                msg.sender,
                userBal,
                amount
            );

        uint256 usd6 = _ethToUsd6(amount);
        if (s_maxWithdrawUsd6 > 0 && usd6 > s_maxWithdrawUsd6)
            revert WithdrawExceedsPerTx(NATIVE_TOKEN, s_maxWithdrawUsd6, usd6);

        // effects
        s_balances[msg.sender].ethAmount = userBal - amount;

        unchecked {
            s_totalWithdrawals++;
        }

        // interaction
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) revert NativeTransferFailed(msg.sender, amount);

        emit Withdrawal(NATIVE_TOKEN, msg.sender, amount, usd6);
    }

    /// @notice Withdraws USDC from the user's balance.
    /// @dev Decrements global USD counter 1:1.
    /// @param amount The amount of USDC (6 decimals) to withdraw.
    function withdrawUSDC(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 userBal = s_balances[msg.sender].usdcAmount;
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
        s_balances[msg.sender].usdcAmount = userBal - amount;
        s_totalUsdStored6 = s_totalUsdStored6 - usd6;
        unchecked {
            s_totalWithdrawals++;
        }

        // interaction
        IERC20Metadata(USDC_ADDRESS).safeTransfer(msg.sender, amount);

        emit Withdrawal(USDC_ADDRESS, msg.sender, amount, usd6);
    }

    // -----------------------------
    // Views
    // -----------------------------

    /// @notice Returns the user's balance for a specific token (ETH or USDC).
    /// @param token The token address to query (address(0) for ETH).
    /// @param user The address of the user.
    /// @return The balance amount.
    function getTokenBalance(
        address token,
        address user
    ) external view returns (uint256) {
        if (token == NATIVE_TOKEN) {
            return s_balances[user].ethAmount;
        } else if (token == USDC_ADDRESS) {
            return s_balances[user].usdcAmount;
        } else {
            return 0;
        }
    }

    /// @notice Returns the contract's physical balance of a given token.
    /// @param token The token address to query.
    /// @return The contract's balance.
    function getContractTokenBalance(
        address token
    ) external view returns (uint256) {
        if (token == NATIVE_TOKEN) return address(this).balance;
        return IERC20Metadata(token).balanceOf(address(this));
    }

    /// @notice Returns the configured bank capacity in USD.
    /// @return The cap amount in USD (6 decimals).
    function getBankCapUsd6() external view returns (uint256) {
        return s_bankCapUsd6;
    }

    /// @notice Calculates the current Total Value Locked (TVL) of the bank in USD.
    /// @dev Sums the USD value of the contract's ETH balance (at current spot price) and USDC balance.
    ///      This approach prevents accounting drift caused by ETH price volatility and avoids
    ///      locking funds during price appreciation scenarios.
    /// @return The total value in USD with 6 decimals.
    function _calculateCurrentTVL() internal view returns (uint256) {
        // 1. Get ETH value in USD6
        uint256 ethBalance = address(this).balance;
        uint256 ethValueUsd6 = 0;

        if (ethBalance > 0) {
            // Reuses the internal helper to convert current ETH balance to USD
            ethValueUsd6 = _ethToUsd6(ethBalance);
        }

        // 2. Get USDC value (already in 6 decimals)
        uint256 usdcBalance = IERC20Metadata(USDC_ADDRESS).balanceOf(
            address(this)
        );

        return ethValueUsd6 + usdcBalance;
    }

    // -----------------------------
    // Internal helper: convert amount -> USD6 using ETH/USD feed
    // -----------------------------

    /// @notice Converts a token amount to USD with 6 decimals.
    /// @dev WARNING: This function uses the ETH/USD feed for ANY token passed to it.
    ///      Currently only used for NATIVE_TOKEN, but dangerous if reused.
    /// @param amount The amount to convert.
    /// @return usd6 The calculated value in USD (6 decimals).
    function _ethToUsd6(uint256 amount) internal view returns (uint256) {
        // read ETH/USD price
        (, int256 priceInt, , , ) = i_ethUsdPriceFeed.latestRoundData();
        if (priceInt <= 0) revert InvalidPriceFeed();
        uint256 price = uint256(priceInt);
        uint8 priceDecimals = i_ethUsdPriceFeed.decimals();

        uint8 tokenDecimals = 18;

        // usd6 = amount * price * 10^USDC_DECIMALS / (10^tokenDecimals * 10^priceDecimals)
        // Avoid intermediate truncation: promote exponents to uint256
        uint256 scaled = amount * price; // amount * price
        uint256 denom = (10 ** uint256(tokenDecimals)) *
            (10 ** uint256(priceDecimals));
        uint256 usd6 = (scaled * (10 ** uint256(USDC_DECIMALS))) / denom;
        return usd6;
    }

    /// @notice Returns the current total value stored in the bank in USD.
    /// @return The total USD value (6 decimals).
    function getTotalUsdStored6() external view returns (uint256) {
        return s_totalUsdStored6;
    }

    /// @notice Returns the maximum withdrawal limit per transaction.
    /// @return The limit in USD (6 decimals).
    function getMaxWithdrawUsd6() external view returns (uint256) {
        return s_maxWithdrawUsd6;
    }

    // -----------------------------
    // Fallback / receive
    // -----------------------------

    /// @notice Receive function to handle direct ETH transfers.
    /// @dev Calls _depositETH to ensure accounting is updated.
    receive() external payable {
        _depositETH(msg.sender, msg.value);
    }

    /// @notice Fallback function to handle direct ETH transfers.
    /// @dev Calls _depositETH to ensure accounting is updated.
    fallback() external payable {
        _depositETH(msg.sender, msg.value);
    }
}
