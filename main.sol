// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Field Note: "amber ledger / quiet cognition"
    -------------------------------------------
    A single-file ETH vault in an "AI bank account + savings" style.
    Checking = liquid internal balance; Savings = user vaults ("jars") with optional locks.
    Withdrawals are staged (request -> execute after delay) to reduce hot-wallet mistakes.

    Design goals:
    - Safe for EVM mainnets (no external dependencies, nonReentrant, pausable, pull-based ETH transfers).
    - No constructor parameters (deploy-and-go defaults).
    - Explicit custom errors + structured events for indexing.
*/

/// @notice Common custom errors (cheaper than revert strings).
error Nebula__Unauthorized();
error Nebula__ZeroAddress();
error Nebula__ZeroAmount();
error Nebula__TooLarge();
error Nebula__BalanceTooLow();
error Nebula__VaultNotFound();
error Nebula__VaultLocked(uint64 unlockAt);
error Nebula__Cooldown(uint64 nextAllowedAt);
error Nebula__AlreadyExists();
error Nebula__NotReady(uint64 availableAt);
error Nebula__Paused();
error Nebula__BadState();
error Nebula__BadParam();
error Nebula__FeeTooHigh();
error Nebula__SignatureExpired(uint256 deadline);
error Nebula__SignatureInvalid();
error Nebula__Overflow();
error Nebula__Underflow();

/// @notice Events for transparency and indexing.
event NebulaOwnershipTransferred(address indexed previousOwner, address indexed newOwner);
event NebulaGuardianUpdated(address indexed previousGuardian, address indexed newGuardian);
event NebulaPaused(bool paused);

event NebulaDeposit(address indexed user, uint256 creditedWei, uint256 feeWei, bytes32 indexed memoTag);
event NebulaTransferInternal(address indexed user, address indexed to, uint256 amountWei, bytes32 indexed memoTag);

event NebulaWithdrawRequested(
    address indexed user,
    address indexed to,
    uint256 amountWei,
    uint256 feeWei,
    uint64 availableAt,
    bytes32 indexed ticket
);
event NebulaWithdrawCancelled(address indexed user, bytes32 indexed ticket, uint256 refundedWei);
event NebulaWithdrawExecuted(address indexed user, address indexed to, uint256 amountWei, bytes32 indexed ticket);

event NebulaVaultCreated(
    address indexed user,
    uint256 indexed vaultId,
    bytes32 indexed labelHash,
    uint256 goalWei,
    uint64 unlockAt,
    uint8 mode
);
event NebulaVaultToppedUp(address indexed user, uint256 indexed vaultId, uint256 amountWei, uint256 newBalanceWei);
event NebulaVaultMovedOut(address indexed user, uint256 indexed vaultId, uint256 amountWei, uint256 newVaultBalanceWei);
