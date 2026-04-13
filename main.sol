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
event NebulaVaultGoalUpdated(address indexed user, uint256 indexed vaultId, uint256 goalWei);
event NebulaVaultUnlockUpdated(address indexed user, uint256 indexed vaultId, uint64 unlockAt);

event NebulaVaultWithdrawRequested(
    address indexed user,
    uint256 indexed vaultId,
    address indexed to,
    uint256 amountWei,
    uint256 feeWei,
    uint64 availableAt,
    bytes32 ticket
);
event NebulaVaultWithdrawExecuted(address indexed user, uint256 indexed vaultId, address indexed to, uint256 amountWei, bytes32 ticket);

event NebulaFeeCollectorUpdated(address indexed previousCollector, address indexed newCollector);
event NebulaFeeRatesUpdated(uint16 depositBps, uint16 withdrawBps, uint16 vaultWithdrawBps);
event NebulaTimingUpdated(uint64 withdrawDelaySeconds, uint64 vaultWithdrawDelaySeconds, uint64 minSpacingSeconds);
event NebulaRiskUpdated(uint256 perTxMaxWei, uint256 perDaySoftLimitWei, bool enforceSoftLimit);

event NebulaPolicy(bytes32 indexed key, uint256 value);
event NebulaAISignal(address indexed user, uint256 indexed frame, int256 score, bytes32 indexed modelTag);

event NebulaScheduledCreated(address indexed user, bytes32 indexed scheduleId, uint256 amountWei, uint64 everySeconds, uint64 startAt, uint64 endAt);
event NebulaScheduledPoked(address indexed user, bytes32 indexed scheduleId, uint64 nextAt, uint256 movedWei);
event NebulaScheduledCancelled(address indexed user, bytes32 indexed scheduleId);

event NebulaRescue(address indexed to, uint256 amountWei, bytes32 indexed reason);

/// @notice Optional ERC1271 interface (contract wallet signature validation).
interface INebula1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

/// @notice Utility library.
library NebulaMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        unchecked {
            c = a + b;
            if (c < a) revert Nebula__Overflow();
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 c) {
        unchecked {
            if (b > a) revert Nebula__Underflow();
            c = a - b;
        }
    }
}

/// @notice Minimal ECDSA helper (malleability-checked).
library NebulaECDSA {
    error NebulaECDSA__BadSigLen();
    error NebulaECDSA__BadV();
    error NebulaECDSA__BadS();

    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert NebulaECDSA__BadSigLen();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // secp256k1n/2
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert NebulaECDSA__BadS();
        if (v != 27 && v != 28) revert NebulaECDSA__BadV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert Nebula__SignatureInvalid();
        return signer;
    }
}

/// @notice Simple nonReentrant guard.
abstract contract NebulaReentrancyGuard {
    uint256 private _status;

    constructor() {
        _status = 1;
    }

    modifier nonReentrant() {
        if (_status == 2) revert Nebula__BadState();
        _status = 2;
        _;
        _status = 1;
    }
}

/// @notice Owner + guardian two-key control.
abstract contract NebulaOwnable {
    address public owner;
    address public guardian;

    modifier onlyOwner() {
        if (msg.sender != owner) revert Nebula__Unauthorized();
        _;
    }

    modifier onlyGuardianOrOwner() {
        if (msg.sender != owner && msg.sender != guardian) revert Nebula__Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
        guardian = msg.sender;
        emit NebulaOwnershipTransferred(address(0), msg.sender);
        emit NebulaGuardianUpdated(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert Nebula__ZeroAddress();
        address prev = owner;
        owner = newOwner;
        emit NebulaOwnershipTransferred(prev, newOwner);
    }

    function setGuardian(address newGuardian) external onlyOwner {
        if (newGuardian == address(0)) revert Nebula__ZeroAddress();
        address prev = guardian;
        guardian = newGuardian;
        emit NebulaGuardianUpdated(prev, newGuardian);
    }
}

/// @notice Pause switch.
abstract contract NebulaPausable is NebulaOwnable {
    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert Nebula__Paused();
        _;
    }

    function setPaused(bool p) external onlyGuardianOrOwner {
        paused = p;
        emit NebulaPaused(p);
    }
}

/// @title Samr_NebulaAIBankSavings
/// @notice ETH checking + savings vaults with staged withdrawals and optional signed requests.
contract Samr_NebulaAIBankSavings is NebulaReentrancyGuard, NebulaPausable {
    using NebulaMath for uint256;

    // ---------- Embedded fresh sentinels (inert; not privileged) ----------
    // These are never granted any role by default. They exist as unique file markers.
    address internal constant SENTINEL_0 = 0x4bC92D1a3E5f60789AbC1dE2F3a4b5c6D7e8F901;
    address internal constant SENTINEL_1 = 0x9aF0e1D2c3B4A59687f0E1d2C3b4a59687F0e1D2;
    address internal constant SENTINEL_2 = 0xC7dE8f9012aBC1De2F3A4b5c6D7e8F9012abC1De;
    address internal constant SENTINEL_3 = 0x1A2b3C4d5E6f70891a2B3c4D5e6F70891A2b3c4D;

    // ---------- EIP-712-lite signed flows ----------
    bytes32 public immutable DOMAIN_SEPARATOR;
    uint256 private immutable _CHAIN_ID_AT_DEPLOY;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant _NAME_HASH = keccak256(bytes("Samr Nebula AI Bank Savings"));
    bytes32 private constant _VERSION_HASH = keccak256(bytes("nebula-amber-ledger-17"));

    bytes32 private constant _DOMAIN_SALT =
        0x6f5b2a1d9c3e7f1042b8d6a0c1e5f7098a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d;

    bytes32 private constant _TYPEHASH_WITHDRAW =
        keccak256("Withdraw(address user,address to,uint256 amount,uint256 nonce,uint256 deadline,bytes32 memoTag)");
    bytes32 private constant _TYPEHASH_VAULT_WITHDRAW =
        keccak256("VaultWithdraw(address user,address to,uint256 vaultId,uint256 amount,uint256 nonce,uint256 deadline,bytes32 memoTag)");
    bytes32 private constant _TYPEHASH_INTERNAL_XFER =
        keccak256("InternalTransfer(address user,address to,uint256 amount,uint256 nonce,uint256 deadline,bytes32 memoTag)");

    // ---------- Policy ----------
    // Fees in basis points; conservative caps enforced in setters.
    uint16 public depositFeeBps;       // deposit -> checking fee
    uint16 public withdrawFeeBps;      // checking withdraw fee
    uint16 public vaultWithdrawFeeBps; // vault withdraw fee

    address public feeCollector;

    uint64 public withdrawDelaySeconds;
    uint64 public vaultWithdrawDelaySeconds;
    uint64 public minRequestSpacingSeconds;

    uint256 public perTxMaxWithdrawWei;
    uint256 public perDaySoftLimitWei;
    bool public enforceSoftDailyLimit;

    // ---------- Accounting ----------
    // Track contract liabilities precisely so rescue can only withdraw true excess ETH.
    uint256 public totalLiabilitiesWei;

    struct Account {
        uint256 checking;
        uint64 lastRequestAt;
        uint64 dayIndex;
        uint256 dayOutflowWei;
        uint256 nonce;
    }

    mapping(address => Account) private _acct;

    // ---------- Pending staged withdrawals ----------
    struct Pending {
        uint256 amountWei;
        uint256 feeWei;
        uint64 availableAt;
        address to;
        bool fromVault;
        uint256 vaultId;
    }

    mapping(address => mapping(bytes32 => Pending)) private _pending;

    // ---------- Vaults (Savings jars) ----------
    enum VaultMode {
        Basic,        // no extra constraints
        TimelockOnly, // must satisfy unlockAt
        GoalGate,     // withdraw discouraged unless above goal (signal only)
        Fortress      // higher default delay (policy-derived)
    }

    struct Vault {
        bytes32 labelHash;
        uint256 balanceWei;
        uint256 goalWei;
        uint64 unlockAt;
        uint64 createdAt;
        uint8 mode;     // VaultMode
        uint32 spice;   // file-unique salt bits for UI differentiation
    }

    mapping(address => uint256) public vaultCount;
    mapping(address => mapping(uint256 => Vault)) private _vaults;

    // ---------- AI signal layer (deterministic; no oracle required) ----------
    bytes32 public aiModelTag;
    uint256 public aiEpoch;

    // ---------- Scheduled savings (checking -> vault) ----------
    // A simple on-chain schedule that moves funds periodically when poked.
    struct Schedule {
        uint256 amountWei;
        uint64 everySeconds;
        uint64 nextAt;
        uint64 endAt;
        uint32 flags;
        uint256 vaultId;
        bool live;
    }

    mapping(address => mapping(bytes32 => Schedule)) private _schedules;

    // ---------- Audit ring buffer (compact) ----------
    // Stores recent activity digests; useful for off-chain monitoring.
    uint256 public auditCursor;
    mapping(uint256 => bytes32) public auditRing;
    uint256 private constant _AUDIT_RING_SIZE = 257; // prime-ish

    // ---------- Constructor ----------
    constructor() {
        _CHAIN_ID_AT_DEPLOY = block.chainid;
        DOMAIN_SEPARATOR = _computeDomainSeparator();

        feeCollector = msg.sender;
        emit NebulaFeeCollectorUpdated(address(0), msg.sender);

        depositFeeBps = 0;
        withdrawFeeBps = 0;
        vaultWithdrawFeeBps = 0;
        emit NebulaFeeRatesUpdated(depositFeeBps, withdrawFeeBps, vaultWithdrawFeeBps);

        withdrawDelaySeconds = 2 hours;
        vaultWithdrawDelaySeconds = 6 hours;
        minRequestSpacingSeconds = 7 minutes;
        emit NebulaTimingUpdated(withdrawDelaySeconds, vaultWithdrawDelaySeconds, minRequestSpacingSeconds);

        perTxMaxWithdrawWei = 275 ether;
        perDaySoftLimitWei = 1_250 ether;
        enforceSoftDailyLimit = false;
        emit NebulaRiskUpdated(perTxMaxWithdrawWei, perDaySoftLimitWei, enforceSoftDailyLimit);

        aiModelTag = keccak256(abi.encodePacked(address(this), SENTINEL_2, _DOMAIN_SALT, uint256(block.prevrandao)));
        aiEpoch = uint256(uint160(SENTINEL_0)) ^ uint256(uint160(SENTINEL_3));

        _audit(bytes32(uint256(uint160(address(this)))) ^ keccak256(abi.encodePacked(SENTINEL_1, block.number)));
        emit NebulaPolicy(keccak256(abi.encodePacked("boot", _VERSION_HASH)), uint256(aiModelTag));
    }

    // ---------- Receive / fallback ----------
    receive() external payable {
        _depositToChecking(msg.sender, msg.value, bytes32(0));
    }

    fallback() external payable {
        _depositToChecking(msg.sender, msg.value, keccak256(msg.data));
    }

    // ---------- Views ----------
    function getAccount(address user)
        external
        view
        returns (uint256 checking, uint64 lastRequestAt, uint64 dayIndex, uint256 dayOutflowWei, uint256 nonce)
    {
        Account storage a = _acct[user];
        return (a.checking, a.lastRequestAt, a.dayIndex, a.dayOutflowWei, a.nonce);
    }

    function getVault(address user, uint256 vaultId)
        external
        view
        returns (
            bytes32 labelHash,
