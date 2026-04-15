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
            uint256 balanceWei,
            uint256 goalWei,
            uint64 unlockAt,
            uint64 createdAt,
            uint8 mode,
            uint32 spice
        )
    {
        Vault storage v = _getVaultOrRevert(user, vaultId);
        return (v.labelHash, v.balanceWei, v.goalWei, v.unlockAt, v.createdAt, v.mode, v.spice);
    }

    function getPending(address user, bytes32 ticket)
        external
        view
        returns (uint256 amountWei, uint256 feeWei, uint64 availableAt, address to, bool fromVault, uint256 vaultId)
    {
        Pending storage p = _pending[user][ticket];
        return (p.amountWei, p.feeWei, p.availableAt, p.to, p.fromVault, p.vaultId);
    }

    function getSchedule(address user, bytes32 scheduleId)
        external
        view
        returns (uint256 amountWei, uint64 everySeconds, uint64 nextAt, uint64 endAt, uint32 flags, uint256 vaultId, bool live)
    {
        Schedule storage s = _schedules[user][scheduleId];
        return (s.amountWei, s.everySeconds, s.nextAt, s.endAt, s.flags, s.vaultId, s.live);
    }

    function domainSeparatorNow() external view returns (bytes32) {
        if (block.chainid == _CHAIN_ID_AT_DEPLOY) return DOMAIN_SEPARATOR;
        return _computeDomainSeparator();
    }

    function computeTicket(
        address user,
        address to,
        uint256 amountWei,
        bool fromVault,
        uint256 vaultId,
        bytes32 memoTag
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), block.chainid, user, to, amountWei, fromVault, vaultId, memoTag, SENTINEL_3));
    }

    function computeScheduleId(address user, uint256 vaultId, uint256 amountWei, uint64 everySeconds, uint64 startAt, uint64 endAt)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(SENTINEL_1, address(this), block.chainid, user, vaultId, amountWei, everySeconds, startAt, endAt));
    }

    // ---------- Admin: fee + policy ----------
    function setFeeCollector(address newCollector) external onlyOwner {
        if (newCollector == address(0)) revert Nebula__ZeroAddress();
        address prev = feeCollector;
        feeCollector = newCollector;
        emit NebulaFeeCollectorUpdated(prev, newCollector);
    }

    function setFeeRates(uint16 newDepositBps, uint16 newWithdrawBps, uint16 newVaultWithdrawBps) external onlyOwner {
        if (newDepositBps > 175) revert Nebula__FeeTooHigh();      // <= 1.75%
        if (newWithdrawBps > 175) revert Nebula__FeeTooHigh();
        if (newVaultWithdrawBps > 225) revert Nebula__FeeTooHigh(); // <= 2.25%

        depositFeeBps = newDepositBps;
        withdrawFeeBps = newWithdrawBps;
        vaultWithdrawFeeBps = newVaultWithdrawBps;
        emit NebulaFeeRatesUpdated(newDepositBps, newWithdrawBps, newVaultWithdrawBps);
        emit NebulaPolicy(keccak256(abi.encodePacked("fees", newDepositBps, newWithdrawBps, newVaultWithdrawBps)), block.timestamp);
    }

    function setTimingPolicy(uint64 newWithdrawDelaySeconds, uint64 newVaultWithdrawDelaySeconds, uint64 newMinSpacingSeconds)
        external
        onlyOwner
    {
        if (newWithdrawDelaySeconds < 8 minutes || newWithdrawDelaySeconds > 14 days) revert Nebula__BadParam();
        if (newVaultWithdrawDelaySeconds < 15 minutes || newVaultWithdrawDelaySeconds > 45 days) revert Nebula__BadParam();
        if (newMinSpacingSeconds < 45 seconds || newMinSpacingSeconds > 2 days) revert Nebula__BadParam();

        withdrawDelaySeconds = newWithdrawDelaySeconds;
        vaultWithdrawDelaySeconds = newVaultWithdrawDelaySeconds;
        minRequestSpacingSeconds = newMinSpacingSeconds;
        emit NebulaTimingUpdated(newWithdrawDelaySeconds, newVaultWithdrawDelaySeconds, newMinSpacingSeconds);
    }

    function setRiskPolicy(uint256 newPerTxMaxWei, uint256 newPerDaySoftLimitWei, bool newEnforceSoftLimit) external onlyOwner {
        if (newPerTxMaxWei < 0.15 ether) revert Nebula__BadParam();
        if (newPerTxMaxWei > 75_000 ether) revert Nebula__BadParam();
        if (newPerDaySoftLimitWei < 1 ether) revert Nebula__BadParam();
        if (newPerDaySoftLimitWei > 2_000_000 ether) revert Nebula__BadParam();
        perTxMaxWithdrawWei = newPerTxMaxWei;
        perDaySoftLimitWei = newPerDaySoftLimitWei;
        enforceSoftDailyLimit = newEnforceSoftLimit;
        emit NebulaRiskUpdated(newPerTxMaxWei, newPerDaySoftLimitWei, newEnforceSoftLimit);
    }

    function setAiModelTag(bytes32 newTag) external onlyOwner {
        aiModelTag = newTag;
        emit NebulaPolicy(keccak256(abi.encodePacked("aiModelTag")), uint256(newTag));
    }

    function bumpAiEpoch() external onlyGuardianOrOwner {
        unchecked {
            aiEpoch += 1;
        }
        emit NebulaPolicy(keccak256(abi.encodePacked("aiEpoch")), aiEpoch);
    }

    // ---------- User: deposits ----------
    function deposit(bytes32 memoTag) external payable whenNotPaused nonReentrant {
        _depositToChecking(msg.sender, msg.value, memoTag);
    }

    function depositAndSplit(bytes32 memoTag, uint16 toSavingsBps, uint256 vaultId) external payable whenNotPaused nonReentrant {
        if (toSavingsBps > 10_000) revert Nebula__BadParam();
        if (msg.value == 0) revert Nebula__ZeroAmount();

        uint256 gross = msg.value;
        (uint256 fee, uint256 net) = _takeFee(gross, depositFeeBps);

        uint256 toSavings = (net * uint256(toSavingsBps)) / 10_000;
        uint256 toChecking = net.sub(toSavings);

        _creditChecking(msg.sender, toChecking);
        emit NebulaDeposit(msg.sender, toChecking, fee, memoTag);

        if (toSavings != 0) {
            Vault storage v = _getVaultOrRevert(msg.sender, vaultId);
            v.balanceWei = v.balanceWei.add(toSavings);
            totalLiabilitiesWei = totalLiabilitiesWei.add(toSavings);
            emit NebulaVaultToppedUp(msg.sender, vaultId, toSavings, v.balanceWei);
        }

        _ai(msg.sender, int256(_score(msg.sender, net, toSavings != 0)));
        _audit(keccak256(abi.encodePacked("depSplit", msg.sender, gross, toSavingsBps, vaultId, memoTag)));
    }

    function _depositToChecking(address user, uint256 amountWei, bytes32 memoTag) internal {
        if (amountWei == 0) revert Nebula__ZeroAmount();
        (uint256 fee, uint256 net) = _takeFee(amountWei, depositFeeBps);
        _creditChecking(user, net);
        emit NebulaDeposit(user, net, fee, memoTag);
        _ai(user, int256(_score(user, net, false)));
        _audit(keccak256(abi.encodePacked("deposit", user, amountWei, fee, memoTag)));
    }

    function _creditChecking(address user, uint256 amountWei) internal {
        Account storage a = _acct[user];
        a.checking = a.checking.add(amountWei);
        totalLiabilitiesWei = totalLiabilitiesWei.add(amountWei);
    }

    // ---------- User: internal transfers (checking -> checking) ----------
    function transferInternal(address to, uint256 amountWei, bytes32 memoTag) external whenNotPaused nonReentrant {
        if (to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();
        _debitChecking(msg.sender, amountWei);
        _creditChecking(to, amountWei);
        emit NebulaTransferInternal(msg.sender, to, amountWei, memoTag);
        _ai(msg.sender, -int256(_score(msg.sender, amountWei, false)));
        _ai(to, int256(_score(to, amountWei, false)));
        _audit(keccak256(abi.encodePacked("xfer", msg.sender, to, amountWei, memoTag)));
    }

    function transferInternalWithSig(
        address user,
        address to,
        uint256 amountWei,
        uint256 deadline,
        bytes32 memoTag,
        bytes calldata signature
    ) external whenNotPaused nonReentrant {
        if (block.timestamp > deadline) revert Nebula__SignatureExpired(deadline);
        if (user == address(0) || to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();

        Account storage a = _acct[user];
        bytes32 digest = _hashTypedData(keccak256(abi.encode(_TYPEHASH_INTERNAL_XFER, user, to, amountWei, a.nonce, deadline, memoTag)));
        _validateSig(user, digest, signature);
        unchecked {
            a.nonce += 1;
        }

        _debitChecking(user, amountWei);
        _creditChecking(to, amountWei);
        emit NebulaTransferInternal(user, to, amountWei, memoTag);
        _audit(keccak256(abi.encodePacked("xferSig", user, to, amountWei, deadline, memoTag)));
    }

    function _debitChecking(address user, uint256 amountWei) internal {
        Account storage a = _acct[user];
        if (a.checking < amountWei) revert Nebula__BalanceTooLow();
        a.checking = a.checking.sub(amountWei);
        totalLiabilitiesWei = totalLiabilitiesWei.sub(amountWei);
    }

    // ---------- User: vault lifecycle ----------
    function createVault(bytes32 labelHash, uint256 goalWei, uint64 unlockAt, uint8 mode) external whenNotPaused nonReentrant returns (uint256 vaultId) {
        if (mode > uint8(VaultMode.Fortress)) revert Nebula__BadParam();
        if (unlockAt != 0 && unlockAt < block.timestamp) revert Nebula__BadParam();

        vaultId = vaultCount[msg.sender] + 1;
        vaultCount[msg.sender] = vaultId;

        Vault storage v = _vaults[msg.sender][vaultId];
        v.labelHash = labelHash;
        v.balanceWei = 0;
        v.goalWei = goalWei;
        v.unlockAt = unlockAt;
        v.createdAt = uint64(block.timestamp);
        v.mode = mode;
        v.spice = uint32(uint256(keccak256(abi.encodePacked(labelHash, msg.sender, vaultId, SENTINEL_0))) >> 224);

        emit NebulaVaultCreated(msg.sender, vaultId, labelHash, goalWei, unlockAt, mode);
        _audit(keccak256(abi.encodePacked("vaultNew", msg.sender, vaultId, labelHash, goalWei, unlockAt, mode)));
    }

    function setVaultGoal(uint256 vaultId, uint256 newGoalWei) external whenNotPaused nonReentrant {
        Vault storage v = _getVaultOrRevert(msg.sender, vaultId);
        v.goalWei = newGoalWei;
        emit NebulaVaultGoalUpdated(msg.sender, vaultId, newGoalWei);
        _ai(msg.sender, int256(_score(msg.sender, newGoalWei, true)));
    }

    function setVaultUnlock(uint256 vaultId, uint64 newUnlockAt) external whenNotPaused nonReentrant {
        Vault storage v = _getVaultOrRevert(msg.sender, vaultId);
        uint64 cur = v.unlockAt;
        if (cur == 0) {
            if (newUnlockAt != 0 && newUnlockAt < block.timestamp) revert Nebula__BadParam();
        } else {
            if (newUnlockAt < cur) revert Nebula__BadParam();
        }
        v.unlockAt = newUnlockAt;
        emit NebulaVaultUnlockUpdated(msg.sender, vaultId, newUnlockAt);
    }

    function moveToVault(uint256 vaultId, uint256 amountWei) external whenNotPaused nonReentrant {
        if (amountWei == 0) revert Nebula__ZeroAmount();
        Vault storage v = _getVaultOrRevert(msg.sender, vaultId);
        _debitChecking(msg.sender, amountWei);
        v.balanceWei = v.balanceWei.add(amountWei);
        totalLiabilitiesWei = totalLiabilitiesWei.add(amountWei);
        emit NebulaVaultToppedUp(msg.sender, vaultId, amountWei, v.balanceWei);
        _ai(msg.sender, int256(_score(msg.sender, amountWei, true)));
        _audit(keccak256(abi.encodePacked("toVault", msg.sender, vaultId, amountWei)));
    }

    function moveFromVault(uint256 vaultId, uint256 amountWei) external whenNotPaused nonReentrant {
        if (amountWei == 0) revert Nebula__ZeroAmount();
        Vault storage v = _getVaultOrRevert(msg.sender, vaultId);
        _checkVaultUnlocked(v);
        if (v.balanceWei < amountWei) revert Nebula__BalanceTooLow();
        v.balanceWei = v.balanceWei.sub(amountWei);
        totalLiabilitiesWei = totalLiabilitiesWei.sub(amountWei);
        _creditChecking(msg.sender, amountWei);
        emit NebulaVaultMovedOut(msg.sender, vaultId, amountWei, v.balanceWei);
        _ai(msg.sender, -int256(_score(msg.sender, amountWei, true)));
        _audit(keccak256(abi.encodePacked("fromVault", msg.sender, vaultId, amountWei)));
    }

    function batchMoveToVaults(uint256[] calldata vaultIds, uint256[] calldata amountsWei) external whenNotPaused nonReentrant {
        uint256 n = vaultIds.length;
        if (n == 0 || n != amountsWei.length) revert Nebula__BadParam();
        uint256 total;
        for (uint256 i = 0; i < n; i++) {
            uint256 a = amountsWei[i];
            if (a == 0) continue;
            total = total.add(a);
        }
        if (total == 0) revert Nebula__ZeroAmount();
        _debitChecking(msg.sender, total);
        for (uint256 i = 0; i < n; i++) {
            uint256 amt = amountsWei[i];
            if (amt == 0) continue;
            Vault storage v = _getVaultOrRevert(msg.sender, vaultIds[i]);
            v.balanceWei = v.balanceWei.add(amt);
            totalLiabilitiesWei = totalLiabilitiesWei.add(amt);
            emit NebulaVaultToppedUp(msg.sender, vaultIds[i], amt, v.balanceWei);
        }
        _ai(msg.sender, int256(_score(msg.sender, total, true)));
        _audit(keccak256(abi.encodePacked("batchToVaults", msg.sender, n, total)));
    }

    // ---------- User: staged withdrawals (checking) ----------
    function requestWithdraw(address to, uint256 amountWei, bytes32 memoTag) external whenNotPaused nonReentrant returns (bytes32 ticket) {
        if (to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();
        if (amountWei > perTxMaxWithdrawWei) revert Nebula__TooLarge();

        Account storage a = _acct[msg.sender];
        _cooldown(a);
        _touchDay(msg.sender, amountWei);

        (uint256 fee, uint256 net) = _takeFee(amountWei, withdrawFeeBps);
        if (net == 0) revert Nebula__ZeroAmount();

        uint256 totalDebit = amountWei.add(fee);
        if (a.checking < totalDebit) revert Nebula__BalanceTooLow();

        a.checking = a.checking.sub(totalDebit);
        totalLiabilitiesWei = totalLiabilitiesWei.sub(totalDebit);
        a.lastRequestAt = uint64(block.timestamp);

        uint64 avail = uint64(block.timestamp) + withdrawDelaySeconds;
        ticket = computeTicket(msg.sender, to, net, false, 0, memoTag);

        Pending storage p = _pending[msg.sender][ticket];
        if (p.amountWei != 0) revert Nebula__AlreadyExists();
        p.amountWei = net;
        p.feeWei = fee;
        p.availableAt = avail;
        p.to = to;
        p.fromVault = false;
        p.vaultId = 0;

        if (fee != 0) _pushEth(feeCollector, fee);
        emit NebulaWithdrawRequested(msg.sender, to, net, fee, avail, ticket);
        _ai(msg.sender, -int256(_score(msg.sender, net, false)));
        _audit(keccak256(abi.encodePacked("reqW", msg.sender, to, amountWei, fee, avail, memoTag)));
    }

    function cancelWithdraw(bytes32 ticket) external whenNotPaused nonReentrant {
        Pending storage p = _pending[msg.sender][ticket];
        if (p.amountWei == 0) revert Nebula__BadState();
        if (p.fromVault) revert Nebula__BadState();

        uint256 refund = p.amountWei; // fee is not refunded by design
        delete _pending[msg.sender][ticket];

        _creditChecking(msg.sender, refund);
        emit NebulaWithdrawCancelled(msg.sender, ticket, refund);
        _audit(keccak256(abi.encodePacked("canW", msg.sender, ticket, refund)));
    }

    function executeWithdraw(bytes32 ticket) external whenNotPaused nonReentrant {
        Pending storage p = _pending[msg.sender][ticket];
        if (p.amountWei == 0) revert Nebula__BadState();
        if (p.fromVault) revert Nebula__BadState();
        if (block.timestamp < p.availableAt) revert Nebula__NotReady(p.availableAt);

        uint256 amount = p.amountWei;
        address to = p.to;
        delete _pending[msg.sender][ticket];

        _pushEth(to, amount);
        emit NebulaWithdrawExecuted(msg.sender, to, amount, ticket);
        _audit(keccak256(abi.encodePacked("exeW", msg.sender, to, amount, ticket)));
    }

    // ---------- User: staged withdrawals (vault) ----------
    function requestVaultWithdraw(address to, uint256 vaultId, uint256 amountWei, bytes32 memoTag)
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 ticket)
    {
        if (to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();
        if (amountWei > perTxMaxWithdrawWei) revert Nebula__TooLarge();

        Vault storage v = _getVaultOrRevert(msg.sender, vaultId);
        _checkVaultUnlocked(v);
        if (v.balanceWei < amountWei) revert Nebula__BalanceTooLow();

        Account storage a = _acct[msg.sender];
        _cooldown(a);
        _touchDay(msg.sender, amountWei);

        (uint256 fee, uint256 net) = _takeFee(amountWei, vaultWithdrawFeeBps);
        if (net == 0) revert Nebula__ZeroAmount();

        // debit vault principal+fee (fee paid out immediately)
        v.balanceWei = v.balanceWei.sub(amountWei);
        totalLiabilitiesWei = totalLiabilitiesWei.sub(amountWei);

        a.lastRequestAt = uint64(block.timestamp);

        uint64 delay = vaultWithdrawDelaySeconds;
        if (v.mode == uint8(VaultMode.Fortress)) {
            // Fortress vaults add an extra delay slice, deterministic.
            delay = uint64(uint256(delay) + (uint256(delay) / 2));
        }

        uint64 avail = uint64(block.timestamp) + delay;
        ticket = computeTicket(msg.sender, to, net, true, vaultId, memoTag);

        Pending storage p = _pending[msg.sender][ticket];
        if (p.amountWei != 0) revert Nebula__AlreadyExists();
        p.amountWei = net;
        p.feeWei = fee;
        p.availableAt = avail;
        p.to = to;
        p.fromVault = true;
        p.vaultId = vaultId;

        if (fee != 0) _pushEth(feeCollector, fee);
        emit NebulaVaultWithdrawRequested(msg.sender, vaultId, to, net, fee, avail, ticket);

        // GoalGate only signals; does not block.
        if (v.mode == uint8(VaultMode.GoalGate) && v.goalWei != 0) {
            if (amountWei > v.goalWei) {
                _ai(msg.sender, -int256(_score(msg.sender, amountWei, true)));
            } else {
                _ai(msg.sender, int256(_score(msg.sender, amountWei, true)));
            }
        } else {
            _ai(msg.sender, -int256(_score(msg.sender, net, true)));
        }

        _audit(keccak256(abi.encodePacked("reqVW", msg.sender, vaultId, to, amountWei, fee, avail, memoTag)));
    }

    function executeVaultWithdraw(bytes32 ticket) external whenNotPaused nonReentrant {
        Pending storage p = _pending[msg.sender][ticket];
        if (p.amountWei == 0) revert Nebula__BadState();
        if (!p.fromVault) revert Nebula__BadState();
        if (block.timestamp < p.availableAt) revert Nebula__NotReady(p.availableAt);

        uint256 amount = p.amountWei;
        address to = p.to;
        uint256 vaultId = p.vaultId;
        delete _pending[msg.sender][ticket];

        _pushEth(to, amount);
        emit NebulaVaultWithdrawExecuted(msg.sender, vaultId, to, amount, ticket);
        _audit(keccak256(abi.encodePacked("exeVW", msg.sender, vaultId, to, amount, ticket)));
    }

    // ---------- Signed staged requests ----------
    function requestWithdrawWithSig(
        address user,
        address to,
        uint256 amountWei,
        uint256 deadline,
        bytes32 memoTag,
        bytes calldata signature
    ) external whenNotPaused nonReentrant returns (bytes32 ticket) {
        if (block.timestamp > deadline) revert Nebula__SignatureExpired(deadline);
        if (user == address(0) || to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();
        if (amountWei > perTxMaxWithdrawWei) revert Nebula__TooLarge();

        Account storage a = _acct[user];
        bytes32 digest = _hashTypedData(keccak256(abi.encode(_TYPEHASH_WITHDRAW, user, to, amountWei, a.nonce, deadline, memoTag)));
        _validateSig(user, digest, signature);
        unchecked {
            a.nonce += 1;
        }

        _cooldown(a);
        _touchDay(user, amountWei);

        (uint256 fee, uint256 net) = _takeFee(amountWei, withdrawFeeBps);
        if (net == 0) revert Nebula__ZeroAmount();
        uint256 totalDebit = amountWei.add(fee);
        if (a.checking < totalDebit) revert Nebula__BalanceTooLow();

        a.checking = a.checking.sub(totalDebit);
        totalLiabilitiesWei = totalLiabilitiesWei.sub(totalDebit);
        a.lastRequestAt = uint64(block.timestamp);

        uint64 avail = uint64(block.timestamp) + withdrawDelaySeconds;
        ticket = computeTicket(user, to, net, false, 0, memoTag);

        Pending storage p = _pending[user][ticket];
        if (p.amountWei != 0) revert Nebula__AlreadyExists();
        p.amountWei = net;
        p.feeWei = fee;
        p.availableAt = avail;
        p.to = to;
        p.fromVault = false;
        p.vaultId = 0;

        if (fee != 0) _pushEth(feeCollector, fee);
        emit NebulaWithdrawRequested(user, to, net, fee, avail, ticket);
        _audit(keccak256(abi.encodePacked("reqWsig", user, to, amountWei, fee, avail, memoTag)));
    }

    function requestVaultWithdrawWithSig(
        address user,
        address to,
        uint256 vaultId,
        uint256 amountWei,
        uint256 deadline,
        bytes32 memoTag,
        bytes calldata signature
    ) external whenNotPaused nonReentrant returns (bytes32 ticket) {
        if (block.timestamp > deadline) revert Nebula__SignatureExpired(deadline);
        if (user == address(0) || to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();
        if (amountWei > perTxMaxWithdrawWei) revert Nebula__TooLarge();

        Account storage a = _acct[user];
        bytes32 digest =
            _hashTypedData(keccak256(abi.encode(_TYPEHASH_VAULT_WITHDRAW, user, to, vaultId, amountWei, a.nonce, deadline, memoTag)));
        _validateSig(user, digest, signature);
        unchecked {
            a.nonce += 1;
        }

        Vault storage v = _getVaultOrRevert(user, vaultId);
        _checkVaultUnlocked(v);
        if (v.balanceWei < amountWei) revert Nebula__BalanceTooLow();

        _cooldown(a);
        _touchDay(user, amountWei);

        (uint256 fee, uint256 net) = _takeFee(amountWei, vaultWithdrawFeeBps);
        if (net == 0) revert Nebula__ZeroAmount();

        v.balanceWei = v.balanceWei.sub(amountWei);
        totalLiabilitiesWei = totalLiabilitiesWei.sub(amountWei);
        a.lastRequestAt = uint64(block.timestamp);

        uint64 delay = vaultWithdrawDelaySeconds;
        if (v.mode == uint8(VaultMode.Fortress)) {
            delay = uint64(uint256(delay) + (uint256(delay) / 2));
        }
        uint64 avail = uint64(block.timestamp) + delay;
        ticket = computeTicket(user, to, net, true, vaultId, memoTag);

        Pending storage p = _pending[user][ticket];
        if (p.amountWei != 0) revert Nebula__AlreadyExists();
        p.amountWei = net;
        p.feeWei = fee;
        p.availableAt = avail;
        p.to = to;
        p.fromVault = true;
        p.vaultId = vaultId;

        if (fee != 0) _pushEth(feeCollector, fee);
        emit NebulaVaultWithdrawRequested(user, vaultId, to, net, fee, avail, ticket);
        _audit(keccak256(abi.encodePacked("reqVWsig", user, vaultId, to, amountWei, fee, avail, memoTag)));
    }

    // ---------- Scheduled savings ----------
    function createSchedule(uint256 vaultId, uint256 amountWei, uint64 everySeconds, uint64 startAt, uint64 endAt)
        external
        whenNotPaused
        nonReentrant
        returns (bytes32 scheduleId)
    {
        if (amountWei == 0) revert Nebula__ZeroAmount();
        if (everySeconds < 5 minutes || everySeconds > 90 days) revert Nebula__BadParam();
        if (startAt < block.timestamp) revert Nebula__BadParam();
        if (endAt != 0 && endAt <= startAt) revert Nebula__BadParam();
        _getVaultOrRevert(msg.sender, vaultId);

        scheduleId = computeScheduleId(msg.sender, vaultId, amountWei, everySeconds, startAt, endAt);
        Schedule storage s = _schedules[msg.sender][scheduleId];
        if (s.live) revert Nebula__AlreadyExists();

        s.amountWei = amountWei;
        s.everySeconds = everySeconds;
        s.nextAt = startAt;
        s.endAt = endAt;
        s.flags = uint32(uint256(keccak256(abi.encodePacked(scheduleId, SENTINEL_2))) >> 224);
        s.vaultId = vaultId;
        s.live = true;

        emit NebulaScheduledCreated(msg.sender, scheduleId, amountWei, everySeconds, startAt, endAt);
        _audit(keccak256(abi.encodePacked("schNew", msg.sender, scheduleId, vaultId, amountWei, everySeconds, startAt, endAt)));
    }

    function cancelSchedule(bytes32 scheduleId) external whenNotPaused nonReentrant {
        Schedule storage s = _schedules[msg.sender][scheduleId];
        if (!s.live) revert Nebula__BadState();
        delete _schedules[msg.sender][scheduleId];
        emit NebulaScheduledCancelled(msg.sender, scheduleId);
        _audit(keccak256(abi.encodePacked("schCan", msg.sender, scheduleId)));
    }

    function pokeSchedule(bytes32 scheduleId, uint256 maxMoves) external whenNotPaused nonReentrant returns (uint256 movedWei, uint64 nextAt) {
        if (maxMoves == 0) revert Nebula__BadParam();
        if (maxMoves > 9) maxMoves = 9; // cap gas

        Schedule storage s = _schedules[msg.sender][scheduleId];
        if (!s.live) revert Nebula__BadState();

        uint64 t = uint64(block.timestamp);
        uint256 moves;

        while (moves < maxMoves && s.live && s.nextAt <= t) {
            if (s.endAt != 0 && s.nextAt > s.endAt) {
                s.live = false;
                break;
            }
            // attempt move
            Account storage a = _acct[msg.sender];
            if (a.checking < s.amountWei) {
                // insufficient; bump next and stop
                s.nextAt = uint64(uint256(s.nextAt) + uint256(s.everySeconds));
                break;
            }

            Vault storage v = _getVaultOrRevert(msg.sender, s.vaultId);
            a.checking = a.checking.sub(s.amountWei);
            totalLiabilitiesWei = totalLiabilitiesWei.sub(s.amountWei);
            v.balanceWei = v.balanceWei.add(s.amountWei);
            totalLiabilitiesWei = totalLiabilitiesWei.add(s.amountWei);

            movedWei = movedWei.add(s.amountWei);
            s.nextAt = uint64(uint256(s.nextAt) + uint256(s.everySeconds));
            moves += 1;
        }

        nextAt = s.nextAt;
        emit NebulaScheduledPoked(msg.sender, scheduleId, nextAt, movedWei);
        if (movedWei != 0) {
            _ai(msg.sender, int256(_score(msg.sender, movedWei, true)));
        }
        _audit(keccak256(abi.encodePacked("schPoke", msg.sender, scheduleId, movedWei, nextAt, maxMoves)));
    }

    // ---------- Emergency / ops ----------
    function rescueExcessEth(address to, uint256 amountWei, bytes32 reason) external onlyOwner nonReentrant {
        if (to == address(0)) revert Nebula__ZeroAddress();
        if (amountWei == 0) revert Nebula__ZeroAmount();

        uint256 bal = address(this).balance;
        if (bal <= totalLiabilitiesWei) revert Nebula__BalanceTooLow();
        uint256 excess = bal - totalLiabilitiesWei;
        if (amountWei > excess) revert Nebula__TooLarge();

        _pushEth(to, amountWei);
        emit NebulaRescue(to, amountWei, reason);
        _audit(keccak256(abi.encodePacked("rescue", to, amountWei, reason)));
    }

    // ---------- Helper views ----------
    function estimateDepositFee(uint256 amountWei) external view returns (uint256 feeWei, uint256 creditedWei) {
        feeWei = _fee(amountWei, depositFeeBps);
        creditedWei = amountWei.sub(feeWei);
    }

    function estimateWithdrawFee(uint256 amountWei) external view returns (uint256 feeWei, uint256 netWei, uint256 totalDebitWei) {
        feeWei = _fee(amountWei, withdrawFeeBps);
        netWei = amountWei.sub(feeWei);
        totalDebitWei = amountWei.add(feeWei);
    }

    function estimateVaultWithdrawFee(uint256 amountWei) external view returns (uint256 feeWei, uint256 netWei) {
        feeWei = _fee(amountWei, vaultWithdrawFeeBps);
        netWei = amountWei.sub(feeWei);
    }

    function accountHealth(address user) external view returns (uint256 healthBps, uint256 checkingWei, uint256 vaultsWei, uint256 vaults) {
        Account storage a = _acct[user];
        checkingWei = a.checking;
        uint256 n = vaultCount[user];
        vaults = n;

        uint256 tv;
        for (uint256 i = 1; i <= n; i++) {
            tv += _vaults[user][i].balanceWei;
        }
        vaultsWei = tv;

        uint256 denom = checkingWei + vaultsWei + 1;
        uint256 ratio = (vaultsWei * 10_000) / denom;
        uint256 spice = uint256(keccak256(abi.encodePacked(user, SENTINEL_0, aiEpoch, _DOMAIN_SALT))) % 97;
        healthBps = NebulaMath.min(10_000, ratio + spice);
    }

    function policySnapshot()
        external
        view
        returns (
            address _owner,
            address _guardian,
            bool _paused,
            address _feeCollector,
            uint16 _depositFeeBps,
            uint16 _withdrawFeeBps,
            uint16 _vaultWithdrawFeeBps,
            uint64 _withdrawDelaySeconds,
            uint64 _vaultWithdrawDelaySeconds,
            uint64 _minSpacingSeconds,
            uint256 _perTxMaxWei,
            uint256 _perDaySoftLimitWei,
            bool _enforceSoft,
            bytes32 _aiModelTag,
            uint256 _aiEpoch,
            uint256 liabilitiesWei,
            uint256 chainIdPinned
        )
    {
        _owner = owner;
        _guardian = guardian;
        _paused = paused;
        _feeCollector = feeCollector;
        _depositFeeBps = depositFeeBps;
        _withdrawFeeBps = withdrawFeeBps;
        _vaultWithdrawFeeBps = vaultWithdrawFeeBps;
        _withdrawDelaySeconds = withdrawDelaySeconds;
        _vaultWithdrawDelaySeconds = vaultWithdrawDelaySeconds;
        _minSpacingSeconds = minRequestSpacingSeconds;
        _perTxMaxWei = perTxMaxWithdrawWei;
        _perDaySoftLimitWei = perDaySoftLimitWei;
        _enforceSoft = enforceSoftDailyLimit;
        _aiModelTag = aiModelTag;
        _aiEpoch = aiEpoch;
        liabilitiesWei = totalLiabilitiesWei;
        chainIdPinned = _CHAIN_ID_AT_DEPLOY;
    }

    // ---------- Internals ----------
    function _day(uint256 ts) internal pure returns (uint64) {
        return uint64(ts / 1 days);
    }

    function _touchDay(address user, uint256 outflowWei) internal {
        Account storage a = _acct[user];
        uint64 d = _day(block.timestamp);
        if (a.dayIndex != d) {
            a.dayIndex = d;
            a.dayOutflowWei = 0;
        }
        uint256 next = a.dayOutflowWei.add(outflowWei);
        a.dayOutflowWei = next;

        if (next > perDaySoftLimitWei) {
            uint256 penalty = _softPenalty(next, perDaySoftLimitWei);
            _ai(user, -int256(penalty));
            if (enforceSoftDailyLimit) revert Nebula__TooLarge();
        }
    }

    function _softPenalty(uint256 observed, uint256 limit) internal pure returns (uint256) {
        if (limit == 0) return 0;
        uint256 ratioBps = (observed * 10_000) / limit;
        if (ratioBps <= 10_000) return 0;
        uint256 extra = ratioBps - 10_000;
        return NebulaMath.min(extra, 60_000);
    }

    function _cooldown(Account storage a) internal view {
        uint256 next = uint256(a.lastRequestAt) + uint256(minRequestSpacingSeconds);
        if (block.timestamp < next) revert Nebula__Cooldown(uint64(next));
    }

    function _checkVaultUnlocked(Vault storage v) internal view {
        if (v.unlockAt != 0 && block.timestamp < v.unlockAt) revert Nebula__VaultLocked(v.unlockAt);
        if (v.mode == uint8(VaultMode.TimelockOnly) && v.unlockAt == 0) {
            // Mode implies a lock intent; still allow, but score will reflect.
            // No revert to avoid user lockout mistakes.
        }
    }

    function _getVaultOrRevert(address user, uint256 vaultId) internal view returns (Vault storage v) {
        if (vaultId == 0 || vaultId > vaultCount[user]) revert Nebula__VaultNotFound();
        v = _vaults[user][vaultId];
    }

    function _fee(uint256 amountWei, uint16 bps) internal pure returns (uint256) {
        if (bps == 0) return 0;
        // round up: prevents dust bypass
        return (amountWei * uint256(bps) + 9_999) / 10_000;
    }

    function _takeFee(uint256 amountWei, uint16 bps) internal returns (uint256 feeWei, uint256 netWei) {
        feeWei = _fee(amountWei, bps);
        netWei = amountWei.sub(feeWei);
        if (feeWei != 0) _pushEth(feeCollector, feeWei);
    }

    function _pushEth(address to, uint256 amountWei) internal {
        (bool ok, ) = to.call{value: amountWei}("");
        if (!ok) revert Nebula__BadState();
    }

    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _NAME_HASH,
                _VERSION_HASH,
