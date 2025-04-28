// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// The interface for the getter for a field called circuit breaker
interface ICircuitBreaker {
    function circuitBreaker() view external returns (bool);
}


/// This contract allows the registration of hashed call packages which can be made from this contract after a period
/// with a speedup if a circuit breaker is triggered in a second contract
contract CircuitBrokenTimelock {
    
    struct CallPackage {
        uint256 nonce;
        address[] targets;
        bytes[] calls;
    }
    /// The registered call packages
    mapping(bytes32 => uint256) public hashRegisteredAt;
    /// Allowed executors
    mapping(address => bool) public authorities;
    // Timeline to execute
    uint256 delayTime;
    // The amount of time after which you can execute 
    uint256 delayTimeCircuitBroken;
    // The circuit breaker contract
    ICircuitBreaker breaker;

    modifier onlySelf() {
        require(msg.sender == address(this), "Only Self");
        _;
    }

    modifier onlyAuth() {
        require(authorities[msg.sender], "Not authority");
        _;
    }

    constructor (uint256 longDelay, uint256 shortDelay, address[] memory firstAuth, address circuitBreaker) {
        delayTime = longDelay;
        delayTimeCircuitBroken = shortDelay;
        for (uint256 i = 0; i < firstAuth.length; i++) {
            authorities[firstAuth[i]] = true;
        }
        breaker = ICircuitBreaker(circuitBreaker);
    }

    /// @notice Registers a call package
    /// @param package The packaged set of calls we will execute as group
    function register(CallPackage memory package) external onlyAuth() {
        require(package.calls.length == package.targets.length, "Badly formed");

        bytes32 hashed = keccak256(abi.encode(package));
        hashRegisteredAt[hashed] = block.timestamp;
    }

    /// @notice Executes a registered call package, this call package can be executed only after either the long delay time or
    ///         a short delay time if a circuit breaker has passed.
    /// @param package The packaged set of calls we want to execute
    function execute(CallPackage memory package) external onlyAuth() {
        bytes32 hashed = keccak256(abi.encode(package));
        uint256 timeRegistered = hashRegisteredAt[hashed];
        // Zero means this package is not registered
        require(timeRegistered != 0, "Not registered");
        
        // We do this slightly more complex ordering of checks to ensure that if there is a bug in 'breaker' we can still make calls.
        if (block.timestamp - timeRegistered < delayTime) {
            if (!breaker.circuitBreaker()){
                revert("Not enough time elapsed");
            }
            if( block.timestamp - timeRegistered < delayTimeCircuitBroken ) {
                revert("Not enough time elapsed");
            }
        }

        // Now we are executing
        // First delete this hash from history
        hashRegisteredAt[hashed] = 0;
        for (uint256 i = 0; i < package.calls.length; i++) {
            (bool succeeded, ) = package.targets[i].call(package.calls[i]);
            require(succeeded, "All calls must succeed");
        }
    }

    function setAuthority(address who, bool to) external onlySelf() {
        authorities[who] = to;
    }

    function setDelayTime(uint256 to) external onlySelf() {
        delayTime = to;
    }

    function setDelayTimeCircuitBroken(uint256 to) external onlySelf() {
        delayTimeCircuitBroken = to; 
    }

    function setBreaker(address to) external onlySelf() {
        breaker = ICircuitBreaker(to);
    }
}