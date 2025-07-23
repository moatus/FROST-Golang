# FROST Library Testing Guide

This document explains the test organization and how to run different test suites for the FROST threshold signature library.

## Test Organization

The FROST library tests are organized into three categories:

### 🔴 **Critical Tests** (Security & Core Functionality)
These tests validate the core security properties and essential functionality:

- **Core FROST Protocol**: `TestFROSTKeygen`, `TestFROSTValidations`
- **Cryptographic Security**: `TestBitcoinFROSTSigning`, `TestEthereumSignatureVerification`, `TestSolanaFROSTSigningSession`
- **Memory Safety**: `TestZeroization`, `TestMemorySafety`
- **BLS-Anchored Security**: `TestDeterministicKeyGeneration`, `TestHKDFDeterminism`
- **HD Wallet Security**: `TestHDWalletSigning`, `TestUserControlledFROSTWallets`
- **Security Framework**: `TestSecurityFrameworkIntegration`, `TestThresholdValidation`

### 🟡 **Feature Tests** (Blockchain-Specific & Edge Cases)
These tests validate specific features and edge cases:

- **Blockchain Compatibility**: `TestBitcoinChallenge`, `TestEthereumChallenge`, `TestSolanaChallenge`
- **Format Validation**: `TestBitcoinSignatureFormat`, `TestEthereumSignatureFormat`
- **Edge Cases**: `TestFROSTErrors`, `TestEdgeCases`, `TestPointValidation`
- **Performance**: `TestHashAlgorithmPerformance`, `TestPerformanceWithImprovements`

### 🔵 **Integration Tests** (Blockchain Integration)
These tests validate integration with specific blockchain ecosystems:

- **Solana Integration**: `TestSolanaTransactionBuilding`, `TestSolanaTokenTransactions`
- **Compatibility**: `TestEthereumChainflipCompatibility`, `TestBlake2bCompatibility`

## Running Tests

### Quick Start

```bash
# Run only critical security tests (recommended for CI)
./test-critical.sh

# Run only feature and edge case tests
./test-features.sh

# Run all tests
go test -v .
```

### Manual Test Selection

```bash
# Run specific test categories
go test -v . -run "TestFROSTKeygen|TestBitcoinFROSTSigning|TestEthereumSignatureVerification"

# Run tests with timeout
go test -v . -timeout 5m

# Note: Go test does not support a -skip flag. To exclude specific tests:
# 1. Use build tags to conditionally compile tests
# 2. Add t.Skip() calls inside tests to skip them conditionally
# 3. Use -run flag to specify only the tests you want to run
```

## CI/CD Recommendations

### For Pull Requests
```bash
./test-critical.sh  # Fast, security-focused validation
```

### For Release Validation
```bash
go test -v .  # Full test suite
```

### For Performance Monitoring
```bash
./test-features.sh  # Includes performance benchmarks
```

## Test Configuration

The test organization is controlled by `.testignore` which lists tests to skip in critical test runs. This allows for:

- **Fast CI feedback** (critical tests run in ~0.1s)
- **Comprehensive validation** (full suite available when needed)
- **Flexible test selection** (easy to customize for different scenarios)

## Security Test Priority

1. **Tier 1 (Must Pass)**: Core FROST protocol, cryptographic security, memory safety
2. **Tier 2 (Should Pass)**: Security framework, HD wallets, configuration validation
3. **Tier 3 (Nice to Pass)**: Performance, compatibility, edge cases

If any Tier 1 test fails, it indicates a critical security vulnerability or protocol failure.

## Adding New Tests

When adding new tests, categorize them appropriately:

- **Security-critical tests**: Add to critical test suite (don't add to `.testignore`)
- **Feature tests**: Add to `.testignore` to keep critical suite fast
- **Integration tests**: Add to `.testignore` and consider separate CI job

## Performance

- **Critical tests**: ~0.1s (suitable for frequent CI runs)
- **Feature tests**: ~0.5s (includes performance benchmarks)
- **Full test suite**: ~1s (comprehensive validation)

This organization ensures fast feedback for developers while maintaining comprehensive test coverage for releases.
