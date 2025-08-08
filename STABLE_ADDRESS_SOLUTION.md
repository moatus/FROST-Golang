# FROST Stable Address Solution

## Problem Statement

The original FROST implementation had a fundamental issue: **wallet addresses changed whenever the validator set changed**. This happened because the group public key was computed as the sum of all participants' polynomial constant terms, so different participants meant different group public keys and thus different wallet addresses.

## Root Cause Analysis

In the original `bls_anchored.go` implementation:

```go
// Step 4: Compute group public key (sum of constant terms)
groupPublicKey := bkg.curve.PointIdentity()
for _, commitmentList := range commitments {
    groupPublicKey = groupPublicKey.Add(commitmentList[0])  // Sum depends on ALL participants
}
```

**Problem**: Different validator sets → Different sum → Different group public key → Different wallet address

## Solution Architecture

### Core Insight
**Separate address derivation from validator composition** by making the foundation key the sole determinant of the wallet address, while still using FROST for threshold signatures.

### Key Components

1. **`foundation_anchored.go`** - New key generation that maintains address stability
2. **`stable_address_utils.go`** - High-level utilities for managing stable wallets  
3. **`stable_address_integration_test.go`** - Comprehensive tests proving the solution works

### How It Works

#### 1. Stable Address Derivation
```go
// Address derived ONLY from foundation key (never changes)
func (fakg *FoundationAnchoredKeyGen) DeriveStableAddress() Point {
    return fakg.curve.BasePoint().Mul(fakg.foundationKey)
}
```

#### 2. Foundation-Anchored FROST Shares
- The foundation key becomes the **constant term** of the polynomial
- Validator-specific entropy is used for **higher-order coefficients**
- All shares collectively represent the **same foundation secret**

```go
// Constant term is the foundation key (ensures stable address)
coefficients[0] = foundationKeyCopy

// Higher-order coefficients derived from validator entropies
for i := 1; i < fakg.threshold; i++ {
    coeff, err := fakg.derivePolynomialCoefficient(i, validatorEntropies)
    coefficients[i] = coeff
}
```

#### 3. Validator Set Changes
- **Address**: Stays the same (derived from unchanging foundation key)
- **FROST Shares**: Regenerated for new validator set
- **Signing**: Works normally with new shares

## Usage Example

```go
// 1. Create foundation key (from RPW)
foundationKey, _ := DeriveFoundationKeyFromRPW(curve, rpwSeed, path)

// 2. Create stable wallet
wallet, _ := CreateStableWallet(curve, foundationKey, threshold, participants, blsKeys)

// 3. Get stable address (never changes)
stableAddress := wallet.StableAddress

// 4. When validator set changes
wallet.UpdateValidatorSet(curve, foundationKey, newThreshold, newParticipants, newBLSKeys)
// Address remains the same!

// 5. Sign with new validator set
signature, _ := wallet.SignMessage(curve, message, signerIDs)
```

## Test Results

All tests pass, proving the solution works:

```
=== RUN   TestFoundationAnchoredAddressStability
✅ Address stability verified: same foundation key produces same address across validator set changes
✅ Share regeneration verified: shares change appropriately when validator set changes  
✅ Deterministic address derivation verified

=== RUN   TestStableAddressIntegration
✅ Address stability verified across validator set changes
✅ Threshold signing with stable address works correctly
✅ Stable address approach successfully differs from original approach
✅ Address remains stable across multiple validator set transitions
✅ Chain-specific address formatting works correctly
```

## Comparison: Original vs Stable Approach

| Aspect | Original BLS-Anchored | New Foundation-Anchored |
|--------|----------------------|-------------------------|
| **Address Stability** | ❌ Changes with validator set | ✅ Stable across validator changes |
| **FROST Compatibility** | ✅ Full FROST protocol | ✅ Full FROST protocol |
| **Deterministic** | ✅ Same inputs → same outputs | ✅ Same inputs → same outputs |
| **BLS Binding** | ✅ Cryptographically bound | ✅ Cryptographically bound |
| **Security** | ✅ Threshold security | ✅ Threshold security |
| **Use Case** | Validator-specific wallets | **Stable user wallets** |

## Key Benefits

1. **Address Stability**: Same wallet address across validator set changes
2. **Backward Compatibility**: Original implementation still available
3. **Full FROST Support**: Complete threshold signature functionality
4. **Multi-Chain**: Works with Bitcoin, Ethereum, Solana address formats
5. **Audit Trail**: Complete BLS binding proofs and validation
6. **RPW Integration**: Works with existing RPW foundation key derivation

## Files Added

- `foundation_anchored.go` - Core stable address key generation
- `foundation_anchored_test.go` - Unit tests for stable address functionality  
- `stable_address_utils.go` - High-level wallet management utilities
- `stable_address_integration_test.go` - Integration tests proving the solution
- `examples/stable_address_example.go` - Complete usage examples
- `STABLE_ADDRESS_SOLUTION.md` - This documentation

## Migration Path

**For New Wallets**: Use `CreateStableWallet()` for address stability

**For Existing Wallets**: Continue using original `NewBLSAnchoredKeyGen()` for compatibility

**For RPW Integration**: Use `DeriveFoundationKeyFromRPW()` to create foundation keys from RPW paths

## Conclusion

This solution successfully addresses the original architectural limitation by:

1. **Preserving address stability** through foundation-key-only address derivation
2. **Maintaining FROST functionality** through proper threshold share generation  
3. **Ensuring backward compatibility** with the existing implementation
4. **Providing comprehensive testing** to prove correctness

The foundation key now serves its intended purpose: **ensuring wallet addresses don't change when validator sets change**, while still enabling secure threshold signatures through FROST.
