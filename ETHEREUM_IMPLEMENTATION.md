# Ethereum FROST Implementation

This document describes the Ethereum-specific FROST implementation inspired by Chainflip's approach.

## Overview

The Ethereum FROST implementation provides EVM-optimized challenge computation that is compatible with Ethereum smart contracts, particularly the Key Manager contract used by Chainflip.

## Key Features

### 1. EVM-Optimized Challenge Computation

Unlike standard FROST which uses SHA256, Ethereum FROST uses Keccak256 with a specific data format:

```
challenge = keccak256(pubkey_x || parity || msg_hash || nonce_address)
```

Where:
- `pubkey_x`: 32-byte x-coordinate of the public key
- `parity`: 1 byte (0 for even Y, 1 for odd Y)
- `msg_hash`: 32-byte message hash
- `nonce_address`: 20-byte Ethereum address derived from nonce commitment

### 2. Key Compatibility

Public keys must satisfy Ethereum Key Manager contract requirements:
- The x-coordinate must be less than half the secp256k1 curve order
- This ensures compatibility with the on-chain verification logic

### 3. Signature Format

Supports standard Ethereum signature formats:
- **ToRSV()**: Returns (r, s, v) components for transaction signing
- **ToBytes()**: Returns 65-byte format (r || s || v) for message signing

## API Usage

### Creating an Ethereum Signing Session

```go
// Create Ethereum-specific signing session
session, err := NewEthereumSigningSession(curve, keyShare, message, signers, threshold)
```

### Key Generation

```go
// Generate Ethereum-compatible key pair
privateKey, publicKey, err := EthereumKeyGeneration()

// Check if existing key is compatible
isValid := IsValidEthereumPubkey(publicKey)
```

### Challenge Computation

```go
// Compute Ethereum challenge
challenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
```

### Signature Operations

```go
// Create signature response
response := EthereumSignResponse(nonce, nonceCommitment, privateKey, challenge)

// Verify signature
err := EthereumVerifySignature(signature, publicKey, message)
```

## Implementation Details

### Challenge Type System

The implementation uses a `ChallengeType` enum to support multiple challenge computation methods:

```go
type ChallengeType int

const (
    StandardFROST ChallengeType = iota
    BitcoinBIP340
    EthereumEVM
)
```

### Address Conversion

Ethereum addresses are derived from secp256k1 points using:

```go
// Convert point to Ethereum address
address, err := PointToEthereumAddress(point)
```

The conversion follows Ethereum's standard:
1. Get uncompressed public key (x || y)
2. Compute keccak256(x || y)
3. Take last 20 bytes as address

### Signature Equation

Ethereum FROST uses the signature equation:
- **Signing**: `s = k - e*d (mod n)`
- **Verification**: `g^s = R - e*P`

This matches Chainflip's `build_response` implementation.

## Compatibility with Chainflip

The implementation is designed to be compatible with Chainflip's Ethereum FROST:

1. **Challenge Format**: Uses identical keccak256-based challenge computation
2. **Data Ordering**: Matches Chainflip's `message_challenge` function
3. **Key Constraints**: Implements the same x-coordinate validation
4. **Signature Response**: Uses Chainflip's `nonce - challenge * private_key` formula

## Testing

Comprehensive tests verify:

- Challenge computation correctness
- Ethereum address derivation
- Key compatibility validation
- Signature generation and verification
- Format compatibility with Ethereum standards
- Compatibility with Chainflip's approach

## Security Considerations

1. **Key Validation**: All public keys are validated for Ethereum compatibility
2. **Challenge Uniqueness**: Ethereum and standard FROST produce different challenges
3. **Deterministic Computation**: All operations are deterministic for the same inputs
4. **Memory Safety**: Proper zeroization of sensitive data (inherited from base FROST)

## Example Usage

```go
package main

import (
    "fmt"
    "github.com/canopy-network/canopy/lib/frost"
)

func main() {
    curve := frost.NewSecp256k1Curve()
    
    // Generate Ethereum-compatible keys
    privateKey, publicKey, err := frost.EthereumKeyGeneration()
    if err != nil {
        panic(err)
    }
    
    // Create message to sign
    message := make([]byte, 32)
    copy(message, []byte("Hello Ethereum FROST!"))
    
    // Create key share (simplified for example)
    keyShare := &frost.KeyShare{
        ParticipantID:  1,
        SecretShare:    privateKey,
        PublicKey:      publicKey,
        GroupPublicKey: publicKey, // Single party for simplicity
    }
    
    // Create Ethereum signing session
    signers := []frost.ParticipantIndex{1}
    session, err := frost.NewEthereumSigningSession(curve, keyShare, message, signers, 1)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Ethereum FROST session created successfully!")
}
```

## Future Enhancements

1. **EIP-712 Support**: Add structured data signing support
2. **Multi-Chain**: Extend to other EVM-compatible chains
3. **Gas Optimization**: Further optimize for on-chain verification
4. **Hardware Wallet**: Add hardware wallet integration support

## References

- [Chainflip FROST Implementation](https://github.com/chainflip-io/chainflip-backend)
- [FROST RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)
- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
- [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
