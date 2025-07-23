package frost

import (
    "crypto/sha512"
    "fmt"
)

// Shared Ed25519 curve instance to avoid repeated creation
var sharedEd25519Curve = NewEd25519Curve()

// SolanaSignature represents a Solana Ed25519 signature
type SolanaSignature struct {
    R Point  // Nonce commitment point (32 bytes)
    S Scalar // Signature response (32 bytes)
}

// Bytes returns the 64-byte signature in Solana format (R || S)
func (sig *SolanaSignature) Bytes() ([]byte, error) {
    // Check for nil values to prevent incomplete signatures
    if sig.R == nil {
        return nil, fmt.Errorf("signature R component is nil")
    }
    if sig.S == nil {
        return nil, fmt.Errorf("signature S component is nil")
    }

    result := make([]byte, 64)
    copy(result[:32], sig.R.CompressedBytes())
    copy(result[32:], sig.S.Bytes())

    return result, nil
}

// SolanaChallenge computes the Solana Ed25519 challenge using SHA512
// Following Chainflip's implementation: SHA512(nonce_commitment || pubkey || payload)
// This matches RFC 8032 Ed25519 signature specification
func SolanaChallenge(R Point, pubKey Point, message []byte) (Scalar, error) {
    // Validate inputs
    if R == nil || pubKey == nil {
        return nil, fmt.Errorf("challenge computation requires non-nil points")
    }

    // Note: Empty messages are valid per Solana Ed25519 spec (RFC 8032)

    // Use SHA512 as per RFC 8032 Ed25519 specification
    hasher := sha512.New()
    
    // Chainflip's order: nonce_commitment || pubkey || payload
    hasher.Write(R.CompressedBytes())    // 32 bytes
    hasher.Write(pubKey.CompressedBytes()) // 32 bytes  
    hasher.Write(message)                // Variable length
    
    challengeBytes := hasher.Sum(nil) // 64 bytes from SHA512
    
    // Convert to scalar using uniform bytes (proper modular reduction)
    // This works because Ed25519 curve already supports ScalarFromUniformBytes with 64-byte input
    // Use a shared curve instance to avoid creating new instances repeatedly
    challenge, err := sharedEd25519Curve.ScalarFromUniformBytes(challengeBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to derive Solana challenge scalar: %w", err)
    }
    
    return challenge, nil
}

// SolanaSignResponse computes the signature response for Solana Ed25519
// Following standard Ed25519: s = k + e*d (mod l)
func SolanaSignResponse(nonce Scalar, privateKey Scalar, challenge Scalar) (Scalar, error) {
    // Add nil checks for all pointer parameters to prevent runtime panics
    if nonce == nil {
        return nil, fmt.Errorf("nonce scalar cannot be nil")
    }
    if privateKey == nil {
        return nil, fmt.Errorf("private key scalar cannot be nil")
    }
    if challenge == nil {
        return nil, fmt.Errorf("challenge scalar cannot be nil")
    }

    // Ed25519: s = k + e*d (mod l)
    // No Y-parity handling needed for Ed25519 (unlike secp256k1 BIP-340)
    return nonce.Add(challenge.Mul(privateKey)), nil
}

// SolanaVerifyResponse verifies a party's signature response during FROST signing
func SolanaVerifyResponse(publicKey Point, lambdaI Scalar, commitment Point, groupCommitment Point, challenge Scalar, response Scalar) bool {
    // Add nil checks for all pointer parameters to prevent runtime panics
    if publicKey == nil || lambdaI == nil || commitment == nil || challenge == nil || response == nil {
        return false
    }

    // Compute expected point: s*G using shared curve instance
    leftSide := sharedEd25519Curve.BasePoint().Mul(response)

    // Compute right side: R_i + lambda_i * c * Y_i
    // where R_i is the commitment, lambda_i is the Lagrange coefficient,
    // c is the challenge, and Y_i is the public key
    rightSide := commitment.Add(publicKey.Mul(lambdaI.Mul(challenge)))

    return leftSide.Equal(rightSide)
}

// SolanaVerifyFROSTSignature verifies a complete FROST signature using Solana Ed25519 challenge
func SolanaVerifyFROSTSignature(curve Curve, signature *Signature, message []byte, groupPubKey Point) (bool, error) {
    // Recompute challenge using Solana challenge computation
    challenge, err := SolanaChallenge(signature.R, groupPubKey, message)
    if err != nil {
        return false, fmt.Errorf("failed to compute Solana challenge for verification: %w", err)
    }
    
    // Verify: g^s = R + c * GroupPubKey
    leftSide := curve.BasePoint().Mul(signature.S)
    rightSide := signature.R.Add(groupPubKey.Mul(challenge))
    
    return leftSide.Equal(rightSide), nil
}

// SolanaSignatureFromBytes creates a SolanaSignature from 64-byte representation
func SolanaSignatureFromBytes(data []byte) (*SolanaSignature, error) {
    if len(data) != 64 {
        return nil, fmt.Errorf("Solana signature must be 64 bytes, got %d", len(data))
    }
    
    curve := NewEd25519Curve()
    
    // Parse R point (first 32 bytes)
    R, err := curve.PointFromBytes(data[:32])
    if err != nil {
        return nil, fmt.Errorf("invalid R point in Solana signature: %w", err)
    }
    
    // Parse S scalar (last 32 bytes)
    S, err := curve.ScalarFromBytes(data[32:])
    if err != nil {
        return nil, fmt.Errorf("invalid S scalar in Solana signature: %w", err)
    }
    
    return &SolanaSignature{R: R, S: S}, nil
}

// VerifySolanaSignature verifies a Solana signature against a message and public key
// This provides compatibility with Solana's ed25519_dalek verification
func VerifySolanaSignature(signature *SolanaSignature, publicKey Point, message []byte) error {
    // Recompute challenge
    challenge, err := SolanaChallenge(signature.R, publicKey, message)
    if err != nil {
        return fmt.Errorf("failed to compute challenge: %w", err)
    }
    
    // Verify: g^s = R + c * PublicKey
    curve := NewEd25519Curve()
    leftSide := curve.BasePoint().Mul(signature.S)
    rightSide := signature.R.Add(publicKey.Mul(challenge))
    
    if !leftSide.Equal(rightSide) {
        return fmt.Errorf("Solana signature verification failed")
    }
    
    return nil
}

// SolanaKeyGeneration generates a Solana-compatible Ed25519 key pair
func SolanaKeyGeneration() (Scalar, Point, error) {
    curve := NewEd25519Curve()
    
    // Generate random private key
    privateKey, err := curve.ScalarRandom()
    if err != nil {
        return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
    }
    
    // Compute public key
    publicKey := curve.BasePoint().Mul(privateKey)
    
    return privateKey, publicKey, nil
}

// IsValidSolanaPubkey checks if a public key is valid for Solana
func IsValidSolanaPubkey(pubKey Point) bool {
    if pubKey == nil {
        return false
    }
    
    // For Ed25519, any valid point on the curve is acceptable
    // The validation happens during point creation
    return true
}
