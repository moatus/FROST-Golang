package frost

import (
    "crypto/sha256"
    "crypto/sha512"
    "fmt"
)

// SchnorrProof represents a Schnorr proof of knowledge
type SchnorrProof struct {
    Challenge Scalar
    Response  Scalar
}

// NewSchnorrProof creates a new Schnorr proof of knowledge for a secret
func NewSchnorrProof(curve Curve, secret Scalar, publicKey Point) (*SchnorrProof, error) {
    // Generate random nonce
    nonce, err := curve.ScalarRandom()
    if err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    defer nonce.Zeroize()
    
    // Compute commitment: R = g^r
    commitment := curve.BasePoint().Mul(nonce)
    
    // Compute challenge: c = H(g^x || R)
    challenge, err := computeSchnorrChallenge(curve, publicKey, commitment)
    if err != nil {
        return nil, fmt.Errorf("failed to compute challenge: %w", err)
    }
    
    // Compute response: s = r + c*x
    response := nonce.Add(challenge.Mul(secret))
    
    return &SchnorrProof{
        Challenge: challenge,
        Response:  response,
    }, nil
}

// Verify verifies a Schnorr proof
func (sp *SchnorrProof) Verify(curve Curve, publicKey Point) bool {
    // Recompute commitment: R' = g^s - c*X = g^s - c*g^x = g^(s-cx) = g^r
    commitment := curve.BasePoint().Mul(sp.Response).Sub(publicKey.Mul(sp.Challenge))
    
    // Recompute challenge
    expectedChallenge, err := computeSchnorrChallenge(curve, publicKey, commitment)
    if err != nil {
        return false // Cannot verify if challenge computation fails
    }
    
    // Verify challenge matches
    return sp.Challenge.Equal(expectedChallenge)
}

// computeSchnorrChallenge computes the Fiat-Shamir challenge for Schnorr proof following RFC standards
func computeSchnorrChallenge(curve Curve, publicKey, commitment Point) (Scalar, error) {
    // Use SHA512 for Ed25519 per RFC9591 section 3.2, SHA256 for others
    if curve.Name() == "Ed25519" {
        return computeSchnorrChallengeEd25519(curve, publicKey, commitment)
    }
    return computeSchnorrChallengeGeneric(curve, publicKey, commitment)
}

// computeSchnorrChallengeEd25519 uses SHA512 per RFC9591 section 3.2
func computeSchnorrChallengeEd25519(curve Curve, publicKey, commitment Point) (Scalar, error) {
    hasher := sha512.New()

    // RFC9591 format: commitment || publicKey || domain_separator
    hasher.Write(commitment.CompressedBytes())
    hasher.Write(publicKey.CompressedBytes())
    hasher.Write([]byte("FROST_SCHNORR_CHALLENGE_Ed25519"))

    challengeBytes := hasher.Sum(nil) // 64 bytes from SHA512

    // Use ScalarFromUniformBytes for proper modular reduction
    challenge, err := curve.ScalarFromUniformBytes(challengeBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to convert challenge bytes to scalar: %w", err)
    }
    return challenge, nil
}

// computeSchnorrChallengeGeneric uses SHA256 with domain separation for other curves
func computeSchnorrChallengeGeneric(curve Curve, publicKey, commitment Point) (Scalar, error) {
    hasher := sha256.New()

    // Domain separator to prevent cross-protocol attacks
    hasher.Write([]byte("FROST_SCHNORR_CHALLENGE"))
    hasher.Write([]byte(curve.Name()))

    // Write commitment and public key
    hasher.Write(commitment.CompressedBytes())
    hasher.Write(publicKey.CompressedBytes())

    challengeBytes := hasher.Sum(nil)

    // Use ScalarFromUniformBytes for proper modular reduction and uniform distribution
    challenge, err := curve.ScalarFromUniformBytes(challengeBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to convert challenge bytes to scalar: %w", err)
    }
    return challenge, nil
}