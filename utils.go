package frost

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "hash"
)

// HashFunction defines the interface for hash functions used in FROST
type HashFunction interface {
    hash.Hash
}

// DefaultHashFunction returns SHA-256 as the default hash function
func DefaultHashFunction() HashFunction {
    return sha256.New()
}

// HashToScalar hashes data to a scalar value using uniform distribution
func HashToScalar(curve Curve, data ...[]byte) (Scalar, error) {
    hasher := DefaultHashFunction()

    // Add domain separator to prevent hash collisions across different protocol contexts
    hasher.Write([]byte("FROST_HASH_TO_SCALAR"))
    hasher.Write([]byte(curve.Name()))

    for _, d := range data {
        hasher.Write(d)
    }

    hashBytes := hasher.Sum(nil)

    // Use ScalarFromUniformBytes for proper modular reduction and uniform distribution
    // This follows RFC 9380 guidelines for hash-to-scalar conversion
    return curve.ScalarFromUniformBytes(hashBytes)
}

// ChallengeHash computes a Fiat-Shamir challenge with uniform distribution
func ChallengeHash(curve Curve, transcript ...[]byte) (Scalar, error) {
    hasher := DefaultHashFunction()

    // Add domain separator
    hasher.Write([]byte("FROST_CHALLENGE"))
    hasher.Write([]byte(curve.Name()))

    // Add all transcript elements
    for _, data := range transcript {
        // Write length prefix to avoid ambiguity
        lengthBytes := make([]byte, 4)
        binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))
        hasher.Write(lengthBytes)
        hasher.Write(data)
    }

    hashBytes := hasher.Sum(nil)

    // Use ScalarFromUniformBytes for proper modular reduction and uniform distribution
    // This avoids bias from direct truncation
    return curve.ScalarFromUniformBytes(hashBytes)
}

// NonceGeneration generates cryptographically secure nonces
type NonceGeneration struct {
    curve Curve
}

// NewNonceGeneration creates a new nonce generator
func NewNonceGeneration(curve Curve) *NonceGeneration {
    return &NonceGeneration{curve: curve}
}

// GenerateNonce generates a random nonce
func (ng *NonceGeneration) GenerateNonce() (Scalar, error) {
    return ng.curve.ScalarRandom()
}

// GenerateDeterministicNonce generates a deterministic nonce from seed material
func (ng *NonceGeneration) GenerateDeterministicNonce(seed []byte, context []byte) (Scalar, error) {
    hasher := DefaultHashFunction()

    // Domain separation
    hasher.Write([]byte("FROST_NONCE"))
    hasher.Write([]byte(ng.curve.Name()))

    // Add seed and context
    hasher.Write(seed)
    if context != nil {
        hasher.Write(context)
    }

    // Removed randomness to ensure deterministic behavior
    // If randomness is needed, use GenerateNonce() instead

    hashBytes := hasher.Sum(nil)

    // Use ScalarFromUniformBytes for proper modular reduction
    return ng.curve.ScalarFromUniformBytes(hashBytes)
}

// ToScalar converts participant index to a scalar with proper bounds validation
func (pi ParticipantIndex) ToScalar(curve Curve) (Scalar, error) {
    // Validate curve scalar size
    scalarSize := curve.ScalarSize()
    if scalarSize < 4 {
        return nil, fmt.Errorf("curve scalar size %d is too small (minimum 4 bytes required)", scalarSize)
    }

    bytes := make([]byte, scalarSize)
    binary.BigEndian.PutUint32(bytes[scalarSize-4:], uint32(pi))
    return curve.ScalarFromBytes(bytes)
}

// FromScalar creates a participant index from a scalar with proper validation
func ParticipantIndexFromScalar(scalar Scalar) ParticipantIndex {
    if scalar == nil {
        return ParticipantIndex(0)
    }

    bytes := scalar.Bytes()
    // Validate byte slice length before accessing
    if len(bytes) < 4 {
        return ParticipantIndex(0)
    }

    // Take the last 4 bytes as uint32
    return ParticipantIndex(binary.BigEndian.Uint32(bytes[len(bytes)-4:]))
}

// SecureCompare performs constant-time comparison of byte slices
func SecureCompare(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    
    var result byte
    for i := 0; i < len(a); i++ {
        result |= a[i] ^ b[i]
    }
    
    return result == 0
}

// ZeroizeBytes securely clears a byte slice
func ZeroizeBytes(data []byte) {
    for i := range data {
        data[i] = 0
    }
}

// ZeroizeScalarSlice securely clears a slice of scalars
func ZeroizeScalarSlice(scalars []Scalar) {
    for _, scalar := range scalars {
        if scalar != nil {
            scalar.Zeroize()
        }
    }
}

// min returns the minimum of two integers
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// BatchInvert efficiently inverts multiple scalars using Montgomery's trick
func BatchInvert(curve Curve, scalars []Scalar) ([]Scalar, error) {
    n := len(scalars)
    if n == 0 {
        return nil, nil
    }
    
    // Check for zero scalars
    for i, scalar := range scalars {
        if scalar.IsZero() {
            return nil, fmt.Errorf("scalar at index %d is zero", i)
        }
    }
    
    if n == 1 {
        inv, err := scalars[0].Invert()
        if err != nil {
            return nil, err
        }
        return []Scalar{inv}, nil
    }
    
    // Montgomery's batch inversion trick
    // Compute partial products
    partials := make([]Scalar, n)
    partials[0] = scalars[0]
    
    for i := 1; i < n; i++ {
        partials[i] = partials[i-1].Mul(scalars[i])
    }
    
    // Invert the final product
    allInv, err := partials[n-1].Invert()
    if err != nil {
        return nil, err
    }
    
    // Work backwards to compute individual inverses
    inverses := make([]Scalar, n)
    inverses[n-1] = allInv.Mul(partials[n-2])
    
    for i := n - 2; i > 0; i-- {
        inverses[i] = allInv.Mul(partials[i-1])
        allInv = allInv.Mul(scalars[i+1])
    }
    
    inverses[0] = allInv
    
    return inverses, nil
}
