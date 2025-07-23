package frost

import (
    "crypto/sha256"
    "errors"
    "fmt"
    "math/big"
)

// Maximum allowed share index to prevent overflow
const MaxShareIndex = 1000000

// Commitment represents a cryptographic commitment
type Commitment struct {
    curve Curve
    point Point
}

// NewCommitment creates a new commitment with input validation
func NewCommitment(curve Curve, point Point) (*Commitment, error) {
    if curve == nil {
        return nil, fmt.Errorf("curve cannot be nil")
    }
    if point == nil {
        return nil, fmt.Errorf("point cannot be nil")
    }

    return &Commitment{
        curve: curve,
        point: point,
    }, nil
}

// Point returns the commitment point
func (c *Commitment) Point() Point {
    return c.point
}

// Bytes returns the serialized commitment
func (c *Commitment) Bytes() []byte {
    if c == nil || c.point == nil {
        return nil
    }
    return c.point.CompressedBytes()
}

// Equal checks if two commitments are equal
func (c *Commitment) Equal(other *Commitment) bool {
    if c == nil || other == nil {
        return false
    }
    if c.point == nil || other.point == nil {
        return false
    }
    return c.point.Equal(other.point)
}

// PedersenCommitment implements Pedersen commitments
type PedersenCommitment struct {
    curve     Curve
    generator Point // G
    blinding  Point // H (independent generator for blinding)
}

// NewPedersenCommitment creates a new Pedersen commitment scheme
func NewPedersenCommitment(curve Curve) (*PedersenCommitment, error) {
    generator := curve.BasePoint()
    
    // Generate independent blinding generator using hash-to-curve
    // For simplicity, we'll use a deterministic method
    blinding, err := generateBlindingGenerator(curve)
    if err != nil {
        return nil, fmt.Errorf("failed to generate blinding generator: %w", err)
    }

    return &PedersenCommitment{
        curve:     curve,
        generator: generator,
        blinding:  blinding,
    }, nil
}

// Commit creates a Pedersen commitment: Com(value, randomness) = value*G + randomness*H
func (pc *PedersenCommitment) Commit(value, randomness Scalar) (*Commitment, error) {
    // Validate inputs to prevent panics
    if value == nil {
        return nil, fmt.Errorf("value scalar cannot be nil")
    }
    if randomness == nil {
        return nil, fmt.Errorf("randomness scalar cannot be nil")
    }

    // value * G
    valueCommit := pc.generator.Mul(value)

    // randomness * H
    blindingCommit := pc.blinding.Mul(randomness)

    // Combine: value*G + randomness*H
    commitment := valueCommit.Add(blindingCommit)

    return NewCommitment(pc.curve, commitment)
}

// Verify verifies a Pedersen commitment
func (pc *PedersenCommitment) Verify(commitment *Commitment, value, randomness Scalar) (bool, error) {
    expected, err := pc.Commit(value, randomness)
    if err != nil {
        return false, err
    }
    return commitment.Equal(expected), nil
}

// generateBlindingGenerator creates an independent generator for blinding
func generateBlindingGenerator(curve Curve) (Point, error) {
    // Use a deterministic method to generate H from G
    // H = hash_to_curve("FROST_BLINDING_GENERATOR" || curve_name)
    basePoint := curve.BasePoint()
    baseBytes := basePoint.Bytes()
    
    // Create a deterministic seed
    hasher := sha256.New()
    hasher.Write([]byte("FROST_BLINDING_GENERATOR"))
    hasher.Write([]byte(curve.Name()))
    hasher.Write(baseBytes)
    seed := hasher.Sum(nil)
    
    // Convert seed to scalar using proper hash-to-scalar conversion
    // This ensures uniform distribution over the scalar field
    scalar, err := curve.ScalarFromUniformBytes(seed)
    if err != nil {
        return nil, fmt.Errorf("failed to convert seed to scalar: %w", err)
    }
    
    // Ensure we don't get the identity point
    if scalar.IsZero() {
        scalar = curve.ScalarOne()
    }
    
    return basePoint.Mul(scalar), nil
}

// PolynomialCommitment represents a commitment to a polynomial
type PolynomialCommitment struct {
    curve       Curve
    commitments []*Commitment // Commitments to each coefficient
}

// NewPolynomialCommitment creates commitments to polynomial coefficients
func NewPolynomialCommitment(curve Curve, polynomial *Polynomial) (*PolynomialCommitment, error) {
    pedersen, err := NewPedersenCommitment(curve)
    if err != nil {
        return nil, err
    }

    commitments := make([]*Commitment, len(polynomial.coefficients))
    
    for i, coeff := range polynomial.coefficients {
        // Generate secure random blinding factor for each coefficient to maintain hiding property
        // Using zero randomness removes the hiding property and weakens security
        randomness, err := curve.ScalarRandom()
        if err != nil {
            return nil, fmt.Errorf("failed to generate randomness for coefficient %d: %w", i, err)
        }
        defer randomness.Zeroize() // Clean up randomness after use

        commitment, err := pedersen.Commit(coeff, randomness)
        if err != nil {
            return nil, fmt.Errorf("failed to create commitment for coefficient %d: %w", i, err)
        }
        commitments[i] = commitment
    }

    return &PolynomialCommitment{
        curve:       curve,
        commitments: commitments,
    }, nil
}

// Verify verifies that a share is consistent with the polynomial commitment
func (pc *PolynomialCommitment) Verify(share *Share) (bool, error) {
    // Input validation
    if share == nil {
        return false, fmt.Errorf("share cannot be nil")
    }
    if share.Index == nil {
        return false, fmt.Errorf("share index cannot be nil")
    }
    if share.Value == nil {
        return false, fmt.Errorf("share value cannot be nil")
    }

    if len(pc.commitments) == 0 {
        return false, errors.New("no commitments available")
    }

    // Bounds checking for share index
    if share.Index.IsZero() {
        return false, fmt.Errorf("share index cannot be zero")
    }

    // Improved bounds check: use direct comparison against maximum allowed share index
    // This is safer and clearer than indirect byte-length checks
    indexBytes := share.Index.Bytes()
    indexBig := new(big.Int).SetBytes(indexBytes)
    maxIndexBig := big.NewInt(MaxShareIndex)

    if indexBig.Cmp(maxIndexBig) > 0 {
        return false, fmt.Errorf("share index %s exceeds maximum allowed value %d", indexBig.String(), MaxShareIndex)
    }

    // Calculate expected commitment: ∏ᵢ Cᵢˣⁱ where Cᵢ is commitment to coefficient i
    expected := pc.curve.PointIdentity()

    // Start with x^0 = 1
    xPower := pc.curve.ScalarOne()

    for _, commitment := range pc.commitments {
        // Add Cᵢ * x^i to the expected value
        term := commitment.Point().Mul(xPower)
        expected = expected.Add(term)

        // Update x^i to x^(i+1)
        xPower = xPower.Mul(share.Index)
    }

    // The expected commitment should equal share.Value * G
    generator := pc.curve.BasePoint()
    actualCommitment := generator.Mul(share.Value)

    return expected.Equal(actualCommitment), nil
}

// GetCommitments returns a defensive copy of the coefficient commitments
func (pc *PolynomialCommitment) GetCommitments() []*Commitment {
    // Return a defensive copy to prevent external modification of internal state
    result := make([]*Commitment, len(pc.commitments))
    copy(result, pc.commitments)
    return result
}
