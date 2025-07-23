package frost

import (
    "errors"
    "fmt"
)

// Share represents a Shamir secret share
type Share struct {
    Index Scalar // x-coordinate (participant index)
    Value Scalar // y-coordinate (share value)
}

// NewShare creates a new share
func NewShare(index, value Scalar) *Share {
    return &Share{
        Index: index,
        Value: value,
    }
}

// ShamirSecretSharing implements Shamir's Secret Sharing scheme
type ShamirSecretSharing struct {
    curve Curve
}

// NewShamirSecretSharing creates a new Shamir secret sharing instance
func NewShamirSecretSharing(curve Curve) *ShamirSecretSharing {
    return &ShamirSecretSharing{curve: curve}
}

// GenerateShares generates threshold shares of a secret
func (sss *ShamirSecretSharing) GenerateShares(
    secret Scalar,
    threshold int,
    numShares int,
) ([]*Share, error) {
    if threshold <= 0 {
        return nil, errors.New("threshold must be positive")
    }
    if numShares < threshold {
        return nil, errors.New("number of shares must be at least threshold")
    }
    if threshold > 255 {
        return nil, errors.New("threshold too large")
    }
    if numShares > 255 {
        return nil, errors.New("number of shares cannot exceed 255 to prevent byte overflow in share indices")
    }

    // Create polynomial of degree (threshold - 1)
    polynomial, err := NewRandomPolynomial(sss.curve, threshold-1, secret)
    if err != nil {
        return nil, fmt.Errorf("failed to create polynomial: %w", err)
    }
    defer polynomial.Zeroize()

    // Generate shares by evaluating polynomial at different points
    shares := make([]*Share, numShares)
    for i := 0; i < numShares; i++ {
        // Use 1-based indexing (avoid x=0)
        indexBytes := []byte{byte(i + 1)}
        // Pad to scalar size
        paddedIndex := make([]byte, sss.curve.ScalarSize())
        copy(paddedIndex, indexBytes)
        
        index, err := sss.curve.ScalarFromBytes(paddedIndex)
        if err != nil {
            return nil, fmt.Errorf("failed to create index scalar: %w", err)
        }

        value := polynomial.Evaluate(index)
        shares[i] = NewShare(index, value)
    }

    return shares, nil
}

// ReconstructSecret reconstructs the secret from threshold shares using Lagrange interpolation
func (sss *ShamirSecretSharing) ReconstructSecret(shares []*Share, threshold int) (Scalar, error) {
    if len(shares) < threshold {
        return nil, fmt.Errorf("insufficient shares: need %d, got %d", threshold, len(shares))
    }

    // Use first 'threshold' shares
    selectedShares := shares[:threshold]

    // Lagrange interpolation at x = 0
    secret := sss.curve.ScalarZero()

    for i, share := range selectedShares {
        // Calculate Lagrange coefficient
        numerator := sss.curve.ScalarOne()
        denominator := sss.curve.ScalarOne()

        for j, otherShare := range selectedShares {
            if i != j {
                // numerator *= (0 - x_j) = -x_j
                numerator = numerator.Mul(otherShare.Index.Negate())
                
                // denominator *= (x_i - x_j)
                denominator = denominator.Mul(share.Index.Sub(otherShare.Index))
            }
        }

        // Calculate coefficient = numerator / denominator
        denomInv, err := denominator.Invert()
        if err != nil {
            return nil, fmt.Errorf("failed to invert denominator: %w", err)
        }
        
        coefficient := numerator.Mul(denomInv)
        
        // Add this term to the result
        term := share.Value.Mul(coefficient)
        secret = secret.Add(term)
    }

    return secret, nil
}

// VerifyShares verifies that shares are consistent with each other
func (sss *ShamirSecretSharing) VerifyShares(shares []*Share, threshold int) error {
    if len(shares) < threshold {
        return fmt.Errorf("insufficient shares for verification: need %d, got %d", threshold, len(shares))
    }

    // Try to reconstruct with different subsets and verify consistency
    if len(shares) == threshold {
        // Only one possible subset, can't verify consistency
        return nil
    }

    // Reconstruct with first threshold shares
    secret1, err := sss.ReconstructSecret(shares[:threshold], threshold)
    if err != nil {
        return fmt.Errorf("failed to reconstruct with first subset: %w", err)
    }

    // Reconstruct with different subset (if possible)
    if len(shares) > threshold {
        altShares := make([]*Share, threshold)
        copy(altShares[:threshold-1], shares[:threshold-1])
        altShares[threshold-1] = shares[threshold] // Replace last share

        secret2, err := sss.ReconstructSecret(altShares, threshold)
        if err != nil {
            return fmt.Errorf("failed to reconstruct with alternate subset: %w", err)
        }

        if !secret1.Equal(secret2) {
            return errors.New("shares are inconsistent")
        }
    }

    return nil
}
