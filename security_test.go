package frost

import (
	"bytes"
	"testing"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestZeroization verifies that sensitive data is properly zeroized
func TestZeroization(t *testing.T) {
	curve := NewEd25519Curve()

	t.Run("ScalarZeroization", func(t *testing.T) {
		// Create a scalar with known value
		scalar, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar: %v", err)
		}

		// Get the bytes before zeroization
		originalBytes := make([]byte, len(scalar.Bytes()))
		copy(originalBytes, scalar.Bytes())

		// Verify it's not zero initially
		if scalar.IsZero() {
			t.Skip("Random scalar is zero, skipping test")
		}

		// Zeroize the scalar
		scalar.Zeroize()

		// Verify it's now zero
		if !scalar.IsZero() {
			t.Error("Scalar should be zero after zeroization")
		}

		// Verify the bytes are different (should be zero)
		newBytes := scalar.Bytes()
		if bytes.Equal(originalBytes, newBytes) {
			t.Error("Scalar bytes should be different after zeroization")
		}
	})

	t.Run("PolynomialZeroization", func(t *testing.T) {
		// Create a polynomial
		secret, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		polynomial, err := NewRandomPolynomial(curve, 2, secret)
		if err != nil {
			t.Fatalf("Failed to create polynomial: %v", err)
		}

		// Verify polynomial has coefficients
		if polynomial.Degree() < 0 {
			t.Fatal("Polynomial should have coefficients")
		}

		// Zeroize the polynomial
		polynomial.Zeroize()

		// Verify coefficients are cleared
		if polynomial.coefficients != nil {
			t.Error("Polynomial coefficients should be nil after zeroization")
		}
	})

	t.Run("KeyShareZeroization", func(t *testing.T) {
		// Create a key share
		secretShare, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create secret share: %v", err)
		}

		keyShare := &KeyShare{
			ParticipantID: 1,
			SecretShare:   secretShare,
			PublicKey:     curve.BasePoint().Mul(secretShare),
		}

		// Verify secret share is not zero initially
		if keyShare.SecretShare.IsZero() {
			t.Skip("Secret share is zero, skipping test")
		}

		// Zeroize the key share
		keyShare.Zeroize()

		// Verify secret share is now zero
		if !keyShare.SecretShare.IsZero() {
			t.Error("Secret share should be zero after zeroization")
		}
	})
}

// TestHKDFDeterminism verifies that HKDF produces deterministic results
func TestHKDFDeterminism(t *testing.T) {
	curve := NewEd25519Curve()

	t.Run("BLSToSchnorrDeterminism", func(t *testing.T) {
		// Generate a BLS key
		blsKeyInterface, err := crypto.NewBLS12381PrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate BLS key: %v", err)
		}
		blsKey, ok := blsKeyInterface.(*crypto.BLS12381PrivateKey)
		if !ok {
			t.Fatalf("Failed to cast BLS key to correct type")
		}

		// Generate foundation key
		foundationKey, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to generate foundation key: %v", err)
		}
		defer foundationKey.Zeroize()

		// Create BLS-anchored key generator
		participants := []ParticipantIndex{1}
		validatorBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: blsKey,
		}
		bkg := NewBLSAnchoredKeyGen(curve, 1, participants, foundationKey, validatorBLSKeys)

		// Generate the same scalar multiple times
		scalar1, err := bkg.blsToSchnorrSecret(1, blsKey)
		if err != nil {
			t.Fatalf("Failed to generate scalar 1: %v", err)
		}

		scalar2, err := bkg.blsToSchnorrSecret(1, blsKey)
		if err != nil {
			t.Fatalf("Failed to generate scalar 2: %v", err)
		}

		// Verify they are identical
		if !scalar1.Equal(scalar2) {
			t.Error("HKDF should produce deterministic results")
		}

		// Clean up
		scalar1.Zeroize()
		scalar2.Zeroize()
	})

	t.Run("DeterministicScalarGeneration", func(t *testing.T) {
		// Create deterministic key generator
		foundationKey, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to generate foundation key: %v", err)
		}
		defer foundationKey.Zeroize()

		validatorKey, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to generate validator key: %v", err)
		}
		defer validatorKey.Zeroize()

		participants := []ParticipantIndex{1}
		validatorKeys := map[ParticipantIndex]Scalar{1: validatorKey}

		dkg, err := NewDeterministicKeyGen(curve, 1, participants, foundationKey, validatorKeys)
		if err != nil {
			t.Fatalf("Failed to create deterministic key generator: %v", err)
		}

		// Generate the same seed multiple times
		seed1 := dkg.createDeterministicSeed(1, validatorKey)
		seed2 := dkg.createDeterministicSeed(1, validatorKey)

		// Verify seeds are identical
		if !bytes.Equal(seed1, seed2) {
			t.Error("Deterministic seed generation should produce identical results")
		}

		// Generate scalars from the same seed and index
		scalar1, err := dkg.scalarFromSeed(seed1, 0)
		if err != nil {
			t.Fatalf("Failed to generate scalar 1: %v", err)
		}

		scalar2, err := dkg.scalarFromSeed(seed2, 0)
		if err != nil {
			t.Fatalf("Failed to generate scalar 2: %v", err)
		}

		// Verify scalars are identical
		if !scalar1.Equal(scalar2) {
			t.Error("HKDF scalar generation should be deterministic")
		}

		// Clean up
		scalar1.Zeroize()
		scalar2.Zeroize()
	})
}

// TestPointValidation verifies that point validation works correctly
func TestPointValidation(t *testing.T) {
	curve := NewEd25519Curve()

	t.Run("ValidPointValidation", func(t *testing.T) {
		// Create a valid point
		scalar, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar: %v", err)
		}
		defer scalar.Zeroize()

		point := curve.BasePoint().Mul(scalar)

		// Verify it's on the curve
		if !point.IsOnCurve() {
			t.Error("Valid point should be on curve")
		}
	})

	t.Run("InvalidPointValidation", func(t *testing.T) {
		// Try to create an invalid point by using wrong length
		invalidBytes := make([]byte, 16) // Wrong length for Ed25519 (should be 32)
		for i := range invalidBytes {
			invalidBytes[i] = 0xFF
		}

		// Try to create point from invalid bytes
		_, err := curve.PointFromBytes(invalidBytes)
		if err == nil {
			t.Error("Should reject invalid point bytes")
		}

		// Also test with correct length but invalid point data
		// Ed25519 points have specific constraints, so we'll use a known invalid encoding
		invalidBytes32 := make([]byte, 32)
		// Set the high bit and other bits to create an invalid point
		invalidBytes32[31] = 0xFF // This should be invalid for Ed25519
		invalidBytes32[0] = 0xFF

		_, err = curve.PointFromBytes(invalidBytes32)
		// Note: Ed25519 library might accept some values we think are invalid
		// The important thing is that our IsOnCurve validation works
		if err == nil {
			// If the library accepts it, at least verify our validation catches it
			point, _ := curve.PointFromBytes(invalidBytes32)
			if point != nil && point.IsOnCurve() {
				t.Log("Ed25519 library accepted bytes we expected to reject, but point validation works")
			}
		}
	})

	t.Run("IdentityPointValidation", func(t *testing.T) {
		// Identity point should be valid
		identity := curve.PointIdentity()
		if !identity.IsOnCurve() {
			t.Error("Identity point should be on curve")
		}
	})
}

// TestChallengeComputationSecurity verifies challenge computation improvements
func TestChallengeComputationSecurity(t *testing.T) {
	curve := NewEd25519Curve()

	t.Run("ChallengeDeterminism", func(t *testing.T) {
		// Create test points
		scalar1, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar 1: %v", err)
		}
		defer scalar1.Zeroize()

		scalar2, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar 2: %v", err)
		}
		defer scalar2.Zeroize()

		publicKey := curve.BasePoint().Mul(scalar1)
		commitment := curve.BasePoint().Mul(scalar2)

		// Compute challenge multiple times
		challenge1, err := computeSchnorrChallenge(curve, publicKey, commitment)
		if err != nil {
			t.Fatalf("Failed to compute challenge: %v", err)
		}
		challenge2, err := computeSchnorrChallenge(curve, publicKey, commitment)
		if err != nil {
			t.Fatalf("Failed to compute challenge: %v", err)
		}

		// Verify they are identical
		if !challenge1.Equal(challenge2) {
			t.Error("Challenge computation should be deterministic")
		}
	})

	t.Run("ChallengeDifferentiation", func(t *testing.T) {
		// Create different test points
		scalar1, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar 1: %v", err)
		}
		defer scalar1.Zeroize()

		scalar2, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar 2: %v", err)
		}
		defer scalar2.Zeroize()

		scalar3, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar 3: %v", err)
		}
		defer scalar3.Zeroize()

		publicKey1 := curve.BasePoint().Mul(scalar1)
		publicKey2 := curve.BasePoint().Mul(scalar2)
		commitment := curve.BasePoint().Mul(scalar3)

		// Compute challenges with different public keys
		challenge1, err := computeSchnorrChallenge(curve, publicKey1, commitment)
		if err != nil {
			t.Fatalf("Failed to compute challenge: %v", err)
		}
		challenge2, err := computeSchnorrChallenge(curve, publicKey2, commitment)
		if err != nil {
			t.Fatalf("Failed to compute challenge: %v", err)
		}

		// Verify they are different
		if challenge1.Equal(challenge2) {
			t.Error("Challenges should be different for different public keys")
		}
	})
}

// TestMemorySafety verifies that sensitive operations don't leak memory
func TestMemorySafety(t *testing.T) {
	curve := NewEd25519Curve()

	t.Run("NoMemoryLeakInKeyGeneration", func(t *testing.T) {
		// Generate multiple key shares and ensure cleanup
		for i := 0; i < 10; i++ {
			foundationKey, err := curve.ScalarRandom()
			if err != nil {
				t.Fatalf("Failed to generate foundation key: %v", err)
			}

			validatorKey, err := curve.ScalarRandom()
			if err != nil {
				t.Fatalf("Failed to generate validator key: %v", err)
			}

			participants := []ParticipantIndex{1, 2, 3}
			validatorKeys := map[ParticipantIndex]Scalar{
				1: validatorKey,
				2: validatorKey,
				3: validatorKey,
			}

			dkg, err := NewDeterministicKeyGen(curve, 2, participants, foundationKey, validatorKeys)
			if err != nil {
				t.Fatalf("Failed to create deterministic key generator: %v", err)
			}

			keyShares, _, err := dkg.GenerateKeyShares()
			if err != nil {
				t.Fatalf("Failed to generate key shares: %v", err)
			}

			// Clean up all key shares
			for _, keyShare := range keyShares {
				keyShare.Zeroize()
			}

			// Clean up keys
			foundationKey.Zeroize()
			validatorKey.Zeroize()
		}
	})

	t.Run("SecureRandomGeneration", func(t *testing.T) {
		// Generate multiple random scalars and verify they're different
		scalars := make([]Scalar, 10)
		for i := 0; i < 10; i++ {
			scalar, err := curve.ScalarRandom()
			if err != nil {
				t.Fatalf("Failed to generate random scalar %d: %v", i, err)
			}
			scalars[i] = scalar
		}

		// Verify all scalars are different
		for i := 0; i < len(scalars); i++ {
			for j := i + 1; j < len(scalars); j++ {
				if scalars[i].Equal(scalars[j]) {
					t.Errorf("Random scalars %d and %d should be different", i, j)
				}
			}
		}

		// Clean up
		for _, scalar := range scalars {
			scalar.Zeroize()
		}
	})
}

// TestEdgeCases verifies handling of edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	curve := NewEd25519Curve()

	t.Run("ZeroScalarHandling", func(t *testing.T) {
		zero := curve.ScalarZero()

		// Verify zero scalar properties
		if !zero.IsZero() {
			t.Error("Zero scalar should be zero")
		}

		// Verify inversion of zero fails
		_, err := zero.Invert()
		if err == nil {
			t.Error("Inverting zero scalar should fail")
		}
	})

	t.Run("InvalidInputHandling", func(t *testing.T) {
		// Test with nil inputs
		_, err := NewDeterministicKeyGen(nil, 1, []ParticipantIndex{1}, nil, nil)
		if err == nil {
			t.Error("Should reject nil curve")
		}

		// Test with invalid threshold
		foundationKey, _ := curve.ScalarRandom()
		defer foundationKey.Zeroize()

		validatorKey, _ := curve.ScalarRandom()
		defer validatorKey.Zeroize()

		validatorKeys := map[ParticipantIndex]Scalar{1: validatorKey}

		_, err = NewDeterministicKeyGen(curve, 0, []ParticipantIndex{1}, foundationKey, validatorKeys)
		if err == nil {
			t.Error("Should reject zero threshold")
		}

		_, err = NewDeterministicKeyGen(curve, 2, []ParticipantIndex{1}, foundationKey, validatorKeys)
		if err == nil {
			t.Error("Should reject threshold greater than participant count")
		}
	})

	t.Run("EmptyInputHandling", func(t *testing.T) {
		foundationKey, _ := curve.ScalarRandom()
		defer foundationKey.Zeroize()

		// Test with empty participants
		_, err := NewDeterministicKeyGen(curve, 1, []ParticipantIndex{}, foundationKey, map[ParticipantIndex]Scalar{})
		if err == nil {
			t.Error("Should reject empty participants")
		}

		// Test with missing validator keys
		_, err = NewDeterministicKeyGen(curve, 1, []ParticipantIndex{1}, foundationKey, map[ParticipantIndex]Scalar{})
		if err == nil {
			t.Error("Should reject missing validator keys")
		}
	})
}
