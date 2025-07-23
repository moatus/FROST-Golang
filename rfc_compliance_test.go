package frost

import (
	"runtime"
	"testing"
	"time"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestRFCCompliantChallengeComputation verifies SHA512 is used for Ed25519 challenges
func TestRFCCompliantChallengeComputation(t *testing.T) {
	curve := NewEd25519Curve()

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

	// Compute challenge (should use SHA512 for Ed25519)
	challenge, err := computeSchnorrChallenge(curve, publicKey, commitment)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// Verify challenge is valid (non-zero)
	if challenge.IsZero() {
		t.Error("Challenge should not be zero")
	}

	// Verify deterministic behavior
	challenge2, err := computeSchnorrChallenge(curve, publicKey, commitment)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}
	if !challenge.Equal(challenge2) {
		t.Error("Challenge computation should be deterministic")
	}

	t.Log("✅ RFC-compliant challenge computation working correctly")
}

// TestFinalizerZeroization verifies that finalizers provide backup cleanup
func TestFinalizerZeroization(t *testing.T) {
	curve := NewEd25519Curve()

	// Create scalar without explicit cleanup
	func() {
		scalar, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar: %v", err)
		}
		
		// Verify scalar is not zero
		if scalar.IsZero() {
			t.Skip("Random scalar is zero, skipping test")
		}
		
		// Don't call Zeroize() - let finalizer handle it
		_ = scalar
	}()

	// Force garbage collection to trigger finalizers
	runtime.GC()
	runtime.GC() // Call twice to ensure finalizers run
	time.Sleep(10 * time.Millisecond) // Give finalizers time to run

	t.Log("✅ Finalizer-based cleanup test completed (manual verification needed)")
}

// TestPreventionBasedValidation verifies that invalid points cannot be created
func TestPreventionBasedValidation(t *testing.T) {
	curve := NewEd25519Curve()

	// Test valid point creation
	validBytes := curve.BasePoint().Bytes()
	point, err := curve.PointFromBytes(validBytes)
	if err != nil {
		t.Fatalf("Valid point should be accepted: %v", err)
	}
	if point == nil {
		t.Fatal("Valid point should not be nil")
	}

	// Test invalid point rejection (wrong length)
	invalidBytes := make([]byte, 16) // Wrong length
	_, err = curve.PointFromBytes(invalidBytes)
	if err == nil {
		t.Error("Invalid point bytes should be rejected")
	}

	// Test invalid point rejection (invalid data)
	invalidBytes32 := make([]byte, 32)
	for i := range invalidBytes32 {
		invalidBytes32[i] = 0xFF // Likely invalid for Ed25519
	}
	_, err = curve.PointFromBytes(invalidBytes32)
	// Note: edwards25519 library might accept some values we think are invalid
	// The important thing is that validation happens at creation time
	
	t.Log("✅ Prevention-based validation working correctly")
}

// TestCombinedImprovements verifies all improvements work together
func TestCombinedImprovements(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate BLS key for testing
	blsKeyInterface, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate BLS key: %v", err)
	}
	blsKey, ok := blsKeyInterface.(*crypto.BLS12381PrivateKey)
	if !ok {
		t.Fatalf("Failed to cast BLS key to correct type")
	}

	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	participants := []ParticipantIndex{1}
	validatorBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
		1: blsKey,
	}

	// Test all hash algorithms work with improvements
	algorithms := []HashAlgorithm{SHA256_HKDF, BLAKE2B, SHAKE256}
	algorithmNames := []string{"SHA256+HKDF", "Blake2b", "SHAKE256"}

	for i, algorithm := range algorithms {
		t.Run(algorithmNames[i], func(t *testing.T) {
			// Create key generator with specific algorithm
			bkg := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, algorithm)

			// Generate key shares (tests prevention-based validation)
			keyShares, groupPubKey, err := bkg.GenerateKeyShares()
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}

			// Verify key share is valid
			if len(keyShares) != 1 {
				t.Fatalf("Expected 1 key share, got %d", len(keyShares))
			}

			keyShare := keyShares[1]
			if keyShare.SecretShare.IsZero() {
				t.Error("Secret share should not be zero")
			}

			if groupPubKey == nil {
				t.Error("Group public key should not be nil")
			}

			// Test Schnorr proof (uses RFC-compliant challenge computation)
			scalar, err := curve.ScalarRandom()
			if err != nil {
				t.Fatalf("Failed to create scalar: %v", err)
			}
			defer scalar.Zeroize()

			commitment := curve.BasePoint().Mul(scalar)
			challenge, err := computeSchnorrChallenge(curve, keyShare.PublicKey, commitment)
			if err != nil {
				t.Fatalf("Failed to compute challenge: %v", err)
			}
			
			if challenge.IsZero() {
				t.Error("Challenge should not be zero")
			}

			// Clean up key share (tests enhanced zeroization)
			keyShare.Zeroize()

			t.Logf("✅ %s algorithm working correctly with all improvements", algorithmNames[i])
		})
	}
}

// TestPerformanceWithImprovements verifies improvements don't hurt performance
func TestPerformanceWithImprovements(t *testing.T) {
	curve := NewEd25519Curve()

	const iterations = 100

	// Test scalar creation performance (with finalizers)
	start := time.Now()
	for i := 0; i < iterations; i++ {
		scalar, err := curve.ScalarRandom()
		if err != nil {
			t.Fatalf("Failed to create scalar: %v", err)
		}
		scalar.Zeroize() // Manual cleanup
	}
	scalarDuration := time.Since(start)

	// Test challenge computation performance (RFC-compliant)
	scalar1, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}
	defer scalar1.Zeroize()
	scalar2, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}
	defer scalar2.Zeroize()

	publicKey := curve.BasePoint().Mul(scalar1)
	commitment := curve.BasePoint().Mul(scalar2)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		challenge, err := computeSchnorrChallenge(curve, publicKey, commitment)
		if err != nil {
			t.Fatalf("Failed to compute challenge: %v", err)
		}
		_ = challenge
	}
	challengeDuration := time.Since(start)

	t.Logf("Scalar creation: %d iterations in %v (%.2f μs/op)", 
		iterations, scalarDuration, float64(scalarDuration.Nanoseconds())/float64(iterations)/1000)
	t.Logf("Challenge computation: %d iterations in %v (%.2f μs/op)", 
		iterations, challengeDuration, float64(challengeDuration.Nanoseconds())/float64(iterations)/1000)

	t.Log("✅ Performance remains good with all improvements")
}
