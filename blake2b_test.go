package frost

import (
	"testing"
	"time"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestHashAlgorithmPerformance compares performance of all hash algorithms
func TestHashAlgorithmPerformance(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate test data
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

	// Test all hash algorithms
	bkgSHA256 := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, SHA256_HKDF)
	bkgBlake2b := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, BLAKE2B)
	bkgShake256 := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, SHAKE256)

	const iterations = 1000

	// Benchmark SHA256+HKDF
	startSHA256 := time.Now()
	for i := 0; i < iterations; i++ {
		scalar, err := bkgSHA256.blsToSchnorrSecret(1, blsKey)
		if err != nil {
			t.Fatalf("SHA256+HKDF failed: %v", err)
		}
		scalar.Zeroize()
	}
	sha256Duration := time.Since(startSHA256)

	// Benchmark Blake2b
	startBlake2b := time.Now()
	for i := 0; i < iterations; i++ {
		scalar, err := bkgBlake2b.blsToSchnorrSecret(1, blsKey)
		if err != nil {
			t.Fatalf("Blake2b failed: %v", err)
		}
		scalar.Zeroize()
	}
	blake2bDuration := time.Since(startBlake2b)

	// Benchmark SHAKE256
	startShake256 := time.Now()
	for i := 0; i < iterations; i++ {
		scalar, err := bkgShake256.blsToSchnorrSecret(1, blsKey)
		if err != nil {
			t.Fatalf("SHAKE256 failed: %v", err)
		}
		scalar.Zeroize()
	}
	shake256Duration := time.Since(startShake256)

	// Report results
	t.Logf("SHA256+HKDF: %d iterations in %v (%.2f μs/op)", iterations, sha256Duration, float64(sha256Duration.Nanoseconds())/float64(iterations)/1000)
	t.Logf("Blake2b:     %d iterations in %v (%.2f μs/op)", iterations, blake2bDuration, float64(blake2bDuration.Nanoseconds())/float64(iterations)/1000)
	t.Logf("SHAKE256:    %d iterations in %v (%.2f μs/op)", iterations, shake256Duration, float64(shake256Duration.Nanoseconds())/float64(iterations)/1000)

	blake2bSpeedup := float64(sha256Duration) / float64(blake2bDuration)
	shake256Speedup := float64(sha256Duration) / float64(shake256Duration)
	t.Logf("Blake2b is %.2fx faster than SHA256+HKDF", blake2bSpeedup)
	t.Logf("SHAKE256 is %.2fx faster than SHA256+HKDF", shake256Speedup)
}

// TestBlake2bCompatibility verifies that different hash algorithms produce different but valid results
func TestBlake2bCompatibility(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate test data
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

	// Create key generators with different hash algorithms
	bkgSHA256 := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, SHA256_HKDF)
	bkgBlake2b := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, BLAKE2B)

	// Generate scalars with both algorithms
	scalarSHA256, err := bkgSHA256.blsToSchnorrSecret(1, blsKey)
	if err != nil {
		t.Fatalf("SHA256+HKDF failed: %v", err)
	}
	defer scalarSHA256.Zeroize()

	scalarBlake2b, err := bkgBlake2b.blsToSchnorrSecret(1, blsKey)
	if err != nil {
		t.Fatalf("Blake2b failed: %v", err)
	}
	defer scalarBlake2b.Zeroize()

	// Verify both scalars are valid (non-zero)
	if scalarSHA256.IsZero() {
		t.Error("SHA256+HKDF produced zero scalar")
	}
	if scalarBlake2b.IsZero() {
		t.Error("Blake2b produced zero scalar")
	}

	// Verify they produce different results (as expected)
	if scalarSHA256.Equal(scalarBlake2b) {
		t.Error("Different hash algorithms should produce different scalars")
	}

	t.Log("✅ Both hash algorithms produce valid but different scalars (as expected)")
}

// TestBlake2bDeterminism verifies that Blake2b produces deterministic results
func TestBlake2bDeterminism(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate test data
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

	// Create key generator with Blake2b
	bkg := NewBLSAnchoredKeyGenWithHash(curve, 1, participants, foundationKey, validatorBLSKeys, BLAKE2B)

	// Generate the same scalar multiple times
	scalar1, err := bkg.blsToSchnorrSecret(1, blsKey)
	if err != nil {
		t.Fatalf("Blake2b failed (1): %v", err)
	}
	defer scalar1.Zeroize()

	scalar2, err := bkg.blsToSchnorrSecret(1, blsKey)
	if err != nil {
		t.Fatalf("Blake2b failed (2): %v", err)
	}
	defer scalar2.Zeroize()

	// Verify they are identical (deterministic)
	if !scalar1.Equal(scalar2) {
		t.Error("Blake2b should produce deterministic results")
	}

	t.Log("✅ Blake2b produces deterministic results")
}

// TestDefaultCompatibility verifies that the default constructor uses SHA256+HKDF for compatibility
func TestDefaultCompatibility(t *testing.T) {
	curve := NewEd25519Curve()

	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	participants := []ParticipantIndex{1}
	validatorBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{}

	// Default constructor should use SHA256+HKDF
	bkgDefault := NewBLSAnchoredKeyGen(curve, 1, participants, foundationKey, validatorBLSKeys)

	if bkgDefault.hashAlgorithm != SHA256_HKDF {
		t.Errorf("Default constructor should use SHA256_HKDF, got %d", bkgDefault.hashAlgorithm)
	}

	t.Log("✅ Default constructor uses SHA256+HKDF for compatibility")
}
