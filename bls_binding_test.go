package frost

import (
	"testing"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestBLSBindingVerificationBasic tests the newly implemented BLS binding verification with a simpler approach
func TestBLSBindingVerificationBasic(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate a BLS key for testing
	blsKeyInterface, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate BLS key: %v", err)
	}
	blsKey, ok := blsKeyInterface.(*crypto.BLS12381PrivateKey)
	if !ok {
		t.Fatalf("Failed to cast BLS key to correct type")
	}

	// Get BLS public key bytes
	blsPubKey := blsKey.PublicKey()
	if blsPubKey == nil {
		t.Fatalf("BLS public key is nil")
	}
	blsPubKeyBytes := blsPubKey.Bytes()

	// Create a simple FROST key pair for testing
	frostSecret, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate FROST secret: %v", err)
	}
	defer frostSecret.Zeroize()

	frostPublicKey := curve.BasePoint().Mul(frostSecret)

	// Create a valid binding proof manually
	// Generate a proof commitment
	nonce, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	defer nonce.Zeroize()

	proofCommitment := curve.BasePoint().Mul(nonce)

	// Compute challenge using SHA256_HKDF
	challenge, err := computeBLSBindingChallenge(
		curve,
		1, // participant ID
		blsPubKeyBytes,
		frostPublicKey,
		proofCommitment,
		SHA256_HKDF,
	)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// Compute response: s = nonce + c * frost_secret
	challengeTimesSecret := challenge.Mul(frostSecret)
	response := nonce.Add(challengeTimesSecret)

	// Create binding proof
	bindingProof := &BLSBindingProof{
		ParticipantID: 1,
		BLSPublicKey:  blsPubKeyBytes,
		Challenge:     challenge,
		Response:      response,
		Commitment:    proofCommitment,
	}

	// Test the VerifyBLSBinding function
	err = VerifyBLSBinding(curve, blsPubKeyBytes, frostPublicKey, bindingProof)
	if err != nil {
		t.Errorf("VerifyBLSBinding failed: %v", err)
	} else {
		t.Log("✅ Basic BLS binding verification successful")
	}

	// Test with different hash algorithms
	algorithms := []HashAlgorithm{SHA256_HKDF, BLAKE2B, SHAKE256}
	algorithmNames := []string{"SHA256+HKDF", "Blake2b", "SHAKE256"}

	for i, algorithm := range algorithms {
		t.Run(algorithmNames[i], func(t *testing.T) {
			// Recompute challenge with specific algorithm
			newChallenge, err := computeBLSBindingChallenge(
				curve,
				1,
				blsPubKeyBytes,
				frostPublicKey,
				proofCommitment,
				algorithm,
			)
			if err != nil {
				t.Fatalf("Failed to compute challenge for %s: %v", algorithmNames[i], err)
			}

			// Recompute response with new challenge
			newChallengeTimesSecret := newChallenge.Mul(frostSecret)
			newResponse := nonce.Add(newChallengeTimesSecret)

			// Create new binding proof
			newBindingProof := &BLSBindingProof{
				ParticipantID: 1,
				BLSPublicKey:  blsPubKeyBytes,
				Challenge:     newChallenge,
				Response:      newResponse,
				Commitment:    proofCommitment,
			}

			// Test the algorithm-specific verification
			err = VerifyBLSBindingWithAlgorithm(curve, blsPubKeyBytes, frostPublicKey, newBindingProof, algorithm)
			if err != nil {
				t.Errorf("VerifyBLSBindingWithAlgorithm failed for %s: %v", algorithmNames[i], err)
			} else {
				t.Logf("✅ BLS binding verification successful for %s", algorithmNames[i])
			}
		})
	}
}

// TestBLSBindingVerificationFailures tests that verification properly fails for invalid proofs
func TestBLSBindingVerificationFailures(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate a BLS key for testing
	blsKeyInterface, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate BLS key: %v", err)
	}
	blsKey, ok := blsKeyInterface.(*crypto.BLS12381PrivateKey)
	if !ok {
		t.Fatalf("Failed to cast BLS key to correct type")
	}

	blsPubKey := blsKey.PublicKey()
	blsPubKeyBytes := blsPubKey.Bytes()

	// Create a random FROST public key (not derived from BLS key)
	randomScalar, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}
	defer randomScalar.Zeroize()

	randomPublicKey := curve.BasePoint().Mul(randomScalar)

	// Create an invalid binding proof
	invalidProof := &BLSBindingProof{
		ParticipantID: 1,
		BLSPublicKey:  blsPubKeyBytes,
		Challenge:     curve.ScalarOne(),
		Response:      curve.ScalarOne(),
		Commitment:    curve.BasePoint(),
	}

	// Test that verification fails for invalid proof
	err = VerifyBLSBinding(curve, blsPubKeyBytes, randomPublicKey, invalidProof)
	if err == nil {
		t.Error("Expected VerifyBLSBinding to fail for invalid proof, but it succeeded")
	}

	// Test with nil inputs
	err = VerifyBLSBinding(curve, nil, randomPublicKey, invalidProof)
	if err == nil {
		t.Error("Expected VerifyBLSBinding to fail for nil BLS key bytes")
	}

	err = VerifyBLSBinding(curve, blsPubKeyBytes, nil, invalidProof)
	if err == nil {
		t.Error("Expected VerifyBLSBinding to fail for nil FROST public key")
	}

	err = VerifyBLSBinding(curve, blsPubKeyBytes, randomPublicKey, nil)
	if err == nil {
		t.Error("Expected VerifyBLSBinding to fail for nil binding proof")
	}

	// Test with wrong type for binding proof
	err = VerifyBLSBinding(curve, blsPubKeyBytes, randomPublicKey, "invalid_type")
	if err == nil {
		t.Error("Expected VerifyBLSBinding to fail for wrong binding proof type")
	}

	t.Log("✅ BLS binding verification properly rejects invalid inputs")
}
