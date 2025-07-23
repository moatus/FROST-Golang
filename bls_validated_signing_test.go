package frost

import (
	"testing"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestBLSValidatedSigning tests the BLS-validated signing functions
func TestBLSValidatedSigning(t *testing.T) {
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

	// Generate foundation key
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	// Generate a second BLS key for participant 2
	blsKey2Interface, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate BLS key 2: %v", err)
	}
	blsKey2, ok := blsKey2Interface.(*crypto.BLS12381PrivateKey)
	if !ok {
		t.Fatalf("Failed to cast BLS key 2 to correct type")
	}

	// Create BLS-anchored key generator
	participants := []ParticipantIndex{1, 2}
	validatorBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
		1: blsKey,
		2: blsKey2, // Each participant needs their own BLS key
	}

	bkg := NewBLSAnchoredKeyGen(curve, 2, participants, foundationKey, validatorBLSKeys)

	// Generate key shares with BLS binding proofs
	keyShares, _, err := bkg.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate key shares: %v", err)
	}

	// Verify that key shares have BLS binding proofs
	for participantID, keyShare := range keyShares {
		if keyShare.BLSBindingProof == nil {
			t.Errorf("Key share for participant %d missing BLS binding proof", participantID)
		}
	}

	// Test message
	message := []byte("test message for BLS-validated signing")

	// Create signing session
	signers := []ParticipantIndex{1, 2}
	session, err := NewSigningSession(curve, keyShares[1], message, signers, 2)
	if err != nil {
		t.Fatalf("Failed to create signing session: %v", err)
	}

	t.Run("BLSValidatedCommitment", func(t *testing.T) {
		// Test GenerateBLSValidatedCommitment
		commitment1, err := session.GenerateBLSValidatedCommitment(1, keyShares[1], blsKey)
		if err != nil {
			t.Errorf("GenerateBLSValidatedCommitment failed: %v", err)
			return
		}
		if commitment1 == nil {
			t.Error("Expected non-nil commitment")
			return
		}
		if commitment1.ParticipantID != 1 {
			t.Errorf("Expected participant ID 1, got %d", commitment1.ParticipantID)
		}

		t.Log("✅ BLS-validated commitment generation successful")
	})

	t.Run("BLSValidatedCommitmentFailsWithoutProof", func(t *testing.T) {
		// Create a key share without BLS binding proof
		keyShareWithoutProof := &KeyShare{
			ParticipantID:   1,
			SecretShare:     keyShares[1].SecretShare,
			PublicKey:       keyShares[1].PublicKey,
			GroupPublicKey:  keyShares[1].GroupPublicKey,
			BLSBindingProof: nil, // No proof
		}

		// This should fail
		_, err := session.GenerateBLSValidatedCommitment(1, keyShareWithoutProof, blsKey)
		if err == nil {
			t.Error("Expected error when key share has no BLS binding proof")
		}
		if err.Error() != "key share does not contain BLS binding proof - cannot validate BLS binding" {
			t.Errorf("Unexpected error message: %v", err)
		}

		t.Log("✅ BLS-validated commitment properly rejects key shares without proofs")
	})

	t.Run("BLSValidatedCommitmentFailsWithWrongBLSKey", func(t *testing.T) {
		// Generate a different BLS key
		wrongBLSKeyInterface, err := crypto.NewBLS12381PrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate wrong BLS key: %v", err)
		}
		wrongBLSKey, ok := wrongBLSKeyInterface.(*crypto.BLS12381PrivateKey)
		if !ok {
			t.Fatalf("Failed to cast wrong BLS key to correct type")
		}

		// This should fail because the BLS key doesn't match the binding proof
		_, err = session.GenerateBLSValidatedCommitment(1, keyShares[1], wrongBLSKey)
		if err == nil {
			t.Error("Expected error when using wrong BLS key")
		}

		t.Log("✅ BLS-validated commitment properly rejects wrong BLS keys")
	})

	t.Run("BLSValidatedResponse", func(t *testing.T) {
		// First generate commitments for both participants
		commitment1, err := session.GenerateBLSValidatedCommitment(1, keyShares[1], blsKey)
		if err != nil {
			t.Fatalf("Failed to generate commitment 1: %v", err)
		}

		// Create a second session for participant 2
		session2, err := NewSigningSession(curve, keyShares[2], message, signers, 2)
		if err != nil {
			t.Fatalf("Failed to create signing session 2: %v", err)
		}

		commitment2, err := session2.GenerateBLSValidatedCommitment(2, keyShares[2], blsKey2)
		if err != nil {
			t.Fatalf("Failed to generate commitment 2: %v", err)
		}

		// Collect commitments
		commitments := map[ParticipantIndex]*SigningCommitment{
			1: commitment1,
			2: commitment2,
		}

		// Test GenerateBLSValidatedResponse
		response1, err := session.GenerateBLSValidatedResponse(1, keyShares[1], blsKey, commitments)
		if err != nil {
			t.Errorf("GenerateBLSValidatedResponse failed: %v", err)
		}
		if response1 == nil {
			t.Error("Expected non-nil response")
		}
		if response1.ParticipantID != 1 {
			t.Errorf("Expected participant ID 1, got %d", response1.ParticipantID)
		}

		t.Log("✅ BLS-validated response generation successful")
	})

	t.Run("BLSValidatedResponseFailsWithoutProof", func(t *testing.T) {
		// Create a key share without BLS binding proof
		keyShareWithoutProof := &KeyShare{
			ParticipantID:   1,
			SecretShare:     keyShares[1].SecretShare,
			PublicKey:       keyShares[1].PublicKey,
			GroupPublicKey:  keyShares[1].GroupPublicKey,
			BLSBindingProof: nil, // No proof
		}

		// Create dummy commitments
		commitments := map[ParticipantIndex]*SigningCommitment{
			1: {ParticipantID: 1, Commitment: curve.BasePoint()},
		}

		// This should fail
		_, err := session.GenerateBLSValidatedResponse(1, keyShareWithoutProof, blsKey, commitments)
		if err == nil {
			t.Error("Expected error when key share has no BLS binding proof")
		}

		t.Log("✅ BLS-validated response properly rejects key shares without proofs")
	})

	t.Run("InputValidation", func(t *testing.T) {
		// Test nil inputs
		_, err := session.GenerateBLSValidatedCommitment(1, nil, blsKey)
		if err == nil || err.Error() != "key share cannot be nil" {
			t.Errorf("Expected 'key share cannot be nil' error, got: %v", err)
		}

		_, err = session.GenerateBLSValidatedCommitment(1, keyShares[1], nil)
		if err == nil || err.Error() != "BLS key cannot be nil" {
			t.Errorf("Expected 'BLS key cannot be nil' error, got: %v", err)
		}

		// Test wrong BLS key type
		_, err = session.GenerateBLSValidatedCommitment(1, keyShares[1], "wrong_type")
		if err == nil {
			t.Error("Expected error for wrong BLS key type")
		}

		t.Log("✅ Input validation works correctly")
	})
}

// TestBLSValidatedSigningIntegration tests the full BLS-validated signing flow
func TestBLSValidatedSigningIntegration(t *testing.T) {
	curve := NewEd25519Curve()

	// Generate BLS keys for multiple participants
	blsKey1Interface, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate BLS key 1: %v", err)
	}
	blsKey1 := blsKey1Interface.(*crypto.BLS12381PrivateKey)

	blsKey2Interface, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate BLS key 2: %v", err)
	}
	blsKey2 := blsKey2Interface.(*crypto.BLS12381PrivateKey)

	// Generate foundation key
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	// Create BLS-anchored key generator with different BLS keys
	participants := []ParticipantIndex{1, 2}
	validatorBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
		1: blsKey1,
		2: blsKey2,
	}

	bkg := NewBLSAnchoredKeyGen(curve, 2, participants, foundationKey, validatorBLSKeys)

	// Generate key shares
	keyShares, _, err := bkg.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate key shares: %v", err)
	}

	// Test message
	message := []byte("integration test message")

	// Create signing sessions for both participants
	signers := []ParticipantIndex{1, 2}
	session1, err := NewSigningSession(curve, keyShares[1], message, signers, 2)
	if err != nil {
		t.Fatalf("Failed to create signing session 1: %v", err)
	}

	session2, err := NewSigningSession(curve, keyShares[2], message, signers, 2)
	if err != nil {
		t.Fatalf("Failed to create signing session 2: %v", err)
	}

	// Round 1: Generate BLS-validated commitments
	commitment1, err := session1.GenerateBLSValidatedCommitment(1, keyShares[1], blsKey1)
	if err != nil {
		t.Fatalf("Failed to generate BLS-validated commitment 1: %v", err)
	}

	commitment2, err := session2.GenerateBLSValidatedCommitment(2, keyShares[2], blsKey2)
	if err != nil {
		t.Fatalf("Failed to generate BLS-validated commitment 2: %v", err)
	}

	// Collect commitments
	commitments := map[ParticipantIndex]*SigningCommitment{
		1: commitment1,
		2: commitment2,
	}

	// Round 2: Generate BLS-validated responses
	response1, err := session1.GenerateBLSValidatedResponse(1, keyShares[1], blsKey1, commitments)
	if err != nil {
		t.Fatalf("Failed to generate BLS-validated response 1: %v", err)
	}

	response2, err := session2.GenerateBLSValidatedResponse(2, keyShares[2], blsKey2, commitments)
	if err != nil {
		t.Fatalf("Failed to generate BLS-validated response 2: %v", err)
	}

	// Verify responses are valid
	if response1.ParticipantID != 1 {
		t.Errorf("Expected response 1 participant ID 1, got %d", response1.ParticipantID)
	}
	if response2.ParticipantID != 2 {
		t.Errorf("Expected response 2 participant ID 2, got %d", response2.ParticipantID)
	}

	t.Log("✅ Full BLS-validated signing integration test successful")
}
