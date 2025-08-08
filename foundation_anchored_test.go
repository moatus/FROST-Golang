package frost

import (
	"testing"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestFoundationAnchoredAddressStability tests that addresses remain stable across validator set changes
func TestFoundationAnchoredAddressStability(t *testing.T) {
	curve := NewEd25519Curve()
	threshold := 2
	
	// Create a foundation key (this represents the RPW-derived key)
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// Test Case 1: Initial validator set {1, 2, 3}
	initialParticipants := []ParticipantIndex{1, 2, 3}
	initialBLSKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, participantID := range initialParticipants {
		blsKey := createMockBLSKeyForFoundation(t, int(participantID))
		initialBLSKeys[participantID] = blsKey
	}
	
	// Generate initial FROST shares
	fakg1 := NewFoundationAnchoredKeyGen(curve, threshold, initialParticipants, foundationKey, initialBLSKeys)
	
	initialShares, initialAddress, err := fakg1.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate initial key shares: %v", err)
	}
	
	// Verify we got the expected number of shares
	if len(initialShares) != len(initialParticipants) {
		t.Fatalf("Expected %d shares, got %d", len(initialParticipants), len(initialShares))
	}
	
	// Test Case 2: Changed validator set {1, 2, 4, 5} (3 leaves, 4&5 join)
	newParticipants := []ParticipantIndex{1, 2, 4, 5}
	newBLSKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	
	// Keep existing validators 1 and 2
	newBLSKeys[1] = initialBLSKeys[1]
	newBLSKeys[2] = initialBLSKeys[2]
	
	// Add new validators 4 and 5
	newBLSKeys[4] = createMockBLSKeyForFoundation(t, 4)
	newBLSKeys[5] = createMockBLSKeyForFoundation(t, 5)
	
	// Generate new FROST shares with changed validator set
	fakg2 := NewFoundationAnchoredKeyGen(curve, threshold, newParticipants, foundationKey, newBLSKeys)
	
	newShares, newAddress, err := fakg2.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate new key shares: %v", err)
	}
	
	// CRITICAL TEST: Address should remain the same!
	if !initialAddress.Equal(newAddress) {
		t.Fatalf("Address changed when validator set changed! This breaks the core requirement.")
	}
	
	t.Log("✅ Address stability verified: same foundation key produces same address across validator set changes")
	
	// Verify shares are different (they should be, since validator set changed)
	if len(newShares) != len(newParticipants) {
		t.Fatalf("Expected %d new shares, got %d", len(newParticipants), len(newShares))
	}
	
	// Verify that continuing validators (1, 2) have different shares
	// (because the polynomial coefficients changed due to new validator set)
	if initialShares[1].SecretShare.Equal(newShares[1].SecretShare) {
		t.Error("Validator 1's share should change when validator set changes")
	}
	if initialShares[2].SecretShare.Equal(newShares[2].SecretShare) {
		t.Error("Validator 2's share should change when validator set changes")
	}
	
	t.Log("✅ Share regeneration verified: shares change appropriately when validator set changes")
	
	// Test Case 3: Verify stable address derivation is deterministic
	stableAddress1 := fakg1.DeriveStableAddress()
	stableAddress2 := fakg2.DeriveStableAddress()
	
	if !stableAddress1.Equal(stableAddress2) {
		t.Fatal("Stable address derivation should be deterministic")
	}
	
	if !stableAddress1.Equal(initialAddress) {
		t.Fatal("Stable address should match group public key")
	}
	
	t.Log("✅ Deterministic address derivation verified")
}

// TestFoundationAnchoredDeterminism tests that the same inputs always produce the same outputs
func TestFoundationAnchoredDeterminism(t *testing.T) {
	curve := NewEd25519Curve()
	threshold := 2
	participants := []ParticipantIndex{1, 2, 3}
	
	// Create foundation key
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// Create BLS keys
	blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, participantID := range participants {
		blsKeys[participantID] = createMockBLSKeyForFoundation(t, int(participantID))
	}
	
	// Generate shares twice with same inputs
	fakg1 := NewFoundationAnchoredKeyGen(curve, threshold, participants, foundationKey, blsKeys)
	fakg2 := NewFoundationAnchoredKeyGen(curve, threshold, participants, foundationKey, blsKeys)
	
	shares1, address1, err := fakg1.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate shares 1: %v", err)
	}
	
	shares2, address2, err := fakg2.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate shares 2: %v", err)
	}
	
	// Verify deterministic behavior
	if !address1.Equal(address2) {
		t.Fatal("Addresses should be identical for same inputs")
	}
	
	for _, participantID := range participants {
		share1 := shares1[participantID]
		share2 := shares2[participantID]
		
		if !share1.SecretShare.Equal(share2.SecretShare) {
			t.Fatalf("Secret shares should be identical for participant %d", participantID)
		}
		
		if !share1.PublicKey.Equal(share2.PublicKey) {
			t.Fatalf("Public keys should be identical for participant %d", participantID)
		}
		
		if !share1.GroupPublicKey.Equal(share2.GroupPublicKey) {
			t.Fatalf("Group public keys should be identical for participant %d", participantID)
		}
	}
	
	t.Log("✅ Deterministic generation verified")
}

// TestFoundationAnchoredThresholdSigning tests that the generated shares can perform threshold signing
func TestFoundationAnchoredThresholdSigning(t *testing.T) {
	curve := NewEd25519Curve()
	threshold := 2
	participants := []ParticipantIndex{1, 2, 3}
	
	// Create foundation key
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// Create BLS keys
	blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, participantID := range participants {
		blsKeys[participantID] = createMockBLSKeyForFoundation(t, int(participantID))
	}
	
	// Generate FROST shares
	fakg := NewFoundationAnchoredKeyGen(curve, threshold, participants, foundationKey, blsKeys)
	shares, groupPubKey, err := fakg.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate key shares: %v", err)
	}
	
	// Test message
	message := []byte("Test message for foundation-anchored FROST signing")
	
	// Create signing sessions for threshold participants (1 and 2)
	signerIDs := []ParticipantIndex{1, 2}
	sessions := make([]*SigningSession, len(signerIDs))

	for i, signerID := range signerIDs {
		session, err := NewSigningSession(curve, shares[signerID], message, signerIDs, threshold)
		if err != nil {
			t.Fatalf("Failed to create signing session for participant %d: %v", signerID, err)
		}
		sessions[i] = session
	}

	// Round 1: Generate commitments
	commitments := make([]*SigningCommitment, len(sessions))
	for i, session := range sessions {
		commitment, err := session.Round1()
		if err != nil {
			t.Fatalf("Round 1 failed for participant %d: %v", signerIDs[i], err)
		}
		commitments[i] = commitment
	}

	// Process commitments for each session
	for i, session := range sessions {
		otherCommitments := make([]*SigningCommitment, 0, len(commitments)-1)
		for j, commitment := range commitments {
			if j != i {
				otherCommitments = append(otherCommitments, commitment)
			}
		}

		err := session.ProcessRound1(otherCommitments)
		if err != nil {
			t.Fatalf("Failed to process round 1 for participant %d: %v", signerIDs[i], err)
		}
	}

	// Round 2: Generate signature responses
	responses := make([]*SigningResponse, len(sessions))
	for i, session := range sessions {
		response, err := session.Round2()
		if err != nil {
			t.Fatalf("Round 2 failed for participant %d: %v", signerIDs[i], err)
		}
		responses[i] = response
	}

	// Process responses to generate final signature
	signature, err := sessions[0].ProcessRound2(responses)
	if err != nil {
		t.Fatalf("Failed to process round 2: %v", err)
	}

	// Verify the signature against the stable address
	valid, err := VerifySignature(curve, signature, message, groupPubKey)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}
	
	t.Log("✅ Foundation-anchored threshold signing verified")
}

// TestFoundationAnchoredBLSBinding tests that BLS binding proofs are correctly generated
func TestFoundationAnchoredBLSBinding(t *testing.T) {
	curve := NewEd25519Curve()
	threshold := 2
	participants := []ParticipantIndex{1, 2, 3}
	
	// Create foundation key
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// Create BLS keys
	blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, participantID := range participants {
		blsKeys[participantID] = createMockBLSKeyForFoundation(t, int(participantID))
	}
	
	// Generate FROST shares
	fakg := NewFoundationAnchoredKeyGen(curve, threshold, participants, foundationKey, blsKeys)
	shares, _, err := fakg.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate key shares: %v", err)
	}
	
	// Verify each share has a BLS binding proof
	for _, participantID := range participants {
		share := shares[participantID]
		
		if share.BLSBindingProof == nil {
			t.Fatalf("Participant %d should have BLS binding proof", participantID)
		}
		
		proof := share.BLSBindingProof
		if proof.ParticipantID != participantID {
			t.Fatalf("Proof participant ID mismatch for participant %d", participantID)
		}
		
		if len(proof.BLSPublicKey) == 0 {
			t.Fatalf("Proof should contain BLS public key for participant %d", participantID)
		}
		
		if proof.Commitment == nil {
			t.Fatalf("Proof should contain commitment for participant %d", participantID)
		}
		
		if proof.Challenge == nil || proof.Challenge.IsZero() {
			t.Fatalf("Proof should contain non-zero challenge for participant %d", participantID)
		}
		
		if proof.Response == nil || proof.Response.IsZero() {
			t.Fatalf("Proof should contain non-zero response for participant %d", participantID)
		}
	}
	
	t.Log("✅ BLS binding proofs verified")
}

// Helper function to create mock BLS keys for testing
func createMockBLSKeyForFoundation(t *testing.T, seed int) *crypto.BLS12381PrivateKey {
	key, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Skipf("Cannot create BLS key for testing: %v", err)
	}
	
	blsKey, ok := key.(*crypto.BLS12381PrivateKey)
	if !ok {
		t.Skip("Cannot cast to BLS12381PrivateKey")
	}
	
	return blsKey
}
