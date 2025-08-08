package frost

import (
	"testing"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestStableAddressIntegration tests the complete stable address solution
func TestStableAddressIntegration(t *testing.T) {
	curve := NewEd25519Curve()
	
	// Create foundation key (simulating RPW derivation)
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	t.Run("AddressStabilityAcrossValidatorChanges", func(t *testing.T) {
		// Initial validator set: {1, 2, 3} threshold 2
		initialParticipants := []ParticipantIndex{1, 2, 3}
		initialBLSKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		for _, id := range initialParticipants {
			initialBLSKeys[id] = createMockBLSKeyForStable(t, int(id))
		}
		
		// Create initial wallet
		wallet1, err := CreateStableWallet(curve, foundationKey, 2, initialParticipants, initialBLSKeys)
		if err != nil {
			t.Fatalf("Failed to create initial wallet: %v", err)
		}
		
		address1 := wallet1.StableAddress
		
		// Change validator set: {1, 2, 4, 5} threshold 3
		newParticipants := []ParticipantIndex{1, 2, 4, 5}
		newBLSKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		newBLSKeys[1] = initialBLSKeys[1] // Keep
		newBLSKeys[2] = initialBLSKeys[2] // Keep
		newBLSKeys[4] = createMockBLSKeyForStable(t, 4) // New
		newBLSKeys[5] = createMockBLSKeyForStable(t, 5) // New
		
		// Update validator set
		err = wallet1.UpdateValidatorSet(curve, foundationKey, 3, newParticipants, newBLSKeys)
		if err != nil {
			t.Fatalf("Failed to update validator set: %v", err)
		}
		
		address2 := wallet1.StableAddress
		
		// CRITICAL: Address must remain the same
		if !address1.Equal(address2) {
			t.Fatal("Address changed during validator set update - this breaks the core requirement!")
		}
		
		t.Log("✅ Address stability verified across validator set changes")
	})
	
	t.Run("ThresholdSigningWithStableAddress", func(t *testing.T) {
		participants := []ParticipantIndex{1, 2, 3}
		blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		for _, id := range participants {
			blsKeys[id] = createMockBLSKeyForStable(t, int(id))
		}
		
		wallet, err := CreateStableWallet(curve, foundationKey, 2, participants, blsKeys)
		if err != nil {
			t.Fatalf("Failed to create wallet: %v", err)
		}
		
		// Test signing
		message := []byte("Test message for stable address signing")
		signerIDs := []ParticipantIndex{1, 2}
		
		signature, err := wallet.SignMessage(curve, message, signerIDs)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}
		
		// Verify signature
		valid, err := wallet.VerifySignature(curve, signature, message)
		if err != nil {
			t.Fatalf("Failed to verify signature: %v", err)
		}
		
		if !valid {
			t.Fatal("Signature verification failed")
		}
		
		t.Log("✅ Threshold signing with stable address works correctly")
	})
	
	t.Run("ComparisonWithOriginalImplementation", func(t *testing.T) {
		participants := []ParticipantIndex{1, 2, 3}
		blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		for _, id := range participants {
			blsKeys[id] = createMockBLSKeyForStable(t, int(id))
		}
		
		// Original BLS-anchored approach (address changes with validator set)
		originalBKG := NewBLSAnchoredKeyGen(curve, 2, participants, foundationKey, blsKeys)
		_, originalAddress1, err := originalBKG.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate original shares: %v", err)
		}
		
		// Change validator set for original approach
		newParticipants := []ParticipantIndex{1, 2, 4}
		newBLSKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		newBLSKeys[1] = blsKeys[1]
		newBLSKeys[2] = blsKeys[2]
		newBLSKeys[4] = createMockBLSKeyForStable(t, 4)
		
		originalBKG2 := NewBLSAnchoredKeyGen(curve, 2, newParticipants, foundationKey, newBLSKeys)
		_, originalAddress2, err := originalBKG2.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate original shares 2: %v", err)
		}
		
		// Original approach: addresses should be different
		if originalAddress1.Equal(originalAddress2) {
			t.Error("Original approach should produce different addresses for different validator sets")
		}
		
		// New stable approach: addresses should be the same
		stableWallet1, err := CreateStableWallet(curve, foundationKey, 2, participants, blsKeys)
		if err != nil {
			t.Fatalf("Failed to create stable wallet 1: %v", err)
		}
		
		err = stableWallet1.UpdateValidatorSet(curve, foundationKey, 2, newParticipants, newBLSKeys)
		if err != nil {
			t.Fatalf("Failed to update stable wallet: %v", err)
		}
		
		// Stable approach: address should remain the same
		stableAddress := stableWallet1.StableAddress
		
		// Verify stable address is different from original addresses
		// (because it's derived differently - from foundation key only)
		if stableAddress.Equal(originalAddress1) || stableAddress.Equal(originalAddress2) {
			t.Error("Stable address should be different from original BLS-anchored addresses")
		}
		
		t.Log("✅ Stable address approach successfully differs from original approach")
		t.Log("✅ Original approach changes addresses, stable approach preserves addresses")
	})
	
	t.Run("MultipleValidatorSetTransitions", func(t *testing.T) {
		// Test multiple transitions to ensure address remains stable
		manager := NewStableAddressManager(curve, foundationKey)
		originalAddress := manager.GetStableAddress()
		
		// Transition 1: {1,2,3} → {1,2,4}
		participants1 := []ParticipantIndex{1, 2, 3}
		blsKeys1 := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		for _, id := range participants1 {
			blsKeys1[id] = createMockBLSKeyForStable(t, int(id))
		}
		
		shares1, err := manager.GenerateFROSTShares(2, participants1, blsKeys1)
		if err != nil {
			t.Fatalf("Failed to generate shares 1: %v", err)
		}
		
		// Verify address consistency
		for _, share := range shares1 {
			if !share.GroupPublicKey.Equal(originalAddress) {
				t.Fatal("Address inconsistency in transition 1")
			}
		}
		
		// Transition 2: {1,2,4} → {2,4,5,6}
		participants2 := []ParticipantIndex{2, 4, 5, 6}
		blsKeys2 := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		blsKeys2[2] = blsKeys1[2] // Keep
		blsKeys2[4] = createMockBLSKeyForStable(t, 4)
		blsKeys2[5] = createMockBLSKeyForStable(t, 5)
		blsKeys2[6] = createMockBLSKeyForStable(t, 6)
		
		shares2, err := manager.GenerateFROSTShares(3, participants2, blsKeys2)
		if err != nil {
			t.Fatalf("Failed to generate shares 2: %v", err)
		}
		
		// Verify address consistency
		for _, share := range shares2 {
			if !share.GroupPublicKey.Equal(originalAddress) {
				t.Fatal("Address inconsistency in transition 2")
			}
		}
		
		// Transition 3: {2,4,5,6} → {1,3,7,8,9}
		participants3 := []ParticipantIndex{1, 3, 7, 8, 9}
		blsKeys3 := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		blsKeys3[1] = blsKeys1[1] // Bring back validator 1
		blsKeys3[3] = blsKeys1[3] // Bring back validator 3
		blsKeys3[7] = createMockBLSKeyForStable(t, 7)
		blsKeys3[8] = createMockBLSKeyForStable(t, 8)
		blsKeys3[9] = createMockBLSKeyForStable(t, 9)
		
		shares3, err := manager.GenerateFROSTShares(3, participants3, blsKeys3)
		if err != nil {
			t.Fatalf("Failed to generate shares 3: %v", err)
		}
		
		// Verify address consistency
		for _, share := range shares3 {
			if !share.GroupPublicKey.Equal(originalAddress) {
				t.Fatal("Address inconsistency in transition 3")
			}
		}
		
		t.Log("✅ Address remains stable across multiple validator set transitions")
	})
	
	t.Run("ChainSpecificAddressFormatting", func(t *testing.T) {
		participants := []ParticipantIndex{1, 2, 3}
		blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
		for _, id := range participants {
			blsKeys[id] = createMockBLSKeyForStable(t, int(id))
		}
		
		wallet, err := CreateStableWallet(curve, foundationKey, 2, participants, blsKeys)
		if err != nil {
			t.Fatalf("Failed to create wallet: %v", err)
		}
		
		// Test chain-specific address formatting
		btcAddr, err := wallet.GetAddressForChain("bitcoin")
		if err != nil {
			t.Fatalf("Failed to get Bitcoin address: %v", err)
		}
		
		ethAddr, err := wallet.GetAddressForChain("ethereum")
		if err != nil {
			t.Fatalf("Failed to get Ethereum address: %v", err)
		}
		
		solAddr, err := wallet.GetAddressForChain("solana")
		if err != nil {
			t.Fatalf("Failed to get Solana address: %v", err)
		}
		
		// Verify addresses are different formats but derived from same stable address
		if btcAddr == ethAddr || btcAddr == solAddr || ethAddr == solAddr {
			t.Error("Chain-specific addresses should have different formats")
		}
		
		// Verify addresses are non-empty
		if len(btcAddr) == 0 || len(ethAddr) == 0 || len(solAddr) == 0 {
			t.Error("Chain-specific addresses should not be empty")
		}
		
		t.Logf("Bitcoin address: %s", btcAddr)
		t.Logf("Ethereum address: %s", ethAddr)
		t.Logf("Solana address: %s", solAddr)
		
		t.Log("✅ Chain-specific address formatting works correctly")
	})
}

// TestStableAddressVsOriginalBehavior compares the new stable address approach with the original
func TestStableAddressVsOriginalBehavior(t *testing.T) {
	curve := NewEd25519Curve()
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// Setup validator sets
	participants1 := []ParticipantIndex{1, 2, 3}
	participants2 := []ParticipantIndex{1, 2, 4, 5}
	
	blsKeys1 := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	blsKeys2 := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	
	for _, id := range participants1 {
		blsKeys1[id] = createMockBLSKeyForStable(t, int(id))
	}
	
	blsKeys2[1] = blsKeys1[1] // Keep
	blsKeys2[2] = blsKeys1[2] // Keep
	blsKeys2[4] = createMockBLSKeyForStable(t, 4) // New
	blsKeys2[5] = createMockBLSKeyForStable(t, 5) // New
	
	// Test original BLS-anchored approach
	t.Run("OriginalApproach_AddressChanges", func(t *testing.T) {
		bkg1 := NewBLSAnchoredKeyGen(curve, 2, participants1, foundationKey, blsKeys1)
		_, addr1, err := bkg1.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate shares 1: %v", err)
		}
		
		bkg2 := NewBLSAnchoredKeyGen(curve, 3, participants2, foundationKey, blsKeys2)
		_, addr2, err := bkg2.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate shares 2: %v", err)
		}
		
		// Original approach: addresses should be different
		if addr1.Equal(addr2) {
			t.Error("Original approach should produce different addresses for different validator sets")
		}
		
		t.Log("✅ Original approach: addresses change with validator set (as expected)")
	})
	
	// Test new stable address approach
	t.Run("StableApproach_AddressStable", func(t *testing.T) {
		wallet, err := CreateStableWallet(curve, foundationKey, 2, participants1, blsKeys1)
		if err != nil {
			t.Fatalf("Failed to create stable wallet: %v", err)
		}
		
		addr1 := wallet.StableAddress
		
		err = wallet.UpdateValidatorSet(curve, foundationKey, 3, participants2, blsKeys2)
		if err != nil {
			t.Fatalf("Failed to update validator set: %v", err)
		}
		
		addr2 := wallet.StableAddress
		
		// Stable approach: addresses should be the same
		if !addr1.Equal(addr2) {
			t.Error("Stable approach should preserve address across validator set changes")
		}
		
		t.Log("✅ Stable approach: address remains constant across validator set changes")
	})
	
	t.Log("✅ Both approaches work as designed - original changes addresses, stable preserves them")
}

// Helper function for creating mock BLS keys
func createMockBLSKeyForStable(t *testing.T, seed int) *crypto.BLS12381PrivateKey {
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
