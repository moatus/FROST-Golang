package main

import (
	"fmt"
	"log"

	"github.com/canopy-network/canopy/lib/crypto"
	"path/to/frost" // Replace with actual import path
)

// ExampleStableAddressWorkflow demonstrates the complete stable address solution
func ExampleStableAddressWorkflow() {
	fmt.Println("=== FROST Stable Address Example ===")
	
	// Setup
	curve := frost.NewEd25519Curve()
	
	// 1. Create foundation key (derived from RPW in practice)
	fmt.Println("\n1. Creating foundation key...")
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		log.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// 2. Initial validator set: {1, 2, 3} with threshold 2
	fmt.Println("\n2. Setting up initial validator set {1, 2, 3}...")
	initialThreshold := 2
	initialParticipants := []frost.ParticipantIndex{1, 2, 3}
	
	initialBLSKeys := make(map[frost.ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, participantID := range initialParticipants {
		blsKey := createExampleBLSKey(int(participantID))
		initialBLSKeys[participantID] = blsKey
	}
	
	// 3. Create stable wallet
	fmt.Println("\n3. Creating stable wallet...")
	wallet, err := frost.CreateStableWallet(
		curve,
		foundationKey,
		initialThreshold,
		initialParticipants,
		initialBLSKeys,
	)
	if err != nil {
		log.Fatalf("Failed to create stable wallet: %v", err)
	}
	
	// 4. Display stable address
	stableAddress := wallet.StableAddress
	fmt.Printf("Stable Address: %x\n", stableAddress.CompressedBytes())
	
	// Get chain-specific addresses
	btcAddr, _ := wallet.GetAddressForChain("bitcoin")
	ethAddr, _ := wallet.GetAddressForChain("ethereum")
	solAddr, _ := wallet.GetAddressForChain("solana")
	
	fmt.Printf("Bitcoin Address: %s\n", btcAddr)
	fmt.Printf("Ethereum Address: %s\n", ethAddr)
	fmt.Printf("Solana Address: %s\n", solAddr)
	
	// 5. Test initial signing
	fmt.Println("\n4. Testing initial threshold signing...")
	message := []byte("Initial transaction from stable address")
	signerIDs := []frost.ParticipantIndex{1, 2} // Use threshold signers
	
	signature1, err := wallet.SignMessage(curve, message, signerIDs)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	
	valid1, err := wallet.VerifySignature(curve, signature1, message)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	
	if !valid1 {
		log.Fatal("Initial signature verification failed")
	}
	fmt.Println("✅ Initial signing successful")
	
	// 6. Simulate validator set change: {1, 2, 4, 5} (3 leaves, 4&5 join)
	fmt.Println("\n5. Changing validator set to {1, 2, 4, 5}...")
	newThreshold := 3
	newParticipants := []frost.ParticipantIndex{1, 2, 4, 5}
	
	newBLSKeys := make(map[frost.ParticipantIndex]*crypto.BLS12381PrivateKey)
	// Keep existing validators
	newBLSKeys[1] = initialBLSKeys[1]
	newBLSKeys[2] = initialBLSKeys[2]
	// Add new validators
	newBLSKeys[4] = createExampleBLSKey(4)
	newBLSKeys[5] = createExampleBLSKey(5)
	
	// 7. Update validator set
	err = wallet.UpdateValidatorSet(
		curve,
		foundationKey,
		newThreshold,
		newParticipants,
		newBLSKeys,
	)
	if err != nil {
		log.Fatalf("Failed to update validator set: %v", err)
	}
	
	// 8. Verify address hasn't changed
	newStableAddress := wallet.StableAddress
	if !stableAddress.Equal(newStableAddress) {
		log.Fatal("❌ CRITICAL: Stable address changed during validator set update!")
	}
	fmt.Println("✅ Address stability verified: address unchanged after validator set change")
	
	// 9. Test signing with new validator set
	fmt.Println("\n6. Testing signing with new validator set...")
	message2 := []byte("Transaction after validator set change")
	newSignerIDs := []frost.ParticipantIndex{1, 2, 4} // Use new threshold signers
	
	signature2, err := wallet.SignMessage(curve, message2, newSignerIDs)
	if err != nil {
		log.Fatalf("Failed to sign with new validator set: %v", err)
	}
	
	valid2, err := wallet.VerifySignature(curve, signature2, message2)
	if err != nil {
		log.Fatalf("Failed to verify signature from new validator set: %v", err)
	}
	
	if !valid2 {
		log.Fatal("New validator set signature verification failed")
	}
	fmt.Println("✅ New validator set signing successful")
	
	// 10. Demonstrate that both signatures verify against the same stable address
	fmt.Println("\n7. Verifying both signatures against stable address...")
	
	// Create a fresh manager to verify address derivation
	manager := frost.NewStableAddressManager(curve, foundationKey)
	verificationAddress := manager.GetStableAddress()
	
	if !verificationAddress.Equal(stableAddress) {
		log.Fatal("Address derivation inconsistency")
	}
	
	// Verify both signatures against the stable address
	valid1Check, _ := frost.VerifySignature(curve, signature1, verificationAddress, message)
	valid2Check, _ := frost.VerifySignature(curve, signature2, verificationAddress, message2)
	
	if !valid1Check || !valid2Check {
		log.Fatal("Signature verification against stable address failed")
	}
	
	fmt.Println("✅ Both signatures verify against the same stable address")
	
	// 11. Summary
	fmt.Println("\n=== SUMMARY ===")
	fmt.Printf("Stable Address: %x\n", stableAddress.CompressedBytes())
	fmt.Printf("Initial Validator Set: %v (threshold %d)\n", initialParticipants, initialThreshold)
	fmt.Printf("Updated Validator Set: %v (threshold %d)\n", newParticipants, newThreshold)
	fmt.Println("✅ Address remained stable across validator set changes")
	fmt.Println("✅ Threshold signing works with both validator sets")
	fmt.Println("✅ All signatures verify against the same stable address")
	
	fmt.Println("\n🎉 Stable address solution working correctly!")
}

// ExampleValidatorSetTransition demonstrates a realistic validator set transition
func ExampleValidatorSetTransition() {
	fmt.Println("\n=== Validator Set Transition Example ===")
	
	curve := frost.NewEd25519Curve()
	
	// Foundation key (from RPW)
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		log.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()
	
	// Create stable address manager
	manager := frost.NewStableAddressManager(curve, foundationKey)
	stableAddress := manager.GetStableAddress()
	
	fmt.Printf("Stable Address: %x\n", stableAddress.CompressedBytes())
	
	// Scenario: 5 validators initially, 2 leave, 1 joins
	fmt.Println("\nScenario: 5 validators → 2 leave, 1 joins → 4 validators")
	
	// Initial: {1, 2, 3, 4, 5} threshold 3
	initialValidators := []frost.ParticipantIndex{1, 2, 3, 4, 5}
	initialBLSKeys := make(map[frost.ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, id := range initialValidators {
		initialBLSKeys[id] = createExampleBLSKey(int(id))
	}
	
	initialShares, err := manager.GenerateFROSTShares(3, initialValidators, initialBLSKeys)
	if err != nil {
		log.Fatalf("Failed to generate initial shares: %v", err)
	}
	
	fmt.Printf("Initial validator set: %v\n", initialValidators)
	fmt.Printf("Initial shares generated: %d\n", len(initialShares))
	
	// Transition: validators 3 and 5 leave, validator 6 joins
	// New set: {1, 2, 4, 6} threshold 3
	newValidators := []frost.ParticipantIndex{1, 2, 4, 6}
	newBLSKeys := make(map[frost.ParticipantIndex]*crypto.BLS12381PrivateKey)
	
	// Keep continuing validators
	newBLSKeys[1] = initialBLSKeys[1]
	newBLSKeys[2] = initialBLSKeys[2]
	newBLSKeys[4] = initialBLSKeys[4]
	// Add new validator
	newBLSKeys[6] = createExampleBLSKey(6)
	
	newShares, err := manager.GenerateFROSTShares(3, newValidators, newBLSKeys)
	if err != nil {
		log.Fatalf("Failed to generate new shares: %v", err)
	}
	
	fmt.Printf("New validator set: %v\n", newValidators)
	fmt.Printf("New shares generated: %d\n", len(newShares))
	
	// Verify address consistency
	for _, share := range newShares {
		if !share.GroupPublicKey.Equal(stableAddress) {
			log.Fatal("Address consistency check failed")
		}
	}
	
	fmt.Println("✅ Address consistency maintained across transition")
	
	// Verify continuing validators have different shares (due to new polynomial)
	if initialShares[1].SecretShare.Equal(newShares[1].SecretShare) {
		log.Fatal("Validator 1 should have different share after transition")
	}
	
	fmt.Println("✅ Shares properly regenerated for new validator set")
}

// Helper function to create example BLS keys
func createExampleBLSKey(seed int) *crypto.BLS12381PrivateKey {
	// In practice, this would be your actual BLS key generation
	key, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		log.Fatalf("Failed to create BLS key: %v", err)
	}
	
	blsKey, ok := key.(*crypto.BLS12381PrivateKey)
	if !ok {
		log.Fatal("Failed to cast to BLS12381PrivateKey")
	}
	
	return blsKey
}

func main() {
	ExampleStableAddressWorkflow()
	ExampleValidatorSetTransition()
}
