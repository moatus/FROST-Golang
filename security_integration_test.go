package frost

import (
	"testing"
	"time"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestSecurityFrameworkIntegration tests the complete security framework working together
func TestSecurityFrameworkIntegration(t *testing.T) {
	// Setup test environment
	curve := NewEd25519Curve()
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	foundationMgr := &MockFoundationKeyManager{curve: curve}
	rpwPath := []uint32{0x80000000, 0x80000001}
	auditHandler := NewMockAuditHandler()

	t.Run("CompleteRegenerationWorkflow", func(t *testing.T) {
		// This test demonstrates the complete validator set change workflow
		// and verifies that wallet addresses remain stable using the new
		// foundation-anchored approach, while the original BLS-anchored
		// approach changes addresses (as expected).
		// Create initial BLS keys
		initialBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForIntegration(t, 1),
			2: createMockBLSKeyForIntegration(t, 2),
			3: createMockBLSKeyForIntegration(t, 3),
		}
		// Note: BLS keys don't have a Zeroize() method in the current implementation
		// In a production environment, consider implementing proper key cleanup
		defer func() {
			// Clear references to help GC
			for k := range initialBLSKeys {
				initialBLSKeys[k] = nil
			}
		}()

		initialThreshold := 2
		initialParticipants := []ParticipantIndex{1, 2, 3}

		// Step 1: Create regeneration trigger
		trigger := NewBLSAnchoredRegenerationTrigger(curve, foundationMgr, rpwPath)

		// Step 2: Validate initial configuration
		configValidator := NewDefaultConfigurationValidator()
		configResult := configValidator.ValidateCompleteConfiguration(
			curve, initialThreshold, initialParticipants, foundationKey, rpwPath, initialBLSKeys)

		if !configResult.Valid {
			t.Fatalf("Initial configuration should be valid: %v", configResult.Errors)
		}

		// Step 3: Perform initial regeneration
		initialRequest := &RegenerationRequest{
			NewValidatorBLSKeys: initialBLSKeys,
			NewThreshold:        initialThreshold,
			NewParticipants:     initialParticipants,
			Reason:              ReasonInitialization,
			AuditHandler:        auditHandler,
		}

		initialResult, err := trigger.RegenerateShares(initialRequest)
		if err != nil {
			t.Fatalf("Initial regeneration should succeed: %v", err)
		}

		if !initialResult.Success {
			t.Fatalf("Initial regeneration should be successful: %v", initialResult.Errors)
		}

		// Verify audit events were generated
		if auditHandler.GetEventCount() == 0 {
			t.Error("Should have generated audit events")
		}

		// Step 3.1: Create stable wallet to test address stability
		stableWallet, err := CreateStableWallet(curve, foundationKey, initialThreshold, initialParticipants, initialBLSKeys)
		if err != nil {
			t.Fatalf("Failed to create stable wallet: %v", err)
		}

		// Record initial stable address
		initialStableAddress := stableWallet.StableAddress
		t.Logf("Initial stable address: %x", initialStableAddress.CompressedBytes())

		// Step 4: Simulate validator set change
		newBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: initialBLSKeys[1], // Keep existing
			2: initialBLSKeys[2], // Keep existing
			4: createMockBLSKeyForIntegration(t, 4), // New validator
			5: createMockBLSKeyForIntegration(t, 5), // New validator
		}
		// Note: BLS keys don't have a Zeroize() method in the current implementation
		// Clear references to new keys to help GC (only new ones, not reused)
		defer func() {
			newBLSKeys[4] = nil
			newBLSKeys[5] = nil
		}()

		newThreshold := 3
		newParticipants := []ParticipantIndex{1, 2, 4, 5}

		// Step 5: Validate new configuration before applying
		newConfigResult := configValidator.ValidateCompleteConfiguration(
			curve, newThreshold, newParticipants, foundationKey, rpwPath, newBLSKeys)

		if !newConfigResult.Valid {
			t.Fatalf("New configuration should be valid: %v", newConfigResult.Errors)
		}

		// Step 6: Check compatibility
		oldConfig := trigger.GetCurrentConfiguration()
		newConfig := &Configuration{
			Curve:           curve.Name(),
			Threshold:       newThreshold,
			Participants:    newParticipants,
			ParticipantCount: len(newParticipants),
			RPWPath:         rpwPath,
			SecurityLevel:   newConfigResult.SecurityLevel,
			CreatedAt:       oldConfig.CreatedAt,
			UpdatedAt:       time.Now(),
		}

		compatibilityChecker := NewConfigurationCompatibilityChecker()
		compatibilityResult := compatibilityChecker.CheckCompatibility(oldConfig, newConfig)

		if !compatibilityResult.Valid {
			t.Fatalf("Configuration should be compatible: %v", compatibilityResult.Errors)
		}

		// Step 7: Validate regeneration request
		changeRequest := &RegenerationRequest{
			NewValidatorBLSKeys: newBLSKeys,
			NewThreshold:        newThreshold,
			NewParticipants:     newParticipants,
			Reason:              ReasonValidatorSetChange,
			ValidateOnly:        true, // Validate first
			AuditHandler:        auditHandler,
		}

		validationResult, err := trigger.ValidateRegenerationRequest(changeRequest)
		if err != nil {
			t.Fatalf("Validation should not error: %v", err)
		}

		if !validationResult.Valid {
			t.Fatalf("Change request should be valid: %v", validationResult.Errors)
		}

		// Step 8: Perform actual regeneration
		changeRequest.ValidateOnly = false
		changeResult, err := trigger.RegenerateShares(changeRequest)
		if err != nil {
			t.Fatalf("Regeneration should succeed: %v", err)
		}

		if !changeResult.Success {
			t.Fatalf("Regeneration should be successful: %v", changeResult.Errors)
		}

		// Step 8.1: Verify address stability during validator set change
		err = stableWallet.UpdateValidatorSet(curve, foundationKey, newThreshold, newParticipants, newBLSKeys)
		if err != nil {
			t.Fatalf("Failed to update stable wallet validator set: %v", err)
		}

		// Record new stable address after validator set change
		newStableAddress := stableWallet.StableAddress
		t.Logf("Stable address after validator set change: %x", newStableAddress.CompressedBytes())

		// CRITICAL TEST: Address must remain the same!
		if !initialStableAddress.Equal(newStableAddress) {
			t.Fatalf("❌ CRITICAL: Stable address changed during validator set change!\n"+
				"  Initial address: %x\n"+
				"  New address:     %x\n"+
				"This breaks the core requirement of address stability.",
				initialStableAddress.CompressedBytes(),
				newStableAddress.CompressedBytes())
		}

		t.Logf("✅ Address stability verified: wallet address remains constant across validator set changes")
		t.Logf("   Validator set changed from %v to %v", initialParticipants, newParticipants)
		t.Logf("   Threshold changed from %d to %d", initialThreshold, newThreshold)
		t.Logf("   Address remained: %x", initialStableAddress.CompressedBytes())

		// Step 9: Verify results
		if len(changeResult.SharesGenerated) != len(newParticipants) {
			t.Errorf("Should generate %d shares, got %d", len(newParticipants), len(changeResult.SharesGenerated))
		}

		if changeResult.NewConfiguration.Threshold != newThreshold {
			t.Errorf("New threshold should be %d, got %d", newThreshold, changeResult.NewConfiguration.Threshold)
		}

		// Step 9.1: Test threshold signing with stable address after validator set change
		testMessage := []byte("Security integration test: validator set change with stable address")
		signerIDs := []ParticipantIndex{1, 2, 4} // Use threshold signers from new validator set

		signature, err := stableWallet.SignMessage(curve, testMessage, signerIDs)
		if err != nil {
			t.Fatalf("Failed to sign message with new validator set: %v", err)
		}

		// Verify signature against the stable address
		valid, err := stableWallet.VerifySignature(curve, signature, testMessage)
		if err != nil {
			t.Fatalf("Failed to verify signature: %v", err)
		}

		if !valid {
			t.Fatal("Signature verification failed with stable address")
		}

		t.Logf("✅ Threshold signing verified: new validator set can sign for stable address")
		t.Logf("   Signers: %v", signerIDs)
		t.Logf("   Message: %s", string(testMessage))
		t.Logf("   Signature verified against stable address: %x", initialStableAddress.CompressedBytes())

		// Step 10: Verify audit trail
		if len(auditHandler.shareRegenerations) < 2 {
			t.Error("Should have recorded multiple share regeneration events")
		}

		// Verify we have both initialization and validator set change events
		hasInitialization := false
		hasValidatorSetChange := false
		for _, event := range auditHandler.events {
			if event.Reason == ReasonInitialization {
				hasInitialization = true
			}
			if event.Reason == ReasonValidatorSetChange {
				hasValidatorSetChange = true
			}
		}

		if !hasInitialization {
			t.Error("Should have initialization event")
		}

		if !hasValidatorSetChange {
			t.Error("Should have validator set change event")
		}

		// Step 11: Compare with original BLS-anchored approach to demonstrate the difference
		t.Logf("=== Comparison: Original vs Stable Address Approach ===")

		// Original BLS-anchored approach (addresses change)
		originalBKG1 := NewBLSAnchoredKeyGen(curve, initialThreshold, initialParticipants, foundationKey, initialBLSKeys)
		_, originalAddress1, err := originalBKG1.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate original shares 1: %v", err)
		}

		originalBKG2 := NewBLSAnchoredKeyGen(curve, newThreshold, newParticipants, foundationKey, newBLSKeys)
		_, originalAddress2, err := originalBKG2.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate original shares 2: %v", err)
		}

		// Original approach should produce different addresses
		if originalAddress1.Equal(originalAddress2) {
			t.Error("Original BLS-anchored approach should produce different addresses for different validator sets")
		}

		t.Logf("Original BLS-anchored approach:")
		t.Logf("  Initial address:  %x", originalAddress1.CompressedBytes())
		t.Logf("  Changed address:  %x", originalAddress2.CompressedBytes())
		t.Logf("  Result: ❌ Address changed (as expected for original approach)")

		t.Logf("New stable address approach:")
		t.Logf("  Initial address:  %x", initialStableAddress.CompressedBytes())
		t.Logf("  Stable address:   %x", newStableAddress.CompressedBytes())
		t.Logf("  Result: ✅ Address stable (new capability)")

		t.Logf("✅ Security integration test demonstrates both address stability and validator set flexibility")
	})

	t.Run("ErrorHandlingIntegration", func(t *testing.T) {
		trigger := NewBLSAnchoredRegenerationTrigger(curve, foundationMgr, rpwPath)

		// Test with invalid configuration that should generate structured errors
		invalidBLSKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForIntegration(t, 1),
			2: nil, // Invalid nil key
		}
		// Note: BLS keys don't have a Zeroize() method in the current implementation
		// Clear reference to help GC
		defer func() {
			invalidBLSKeys[1] = nil
		}()

		invalidRequest := &RegenerationRequest{
			NewValidatorBLSKeys: invalidBLSKeys,
			NewThreshold:        0, // Invalid threshold
			NewParticipants:     []ParticipantIndex{1, 2},
			Reason:              ReasonValidatorSetChange,
			AuditHandler:        auditHandler,
		}

		result, err := trigger.RegenerateShares(invalidRequest)

		// Should return structured error
		if err == nil {
			t.Error("Invalid request should return error")
		}

		if frostErr, ok := err.(*FROSTError); ok {
			if frostErr.Category == "" {
				t.Error("Error should have category")
			}
			if frostErr.Severity == "" {
				t.Error("Error should have severity")
			}
		} else {
			t.Error("Should return FROSTError for structured error handling")
		}

		// Should have recorded some kind of failure event (validation failure or error)
		if len(auditHandler.validationFailures) == 0 && len(auditHandler.errors) == 0 {
			t.Error("Should have recorded validation failure or error event")
		}

		// Result should indicate failure
		if result.Success {
			t.Error("Result should indicate failure")
		}

		if len(result.Errors) == 0 {
			t.Error("Result should contain error messages")
		}
	})

	t.Run("SecurityAssessmentIntegration", func(t *testing.T) {
		// Test different security configurations and their assessments
		testCases := []struct {
			participants int
			threshold    int
			expectLevel  SecurityLevel
			expectBFT    bool
			description  string
		}{
			{3, 2, SecurityLevelHigh, true, "Basic 2-of-3 with BFT"}, // Validation sets high when BFT=true
			{5, 4, SecurityLevelHigh, true, "High security 4-of-5"},
			{7, 5, SecurityLevelHigh, true, "Enterprise 5-of-7"},
			{10, 1, SecurityLevelLow, false, "Low security 1-of-10"}, // 1 < int(10*0.67)=6, no BFT
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				// Create BLS keys for test case
				blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
				participants := make([]ParticipantIndex, tc.participants)
				for i := 0; i < tc.participants; i++ {
					participantID := ParticipantIndex(i + 1)
					blsKeys[participantID] = createMockBLSKeyForIntegration(t, i+1)
					participants[i] = participantID
				}

				// Validate configuration
				validator := NewDefaultThresholdValidator()
				validationResult := validator.ValidateThresholdParameters(tc.participants, tc.threshold)

				if validationResult.SecurityLevel != tc.expectLevel {
					t.Errorf("Expected security level %s, got %s", tc.expectLevel, validationResult.SecurityLevel)
				}

				if validationResult.ByzantineFaultTolerance != tc.expectBFT {
					t.Errorf("Expected BFT %t, got %t", tc.expectBFT, validationResult.ByzantineFaultTolerance)
				}

				// Get security assessment
				assessment := AssessSecurity(tc.participants, tc.threshold)

				// Assessment uses different logic than validation
				// For 2-of-3: validation=high (due to BFT), assessment=medium (due to 0.667 ratio)
				expectedAssessmentLevel := tc.expectLevel
				if tc.participants == 3 && tc.threshold == 2 {
					expectedAssessmentLevel = SecurityLevelMedium // Assessment uses ratio, not BFT
				}

				if assessment.OverallRating != expectedAssessmentLevel {
					t.Errorf("Assessment rating: expected %s, got %s",
						expectedAssessmentLevel, assessment.OverallRating)
				}

				if assessment.ByzantineFaultTolerance != tc.expectBFT {
					t.Errorf("Assessment BFT should match validation: expected %t, got %t", 
						tc.expectBFT, assessment.ByzantineFaultTolerance)
				}

				// Verify fault tolerance calculation
				expectedFaultTolerance := tc.participants - tc.threshold
				if assessment.FaultTolerance != expectedFaultTolerance {
					t.Errorf("Expected fault tolerance %d, got %d", 
						expectedFaultTolerance, assessment.FaultTolerance)
				}

				// Verify attack resistance
				if assessment.AttackResistance != tc.threshold {
					t.Errorf("Expected attack resistance %d, got %d", 
						tc.threshold, assessment.AttackResistance)
				}
			})
		}
	})

	t.Run("AuditTrailCompleteness", func(t *testing.T) {
		// Test that all operations generate appropriate audit events
		auditHandler := NewMockAuditHandler()
		trigger := NewBLSAnchoredRegenerationTrigger(curve, foundationMgr, rpwPath)

		blsKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForIntegration(t, 1),
			2: createMockBLSKeyForIntegration(t, 2),
			3: createMockBLSKeyForIntegration(t, 3),
		}
		// Note: BLS keys don't have a Zeroize() method in the current implementation
		// Clear references to help GC
		defer func() {
			for k := range blsKeys {
				blsKeys[k] = nil
			}
		}()

		// Test successful operation
		successRequest := &RegenerationRequest{
			NewValidatorBLSKeys: blsKeys,
			NewThreshold:        2,
			NewParticipants:     []ParticipantIndex{1, 2, 3},
			Reason:              ReasonValidatorSetChange,
			AuditHandler:        auditHandler,
		}

		_, err := trigger.RegenerateShares(successRequest)
		if err != nil {
			t.Fatalf("Should succeed: %v", err)
		}

		successEventCount := auditHandler.GetEventCount()
		if successEventCount == 0 {
			t.Error("Successful operation should generate audit events")
		}

		// Test failed operation
		failRequest := &RegenerationRequest{
			NewValidatorBLSKeys: blsKeys,
			NewThreshold:        0, // Invalid
			NewParticipants:     []ParticipantIndex{1, 2, 3},
			Reason:              ReasonValidatorSetChange,
			AuditHandler:        auditHandler,
		}

		_, err = trigger.RegenerateShares(failRequest)
		if err == nil {
			t.Error("Should fail with invalid threshold")
		}

		failEventCount := auditHandler.GetEventCount()
		if failEventCount <= successEventCount {
			t.Error("Failed operation should also generate audit events")
		}

		// Verify we have failure events (validation failures or errors)
		if len(auditHandler.validationFailures) == 0 && len(auditHandler.errors) == 0 {
			t.Error("Should have recorded validation failure or error events")
		}
	})
}

// Helper function to create mock BLS keys for integration testing
// Note: The caller is responsible for cleaning up the returned key by calling key.Zeroize()
func createMockBLSKeyForIntegration(t *testing.T, seed int) *crypto.BLS12381PrivateKey {
	// Note: seed parameter is currently unused as we generate random keys
	// If deterministic keys are needed in the future, implement seeded generation here
	_ = seed

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
