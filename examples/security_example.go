package examples

import (
	"fmt"
	"log"
	"time"

	"github.com/canopy-network/canopy/lib/frost"
	"github.com/canopy-network/canopy/lib/crypto"
	"github.com/canopy-network/canopy/lib/rpw"
)

// ExampleAuditHandler demonstrates how to implement audit event handling
type ExampleAuditHandler struct {
	events []frost.AuditEvent
}

func NewExampleAuditHandler() *ExampleAuditHandler {
	return &ExampleAuditHandler{
		events: make([]frost.AuditEvent, 0),
	}
}

func (h *ExampleAuditHandler) OnShareRegeneration(event *frost.ShareRegenerationEvent) {
	log.Printf("AUDIT: Share regeneration - Duration: %v, Shares: %d, Success: %t", 
		event.Duration, event.SharesGenerated, event.Success)
	h.events = append(h.events, event.AuditEvent)
}

func (h *ExampleAuditHandler) OnThresholdChange(event *frost.ThresholdChangeEvent) {
	log.Printf("AUDIT: Threshold change - Old: %d, New: %d, Security: %s, Byzantine: %t", 
		event.OldThreshold, event.NewThreshold, event.SecurityLevel, event.ByzantineFaultTolerance)
	h.events = append(h.events, event.AuditEvent)
}

func (h *ExampleAuditHandler) OnValidatorSetUpdate(event *frost.AuditEvent) {
	log.Printf("AUDIT: Validator set update - Participants: %d, Reason: %s", 
		event.ParticipantCount, event.Reason)
	h.events = append(h.events, *event)
}

func (h *ExampleAuditHandler) OnValidationFailure(event *frost.ValidationFailureEvent) {
	log.Printf("AUDIT: Validation failure - Type: %s, Reason: %s, Error: %s", 
		event.ValidationType, event.FailureReason, event.Error)
	h.events = append(h.events, event.AuditEvent)
}

func (h *ExampleAuditHandler) OnConfigurationChange(event *frost.AuditEvent) {
	log.Printf("AUDIT: Configuration change - Type: %s, Reason: %s", 
		event.EventType, event.Reason)
	h.events = append(h.events, *event)
}

func (h *ExampleAuditHandler) OnError(event *frost.AuditEvent) {
	log.Printf("AUDIT: Error - Type: %s, Error: %s", 
		event.EventType, event.Error)
	h.events = append(h.events, *event)
}

func (h *ExampleAuditHandler) GetEvents() []frost.AuditEvent {
	return h.events
}

// ExampleSecureRPWUsage demonstrates secure usage of the enhanced FROST library
func ExampleSecureRPWUsage() {
	// Create audit handler
	auditHandler := NewExampleAuditHandler()
	
	// Example BLS keys (in practice, these would come from your validator system)
	validatorBLSKeys := map[frost.ParticipantIndex]interface{}{
		1: generateExampleBLSKey(1),
		2: generateExampleBLSKey(2),
		3: generateExampleBLSKey(3),
		4: generateExampleBLSKey(4),
		5: generateExampleBLSKey(5),
	}
	
	// Create foundation key manager
	curve := frost.NewSecp256k1Curve() // Example curve
	foundationMgr := rpw.NewFoundationKeyManager(
		curve,
		[]byte("example_genesis_hash"),
		12345, // chain ID
	)

	// Create secure RPW committee with audit handler
	rpwPath := []uint32{0x80000000, 0x80000001} // Hardened derivation path
	threshold := 3

	// Create BLS keys map with proper type
	blsKeys := make(map[frost.ParticipantIndex]*crypto.BLS12381PrivateKey)
	for id := range validatorBLSKeys {
		// Create a real BLS key for demo
		key, err := crypto.NewBLS12381PrivateKey()
		if err != nil {
			log.Fatalf("Failed to create BLS key: %v", err)
		}
		blsKeys[id] = key.(*crypto.BLS12381PrivateKey)
	}

	committee, err := rpw.NewCanopyRPWCommittee(
		curve,
		foundationMgr,
		rpwPath,
		threshold,
		blsKeys,
	)
	if err != nil {
		log.Fatalf("Failed to create committee: %v", err)
	}

	// Register the audit handler with the committee
	committee.SetAuditHandler(auditHandler)

	// Initialize the committee
	err = committee.InitializeFromBLS()
	if err != nil {
		log.Fatalf("Failed to initialize committee: %v", err)
	}
	
	fmt.Printf("✅ RPW committee initialized successfully\n")
	fmt.Printf("  Threshold: %d\n", threshold)
	fmt.Printf("  Validators: %d\n", len(validatorBLSKeys))

	// Get group public key
	groupPubKey, err := committee.GetGroupPublicKey()
	if err != nil {
		log.Printf("Failed to get group public key: %v", err)
	} else {
		fmt.Printf("  Group Public Key: %s\n", groupPubKey.String()[:16]+"...")
	}
	
	// Example: Create a simple message to sign
	message := []byte("Hello, FROST!")
	signers := []frost.ParticipantIndex{1, 2, 3} // Use first 3 validators

	fmt.Printf("\n📝 Signing Example:\n")
	fmt.Printf("  Message: %s\n", string(message))
	fmt.Printf("  Signers: %v\n", signers)

	// Sign the message
	signature, err := committee.SignMessage(message, signers)
	if err != nil {
		log.Printf("Signing failed: %v", err)
	} else {
		fmt.Printf("✅ Message signed successfully!\n")
		fmt.Printf("  Signature R: %s\n", signature.R.String()[:16]+"...")
		fmt.Printf("  Signature S: %s\n", signature.S.String()[:16]+"...")
	}

	// Display audit events
	events := auditHandler.GetEvents()
	fmt.Printf("\nAudit Events (%d total):\n", len(events))
	for i, event := range events {
		fmt.Printf("  %d. %s - %s (%s)\n", i+1, event.EventType, event.Reason, event.Timestamp.Format(time.RFC3339))
	}
}

// generateExampleBLSKey generates an example BLS key for demonstration
// In practice, these would come from your actual validator key management system
func generateExampleBLSKey(seed int) interface{} {
	// This is just for example - in practice, use proper key generation
	// Return a mock key or generate a real one based on your crypto library
	return fmt.Sprintf("mock_bls_key_%d", seed) // Placeholder
}

// ExampleThresholdValidation demonstrates threshold validation
func ExampleThresholdValidation() {
	validator := frost.NewDefaultThresholdValidator()
	
	// Test various threshold configurations
	testCases := []struct {
		participants int
		threshold    int
		description  string
	}{
		{5, 3, "Standard 3-of-5 configuration"},
		{7, 5, "High security 5-of-7 configuration"},
		{3, 2, "Minimal 2-of-3 configuration"},
		{10, 7, "Large committee 7-of-10 configuration"},
		{5, 1, "Low security 1-of-5 configuration"},
		{5, 5, "No fault tolerance 5-of-5 configuration"},
	}
	
	fmt.Printf("Threshold Validation Examples:\n\n")
	
	for _, tc := range testCases {
		result := validator.ValidateThresholdParameters(tc.participants, tc.threshold)
		
		fmt.Printf("%s (%d-of-%d):\n", tc.description, tc.threshold, tc.participants)
		fmt.Printf("  Valid: %t\n", result.Valid)
		fmt.Printf("  Security Level: %s\n", result.SecurityLevel)
		fmt.Printf("  Byzantine Fault Tolerance: %t\n", result.ByzantineFaultTolerance)
		
		if len(result.Errors) > 0 {
			fmt.Printf("  Errors: %v\n", result.Errors)
		}
		if len(result.Warnings) > 0 {
			fmt.Printf("  Warnings: %v\n", result.Warnings)
		}
		if len(result.Recommendations) > 0 {
			fmt.Printf("  Recommendations: %v\n", result.Recommendations)
		}
		fmt.Printf("\n")
	}
}
