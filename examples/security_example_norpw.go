//go:build !rpw

package examples

import (
	"fmt"
	"log"
	"time"

	"github.com/canopy-network/canopy/lib/frost"
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

func (h *ExampleAuditHandler) OnSecurityEvent(event *frost.AuditEvent) {
	log.Printf("AUDIT: Security event - Type: %s, Error: %s", 
		event.EventType, event.Error)
	h.events = append(h.events, *event)
}

func (h *ExampleAuditHandler) GetEvents() []frost.AuditEvent {
	return h.events
}

// ExampleSecureRPWUsage demonstrates secure usage of the enhanced FROST library
// This version provides a mock implementation when RPW is not available
func ExampleSecureRPWUsage() {
	log.Printf("ℹ️  RPW dependency not available - demonstrating FROST security framework with mock implementations")
	
	// Create audit handler
	auditHandler := NewExampleAuditHandler()
	
	// Mock committee configuration
	threshold := 3
	validatorCount := 5
	
	fmt.Printf("🔒 Security Example - Mock FROST Committee\n")
	fmt.Printf("  Threshold: %d\n", threshold)
	fmt.Printf("  Validators: %d\n", validatorCount)
	
	// Demonstrate threshold validation
	validator := frost.NewDefaultThresholdValidator()
	
	// Test various threshold configurations
	testConfigs := []struct {
		name      string
		threshold int
		total     int
		expectErr bool
	}{
		{"Valid 3-of-5", 3, 5, false},
		{"Invalid 6-of-5", 6, 5, true},
		{"Edge case 1-of-1", 1, 1, false},
		{"Invalid 0-of-3", 0, 3, true},
	}
	
	fmt.Printf("\n📊 Threshold Validation Tests:\n")
	for _, config := range testConfigs {
		result := validator.ValidateThresholdParameters(config.total, config.threshold)
		if config.expectErr && result.Valid {
			fmt.Printf("  ❌ %s: Expected error but validation passed\n", config.name)
		} else if !config.expectErr && !result.Valid {
			fmt.Printf("  ❌ %s: Unexpected validation failure: %v\n", config.name, result.Errors)
		} else {
			fmt.Printf("  ✅ %s: Validation passed\n", config.name)
		}

		// Create audit event for validation using builder
		auditEvent := frost.NewAuditEventBuilder(
			frost.AuditEventValidationFailure,
			frost.ReasonValidationError,
		).WithMetadata("test_config", config.name).
			WithMetadata("threshold", config.threshold).
			WithMetadata("total", config.total).
			Build()

		if !result.Valid {
			auditEvent.Error = fmt.Sprintf("Validation failed: %v", result.Errors)
		}
		auditHandler.OnConfigurationChange(auditEvent)
	}
	
	// Mock signing process demonstration
	fmt.Printf("\n🔐 Mock Signing Process:\n")
	message := []byte("Hello, FROST!")
	fmt.Printf("  Message: %s\n", string(message))
	
	// Simulate signing steps
	steps := []string{
		"Generating nonce commitments",
		"Collecting participant commitments", 
		"Computing binding factors",
		"Generating signature shares",
		"Combining signature shares",
		"Verifying final signature",
	}
	
	for i, step := range steps {
		fmt.Printf("  %d. %s... ✅\n", i+1, step)
		time.Sleep(10 * time.Millisecond) // Simulate processing time
		
		// Create audit event for each step
		auditEvent := frost.NewAuditEventBuilder(
			frost.AuditEventConfigurationChange,
			frost.ReasonManualTrigger,
		).WithMetadata("signing_step", step).
			WithMetadata("participant_count", threshold).
			Build()

		auditHandler.OnConfigurationChange(auditEvent)
	}
	
	fmt.Printf("  ✅ Mock signature generated successfully!\n")
	fmt.Printf("  📝 Note: This is a demonstration - no actual cryptographic operations performed\n")
	
	// Display audit events
	events := auditHandler.GetEvents()
	fmt.Printf("\n📋 Audit Events (%d total):\n", len(events))
	for i, event := range events {
		fmt.Printf("  %d. %s - %s (%s)\n", i+1, event.EventType, event.Reason, event.Timestamp.Format(time.RFC3339))
	}
	
	fmt.Printf("\n💡 To use real RPW functionality, build with: go build -tags rpw\n")
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
	
	fmt.Printf("🔍 Threshold Validation Examples:\n")
	
	// Test cases with expected results
	testCases := []struct {
		threshold int
		total     int
		desc      string
	}{
		{3, 5, "Standard 3-of-5 multisig"},
		{2, 3, "Minimal 2-of-3 setup"},
		{5, 7, "High security 5-of-7"},
		{1, 10, "Low threshold 1-of-10"},
	}
	
	for _, tc := range testCases {
		result := validator.ValidateThresholdParameters(tc.total, tc.threshold)
		if !result.Valid {
			fmt.Printf("  ❌ %s: %v\n", tc.desc, result.Errors)
		} else {
			// Calculate security metrics
			byzantineTolerance := (tc.total - 1) / 3
			securityLevel := result.SecurityLevel

			fmt.Printf("  ✅ %s: Valid (Security: %s, Byzantine tolerance: %d, BFT: %t)\n",
				tc.desc, securityLevel, byzantineTolerance, result.ByzantineFaultTolerance)
		}
	}
}
