package frost

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/canopy-network/canopy/lib/crypto"
)

// MockAuditHandler is a test implementation of AuditEventHandler
type MockAuditHandler struct {
	events                []AuditEvent
	shareRegenerations    []*ShareRegenerationEvent
	thresholdChanges      []*ThresholdChangeEvent
	validationFailures    []*ValidationFailureEvent
	validatorSetUpdates   []*AuditEvent
	configurationChanges  []*AuditEvent
	errors                []*AuditEvent
}

func NewMockAuditHandler() *MockAuditHandler {
	return &MockAuditHandler{
		events:               make([]AuditEvent, 0),
		shareRegenerations:   make([]*ShareRegenerationEvent, 0),
		thresholdChanges:     make([]*ThresholdChangeEvent, 0),
		validationFailures:   make([]*ValidationFailureEvent, 0),
		validatorSetUpdates:  make([]*AuditEvent, 0),
		configurationChanges: make([]*AuditEvent, 0),
		errors:               make([]*AuditEvent, 0),
	}
}

func (h *MockAuditHandler) OnShareRegeneration(event *ShareRegenerationEvent) {
	h.shareRegenerations = append(h.shareRegenerations, event)
	h.events = append(h.events, event.AuditEvent)
}

func (h *MockAuditHandler) OnThresholdChange(event *ThresholdChangeEvent) {
	h.thresholdChanges = append(h.thresholdChanges, event)
	h.events = append(h.events, event.AuditEvent)
}

func (h *MockAuditHandler) OnValidatorSetUpdate(event *AuditEvent) {
	h.validatorSetUpdates = append(h.validatorSetUpdates, event)
	h.events = append(h.events, *event)
}

func (h *MockAuditHandler) OnValidationFailure(event *ValidationFailureEvent) {
	h.validationFailures = append(h.validationFailures, event)
	h.events = append(h.events, event.AuditEvent)
}

func (h *MockAuditHandler) OnConfigurationChange(event *AuditEvent) {
	h.configurationChanges = append(h.configurationChanges, event)
	h.events = append(h.events, *event)
}

func (h *MockAuditHandler) OnError(event *AuditEvent) {
	h.errors = append(h.errors, event)
	h.events = append(h.events, *event)
}

func (h *MockAuditHandler) GetEventCount() int {
	return len(h.events)
}

func (h *MockAuditHandler) GetLastEvent() *AuditEvent {
	if len(h.events) == 0 {
		return nil
	}
	return &h.events[len(h.events)-1]
}

// TestAuditEventCreation tests audit event creation and serialization
func TestAuditEventCreation(t *testing.T) {
	t.Run("BasicAuditEvent", func(t *testing.T) {
		event := NewAuditEventBuilder(
			AuditEventShareRegeneration,
			ReasonValidatorSetChange,
		).WithRPWPath([]uint32{0x80000000, 0x80000001}).
			WithCurve("ed25519").
			WithThresholdChange(3, 4).
			WithParticipants([]ParticipantIndex{1, 2, 3}, []ParticipantIndex{1, 2, 3, 4}).
			WithMetadata("test_key", "test_value").
			Build()

		if event.EventType != AuditEventShareRegeneration {
			t.Errorf("Expected event type %s, got %s", AuditEventShareRegeneration, event.EventType)
		}

		if event.Reason != ReasonValidatorSetChange {
			t.Errorf("Expected reason %s, got %s", ReasonValidatorSetChange, event.Reason)
		}

		if event.OldThreshold != 3 || event.NewThreshold != 4 {
			t.Errorf("Expected threshold change 3->4, got %d->%d", event.OldThreshold, event.NewThreshold)
		}

		if len(event.OldParticipants) != 3 || len(event.NewParticipants) != 4 {
			t.Errorf("Expected participant change 3->4, got %d->%d", len(event.OldParticipants), len(event.NewParticipants))
		}

		if event.Metadata["test_key"] != "test_value" {
			t.Error("Metadata should be preserved")
		}

		if event.EventID == "" {
			t.Error("Event should have an ID")
		}

		if event.Timestamp.IsZero() {
			t.Error("Event should have a timestamp")
		}
	})

	t.Run("ShareRegenerationEvent", func(t *testing.T) {
		event := NewAuditEventBuilder(
			AuditEventShareRegeneration,
			ReasonValidatorSetChange,
		).BuildShareRegeneration("bls_anchored", time.Second*2, 5)

		if event.RegenerationType != "bls_anchored" {
			t.Errorf("Expected regeneration type bls_anchored, got %s", event.RegenerationType)
		}

		if event.Duration != time.Second*2 {
			t.Errorf("Expected duration 2s, got %v", event.Duration)
		}

		if event.SharesGenerated != 5 {
			t.Errorf("Expected 5 shares generated, got %d", event.SharesGenerated)
		}
	})

	t.Run("ThresholdChangeEvent", func(t *testing.T) {
		event := NewAuditEventBuilder(
			AuditEventThresholdChange,
			ReasonThresholdUpdate,
		).WithThresholdChange(3, 4).
			BuildThresholdChange(true, "high", true)

		if !event.ValidationPassed {
			t.Error("Validation should have passed")
		}

		if event.SecurityLevel != "high" {
			t.Errorf("Expected security level high, got %s", event.SecurityLevel)
		}

		if !event.ByzantineFaultTolerance {
			t.Error("Should have Byzantine fault tolerance")
		}
	})

	t.Run("ValidationFailureEvent", func(t *testing.T) {
		inputValues := map[string]interface{}{
			"threshold":    0,
			"participants": 5,
		}

		event := NewAuditEventBuilder(
			AuditEventValidationFailure,
			ReasonValidationError,
		).WithError(ErrInvalidThreshold).
			BuildValidationFailure("threshold", "threshold cannot be zero", inputValues)

		if event.ValidationType != "threshold" {
			t.Errorf("Expected validation type threshold, got %s", event.ValidationType)
		}

		if event.FailureReason != "threshold cannot be zero" {
			t.Errorf("Expected specific failure reason, got %s", event.FailureReason)
		}

		if event.InputValues["threshold"] != 0 {
			t.Error("Input values should be preserved")
		}
	})

	t.Run("EventSerialization", func(t *testing.T) {
		event := NewAuditEventBuilder(
			AuditEventShareRegeneration,
			ReasonValidatorSetChange,
		).WithRPWPath([]uint32{0x80000000}).
			WithCurve("ed25519").
			Build()

		// Test JSON serialization
		jsonData, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("Failed to serialize event: %v", err)
		}

		var deserializedEvent AuditEvent
		err = json.Unmarshal(jsonData, &deserializedEvent)
		if err != nil {
			t.Fatalf("Failed to deserialize event: %v", err)
		}

		if deserializedEvent.EventType != event.EventType {
			t.Error("Event type should be preserved in serialization")
		}

		if deserializedEvent.Reason != event.Reason {
			t.Error("Reason should be preserved in serialization")
		}
	})
}

// TestAuditHandler tests the audit handler interface
func TestAuditHandler(t *testing.T) {
	t.Run("MockAuditHandlerImplementation", func(t *testing.T) {
		handler := NewMockAuditHandler()

		// Test share regeneration event
		shareEvent := &ShareRegenerationEvent{
			AuditEvent: AuditEvent{
				EventType: AuditEventShareRegeneration,
				Reason:    ReasonValidatorSetChange,
				Success:   true,
			},
			RegenerationType: "bls_anchored",
			Duration:         time.Second,
			SharesGenerated:  5,
		}
		handler.OnShareRegeneration(shareEvent)

		if len(handler.shareRegenerations) != 1 {
			t.Error("Should have recorded share regeneration event")
		}

		if handler.GetEventCount() != 1 {
			t.Error("Should have recorded one event total")
		}

		// Test threshold change event
		thresholdEvent := &ThresholdChangeEvent{
			AuditEvent: AuditEvent{
				EventType:    AuditEventThresholdChange,
				Reason:       ReasonThresholdUpdate,
				OldThreshold: 3,
				NewThreshold: 4,
				Success:      true,
			},
			ValidationPassed:        true,
			SecurityLevel:           "high",
			ByzantineFaultTolerance: true,
		}
		handler.OnThresholdChange(thresholdEvent)

		if len(handler.thresholdChanges) != 1 {
			t.Error("Should have recorded threshold change event")
		}

		if handler.GetEventCount() != 2 {
			t.Error("Should have recorded two events total")
		}

		// Test validation failure event
		validationEvent := &ValidationFailureEvent{
			AuditEvent: AuditEvent{
				EventType: AuditEventValidationFailure,
				Reason:    ReasonValidationError,
				Success:   false,
				Error:     "validation failed",
			},
			ValidationType: "threshold",
			FailureReason:  "invalid threshold value",
		}
		handler.OnValidationFailure(validationEvent)

		if len(handler.validationFailures) != 1 {
			t.Error("Should have recorded validation failure event")
		}

		lastEvent := handler.GetLastEvent()
		if lastEvent == nil || lastEvent.EventType != AuditEventValidationFailure {
			t.Error("Last event should be validation failure")
		}
	})

	t.Run("NullAuditHandler", func(t *testing.T) {
		// Test that null handler doesn't panic
		handler := &NullAuditHandler{}

		// These should all be no-ops
		handler.OnShareRegeneration(&ShareRegenerationEvent{})
		handler.OnThresholdChange(&ThresholdChangeEvent{})
		handler.OnValidatorSetUpdate(&AuditEvent{})
		handler.OnValidationFailure(&ValidationFailureEvent{})
		handler.OnConfigurationChange(&AuditEvent{})
		handler.OnError(&AuditEvent{})

		// No assertions needed - just ensuring no panics
	})
}

// TestEventIDGeneration tests event ID generation
func TestEventIDGeneration(t *testing.T) {
	t.Run("UniqueEventIDs", func(t *testing.T) {
		// Generate multiple events and ensure IDs are unique
		events := make([]*AuditEvent, 10)
		for i := 0; i < 10; i++ {
			events[i] = NewAuditEventBuilder(
				AuditEventShareRegeneration,
				ReasonValidatorSetChange,
			).Build()
		}

		// Check that all IDs are unique
		ids := make(map[string]bool)
		for _, event := range events {
			if event.EventID == "" {
				t.Error("Event should have non-empty ID")
			}

			if ids[event.EventID] {
				t.Errorf("Duplicate event ID: %s", event.EventID)
			}
			ids[event.EventID] = true
		}
	})

	t.Run("EventIDFormat", func(t *testing.T) {
		event := NewAuditEventBuilder(
			AuditEventShareRegeneration,
			ReasonValidatorSetChange,
		).Build()

		// Event ID should be timestamp-based format
		if len(event.EventID) < 10 {
			t.Error("Event ID should be reasonably long timestamp-based format")
		}
	})
}

// TestRegenerationTrigger tests the regeneration trigger interface
func TestRegenerationTrigger(t *testing.T) {
	// Setup test environment
	curve := NewEd25519Curve()
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	// Create mock foundation manager
	foundationMgr := &MockFoundationKeyManager{
		curve: curve,
	}

	rpwPath := []uint32{0x80000000, 0x80000001}
	auditHandler := NewMockAuditHandler()

	trigger := NewBLSAnchoredRegenerationTrigger(curve, foundationMgr, rpwPath)

	t.Run("ValidateRegenerationRequest", func(t *testing.T) {
		// Create valid BLS keys
		blsKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForAudit(t, 1),
			2: createMockBLSKeyForAudit(t, 2),
			3: createMockBLSKeyForAudit(t, 3),
		}

		request := &RegenerationRequest{
			NewValidatorBLSKeys: blsKeys,
			NewThreshold:        2,
			NewParticipants:     []ParticipantIndex{1, 2, 3},
			Reason:              ReasonValidatorSetChange,
			ValidateOnly:        true,
			AuditHandler:        auditHandler,
		}

		result, err := trigger.ValidateRegenerationRequest(request)
		if err != nil {
			t.Fatalf("Validation should not error: %v", err)
		}

		if !result.Valid {
			t.Errorf("Valid request should pass validation: %v", result.Errors)
		}

		if result.SecurityLevel == SecurityLevelLow {
			t.Error("Valid configuration should not have low security level")
		}
	})

	t.Run("InvalidRegenerationRequest", func(t *testing.T) {
		// Test with invalid threshold
		blsKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForAudit(t, 1),
			2: createMockBLSKeyForAudit(t, 2),
		}

		request := &RegenerationRequest{
			NewValidatorBLSKeys: blsKeys,
			NewThreshold:        0, // Invalid threshold
			NewParticipants:     []ParticipantIndex{1, 2},
			Reason:              ReasonValidatorSetChange,
			ValidateOnly:        true,
			AuditHandler:        auditHandler,
		}

		result, err := trigger.ValidateRegenerationRequest(request)
		if err != nil {
			t.Fatalf("Validation should not error: %v", err)
		}

		if result.Valid {
			t.Error("Invalid request should fail validation")
		}

		if len(result.Errors) == 0 {
			t.Error("Invalid request should have error messages")
		}
	})

	t.Run("MismatchedParticipantsAndKeys", func(t *testing.T) {
		blsKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForAudit(t, 1),
			2: createMockBLSKeyForAudit(t, 2),
		}

		request := &RegenerationRequest{
			NewValidatorBLSKeys: blsKeys,
			NewThreshold:        2,
			NewParticipants:     []ParticipantIndex{1, 2, 3}, // Mismatch: 3 participants, 2 keys
			Reason:              ReasonValidatorSetChange,
			ValidateOnly:        true,
			AuditHandler:        auditHandler,
		}

		result, err := trigger.ValidateRegenerationRequest(request)
		if err != nil {
			t.Fatalf("Validation should not error: %v", err)
		}

		if result.Valid {
			t.Error("Mismatched participants and keys should fail validation")
		}
	})

	t.Run("ValidationOnlyMode", func(t *testing.T) {
		blsKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKeyForAudit(t, 1),
			2: createMockBLSKeyForAudit(t, 2),
			3: createMockBLSKeyForAudit(t, 3),
		}

		request := &RegenerationRequest{
			NewValidatorBLSKeys: blsKeys,
			NewThreshold:        2,
			NewParticipants:     []ParticipantIndex{1, 2, 3},
			Reason:              ReasonValidatorSetChange,
			ValidateOnly:        true, // Only validate, don't execute
			AuditHandler:        auditHandler,
		}

		result, err := trigger.RegenerateShares(request)
		if err != nil {
			t.Fatalf("Validation-only should not error: %v", err)
		}

		if !result.Success {
			t.Errorf("Validation-only should succeed: %v", result.Errors)
		}

		// Should not have generated shares
		if result.SharesGenerated != nil {
			t.Error("Validation-only should not generate shares")
		}

		// Validation-only mode should not emit audit events since no actual operation occurred
		// The audit events are emitted during actual regeneration, not validation
		if result.Duration == 0 {
			t.Error("Should have recorded duration even for validation-only")
		}
	})

	t.Run("GetCurrentConfiguration", func(t *testing.T) {
		config := trigger.GetCurrentConfiguration()
		if config == nil {
			t.Error("Should return current configuration")
		}

		if config.Curve != curve.Name() {
			t.Errorf("Expected curve %s, got %s", curve.Name(), config.Curve)
		}

		if len(config.RPWPath) != len(rpwPath) {
			t.Error("RPW path should match")
		}
	})
}

// MockFoundationKeyManager for testing
type MockFoundationKeyManager struct {
	curve Curve
}

func (m *MockFoundationKeyManager) DeriveRPWKey(path []uint32) (Scalar, error) {
	// Generate a new random scalar each time to avoid zeroization issues
	// In practice, this would do actual deterministic derivation
	return m.curve.ScalarRandom()
}

// Helper function to create mock BLS keys for testing
func createMockBLSKeyForAudit(t *testing.T, seed int) *crypto.BLS12381PrivateKey {
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
