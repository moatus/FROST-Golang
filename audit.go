package frost

import (
	"crypto/rand"
	"fmt"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Share regeneration events
	AuditEventShareRegeneration AuditEventType = "share_regeneration"
	AuditEventThresholdChange   AuditEventType = "threshold_change"
	AuditEventValidatorSetUpdate AuditEventType = "validator_set_update"
	
	// Configuration events
	AuditEventConfigurationChange AuditEventType = "configuration_change"
	AuditEventInitialization     AuditEventType = "initialization"
	
	// Error events
	AuditEventValidationFailure AuditEventType = "validation_failure"
	AuditEventRegenerationFailure AuditEventType = "regeneration_failure"
)

// AuditEventReason represents why an event occurred
type AuditEventReason string

const (
	ReasonValidatorSetChange AuditEventReason = "validator_set_change"
	ReasonEpochTimeout      AuditEventReason = "epoch_timeout"
	ReasonThresholdUpdate   AuditEventReason = "threshold_update"
	ReasonManualTrigger     AuditEventReason = "manual_trigger"
	ReasonInitialization    AuditEventReason = "initialization"
	ReasonRecovery          AuditEventReason = "recovery"
	ReasonValidationError   AuditEventReason = "validation_error"
)

// AuditEvent represents a single audit event in the FROST library
type AuditEvent struct {
	// Event metadata
	EventID   string         `json:"event_id"`
	Timestamp time.Time      `json:"timestamp"`
	EventType AuditEventType `json:"event_type"`
	Reason    AuditEventReason `json:"reason"`
	
	// Context information
	RPWPath      []uint32 `json:"rpw_path,omitempty"`
	CurveName    string   `json:"curve_name,omitempty"`
	
	// Threshold information
	OldThreshold int `json:"old_threshold,omitempty"`
	NewThreshold int `json:"new_threshold,omitempty"`
	
	// Participant information
	OldParticipants []ParticipantIndex `json:"old_participants,omitempty"`
	NewParticipants []ParticipantIndex `json:"new_participants,omitempty"`
	ParticipantCount int               `json:"participant_count,omitempty"`
	
	// Success/failure information
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	
	// Additional context
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ShareRegenerationEvent contains details about share regeneration
type ShareRegenerationEvent struct {
	AuditEvent
	
	// Regeneration-specific fields
	RegenerationType string `json:"regeneration_type"` // "bls_anchored", "deterministic", etc.
	Duration         time.Duration `json:"duration"`
	SharesGenerated  int    `json:"shares_generated"`
}

// ThresholdChangeEvent contains details about threshold changes
type ThresholdChangeEvent struct {
	AuditEvent
	
	// Threshold-specific validation results
	ValidationPassed bool   `json:"validation_passed"`
	SecurityLevel    string `json:"security_level"` // "low", "medium", "high"
	ByzantineFaultTolerance bool `json:"byzantine_fault_tolerance"`
}

// ValidationFailureEvent contains details about validation failures
type ValidationFailureEvent struct {
	AuditEvent
	
	// Validation-specific fields
	ValidationType string `json:"validation_type"` // "threshold", "participant", "configuration"
	FailureReason  string `json:"failure_reason"`
	InputValues    map[string]interface{} `json:"input_values,omitempty"`
}

// AuditEventHandler defines the interface for handling audit events
// Applications implement this interface to record events according to their needs
type AuditEventHandler interface {
	// OnShareRegeneration is called when shares are regenerated
	OnShareRegeneration(event *ShareRegenerationEvent)
	
	// OnThresholdChange is called when threshold parameters change
	OnThresholdChange(event *ThresholdChangeEvent)
	
	// OnValidatorSetUpdate is called when the validator set changes
	OnValidatorSetUpdate(event *AuditEvent)
	
	// OnValidationFailure is called when validation fails
	OnValidationFailure(event *ValidationFailureEvent)
	
	// OnConfigurationChange is called when configuration changes
	OnConfigurationChange(event *AuditEvent)
	
	// OnError is called for general error events
	OnError(event *AuditEvent)
}

// NullAuditHandler is a no-op implementation of AuditEventHandler
// Used when no audit handling is needed
type NullAuditHandler struct{}

func (n *NullAuditHandler) OnShareRegeneration(event *ShareRegenerationEvent) {}
func (n *NullAuditHandler) OnThresholdChange(event *ThresholdChangeEvent) {}
func (n *NullAuditHandler) OnValidatorSetUpdate(event *AuditEvent) {}
func (n *NullAuditHandler) OnValidationFailure(event *ValidationFailureEvent) {}
func (n *NullAuditHandler) OnConfigurationChange(event *AuditEvent) {}
func (n *NullAuditHandler) OnError(event *AuditEvent) {}

// AuditEventBuilder helps construct audit events with proper defaults
type AuditEventBuilder struct {
	event *AuditEvent
}

// NewAuditEventBuilder creates a new audit event builder
func NewAuditEventBuilder(eventType AuditEventType, reason AuditEventReason) *AuditEventBuilder {
	return &AuditEventBuilder{
		event: &AuditEvent{
			EventID:   generateEventID(),
			Timestamp: time.Now(),
			EventType: eventType,
			Reason:    reason,
			Success:   true, // Default to success, can be overridden
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithRPWPath sets the RPW path for the event
func (b *AuditEventBuilder) WithRPWPath(path []uint32) *AuditEventBuilder {
	b.event.RPWPath = path
	return b
}

// WithCurve sets the curve name for the event
func (b *AuditEventBuilder) WithCurve(curveName string) *AuditEventBuilder {
	b.event.CurveName = curveName
	return b
}

// WithThresholdChange sets threshold change information
func (b *AuditEventBuilder) WithThresholdChange(oldThreshold, newThreshold int) *AuditEventBuilder {
	b.event.OldThreshold = oldThreshold
	b.event.NewThreshold = newThreshold
	return b
}

// WithParticipants sets participant information
func (b *AuditEventBuilder) WithParticipants(oldParticipants, newParticipants []ParticipantIndex) *AuditEventBuilder {
	b.event.OldParticipants = oldParticipants
	b.event.NewParticipants = newParticipants
	b.event.ParticipantCount = len(newParticipants)
	return b
}

// WithError marks the event as failed and sets error information
func (b *AuditEventBuilder) WithError(err error) *AuditEventBuilder {
	b.event.Success = false
	if err != nil {
		b.event.Error = err.Error()
	}
	return b
}

// WithMetadata adds metadata to the event
func (b *AuditEventBuilder) WithMetadata(key string, value interface{}) *AuditEventBuilder {
	b.event.Metadata[key] = value
	return b
}

// Build returns the constructed audit event
func (b *AuditEventBuilder) Build() *AuditEvent {
	return b.event
}

// BuildShareRegeneration returns a ShareRegenerationEvent
func (b *AuditEventBuilder) BuildShareRegeneration(regenerationType string, duration time.Duration, sharesGenerated int) *ShareRegenerationEvent {
	return &ShareRegenerationEvent{
		AuditEvent:       *b.event,
		RegenerationType: regenerationType,
		Duration:         duration,
		SharesGenerated:  sharesGenerated,
	}
}

// BuildThresholdChange returns a ThresholdChangeEvent
func (b *AuditEventBuilder) BuildThresholdChange(validationPassed bool, securityLevel string, byzantineFaultTolerance bool) *ThresholdChangeEvent {
	return &ThresholdChangeEvent{
		AuditEvent:              *b.event,
		ValidationPassed:        validationPassed,
		SecurityLevel:           securityLevel,
		ByzantineFaultTolerance: byzantineFaultTolerance,
	}
}

// BuildValidationFailure returns a ValidationFailureEvent
func (b *AuditEventBuilder) BuildValidationFailure(validationType, failureReason string, inputValues map[string]interface{}) *ValidationFailureEvent {
	return &ValidationFailureEvent{
		AuditEvent:     *b.event,
		ValidationType: validationType,
		FailureReason:  failureReason,
		InputValues:    inputValues,
	}
}

// generateEventID generates a unique event ID
// Uses a combination of timestamp and random bytes to ensure uniqueness
func generateEventID() string {
	timestamp := time.Now().Format("20060102150405.000000")

	// Add 4 random bytes to ensure uniqueness even for events created at the same microsecond
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to a simple counter if random generation fails
		// This is not thread-safe but better than duplicate IDs
		return fmt.Sprintf("%s.%d", timestamp, time.Now().UnixNano()%10000)
	}

	return fmt.Sprintf("%s.%x", timestamp, randomBytes)
}
