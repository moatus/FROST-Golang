package frost

import (
	"fmt"
	"time"

	"github.com/canopy-network/canopy/lib/crypto"
)

// FoundationKeyManager interface for deriving RPW keys
type FoundationKeyManager interface {
	DeriveRPWKey(path []uint32) (Scalar, error)
}

// RegenerationTrigger defines the interface for triggering share regeneration
type RegenerationTrigger interface {
	// RegenerateShares triggers share regeneration with new parameters
	RegenerateShares(request *RegenerationRequest) (*RegenerationResult, error)
	
	// ValidateRegenerationRequest validates a regeneration request without executing it
	ValidateRegenerationRequest(request *RegenerationRequest) (*ValidationResult, error)
	
	// GetCurrentConfiguration returns the current configuration
	GetCurrentConfiguration() *Configuration
}

// RegenerationRequest contains parameters for share regeneration
type RegenerationRequest struct {
	// Core parameters
	NewValidatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey `json:"-"` // Not serialized for security
	NewThreshold        int                                              `json:"new_threshold"`
	NewParticipants     []ParticipantIndex                               `json:"new_participants"`
	
	// Context information
	Reason      AuditEventReason `json:"reason"`
	RequestedBy string           `json:"requested_by,omitempty"`
	RequestID   string           `json:"request_id,omitempty"`
	
	// Configuration options
	ValidateOnly    bool                   `json:"validate_only"`    // Only validate, don't execute
	ForceRegenerate bool                   `json:"force_regenerate"` // Skip some safety checks
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	
	// Audit handler for events
	AuditHandler AuditEventHandler `json:"-"` // Not serialized
}

// RegenerationResult contains the result of share regeneration
type RegenerationResult struct {
	// Success information
	Success         bool                                             `json:"success"`
	SharesGenerated map[ParticipantIndex]*KeyShare                   `json:"-"` // Not serialized for security
	GroupPublicKey  Point                                            `json:"-"` // Not serialized
	
	// Validation results
	ValidationResult *ValidationResult `json:"validation_result"`
	SecurityAssessment *SecurityAssessment `json:"security_assessment"`
	
	// Execution information
	Duration        time.Duration `json:"duration"`
	RegenerationType string       `json:"regeneration_type"`
	
	// Configuration changes
	OldConfiguration *Configuration `json:"old_configuration"`
	NewConfiguration *Configuration `json:"new_configuration"`
	
	// Error information
	Error   error    `json:"-"` // Not serialized
	Errors  []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	
	// Audit information
	AuditEvents []AuditEvent `json:"audit_events,omitempty"`
}

// Configuration represents the current FROST configuration
type Configuration struct {
	Curve           string             `json:"curve"`
	Threshold       int                `json:"threshold"`
	Participants    []ParticipantIndex `json:"participants"`
	ParticipantCount int               `json:"participant_count"`
	RPWPath         []uint32           `json:"rpw_path,omitempty"`
	SecurityLevel   SecurityLevel      `json:"security_level"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

// BLSAnchoredRegenerationTrigger implements RegenerationTrigger for BLS-anchored FROST
type BLSAnchoredRegenerationTrigger struct {
	curve         Curve
	foundationMgr FoundationKeyManager
	rpwPath       []uint32
	
	// Current state
	currentConfig    *Configuration
	currentKeyShares map[ParticipantIndex]*KeyShare
	groupPublicKey   Point
	
	// Validation
	validator *ThresholdValidator
}

// NewBLSAnchoredRegenerationTrigger creates a new BLS-anchored regeneration trigger
func NewBLSAnchoredRegenerationTrigger(
	curve Curve,
	foundationMgr FoundationKeyManager,
	rpwPath []uint32,
) *BLSAnchoredRegenerationTrigger {
	if foundationMgr == nil {
		panic("foundationMgr cannot be nil")
	}

	return &BLSAnchoredRegenerationTrigger{
		curve:         curve,
		foundationMgr: foundationMgr,
		rpwPath:       rpwPath,
		validator:     NewDefaultThresholdValidator(),
		currentConfig: &Configuration{
			Curve:     curve.Name(),
			RPWPath:   rpwPath,
			CreatedAt: time.Now(),
		},
	}
}

// RegenerateShares implements the RegenerationTrigger interface
func (brt *BLSAnchoredRegenerationTrigger) RegenerateShares(request *RegenerationRequest) (*RegenerationResult, error) {
	startTime := time.Now()
	
	result := &RegenerationResult{
		Success:          false,
		RegenerationType: "bls_anchored",
		Duration:         0,
		OldConfiguration: brt.currentConfig,
		AuditEvents:      []AuditEvent{},
		Errors:           []string{},
		Warnings:         []string{},
	}

	// Validate the request first
	validationResult, err := brt.ValidateRegenerationRequest(request)
	if err != nil {
		result.Error = err
		result.Errors = append(result.Errors, err.Error())
		brt.emitAuditEvent(request.AuditHandler, AuditEventValidationFailure, request.Reason, result, err)
		return result, err
	}
	
	result.ValidationResult = validationResult
	if !validationResult.Valid {
		err := ErrInvalidThreshold.WithContext("validation_errors", validationResult.Errors)
		result.Error = err
		result.Errors = append(result.Errors, validationResult.Errors...)
		brt.emitAuditEvent(request.AuditHandler, AuditEventValidationFailure, request.Reason, result, err)
		return result, err
	}

	// If validation-only, return early
	if request.ValidateOnly {
		result.Success = true
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Perform the actual regeneration
	err = brt.performRegeneration(request, result)
	result.Duration = time.Since(startTime)
	
	if err != nil {
		result.Error = err
		result.Errors = append(result.Errors, err.Error())
		brt.emitAuditEvent(request.AuditHandler, AuditEventRegenerationFailure, request.Reason, result, err)
		return result, err
	}

	result.Success = true
	
	// Update current configuration
	brt.updateCurrentConfiguration(request, result)
	
	// Emit success audit event
	brt.emitAuditEvent(request.AuditHandler, AuditEventShareRegeneration, request.Reason, result, nil)
	
	return result, nil
}

// ValidateRegenerationRequest validates a regeneration request
func (brt *BLSAnchoredRegenerationTrigger) ValidateRegenerationRequest(request *RegenerationRequest) (*ValidationResult, error) {
	if request == nil {
		return nil, ErrInvalidState.WithContext("reason", "request is nil")
	}

	// Validate BLS keys
	if len(request.NewValidatorBLSKeys) == 0 {
		return &ValidationResult{
			Valid:  false,
			Errors: []string{"no BLS validator keys provided"},
		}, nil
	}

	// Validate participants match BLS keys
	if len(request.NewParticipants) != len(request.NewValidatorBLSKeys) {
		return &ValidationResult{
			Valid:  false,
			Errors: []string{"participant count does not match BLS key count"},
		}, nil
	}

	// Validate all participants have corresponding BLS keys
	for _, participant := range request.NewParticipants {
		if _, exists := request.NewValidatorBLSKeys[participant]; !exists {
			return &ValidationResult{
				Valid:  false,
				Errors: []string{fmt.Sprintf("no BLS key for participant %d", participant)},
			}, nil
		}
	}

	// Validate threshold parameters
	thresholdResult := brt.validator.ValidateThresholdParameters(len(request.NewParticipants), request.NewThreshold)
	if !thresholdResult.Valid {
		return thresholdResult, nil
	}

	// Validate participants for duplicates
	participantResult := ValidateParticipants(request.NewParticipants)
	if !participantResult.Valid {
		return participantResult, nil
	}

	// Combine results
	combinedResult := &ValidationResult{
		Valid:                   true,
		SecurityLevel:           thresholdResult.SecurityLevel,
		ByzantineFaultTolerance: thresholdResult.ByzantineFaultTolerance,
		Warnings:                append(thresholdResult.Warnings, participantResult.Warnings...),
		Errors:                  []string{},
		Recommendations:         thresholdResult.Recommendations,
	}

	return combinedResult, nil
}

// GetCurrentConfiguration returns the current configuration
func (brt *BLSAnchoredRegenerationTrigger) GetCurrentConfiguration() *Configuration {
	return brt.currentConfig
}

// performRegeneration performs the actual share regeneration
func (brt *BLSAnchoredRegenerationTrigger) performRegeneration(request *RegenerationRequest, result *RegenerationResult) error {
	// Derive foundation secret
	foundationSecret, err := brt.foundationMgr.DeriveRPWKey(brt.rpwPath)
	if err != nil {
		return WrapError(err, ErrorCategoryFoundation, ErrorSeverityHigh, "FOUNDATION_DERIVATION_FAILED", "failed to derive foundation secret")
	}
	defer foundationSecret.Zeroize()

	// Create BLS-anchored key generator
	bkg := NewBLSAnchoredKeyGen(
		brt.curve,
		request.NewThreshold,
		request.NewParticipants,
		foundationSecret,
		request.NewValidatorBLSKeys,
	)

	// Generate key shares
	keyShares, groupPublicKey, err := bkg.GenerateKeyShares()
	if err != nil {
		return WrapError(err, ErrorCategoryKeyGeneration, ErrorSeverityHigh, "SHARE_GENERATION_FAILED", "failed to generate key shares")
	}

	// Clean up old shares
	if brt.currentKeyShares != nil {
		for _, keyShare := range brt.currentKeyShares {
			keyShare.Zeroize()
		}
	}

	// Store new shares
	brt.currentKeyShares = keyShares
	brt.groupPublicKey = groupPublicKey
	
	// Set result data
	result.SharesGenerated = keyShares
	result.GroupPublicKey = groupPublicKey
	result.SecurityAssessment = AssessSecurity(len(request.NewParticipants), request.NewThreshold)

	return nil
}

// updateCurrentConfiguration updates the current configuration after successful regeneration
func (brt *BLSAnchoredRegenerationTrigger) updateCurrentConfiguration(request *RegenerationRequest, result *RegenerationResult) {
	brt.currentConfig = &Configuration{
		Curve:           brt.curve.Name(),
		Threshold:       request.NewThreshold,
		Participants:    request.NewParticipants,
		ParticipantCount: len(request.NewParticipants),
		RPWPath:         brt.rpwPath,
		SecurityLevel:   result.ValidationResult.SecurityLevel,
		CreatedAt:       brt.currentConfig.CreatedAt,
		UpdatedAt:       time.Now(),
	}
	result.NewConfiguration = brt.currentConfig
}

// emitAuditEvent emits an audit event if a handler is provided
func (brt *BLSAnchoredRegenerationTrigger) emitAuditEvent(
	handler AuditEventHandler,
	eventType AuditEventType,
	reason AuditEventReason,
	result *RegenerationResult,
	err error,
) {
	if handler == nil {
		return
	}

	builder := NewAuditEventBuilder(eventType, reason).
		WithRPWPath(brt.rpwPath).
		WithCurve(brt.curve.Name())

	if result.OldConfiguration != nil && result.NewConfiguration != nil {
		builder.WithThresholdChange(result.OldConfiguration.Threshold, result.NewConfiguration.Threshold).
			WithParticipants(result.OldConfiguration.Participants, result.NewConfiguration.Participants)
	}

	if err != nil {
		builder.WithError(err)
	}

	switch eventType {
	case AuditEventShareRegeneration:
		event := builder.BuildShareRegeneration("bls_anchored", result.Duration, len(result.SharesGenerated))
		handler.OnShareRegeneration(event)
	case AuditEventThresholdChange:
		event := builder.BuildThresholdChange(
			result.ValidationResult.Valid,
			string(result.ValidationResult.SecurityLevel),
			result.ValidationResult.ByzantineFaultTolerance,
		)
		handler.OnThresholdChange(event)
	case AuditEventValidationFailure, AuditEventRegenerationFailure:
		event := builder.Build()
		handler.OnError(event)
	default:
		event := builder.Build()
		handler.OnConfigurationChange(event)
	}
}
