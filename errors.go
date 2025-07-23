package frost

import (
	"fmt"
)

// ErrorCategory represents the category of FROST error
type ErrorCategory string

const (
	ErrorCategoryValidation     ErrorCategory = "validation"
	ErrorCategoryConfiguration  ErrorCategory = "configuration"
	ErrorCategoryThreshold      ErrorCategory = "threshold"
	ErrorCategoryParticipant    ErrorCategory = "participant"
	ErrorCategoryCryptographic  ErrorCategory = "cryptographic"
	ErrorCategoryBLSIntegration ErrorCategory = "bls_integration"
	ErrorCategoryKeyGeneration  ErrorCategory = "key_generation"
	ErrorCategorySigning        ErrorCategory = "signing"
	ErrorCategoryFoundation     ErrorCategory = "foundation"
	ErrorCategoryInternal       ErrorCategory = "internal"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "low"      // Non-critical, operation can continue
	ErrorSeverityMedium   ErrorSeverity = "medium"   // Important, may affect functionality
	ErrorSeverityHigh     ErrorSeverity = "high"     // Critical, operation should stop
	ErrorSeverityCritical ErrorSeverity = "critical" // System-level failure
)

// FROSTError represents a structured error in the FROST library
type FROSTError struct {
	Category    ErrorCategory `json:"category"`
	Severity    ErrorSeverity `json:"severity"`
	Code        string        `json:"code"`
	Message     string        `json:"message"`
	Details     string        `json:"details,omitempty"`
	Cause       error         `json:"-"` // Original error, not serialized
	Context     map[string]interface{} `json:"context,omitempty"`
	Recoverable bool          `json:"recoverable"`
}

// Error implements the error interface
func (e *FROSTError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s:%s] %s: %s", e.Category, e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s:%s] %s", e.Category, e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *FROSTError) Unwrap() error {
	return e.Cause
}

// WithContext adds context information to the error
func (e *FROSTError) WithContext(key string, value interface{}) *FROSTError {
	// Create a copy to avoid race conditions
	newError := &FROSTError{
		Category:    e.Category,
		Severity:    e.Severity,
		Code:        e.Code,
		Message:     e.Message,
		Recoverable: e.Recoverable,
		Cause:       e.Cause,
		Context:     make(map[string]interface{}),
	}

	// Copy existing context
	if e.Context != nil {
		for k, v := range e.Context {
			newError.Context[k] = v
		}
	}

	// Add new context
	newError.Context[key] = value
	return newError
}

// WithCause sets the underlying cause of the error
func (e *FROSTError) WithCause(cause error) *FROSTError {
	// Create a copy to avoid race conditions
	newError := &FROSTError{
		Category:    e.Category,
		Severity:    e.Severity,
		Code:        e.Code,
		Message:     e.Message,
		Recoverable: e.Recoverable,
		Cause:       cause,
		Context:     make(map[string]interface{}),
	}

	// Copy existing context
	if e.Context != nil {
		for k, v := range e.Context {
			newError.Context[k] = v
		}
	}

	return newError
}

// IsRecoverable returns whether the error is recoverable
func (e *FROSTError) IsRecoverable() bool {
	return e.Recoverable
}

// NewFROSTError creates a new FROST error
func NewFROSTError(category ErrorCategory, severity ErrorSeverity, code, message string) *FROSTError {
	return &FROSTError{
		Category:    category,
		Severity:    severity,
		Code:        code,
		Message:     message,
		Context:     make(map[string]interface{}),
		Recoverable: severity != ErrorSeverityCritical,
	}
}

// Validation Errors
var (
	ErrInvalidThreshold = NewFROSTError(
		ErrorCategoryThreshold, ErrorSeverityHigh, "INVALID_THRESHOLD",
		"threshold value is invalid")
	
	ErrThresholdTooHigh = NewFROSTError(
		ErrorCategoryThreshold, ErrorSeverityHigh, "THRESHOLD_TOO_HIGH",
		"threshold exceeds participant count")
	
	ErrThresholdTooLow = NewFROSTError(
		ErrorCategoryThreshold, ErrorSeverityHigh, "THRESHOLD_TOO_LOW",
		"threshold is too low for security requirements")
	
	ErrInsufficientParticipants = NewFROSTError(
		ErrorCategoryParticipant, ErrorSeverityHigh, "INSUFFICIENT_PARTICIPANTS",
		"insufficient participants for threshold signature")
	
	ErrDuplicateParticipants = NewFROSTError(
		ErrorCategoryParticipant, ErrorSeverityMedium, "DUPLICATE_PARTICIPANTS",
		"duplicate participants detected")
	
	ErrInvalidParticipantID = NewFROSTError(
		ErrorCategoryParticipant, ErrorSeverityMedium, "INVALID_PARTICIPANT_ID",
		"participant ID is invalid")
	
	ErrParticipantNotFound = NewFROSTError(
		ErrorCategoryParticipant, ErrorSeverityMedium, "PARTICIPANT_NOT_FOUND",
		"participant not found in validator set")
)

// Configuration Errors
var (
	ErrInvalidCurve = NewFROSTError(
		ErrorCategoryConfiguration, ErrorSeverityHigh, "INVALID_CURVE",
		"cryptographic curve is invalid or unsupported")
	
	ErrInvalidFoundationKey = NewFROSTError(
		ErrorCategoryFoundation, ErrorSeverityHigh, "INVALID_FOUNDATION_KEY",
		"foundation key is invalid")
	
	ErrInvalidRPWPath = NewFROSTError(
		ErrorCategoryFoundation, ErrorSeverityMedium, "INVALID_RPW_PATH",
		"RPW derivation path is invalid")
	
	ErrConfigurationMismatch = NewFROSTError(
		ErrorCategoryConfiguration, ErrorSeverityHigh, "CONFIGURATION_MISMATCH",
		"configuration parameters are inconsistent")
)

// BLS Integration Errors
var (
	ErrBLSKeyInvalid = NewFROSTError(
		ErrorCategoryBLSIntegration, ErrorSeverityHigh, "BLS_KEY_INVALID",
		"BLS key is invalid or corrupted")
	
	ErrBLSBindingFailed = NewFROSTError(
		ErrorCategoryBLSIntegration, ErrorSeverityHigh, "BLS_BINDING_FAILED",
		"failed to bind FROST share to BLS key")
	
	ErrBLSVerificationFailed = NewFROSTError(
		ErrorCategoryBLSIntegration, ErrorSeverityHigh, "BLS_VERIFICATION_FAILED",
		"BLS binding verification failed")
	
	ErrBLSKeyMismatch = NewFROSTError(
		ErrorCategoryBLSIntegration, ErrorSeverityHigh, "BLS_KEY_MISMATCH",
		"BLS key does not match expected value")
)

// Key Generation Errors
var (
	ErrKeyGenerationFailed = NewFROSTError(
		ErrorCategoryKeyGeneration, ErrorSeverityHigh, "KEY_GENERATION_FAILED",
		"FROST key generation failed")
	
	ErrShareGenerationFailed = NewFROSTError(
		ErrorCategoryKeyGeneration, ErrorSeverityHigh, "SHARE_GENERATION_FAILED",
		"failed to generate key shares")
	
	ErrShareVerificationFailed = NewFROSTError(
		ErrorCategoryKeyGeneration, ErrorSeverityHigh, "SHARE_VERIFICATION_FAILED",
		"key share verification failed")
	
	ErrInconsistentShares = NewFROSTError(
		ErrorCategoryKeyGeneration, ErrorSeverityHigh, "INCONSISTENT_SHARES",
		"generated shares are inconsistent")
)

// Signing Errors
var (
	ErrSigningFailed = NewFROSTError(
		ErrorCategorySigning, ErrorSeverityHigh, "SIGNING_FAILED",
		"FROST signature generation failed")
	
	ErrInsufficientSigners = NewFROSTError(
		ErrorCategorySigning, ErrorSeverityMedium, "INSUFFICIENT_SIGNERS",
		"insufficient signers for threshold signature")
	
	ErrSignatureVerificationFailed = NewFROSTError(
		ErrorCategorySigning, ErrorSeverityHigh, "SIGNATURE_VERIFICATION_FAILED",
		"signature verification failed")
	
	ErrInvalidSignature = NewFROSTError(
		ErrorCategorySigning, ErrorSeverityHigh, "INVALID_SIGNATURE",
		"signature is invalid or malformed")
)

// Cryptographic Errors
var (
	ErrCryptographicOperation = NewFROSTError(
		ErrorCategoryCryptographic, ErrorSeverityHigh, "CRYPTOGRAPHIC_OPERATION_FAILED",
		"cryptographic operation failed")
	
	ErrRandomnessGeneration = NewFROSTError(
		ErrorCategoryCryptographic, ErrorSeverityCritical, "RANDOMNESS_GENERATION_FAILED",
		"failed to generate secure randomness")
	
	ErrHashComputation = NewFROSTError(
		ErrorCategoryCryptographic, ErrorSeverityHigh, "HASH_COMPUTATION_FAILED",
		"hash computation failed")
)

// Internal Errors
var (
	ErrNotInitialized = NewFROSTError(
		ErrorCategoryInternal, ErrorSeverityHigh, "NOT_INITIALIZED",
		"component not properly initialized")
	
	ErrInvalidState = NewFROSTError(
		ErrorCategoryInternal, ErrorSeverityHigh, "INVALID_STATE",
		"component is in invalid state")
	
	ErrMemoryAllocation = NewFROSTError(
		ErrorCategoryInternal, ErrorSeverityCritical, "MEMORY_ALLOCATION_FAILED",
		"memory allocation failed")
)

// Error helper functions

// WrapError wraps an existing error with FROST error context
func WrapError(err error, category ErrorCategory, severity ErrorSeverity, code, message string) *FROSTError {
	return NewFROSTError(category, severity, code, message).WithCause(err)
}

// IsErrorCategory checks if an error belongs to a specific category
func IsErrorCategory(err error, category ErrorCategory) bool {
	if frostErr, ok := err.(*FROSTError); ok {
		return frostErr.Category == category
	}
	return false
}

// IsErrorSeverity checks if an error has a specific severity
func IsErrorSeverity(err error, severity ErrorSeverity) bool {
	if frostErr, ok := err.(*FROSTError); ok {
		return frostErr.Severity == severity
	}
	return false
}

// IsRecoverableError checks if an error is recoverable
func IsRecoverableError(err error) bool {
	if frostErr, ok := err.(*FROSTError); ok {
		return frostErr.IsRecoverable()
	}
	return true // Non-FROST errors are assumed recoverable
}

// GetErrorContext extracts context from a FROST error
func GetErrorContext(err error) map[string]interface{} {
	if frostErr, ok := err.(*FROSTError); ok {
		return frostErr.Context
	}
	return nil
}
