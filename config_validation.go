package frost

import (
	"fmt"
	"reflect"

	"github.com/canopy-network/canopy/lib/crypto"
)

// Configuration validation constants
const (
	DefaultFoundationKeyMinEntropy = 128        // bits
	DefaultFoundationKeyMaxLength  = 64         // bytes
	DefaultMaxRPWPathDepth        = 10         // reasonable depth limit
	HardenedDerivationOffset      = 0x80000000 // hardened derivation limit
)

// ConfigurationValidator provides validation for FROST configuration parameters
type ConfigurationValidator struct {
	// Supported curves
	supportedCurves map[string]bool
	
	// Foundation key validation
	foundationKeyMinEntropy int
	foundationKeyMaxLength  int
	
	// RPW path validation
	maxRPWPathDepth int
	maxRPWPathValue uint32
}

// NewDefaultConfigurationValidator creates a validator with secure defaults
func NewDefaultConfigurationValidator() *ConfigurationValidator {
	return &ConfigurationValidator{
		supportedCurves: map[string]bool{
			"secp256k1": true,
			"ed25519":   true,
			"ristretto": true,
		},
		foundationKeyMinEntropy: DefaultFoundationKeyMinEntropy,
		foundationKeyMaxLength:  DefaultFoundationKeyMaxLength,
		maxRPWPathDepth:        DefaultMaxRPWPathDepth,
		maxRPWPathValue:        HardenedDerivationOffset,
	}
}

// ValidateCurve validates that a curve is supported and properly configured
func (cv *ConfigurationValidator) ValidateCurve(curve Curve) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	if curve == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "curve cannot be nil")
		return result
	}

	curveName := curve.Name()
	if curveName == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "curve name cannot be empty")
		return result
	}

	// Check if curve is supported
	if !cv.supportedCurves[curveName] {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported curve: %s", curveName))
		result.Recommendations = append(result.Recommendations, "use a supported curve: secp256k1, ed25519, or ristretto")
		return result
	}

	// Curve-specific validations
	switch curveName {
	case "secp256k1":
		result.SecurityLevel = SecurityLevelHigh
		result.Recommendations = append(result.Recommendations, "secp256k1 is well-tested for Bitcoin applications")
	case "ed25519":
		result.SecurityLevel = SecurityLevelHigh
		result.Recommendations = append(result.Recommendations, "ed25519 provides excellent performance and security")
	case "ristretto":
		result.SecurityLevel = SecurityLevelHigh
		result.Recommendations = append(result.Recommendations, "ristretto provides strong security guarantees")
	}

	return result
}

// ValidateFoundationKey validates foundation key parameters
func (cv *ConfigurationValidator) ValidateFoundationKey(foundationKey Scalar) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	if foundationKey == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "foundation key cannot be nil")
		return result
	}

	// Check if key is zero (which would be insecure)
	if foundationKey.IsZero() {
		result.Valid = false
		result.Errors = append(result.Errors, "foundation key cannot be zero")
		result.SecurityLevel = SecurityLevelLow
		return result
	}

	// Check key length constraints
	keyBytes := foundationKey.Bytes()
	if len(keyBytes) > cv.foundationKeyMaxLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("foundation key length %d exceeds maximum %d bytes", len(keyBytes), cv.foundationKeyMaxLength))
		result.SecurityLevel = SecurityLevelLow
		return result
	}

	// Basic entropy check - count unique bytes as a simple heuristic
	uniqueBytes := make(map[byte]bool)
	for _, b := range keyBytes {
		uniqueBytes[b] = true
	}

	// Estimate entropy based on unique byte count (simplified heuristic)
	estimatedEntropy := len(uniqueBytes) * 8 / len(keyBytes) * len(keyBytes)
	if estimatedEntropy < cv.foundationKeyMinEntropy {
		result.Warnings = append(result.Warnings, fmt.Sprintf("foundation key may have low entropy (estimated: %d bits, minimum: %d bits)", estimatedEntropy, cv.foundationKeyMinEntropy))
		result.SecurityLevel = SecurityLevelMedium
	} else {
		result.SecurityLevel = SecurityLevelHigh
	}

	result.Recommendations = append(result.Recommendations, "ensure foundation key is generated with cryptographically secure randomness")

	return result
}

// ValidateRPWPath validates RPW derivation path
func (cv *ConfigurationValidator) ValidateRPWPath(rpwPath []uint32) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	if len(rpwPath) == 0 {
		result.Warnings = append(result.Warnings, "empty RPW path - using root derivation")
		return result
	}

	// Check path depth
	if len(rpwPath) > cv.maxRPWPathDepth {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("RPW path too deep: %d (max: %d)", len(rpwPath), cv.maxRPWPathDepth))
		return result
	}

	// Check for hardened derivation (recommended for security)
	hasHardenedDerivation := false
	for i, component := range rpwPath {
		if component >= cv.maxRPWPathValue {
			hasHardenedDerivation = true
		}
		
		// Warn about non-hardened derivation in security-critical positions
		if i < 2 && component < cv.maxRPWPathValue {
			result.Warnings = append(result.Warnings, fmt.Sprintf("non-hardened derivation at position %d may reduce security", i))
		}
	}

	if !hasHardenedDerivation {
		result.Warnings = append(result.Warnings, "no hardened derivation detected - consider using hardened paths for security")
		result.Recommendations = append(result.Recommendations, "use hardened derivation (values >= 0x80000000) for security-critical paths")
	}

	return result
}

// ValidateBLSKeys validates BLS key parameters
func (cv *ConfigurationValidator) ValidateBLSKeys(blsKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	if len(blsKeys) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "no BLS keys provided")
		return result
	}

	// Validate each BLS key
	zeroKeys := []ParticipantIndex{}
	for participantID, blsKey := range blsKeys {
		if blsKey == nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("BLS key for participant %d is nil", participantID))
			continue
		}

		// Check for zero keys (insecure)
		if isZeroBLSKey(blsKey) {
			zeroKeys = append(zeroKeys, participantID)
		}
	}

	if len(zeroKeys) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("zero BLS keys detected for participants: %v", zeroKeys))
		result.SecurityLevel = SecurityLevelLow
	}

	// Check for duplicate keys (security risk)
	duplicates := findDuplicateBLSKeys(blsKeys)
	if len(duplicates) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "duplicate BLS keys detected")
		result.SecurityLevel = SecurityLevelLow
		for key, participants := range duplicates {
			result.Errors = append(result.Errors, fmt.Sprintf("BLS key %s used by participants: %v", key, participants))
		}
	}

	if result.Valid {
		result.SecurityLevel = SecurityLevelHigh
		result.Recommendations = append(result.Recommendations, "ensure BLS keys are generated with cryptographically secure randomness")
	}

	return result
}

// ValidateCompleteConfiguration validates a complete FROST configuration
func (cv *ConfigurationValidator) ValidateCompleteConfiguration(
	curve Curve,
	threshold int,
	participants []ParticipantIndex,
	foundationKey Scalar,
	rpwPath []uint32,
	blsKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelHigh,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	// Validate curve
	curveResult := cv.ValidateCurve(curve)
	if !curveResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, curveResult.Errors...)
	}
	result.Warnings = append(result.Warnings, curveResult.Warnings...)
	result.Recommendations = append(result.Recommendations, curveResult.Recommendations...)

	// Validate foundation key
	foundationResult := cv.ValidateFoundationKey(foundationKey)
	if !foundationResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, foundationResult.Errors...)
	}
	result.Warnings = append(result.Warnings, foundationResult.Warnings...)
	result.Recommendations = append(result.Recommendations, foundationResult.Recommendations...)

	// Validate RPW path
	rpwResult := cv.ValidateRPWPath(rpwPath)
	if !rpwResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, rpwResult.Errors...)
	}
	result.Warnings = append(result.Warnings, rpwResult.Warnings...)
	result.Recommendations = append(result.Recommendations, rpwResult.Recommendations...)

	// Validate BLS keys
	blsResult := cv.ValidateBLSKeys(blsKeys)
	if !blsResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, blsResult.Errors...)
	}
	result.Warnings = append(result.Warnings, blsResult.Warnings...)
	result.Recommendations = append(result.Recommendations, blsResult.Recommendations...)

	// Validate threshold and participants (reuse existing validation)
	thresholdResult := ValidateConfiguration(curve, threshold, participants, foundationKey)
	if !thresholdResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, thresholdResult.Errors...)
	}
	result.Warnings = append(result.Warnings, thresholdResult.Warnings...)
	result.Recommendations = append(result.Recommendations, thresholdResult.Recommendations...)

	// Set overall security level to the minimum of all validations
	securityLevels := []SecurityLevel{
		curveResult.SecurityLevel,
		foundationResult.SecurityLevel,
		rpwResult.SecurityLevel,
		blsResult.SecurityLevel,
		thresholdResult.SecurityLevel,
	}

	result.SecurityLevel = getMinimumSecurityLevel(securityLevels)
	result.ByzantineFaultTolerance = thresholdResult.ByzantineFaultTolerance

	// Add overall recommendations
	if result.Valid && result.SecurityLevel == SecurityLevelHigh {
		result.Recommendations = append(result.Recommendations, "configuration meets high security standards")
	} else if result.Valid && result.SecurityLevel == SecurityLevelMedium {
		result.Recommendations = append(result.Recommendations, "configuration is acceptable but could be improved")
	}

	return result
}

// Helper functions

// isZeroBLSKey checks if a BLS key is zero (insecure)
func isZeroBLSKey(key *crypto.BLS12381PrivateKey) bool {
	if key == nil {
		return true
	}

	// Get the key bytes and check if all are zero
	keyBytes := key.Bytes()
	for _, b := range keyBytes {
		if b != 0 {
			return false
		}
	}
	return true
}

// findDuplicateBLSKeys finds duplicate BLS keys in the map
func findDuplicateBLSKeys(blsKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey) map[string][]ParticipantIndex {
	keyToParticipants := make(map[string][]ParticipantIndex)
	duplicates := make(map[string][]ParticipantIndex)

	for participantID, blsKey := range blsKeys {
		if blsKey == nil {
			continue
		}

		// Create a string representation of the key for comparison using actual key bytes
		keyBytes := blsKey.Bytes()
		keyStr := fmt.Sprintf("%x", keyBytes) // Use hex representation of key bytes
		
		keyToParticipants[keyStr] = append(keyToParticipants[keyStr], participantID)
	}

	// Find duplicates
	for keyStr, participants := range keyToParticipants {
		if len(participants) > 1 {
			duplicates[keyStr] = participants
		}
	}

	return duplicates
}

// getMinimumSecurityLevel returns the minimum security level from a slice
func getMinimumSecurityLevel(levels []SecurityLevel) SecurityLevel {
	if len(levels) == 0 {
		return SecurityLevelMedium
	}

	minLevel := SecurityLevelHigh
	for _, level := range levels {
		switch level {
		case SecurityLevelLow:
			return SecurityLevelLow // Immediately return lowest
		case SecurityLevelMedium:
			minLevel = SecurityLevelMedium
		}
	}

	return minLevel
}

// ConfigurationCompatibilityChecker checks compatibility between configurations
type ConfigurationCompatibilityChecker struct{}

// NewConfigurationCompatibilityChecker creates a new compatibility checker
func NewConfigurationCompatibilityChecker() *ConfigurationCompatibilityChecker {
	return &ConfigurationCompatibilityChecker{}
}

// CheckCompatibility checks if two configurations are compatible for migration
func (ccc *ConfigurationCompatibilityChecker) CheckCompatibility(oldConfig, newConfig *Configuration) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	if oldConfig == nil || newConfig == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "configurations cannot be nil")
		return result
	}

	// Check curve compatibility
	if oldConfig.Curve == "" || newConfig.Curve == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "curves cannot be empty for compatibility check")
	} else if oldConfig.Curve != newConfig.Curve {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("curve mismatch: %s -> %s", oldConfig.Curve, newConfig.Curve))
	}

	// Check RPW path compatibility
	if !reflect.DeepEqual(oldConfig.RPWPath, newConfig.RPWPath) {
		result.Warnings = append(result.Warnings, "RPW path changed - ensure this is intentional")
	}

	// Check threshold changes
	if oldConfig.Threshold != newConfig.Threshold {
		if newConfig.Threshold > oldConfig.Threshold {
			result.Recommendations = append(result.Recommendations, "threshold increased - improved security")
		} else {
			result.Warnings = append(result.Warnings, "threshold decreased - reduced security")
		}
	}

	// Check participant count changes
	if oldConfig.ParticipantCount != newConfig.ParticipantCount {
		if newConfig.ParticipantCount > oldConfig.ParticipantCount {
			result.Recommendations = append(result.Recommendations, "participant count increased - improved decentralization")
		} else {
			result.Warnings = append(result.Warnings, "participant count decreased - reduced decentralization")
		}
	}

	return result
}
