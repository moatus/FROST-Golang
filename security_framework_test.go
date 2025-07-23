package frost

import (
	"fmt"
	"testing"

	"github.com/canopy-network/canopy/lib/crypto"
)

// TestThresholdValidation tests the threshold validation system
func TestThresholdValidation(t *testing.T) {
	validator := NewDefaultThresholdValidator()

	t.Run("ValidThresholdConfigurations", func(t *testing.T) {
		testCases := []struct {
			participants int
			threshold    int
			expectValid  bool
			expectLevel  SecurityLevel
			expectBFT    bool
			description  string
		}{
			{5, 3, true, SecurityLevelHigh, true, "Standard 3-of-5 with BFT"}, // 3 >= int(5*0.67) = 3
			{5, 4, true, SecurityLevelHigh, true, "High security 4-of-5 with BFT"},
			{7, 5, true, SecurityLevelHigh, true, "Large committee 5-of-7 with BFT"},
			{3, 2, true, SecurityLevelHigh, true, "Minimal 2-of-3 with BFT"}, // 2 >= int(3*0.67) = 2
			{10, 7, true, SecurityLevelHigh, true, "Enterprise 7-of-10 with BFT"},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				result := validator.ValidateThresholdParameters(tc.participants, tc.threshold)
				
				if result.Valid != tc.expectValid {
					t.Errorf("Expected valid=%t, got %t", tc.expectValid, result.Valid)
				}
				
				if result.SecurityLevel != tc.expectLevel {
					t.Errorf("Expected security level %s, got %s", tc.expectLevel, result.SecurityLevel)
				}
				
				if result.ByzantineFaultTolerance != tc.expectBFT {
					t.Errorf("Expected BFT=%t, got %t", tc.expectBFT, result.ByzantineFaultTolerance)
				}
				
				if !result.Valid && len(result.Errors) == 0 {
					t.Error("Invalid result should have errors")
				}
			})
		}
	})

	t.Run("InvalidThresholdConfigurations", func(t *testing.T) {
		testCases := []struct {
			participants int
			threshold    int
			description  string
		}{
			{5, 0, "Zero threshold"},
			{5, -1, "Negative threshold"},
			{5, 6, "Threshold exceeds participants"},
			{0, 1, "Zero participants"},
			{-1, 1, "Negative participants"},
			{2, 1, "Below minimum participants"},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				result := validator.ValidateThresholdParameters(tc.participants, tc.threshold)
				
				if result.Valid {
					t.Errorf("Expected invalid result for %s", tc.description)
				}
				
				if len(result.Errors) == 0 {
					t.Error("Invalid result should have error messages")
				}
				
				if result.SecurityLevel != SecurityLevelLow {
					t.Errorf("Invalid configuration should have low security level, got %s", result.SecurityLevel)
				}
			})
		}
	})

	t.Run("EdgeCases", func(t *testing.T) {
		// Test threshold = participant count (no fault tolerance)
		result := validator.ValidateThresholdParameters(5, 5)
		if len(result.Warnings) == 0 {
			t.Error("Threshold equal to participant count should generate warnings")
		}
		if len(result.Recommendations) == 0 {
			t.Error("Should provide recommendations for no fault tolerance")
		}

		// Test low threshold ratio (should generate warnings)
		result = validator.ValidateThresholdParameters(10, 2) // 20% ratio, below recommended minimum
		if len(result.Warnings) == 0 {
			t.Error("Low threshold ratio should generate warnings")
		}
		if result.SecurityLevel != SecurityLevelLow {
			t.Error("Low threshold ratio should have low security level")
		}
	})

	t.Run("ByzantineFaultToleranceCalculation", func(t *testing.T) {
		// Test BFT threshold calculation (should be >= 2/3 of participants)
		testCases := []struct {
			participants int
			threshold    int
			expectBFT    bool
		}{
			{3, 2, true},  // int(3*0.67) = 2, threshold = 2, >= 2
			{3, 3, true},  // int(3*0.67) = 2, threshold = 3, >= 2
			{6, 4, true},  // int(6*0.67) = 4, threshold = 4, >= 4
			{6, 5, true},  // int(6*0.67) = 4, threshold = 5, >= 4
			{9, 6, true},  // int(9*0.67) = 6, threshold = 6, >= 6
			{9, 7, true},  // int(9*0.67) = 6, threshold = 7, >= 6
		}

		for _, tc := range testCases {
			result := validator.ValidateThresholdParameters(tc.participants, tc.threshold)
			if result.ByzantineFaultTolerance != tc.expectBFT {
				t.Errorf("For %d-of-%d, expected BFT=%t, got %t", 
					tc.threshold, tc.participants, tc.expectBFT, result.ByzantineFaultTolerance)
			}
		}
	})

	t.Run("SecurityAssessment", func(t *testing.T) {
		// Test comprehensive security assessment
		assessment := AssessSecurity(7, 5)

		if assessment.FaultTolerance != 2 {
			t.Errorf("Expected fault tolerance 2, got %d", assessment.FaultTolerance)
		}

		if assessment.AttackResistance != 5 {
			t.Errorf("Expected attack resistance 5, got %d", assessment.AttackResistance)
		}

		if !assessment.ByzantineFaultTolerance {
			t.Error("5-of-7 should have Byzantine fault tolerance")
		}

		if assessment.OverallRating != SecurityLevelHigh {
			t.Errorf("Expected high security rating, got %s", assessment.OverallRating)
		}

		// For 5-of-7 with BFT and fault tolerance=2, there should be no recommendations
		// Let's test a case that should have recommendations instead
		lowSecAssessment := AssessSecurity(5, 1) // 1-of-5 should have recommendations
		if len(lowSecAssessment.SecurityRecommendations) == 0 {
			t.Error("Low security configuration should provide recommendations")
		}
	})
}

// TestParticipantValidation tests participant validation
func TestParticipantValidation(t *testing.T) {
	t.Run("ValidParticipants", func(t *testing.T) {
		participants := []ParticipantIndex{1, 2, 3, 4, 5}
		result := ValidateParticipants(participants)
		
		if !result.Valid {
			t.Errorf("Valid participants should pass validation: %v", result.Errors)
		}
	})

	t.Run("DuplicateParticipants", func(t *testing.T) {
		participants := []ParticipantIndex{1, 2, 3, 2, 4} // Duplicate 2
		result := ValidateParticipants(participants)
		
		if result.Valid {
			t.Error("Duplicate participants should fail validation")
		}
		
		if len(result.Errors) == 0 {
			t.Error("Should have error messages for duplicates")
		}
	})

	t.Run("EmptyParticipants", func(t *testing.T) {
		participants := []ParticipantIndex{}
		result := ValidateParticipants(participants)
		
		if result.Valid {
			t.Error("Empty participants should fail validation")
		}
	})

	t.Run("ZeroParticipantID", func(t *testing.T) {
		participants := []ParticipantIndex{0, 1, 2}
		result := ValidateParticipants(participants)
		
		// Should be valid but generate warnings
		if !result.Valid {
			t.Error("Zero participant ID should be valid but generate warnings")
		}
		
		if len(result.Warnings) == 0 {
			t.Error("Zero participant ID should generate warnings")
		}
	})
}

// TestConfigurationValidation tests configuration validation
func TestConfigurationValidation(t *testing.T) {
	// Create test curve and foundation key
	curve := NewEd25519Curve()
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	validator := NewDefaultConfigurationValidator()

	t.Run("ValidCurve", func(t *testing.T) {
		result := validator.ValidateCurve(curve)
		
		if !result.Valid {
			t.Errorf("Valid curve should pass validation: %v", result.Errors)
		}
		
		if result.SecurityLevel != SecurityLevelHigh {
			t.Errorf("Ed25519 should have high security level, got %s", result.SecurityLevel)
		}
	})

	t.Run("NilCurve", func(t *testing.T) {
		result := validator.ValidateCurve(nil)
		
		if result.Valid {
			t.Error("Nil curve should fail validation")
		}
		
		if len(result.Errors) == 0 {
			t.Error("Should have error messages for nil curve")
		}
	})

	t.Run("ValidFoundationKey", func(t *testing.T) {
		result := validator.ValidateFoundationKey(foundationKey)
		
		if !result.Valid {
			t.Errorf("Valid foundation key should pass validation: %v", result.Errors)
		}
	})

	t.Run("NilFoundationKey", func(t *testing.T) {
		result := validator.ValidateFoundationKey(nil)
		
		if result.Valid {
			t.Error("Nil foundation key should fail validation")
		}
	})

	t.Run("ZeroFoundationKey", func(t *testing.T) {
		zeroKey := curve.ScalarZero()
		result := validator.ValidateFoundationKey(zeroKey)
		
		if result.Valid {
			t.Error("Zero foundation key should fail validation")
		}
		
		if result.SecurityLevel != SecurityLevelLow {
			t.Error("Zero foundation key should have low security level")
		}
	})

	t.Run("ValidRPWPath", func(t *testing.T) {
		// Test hardened derivation path
		hardenedPath := []uint32{0x80000000, 0x80000001}
		result := validator.ValidateRPWPath(hardenedPath)
		
		if !result.Valid {
			t.Errorf("Valid RPW path should pass validation: %v", result.Errors)
		}
	})

	t.Run("NonHardenedRPWPath", func(t *testing.T) {
		// Test non-hardened derivation path
		nonHardenedPath := []uint32{0, 1}
		result := validator.ValidateRPWPath(nonHardenedPath)
		
		if !result.Valid {
			t.Error("Non-hardened path should be valid but generate warnings")
		}
		
		if len(result.Warnings) == 0 {
			t.Error("Non-hardened path should generate warnings")
		}
	})

	t.Run("EmptyRPWPath", func(t *testing.T) {
		emptyPath := []uint32{}
		result := validator.ValidateRPWPath(emptyPath)
		
		if !result.Valid {
			t.Error("Empty path should be valid")
		}
		
		if len(result.Warnings) == 0 {
			t.Error("Empty path should generate warnings")
		}
	})

	t.Run("TooDeepRPWPath", func(t *testing.T) {
		// Create path deeper than maximum
		deepPath := make([]uint32, 15) // Exceeds default max of 10
		for i := range deepPath {
			deepPath[i] = uint32(i) + 0x80000000
		}
		
		result := validator.ValidateRPWPath(deepPath)
		
		if result.Valid {
			t.Error("Too deep RPW path should fail validation")
		}
	})
}

// TestBLSKeyValidation tests BLS key validation
func TestBLSKeyValidation(t *testing.T) {
	validator := NewDefaultConfigurationValidator()

	t.Run("ValidBLSKeys", func(t *testing.T) {
		// Create mock BLS keys (in practice these would be real keys)
		blsKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKey(t, 1),
			2: createMockBLSKey(t, 2),
			3: createMockBLSKey(t, 3),
		}
		
		result := validator.ValidateBLSKeys(blsKeys)
		
		if !result.Valid {
			t.Errorf("Valid BLS keys should pass validation: %v", result.Errors)
		}
	})

	t.Run("EmptyBLSKeys", func(t *testing.T) {
		emptyKeys := map[ParticipantIndex]*crypto.BLS12381PrivateKey{}
		result := validator.ValidateBLSKeys(emptyKeys)
		
		if result.Valid {
			t.Error("Empty BLS keys should fail validation")
		}
	})

	t.Run("NilBLSKey", func(t *testing.T) {
		keysWithNil := map[ParticipantIndex]*crypto.BLS12381PrivateKey{
			1: createMockBLSKey(t, 1),
			2: nil, // Nil key
			3: createMockBLSKey(t, 3),
		}
		
		result := validator.ValidateBLSKeys(keysWithNil)
		
		if result.Valid {
			t.Error("BLS keys with nil should fail validation")
		}
	})
}

// TestFROSTErrors tests the structured error handling system
func TestFROSTErrors(t *testing.T) {
	t.Run("ErrorCreation", func(t *testing.T) {
		err := NewFROSTError(
			ErrorCategoryValidation,
			ErrorSeverityHigh,
			"TEST_ERROR",
			"Test error message",
		)

		if err.Category != ErrorCategoryValidation {
			t.Errorf("Expected category %s, got %s", ErrorCategoryValidation, err.Category)
		}

		if err.Severity != ErrorSeverityHigh {
			t.Errorf("Expected severity %s, got %s", ErrorSeverityHigh, err.Severity)
		}

		if err.Code != "TEST_ERROR" {
			t.Errorf("Expected code TEST_ERROR, got %s", err.Code)
		}

		if !err.IsRecoverable() {
			t.Error("High severity error should be recoverable")
		}
	})

	t.Run("CriticalErrorNotRecoverable", func(t *testing.T) {
		err := NewFROSTError(
			ErrorCategoryInternal,
			ErrorSeverityCritical,
			"CRITICAL_ERROR",
			"Critical system error",
		)

		if err.IsRecoverable() {
			t.Error("Critical error should not be recoverable")
		}
	})

	t.Run("ErrorWithContext", func(t *testing.T) {
		err := NewFROSTError(
			ErrorCategoryThreshold,
			ErrorSeverityMedium,
			"CONTEXT_ERROR",
			"Error with context",
		).WithContext("threshold", 5).WithContext("participants", 3)

		if len(err.Context) != 2 {
			t.Errorf("Expected 2 context items, got %d", len(err.Context))
		}

		if err.Context["threshold"] != 5 {
			t.Error("Context should contain threshold value")
		}
	})

	t.Run("ErrorWithCause", func(t *testing.T) {
		originalErr := fmt.Errorf("original error")
		wrappedErr := NewFROSTError(
			ErrorCategoryCryptographic,
			ErrorSeverityHigh,
			"WRAPPED_ERROR",
			"Wrapped error",
		).WithCause(originalErr)

		if wrappedErr.Unwrap() != originalErr {
			t.Error("Should unwrap to original error")
		}
	})

	t.Run("PredefinedErrors", func(t *testing.T) {
		// Test some predefined errors
		testErrors := []*FROSTError{
			ErrInvalidThreshold,
			ErrThresholdTooHigh,
			ErrInsufficientParticipants,
			ErrBLSKeyInvalid,
			ErrKeyGenerationFailed,
		}

		for _, err := range testErrors {
			if err.Category == "" {
				t.Errorf("Error %s should have category", err.Code)
			}

			if err.Severity == "" {
				t.Errorf("Error %s should have severity", err.Code)
			}

			if err.Message == "" {
				t.Errorf("Error %s should have message", err.Code)
			}
		}
	})

	t.Run("ErrorHelperFunctions", func(t *testing.T) {
		validationErr := ErrInvalidThreshold.WithContext("value", 0)

		if !IsErrorCategory(validationErr, ErrorCategoryThreshold) {
			t.Error("Should identify threshold error category")
		}

		if !IsErrorSeverity(validationErr, ErrorSeverityHigh) {
			t.Error("Should identify high severity")
		}

		if !IsRecoverableError(validationErr) {
			t.Error("Should identify as recoverable")
		}

		context := GetErrorContext(validationErr)
		if context == nil || context["value"] != 0 {
			t.Error("Should extract error context")
		}
	})

	t.Run("WrapError", func(t *testing.T) {
		originalErr := fmt.Errorf("database connection failed")
		wrappedErr := WrapError(
			originalErr,
			ErrorCategoryInternal,
			ErrorSeverityHigh,
			"DB_CONNECTION_FAILED",
			"Failed to connect to database",
		)

		if wrappedErr.Cause != originalErr {
			t.Error("Should wrap original error")
		}

		if wrappedErr.Category != ErrorCategoryInternal {
			t.Error("Should have correct category")
		}
	})
}

// TestCompleteConfigurationValidation tests end-to-end configuration validation
func TestCompleteConfigurationValidation(t *testing.T) {
	curve := NewEd25519Curve()
	foundationKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to create foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	participants := []ParticipantIndex{1, 2, 3, 4, 5}
	threshold := 3
	rpwPath := []uint32{0x80000000, 0x80000001}

	// Create mock BLS keys
	blsKeys := make(map[ParticipantIndex]*crypto.BLS12381PrivateKey)
	for _, p := range participants {
		blsKeys[p] = createMockBLSKey(t, int(p))
	}

	validator := NewDefaultConfigurationValidator()

	t.Run("ValidCompleteConfiguration", func(t *testing.T) {
		result := validator.ValidateCompleteConfiguration(
			curve, threshold, participants, foundationKey, rpwPath, blsKeys)

		if !result.Valid {
			t.Errorf("Valid configuration should pass: %v", result.Errors)
		}

		if result.SecurityLevel == SecurityLevelLow {
			t.Error("Valid configuration should not have low security level")
		}
	})

	t.Run("InvalidCompleteConfiguration", func(t *testing.T) {
		// Test with invalid threshold
		result := validator.ValidateCompleteConfiguration(
			curve, 0, participants, foundationKey, rpwPath, blsKeys)

		if result.Valid {
			t.Error("Invalid threshold should fail validation")
		}

		if len(result.Errors) == 0 {
			t.Error("Should have error messages")
		}
	})

	t.Run("ConfigurationCompatibility", func(t *testing.T) {
		// Create old and new configurations
		oldConfig := &Configuration{
			Curve:           curve.Name(),
			Threshold:       3,
			Participants:    []ParticipantIndex{1, 2, 3, 4, 5},
			ParticipantCount: 5,
			RPWPath:         rpwPath,
			SecurityLevel:   SecurityLevelMedium,
		}

		newConfig := &Configuration{
			Curve:           curve.Name(),
			Threshold:       4, // Increased threshold
			Participants:    []ParticipantIndex{1, 2, 3, 4, 5, 6}, // Added participant
			ParticipantCount: 6,
			RPWPath:         rpwPath,
			SecurityLevel:   SecurityLevelHigh,
		}

		checker := NewConfigurationCompatibilityChecker()
		result := checker.CheckCompatibility(oldConfig, newConfig)

		if !result.Valid {
			t.Errorf("Compatible configurations should pass: %v", result.Errors)
		}

		if len(result.Recommendations) == 0 {
			t.Error("Should provide recommendations for changes")
		}
	})

	t.Run("IncompatibleConfigurations", func(t *testing.T) {
		oldConfig := &Configuration{
			Curve:    "ed25519",
			RPWPath:  []uint32{0x80000000},
		}

		newConfig := &Configuration{
			Curve:    "secp256k1", // Different curve
			RPWPath:  []uint32{0x80000001}, // Different path
		}

		checker := NewConfigurationCompatibilityChecker()
		result := checker.CheckCompatibility(oldConfig, newConfig)

		if result.Valid {
			t.Error("Incompatible configurations should fail")
		}
	})
}

// Helper function to create mock BLS keys for testing
func createMockBLSKey(t *testing.T, seed int) *crypto.BLS12381PrivateKey {
	// In a real implementation, this would create actual BLS keys
	// For testing, we'll create a mock or skip if BLS key creation is complex
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
