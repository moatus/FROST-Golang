package frost

import (
	"fmt"
	"math"
)

// SecurityLevel represents the security level of threshold parameters
type SecurityLevel string

const (
	SecurityLevelLow    SecurityLevel = "low"
	SecurityLevelMedium SecurityLevel = "medium"
	SecurityLevelHigh   SecurityLevel = "high"
)

// Byzantine fault tolerance constants
const (
	DefaultByzantineRatio = 2.0 / 3.0 // 2/3 for Byzantine fault tolerance
)

// ValidationResult contains the result of parameter validation
type ValidationResult struct {
	Valid                   bool          `json:"valid"`
	SecurityLevel           SecurityLevel `json:"security_level"`
	ByzantineFaultTolerance bool          `json:"byzantine_fault_tolerance"`
	Warnings                []string      `json:"warnings,omitempty"`
	Errors                  []string      `json:"errors,omitempty"`
	Recommendations         []string      `json:"recommendations,omitempty"`
}

// ThresholdValidator provides validation for threshold parameters
type ThresholdValidator struct {
	// Minimum security requirements
	MinParticipants      int     `json:"min_participants"`
	MinThreshold         int     `json:"min_threshold"`
	MaxThreshold         int     `json:"max_threshold"`
	ByzantineRatio       float64 `json:"byzantine_ratio"`        // For Byzantine fault tolerance (typically 2/3)
	RecommendedMinRatio  float64 `json:"recommended_min_ratio"`  // Minimum recommended threshold ratio
	RecommendedMaxRatio  float64 `json:"recommended_max_ratio"`  // Maximum recommended threshold ratio
}

// NewDefaultThresholdValidator creates a validator with secure default parameters
func NewDefaultThresholdValidator() *ThresholdValidator {
	return &ThresholdValidator{
		MinParticipants:     3,                   // Minimum for meaningful threshold
		MinThreshold:        2,                   // Minimum threshold value
		MaxThreshold:        1000,                // Reasonable upper bound
		ByzantineRatio:      DefaultByzantineRatio, // 2/3 for Byzantine fault tolerance
		RecommendedMinRatio: 0.51,                // Just over half
		RecommendedMaxRatio: 0.80,                // Leave room for availability
	}
}

// ValidateThresholdParameters validates threshold and participant parameters
func (tv *ThresholdValidator) ValidateThresholdParameters(participantCount, threshold int) *ValidationResult {
	result := &ValidationResult{
		Valid:                   true,
		SecurityLevel:           SecurityLevelMedium,
		ByzantineFaultTolerance: false,
		Warnings:                []string{},
		Errors:                  []string{},
		Recommendations:         []string{},
	}

	// Basic validation checks
	if threshold <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "threshold must be positive")
	}

	if participantCount <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "participant count must be positive")
	}

	if threshold > participantCount {
		result.Valid = false
		result.Errors = append(result.Errors, "threshold cannot exceed participant count")
	}

	// Early return if basic validation fails
	if !result.Valid {
		result.SecurityLevel = SecurityLevelLow
		return result
	}

	// Minimum requirements
	if participantCount < tv.MinParticipants {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("minimum %d participants required for security", tv.MinParticipants))
	}

	if threshold < tv.MinThreshold {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("minimum threshold of %d required", tv.MinThreshold))
	}

	if threshold > tv.MaxThreshold {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("threshold exceeds maximum of %d", tv.MaxThreshold))
	}

	// Early return if minimum requirements fail
	if !result.Valid {
		result.SecurityLevel = SecurityLevelLow
		return result
	}

	// Calculate ratios for security analysis
	thresholdRatio := float64(threshold) / float64(participantCount)

	// Byzantine fault tolerance check
	byzantineThreshold := int(float64(participantCount) * tv.ByzantineRatio)
	if threshold >= byzantineThreshold {
		result.ByzantineFaultTolerance = true
		result.SecurityLevel = SecurityLevelHigh
	}

	// Security level assessment
	if thresholdRatio < tv.RecommendedMinRatio {
		result.SecurityLevel = SecurityLevelLow
		result.Warnings = append(result.Warnings, "threshold ratio is below recommended minimum for security")
		result.Recommendations = append(result.Recommendations, fmt.Sprintf("consider increasing threshold to at least %d", int(math.Ceil(float64(participantCount)*tv.RecommendedMinRatio))))
	} else if thresholdRatio > tv.RecommendedMaxRatio {
		result.Warnings = append(result.Warnings, "threshold ratio is high, may affect availability")
		result.Recommendations = append(result.Recommendations, "consider if such a high threshold is necessary for your use case")
	}

	// Specific threshold analysis
	if threshold == 1 {
		result.SecurityLevel = SecurityLevelLow
		result.Warnings = append(result.Warnings, "threshold of 1 provides no fault tolerance")
	}

	if threshold == participantCount {
		result.Warnings = append(result.Warnings, "threshold equals participant count - no fault tolerance")
		result.Recommendations = append(result.Recommendations, "consider reducing threshold to allow for node failures")
	}

	// Optimal range recommendations
	optimalMin := int(math.Ceil(float64(participantCount) * tv.RecommendedMinRatio))
	optimalMax := int(math.Ceil(float64(participantCount) * tv.RecommendedMaxRatio))
	if threshold < optimalMin || threshold > optimalMax {
		result.Recommendations = append(result.Recommendations, 
			fmt.Sprintf("optimal threshold range for %d participants is %d-%d", participantCount, optimalMin, optimalMax))
	}

	return result
}

// ValidateParticipants validates participant list for duplicates and validity
func ValidateParticipants(participants []ParticipantIndex) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	if len(participants) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "participant list cannot be empty")
		return result
	}

	// Check for duplicates
	seen := make(map[ParticipantIndex]bool)
	duplicates := []ParticipantIndex{}
	
	for _, participant := range participants {
		if seen[participant] {
			duplicates = append(duplicates, participant)
		}
		seen[participant] = true
	}

	if len(duplicates) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("duplicate participants found: %v", duplicates))
	}

	// Check for zero participant IDs (might be invalid depending on implementation)
	zeroParticipants := []ParticipantIndex{}
	for _, participant := range participants {
		if participant == 0 {
			zeroParticipants = append(zeroParticipants, participant)
		}
	}

	if len(zeroParticipants) > 0 {
		result.Warnings = append(result.Warnings, "participant ID 0 detected - verify this is intentional")
	}

	return result
}

// ValidateConfiguration validates overall FROST configuration
func ValidateConfiguration(curve Curve, threshold int, participants []ParticipantIndex, foundationKey Scalar) *ValidationResult {
	result := &ValidationResult{
		Valid:           true,
		SecurityLevel:   SecurityLevelMedium,
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
	}

	// Validate curve
	if curve == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "curve cannot be nil")
		return result
	}

	// Validate foundation key
	if foundationKey == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "foundation key cannot be nil")
		return result
	}

	// Validate participants
	participantResult := ValidateParticipants(participants)
	if !participantResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, participantResult.Errors...)
	}
	result.Warnings = append(result.Warnings, participantResult.Warnings...)

	// Validate threshold parameters
	validator := NewDefaultThresholdValidator()
	thresholdResult := validator.ValidateThresholdParameters(len(participants), threshold)
	if !thresholdResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, thresholdResult.Errors...)
	}
	result.Warnings = append(result.Warnings, thresholdResult.Warnings...)
	result.Recommendations = append(result.Recommendations, thresholdResult.Recommendations...)

	// Set security level to the minimum of all validations
	result.SecurityLevel = minSecurityLevel(thresholdResult.SecurityLevel, participantResult.SecurityLevel)

	result.ByzantineFaultTolerance = thresholdResult.ByzantineFaultTolerance

	return result
}

// ValidateThresholdChange validates a threshold change operation
func ValidateThresholdChange(oldThreshold, newThreshold, participantCount int) *ValidationResult {
	validator := NewDefaultThresholdValidator()
	result := validator.ValidateThresholdParameters(participantCount, newThreshold)

	// Add change-specific validations
	if oldThreshold == newThreshold {
		result.Warnings = append(result.Warnings, "threshold unchanged")
	}

	if newThreshold > oldThreshold {
		result.Recommendations = append(result.Recommendations, "increasing threshold - ensure sufficient nodes are available")
	} else if newThreshold < oldThreshold {
		result.Warnings = append(result.Warnings, "decreasing threshold - security level may be reduced")
	}

	return result
}

// SecurityAssessment provides a detailed security assessment
type SecurityAssessment struct {
	OverallRating           SecurityLevel `json:"overall_rating"`
	ByzantineFaultTolerance bool          `json:"byzantine_fault_tolerance"`
	FaultTolerance          int           `json:"fault_tolerance"`          // Number of nodes that can fail
	AttackResistance        int           `json:"attack_resistance"`        // Number of nodes needed for attack
	AvailabilityRisk        string        `json:"availability_risk"`        // Risk assessment for availability
	SecurityRecommendations []string      `json:"security_recommendations"`
}

// AssessSecurity provides a comprehensive security assessment
func AssessSecurity(participantCount, threshold int) *SecurityAssessment {
	// Input validation
	if participantCount <= 0 || threshold <= 0 {
		return &SecurityAssessment{
			OverallRating:           SecurityLevelLow,
			ByzantineFaultTolerance: false,
			FaultTolerance:          0,
			AttackResistance:        0,
			AvailabilityRisk:        "critical - invalid parameters",
			SecurityRecommendations: []string{"participantCount and threshold must be positive integers"},
		}
	}

	if threshold > participantCount {
		return &SecurityAssessment{
			OverallRating:           SecurityLevelLow,
			ByzantineFaultTolerance: false,
			FaultTolerance:          0,
			AttackResistance:        0,
			AvailabilityRisk:        "critical - threshold exceeds participant count",
			SecurityRecommendations: []string{"threshold cannot exceed participant count"},
		}
	}

	faultTolerance := participantCount - threshold
	attackResistance := threshold

	assessment := &SecurityAssessment{
		FaultTolerance:          faultTolerance,
		AttackResistance:        attackResistance,
		SecurityRecommendations: []string{},
	}

	// Byzantine fault tolerance
	byzantineThreshold := int(float64(participantCount) * DefaultByzantineRatio)
	assessment.ByzantineFaultTolerance = threshold >= byzantineThreshold

	// Overall security rating
	thresholdRatio := float64(threshold) / float64(participantCount)
	switch {
	case thresholdRatio < 0.5:
		assessment.OverallRating = SecurityLevelLow
	case thresholdRatio >= 0.67:
		assessment.OverallRating = SecurityLevelHigh
	default:
		assessment.OverallRating = SecurityLevelMedium
	}

	// Availability risk assessment
	switch {
	case faultTolerance == 0:
		assessment.AvailabilityRisk = "critical - no fault tolerance"
	case faultTolerance == 1:
		assessment.AvailabilityRisk = "high - single point of failure"
	case faultTolerance <= 3:
		assessment.AvailabilityRisk = "medium - limited fault tolerance"
	default:
		assessment.AvailabilityRisk = "low - good fault tolerance"
	}

	// Generate recommendations
	if !assessment.ByzantineFaultTolerance {
		assessment.SecurityRecommendations = append(assessment.SecurityRecommendations,
			"Consider increasing threshold for Byzantine fault tolerance")
	}

	if faultTolerance < 2 {
		assessment.SecurityRecommendations = append(assessment.SecurityRecommendations,
			"Consider adding more participants or reducing threshold for better availability")
	}

	if assessment.OverallRating == SecurityLevelLow {
		assessment.SecurityRecommendations = append(assessment.SecurityRecommendations,
			"Current configuration has low security - review threshold parameters")
	}

	return assessment
}

// minSecurityLevel returns the minimum security level between two SecurityLevel values
func minSecurityLevel(level1, level2 SecurityLevel) SecurityLevel {
	// Define security level rankings (lower values = lower security)
	levelRanking := map[SecurityLevel]int{
		SecurityLevelLow:    1,
		SecurityLevelMedium: 2,
		SecurityLevelHigh:   3,
	}

	rank1, exists1 := levelRanking[level1]
	if !exists1 {
		rank1 = 2 // Default to medium if unknown
	}

	rank2, exists2 := levelRanking[level2]
	if !exists2 {
		rank2 = 2 // Default to medium if unknown
	}

	// Return the level with the lower ranking (lower security)
	if rank1 <= rank2 {
		return level1
	}
	return level2
}
