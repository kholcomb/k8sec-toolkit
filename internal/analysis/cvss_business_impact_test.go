package analysis

import (
	"encoding/json"
	"testing"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestNewBusinessImpactCalculator(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	if calc.config == nil {
		t.Error("Config should not be nil")
	}

	if calc.config.BaseWeight != 1.0 {
		t.Errorf("Expected base weight 1.0, got %f", calc.config.BaseWeight)
	}

	if calc.config.LowThreshold != 3.9 {
		t.Errorf("Expected low threshold 3.9, got %f", calc.config.LowThreshold)
	}
}

func TestCalculateBaseScore(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	tests := []struct {
		name        string
		impact      CVSSBusinessImpact
		expectedMin float64
		expectedMax float64
	}{
		{
			name: "Maximum base score",
			impact: CVSSBusinessImpact{
				AttackVector:          AttackVectorNetwork,
				AttackComplexity:      AttackComplexityLow,
				PrivilegesRequired:    PrivilegesRequiredNone,
				UserInteraction:       UserInteractionNone,
				Scope:                 ScopeChanged,
				ConfidentialityImpact: ConfidentialityImpactHigh,
				IntegrityImpact:       IntegrityImpactHigh,
				AvailabilityImpact:    AvailabilityImpactHigh,
			},
			expectedMin: 9.0,
			expectedMax: 10.0,
		},
		{
			name: "Medium base score",
			impact: CVSSBusinessImpact{
				AttackVector:          AttackVectorLocal,
				AttackComplexity:      AttackComplexityHigh,
				PrivilegesRequired:    PrivilegesRequiredLow,
				UserInteraction:       UserInteractionRequired,
				Scope:                 ScopeUnchanged,
				ConfidentialityImpact: ConfidentialityImpactLow,
				IntegrityImpact:       IntegrityImpactLow,
				AvailabilityImpact:    AvailabilityImpactNone,
			},
			expectedMin: 1.0,
			expectedMax: 4.0,
		},
		{
			name: "Zero impact score",
			impact: CVSSBusinessImpact{
				AttackVector:          AttackVectorNetwork,
				AttackComplexity:      AttackComplexityLow,
				PrivilegesRequired:    PrivilegesRequiredNone,
				UserInteraction:       UserInteractionNone,
				Scope:                 ScopeUnchanged,
				ConfidentialityImpact: ConfidentialityImpactNone,
				IntegrityImpact:       IntegrityImpactNone,
				AvailabilityImpact:    AvailabilityImpactNone,
			},
			expectedMin: 0.0,
			expectedMax: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calc.calculateBaseScore(tt.impact)

			if score < tt.expectedMin || score > tt.expectedMax {
				t.Errorf("Base score %f not in expected range [%f, %f]", score, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestCalculateTemporalScore(t *testing.T) {
	calc := NewBusinessImpactCalculator()
	baseScore := 8.0

	tests := []struct {
		name     string
		impact   CVSSBusinessImpact
		expected func(float64) bool
	}{
		{
			name: "All temporal metrics defined",
			impact: CVSSBusinessImpact{
				ExploitCodeMaturity: ExploitCodeMaturityFunctional,
				RemediationLevel:    RemediationLevelOfficialFix,
				ReportConfidence:    ReportConfidenceConfirmed,
			},
			expected: func(score float64) bool {
				return score >= 7.0 && score <= 8.0 // Should be slightly lower than base
			},
		},
		{
			name: "Default temporal metrics",
			impact: CVSSBusinessImpact{
				ExploitCodeMaturity: ExploitCodeMaturityNotDefined,
				RemediationLevel:    RemediationLevelNotDefined,
				ReportConfidence:    ReportConfidenceNotDefined,
			},
			expected: func(score float64) bool {
				return score == baseScore // Should equal base score
			},
		},
		{
			name: "Worst case temporal",
			impact: CVSSBusinessImpact{
				ExploitCodeMaturity: ExploitCodeMaturityHigh,
				RemediationLevel:    RemediationLevelUnavailable,
				ReportConfidence:    ReportConfidenceUnknown,
			},
			expected: func(score float64) bool {
				return score >= 7.0 && score <= 8.0 // Slightly reduced due to confidence
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calc.calculateTemporalScore(baseScore, tt.impact)

			if !tt.expected(score) {
				t.Errorf("Temporal score %f not in expected range for %s", score, tt.name)
			}
		})
	}
}

func TestCalculateEnvironmentalScore(t *testing.T) {
	calc := NewBusinessImpactCalculator()
	temporalScore := 7.5

	tests := []struct {
		name     string
		impact   CVSSBusinessImpact
		expected func(float64) bool
	}{
		{
			name: "Mission critical business function",
			impact: CVSSBusinessImpact{
				BusinessFunction:      BusinessFunctionMissionCritical,
				DataClassification:    DataClassificationRestricted,
				ComplianceRequirement: ComplianceRequirementRegulated,
				BusinessContinuity:    BusinessContinuityCritical,
			},
			expected: func(score float64) bool {
				return score > temporalScore // Should be higher than temporal
			},
		},
		{
			name: "Supporting business function",
			impact: CVSSBusinessImpact{
				BusinessFunction:      BusinessFunctionSupporting,
				DataClassification:    DataClassificationPublic,
				ComplianceRequirement: ComplianceRequirementNone,
				BusinessContinuity:    BusinessContinuityLow,
			},
			expected: func(score float64) bool {
				return score < temporalScore // Should be lower than temporal
			},
		},
		{
			name: "Default environmental metrics",
			impact: CVSSBusinessImpact{
				BusinessFunction:      BusinessFunctionNotDefined,
				DataClassification:    DataClassificationNotDefined,
				ComplianceRequirement: ComplianceRequirementNotDefined,
				BusinessContinuity:    BusinessContinuityNotDefined,
			},
			expected: func(score float64) bool {
				return score == temporalScore // Should equal temporal score
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calc.calculateEnvironmentalScore(temporalScore, tt.impact)

			if !tt.expected(score) {
				t.Errorf("Environmental score %f not in expected range for %s", score, tt.name)
			}
		})
	}
}

func TestCalculateScore(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	tests := []struct {
		name        string
		impact      CVSSBusinessImpact
		expectedMin float64
		expectedMax float64
	}{
		{
			name: "Complete high-impact scenario",
			impact: CVSSBusinessImpact{
				AttackVector:          AttackVectorNetwork,
				AttackComplexity:      AttackComplexityLow,
				PrivilegesRequired:    PrivilegesRequiredNone,
				UserInteraction:       UserInteractionNone,
				Scope:                 ScopeChanged,
				ConfidentialityImpact: ConfidentialityImpactHigh,
				IntegrityImpact:       IntegrityImpactHigh,
				AvailabilityImpact:    AvailabilityImpactHigh,
				ExploitCodeMaturity:   ExploitCodeMaturityHigh,
				RemediationLevel:      RemediationLevelUnavailable,
				ReportConfidence:      ReportConfidenceConfirmed,
				BusinessFunction:      BusinessFunctionMissionCritical,
				DataClassification:    DataClassificationRestricted,
				ComplianceRequirement: ComplianceRequirementRegulated,
				BusinessContinuity:    BusinessContinuityCritical,
			},
			expectedMin: 8.0,
			expectedMax: 10.0,
		},
		{
			name: "Complete low-impact scenario",
			impact: CVSSBusinessImpact{
				AttackVector:          AttackVectorPhysical,
				AttackComplexity:      AttackComplexityHigh,
				PrivilegesRequired:    PrivilegesRequiredHigh,
				UserInteraction:       UserInteractionRequired,
				Scope:                 ScopeUnchanged,
				ConfidentialityImpact: ConfidentialityImpactLow,
				IntegrityImpact:       IntegrityImpactNone,
				AvailabilityImpact:    AvailabilityImpactNone,
				BusinessFunction:      BusinessFunctionSupporting,
				DataClassification:    DataClassificationPublic,
			},
			expectedMin: 0.0,
			expectedMax: 2.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calc.CalculateScore(tt.impact)

			if score < tt.expectedMin || score > tt.expectedMax {
				t.Errorf("Score %f not in expected range [%f, %f]", score, tt.expectedMin, tt.expectedMax)
			}

			if score < 0 || score > 10 {
				t.Errorf("Score %f outside valid range [0, 10]", score)
			}
		})
	}
}

func TestGetSeverityLevel(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	tests := []struct {
		score    float64
		expected types.BusinessImpactLevel
	}{
		{0.0, types.BusinessImpactLow},
		{3.8, types.BusinessImpactLow},
		{3.9, types.BusinessImpactLow},
		{4.0, types.BusinessImpactMedium},
		{6.8, types.BusinessImpactMedium},
		{6.9, types.BusinessImpactMedium},
		{7.0, types.BusinessImpactHigh},
		{8.8, types.BusinessImpactHigh},
		{8.9, types.BusinessImpactHigh},
		{9.0, types.BusinessImpactCritical},
		{10.0, types.BusinessImpactCritical},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := calc.GetSeverityLevel(tt.score)
			if result != tt.expected {
				t.Errorf("Score %f: expected %v, got %v", tt.score, tt.expected, result)
			}
		})
	}
}

func TestGenerateVectorString(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	impact := CVSSBusinessImpact{
		AttackVector:          AttackVectorNetwork,
		AttackComplexity:      AttackComplexityLow,
		PrivilegesRequired:    PrivilegesRequiredNone,
		UserInteraction:       UserInteractionNone,
		Scope:                 ScopeChanged,
		ConfidentialityImpact: ConfidentialityImpactHigh,
		IntegrityImpact:       IntegrityImpactHigh,
		AvailabilityImpact:    AvailabilityImpactHigh,
		ExploitCodeMaturity:   ExploitCodeMaturityHigh,
		RemediationLevel:      RemediationLevelOfficialFix,
		ReportConfidence:      ReportConfidenceConfirmed,
		BusinessFunction:      BusinessFunctionCritical,
		DataClassification:    DataClassificationConfidential,
		ComplianceRequirement: ComplianceRequirementRegulated,
		BusinessContinuity:    BusinessContinuityCritical,
	}

	vectorString := calc.GenerateVectorString(impact)

	expectedComponents := []string{
		"CVSS:3.1",
		"AV:NETWORK",
		"AC:LOW",
		"PR:NONE",
		"UI:NONE",
		"S:CHANGED",
		"C:HIGH",
		"I:HIGH",
		"A:HIGH",
		"E:HIGH",
		"RL:OFFICIAL_FIX",
		"RC:CONFIRMED",
		"BF:CRITICAL",
		"DC:CONFIDENTIAL",
		"CR:REGULATED",
		"BC:CRITICAL",
	}

	for _, component := range expectedComponents {
		if !containsSubstring(vectorString, component) {
			t.Errorf("Vector string should contain '%s', got: %s", component, vectorString)
		}
	}
}

func TestParseVectorString(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	vectorString := "CVSS:3.1/AV:NETWORK/AC:LOW/PR:NONE/UI:NONE/S:CHANGED/C:HIGH/I:HIGH/A:HIGH/E:HIGH/RL:OFFICIAL_FIX/RC:CONFIRMED/BF:CRITICAL/DC:CONFIDENTIAL"

	impact, err := calc.ParseVectorString(vectorString)
	if err != nil {
		t.Fatalf("Failed to parse vector string: %v", err)
	}

	if impact.AttackVector != AttackVectorNetwork {
		t.Errorf("Expected AttackVector NETWORK, got %s", impact.AttackVector)
	}

	if impact.AttackComplexity != AttackComplexityLow {
		t.Errorf("Expected AttackComplexity LOW, got %s", impact.AttackComplexity)
	}

	if impact.PrivilegesRequired != PrivilegesRequiredNone {
		t.Errorf("Expected PrivilegesRequired NONE, got %s", impact.PrivilegesRequired)
	}

	if impact.BusinessFunction != BusinessFunctionCritical {
		t.Errorf("Expected BusinessFunction CRITICAL, got %s", impact.BusinessFunction)
	}

	if impact.DataClassification != DataClassificationConfidential {
		t.Errorf("Expected DataClassification CONFIDENTIAL, got %s", impact.DataClassification)
	}
}

func TestCustomWeights(t *testing.T) {
	config := &BusinessImpactConfig{
		BaseWeight:          2.0,
		TemporalWeight:      1.5,
		EnvironmentalWeight: 0.5,
		CustomWeights: map[string]float64{
			"AV:NETWORK": 1.0, // Custom weight for network attack vector
		},
		LowThreshold:      2.0,
		MediumThreshold:   5.0,
		HighThreshold:     8.0,
		CriticalThreshold: 10.0,
	}

	calc := NewBusinessImpactCalculatorWithConfig(config)

	impact := CVSSBusinessImpact{
		AttackVector:          AttackVectorNetwork,
		AttackComplexity:      AttackComplexityLow,
		PrivilegesRequired:    PrivilegesRequiredNone,
		UserInteraction:       UserInteractionNone,
		Scope:                 ScopeUnchanged,
		ConfidentialityImpact: ConfidentialityImpactHigh,
		IntegrityImpact:       IntegrityImpactHigh,
		AvailabilityImpact:    AvailabilityImpactHigh,
	}

	score := calc.CalculateScore(impact)

	// With base weight of 2.0, score should be higher than default
	if score < 15.0 {
		t.Errorf("Expected score > 15.0 with custom weights, got %f", score)
	}

	// Test custom severity levels
	severity := calc.GetSeverityLevel(4.0)
	if severity != types.BusinessImpactMedium {
		t.Errorf("Expected medium severity for score 4.0 with custom thresholds, got %v", severity)
	}
}

func TestLoadConfigFromJSON(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	configJSON := `{
		"base_weight": 1.5,
		"temporal_weight": 0.8,
		"environmental_weight": 1.2,
		"custom_weights": {
			"AV:NETWORK": 0.9,
			"BF:CRITICAL": 2.5
		},
		"low_threshold": 2.5,
		"medium_threshold": 5.5,
		"high_threshold": 7.5,
		"critical_threshold": 9.5
	}`

	err := calc.LoadConfigFromJSON([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load config from JSON: %v", err)
	}

	if calc.config.BaseWeight != 1.5 {
		t.Errorf("Expected base weight 1.5, got %f", calc.config.BaseWeight)
	}

	if calc.config.CustomWeights["AV:NETWORK"] != 0.9 {
		t.Errorf("Expected custom weight 0.9 for AV:NETWORK, got %f", calc.config.CustomWeights["AV:NETWORK"])
	}

	if calc.config.LowThreshold != 2.5 {
		t.Errorf("Expected low threshold 2.5, got %f", calc.config.LowThreshold)
	}
}

func TestRoundTripVectorString(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	original := CVSSBusinessImpact{
		AttackVector:          AttackVectorAdjacent,
		AttackComplexity:      AttackComplexityHigh,
		PrivilegesRequired:    PrivilegesRequiredLow,
		UserInteraction:       UserInteractionRequired,
		Scope:                 ScopeUnchanged,
		ConfidentialityImpact: ConfidentialityImpactLow,
		IntegrityImpact:       IntegrityImpactHigh,
		AvailabilityImpact:    AvailabilityImpactNone,
		BusinessFunction:      BusinessFunctionOperational,
		DataClassification:    DataClassificationInternal,
	}

	// Generate vector string
	vectorString := calc.GenerateVectorString(original)

	// Parse it back
	parsed, err := calc.ParseVectorString(vectorString)
	if err != nil {
		t.Fatalf("Failed to parse generated vector string: %v", err)
	}

	// Verify all fields match
	if parsed.AttackVector != original.AttackVector {
		t.Errorf("AttackVector mismatch: expected %s, got %s", original.AttackVector, parsed.AttackVector)
	}

	if parsed.AttackComplexity != original.AttackComplexity {
		t.Errorf("AttackComplexity mismatch: expected %s, got %s", original.AttackComplexity, parsed.AttackComplexity)
	}

	if parsed.BusinessFunction != original.BusinessFunction {
		t.Errorf("BusinessFunction mismatch: expected %s, got %s", original.BusinessFunction, parsed.BusinessFunction)
	}

	if parsed.DataClassification != original.DataClassification {
		t.Errorf("DataClassification mismatch: expected %s, got %s", original.DataClassification, parsed.DataClassification)
	}
}

func TestPrivilegesRequiredScopeAdjustment(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	// Test that privileges required values are adjusted based on scope
	impact1 := CVSSBusinessImpact{
		AttackVector:          AttackVectorNetwork,
		AttackComplexity:      AttackComplexityLow,
		PrivilegesRequired:    PrivilegesRequiredLow,
		UserInteraction:       UserInteractionNone,
		Scope:                 ScopeUnchanged,
		ConfidentialityImpact: ConfidentialityImpactHigh,
		IntegrityImpact:       IntegrityImpactHigh,
		AvailabilityImpact:    AvailabilityImpactHigh,
	}

	impact2 := impact1
	impact2.Scope = ScopeChanged

	score1 := calc.calculateBaseScore(impact1)
	score2 := calc.calculateBaseScore(impact2)

	// Score with scope changed should be higher
	if score2 <= score1 {
		t.Errorf("Score with scope changed (%f) should be higher than unchanged (%f)", score2, score1)
	}
}

func TestBoundaryValues(t *testing.T) {
	calc := NewBusinessImpactCalculator()

	// Test with extreme configurations
	impact := CVSSBusinessImpact{
		AttackVector:          AttackVectorNetwork,
		AttackComplexity:      AttackComplexityLow,
		PrivilegesRequired:    PrivilegesRequiredNone,
		UserInteraction:       UserInteractionNone,
		Scope:                 ScopeChanged,
		ConfidentialityImpact: ConfidentialityImpactHigh,
		IntegrityImpact:       IntegrityImpactHigh,
		AvailabilityImpact:    AvailabilityImpactHigh,
		BusinessFunction:      BusinessFunctionMissionCritical,
		DataClassification:    DataClassificationRestricted,
		ComplianceRequirement: ComplianceRequirementRegulated,
		BusinessContinuity:    BusinessContinuityCritical,
	}

	score := calc.CalculateScore(impact)

	// Score should never exceed 10.0
	if score > 10.0 {
		t.Errorf("Score %f exceeds maximum of 10.0", score)
	}

	// Score should never be negative
	if score < 0.0 {
		t.Errorf("Score %f is negative", score)
	}
}

func TestConfigMarshalUnmarshal(t *testing.T) {
	originalConfig := &BusinessImpactConfig{
		BaseWeight:          1.5,
		TemporalWeight:      0.8,
		EnvironmentalWeight: 1.2,
		CustomWeights: map[string]float64{
			"AV:NETWORK":  0.9,
			"BF:CRITICAL": 2.5,
		},
		LowThreshold:      2.5,
		MediumThreshold:   5.5,
		HighThreshold:     7.5,
		CriticalThreshold: 9.5,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Unmarshal back
	var newConfig BusinessImpactConfig
	err = json.Unmarshal(jsonData, &newConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify fields match
	if newConfig.BaseWeight != originalConfig.BaseWeight {
		t.Errorf("BaseWeight mismatch: expected %f, got %f", originalConfig.BaseWeight, newConfig.BaseWeight)
	}

	if newConfig.CustomWeights["AV:NETWORK"] != originalConfig.CustomWeights["AV:NETWORK"] {
		t.Errorf("Custom weight mismatch for AV:NETWORK")
	}

	if newConfig.LowThreshold != originalConfig.LowThreshold {
		t.Errorf("LowThreshold mismatch: expected %f, got %f", originalConfig.LowThreshold, newConfig.LowThreshold)
	}
}

// Helper function
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsInMiddle(s, substr))))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
