package analysis

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

// CVSSBusinessImpact provides CVSS-style business impact scoring
type CVSSBusinessImpact struct {
	// Base Metrics (required)
	AttackVector       AttackVector       `json:"attack_vector"`
	AttackComplexity   AttackComplexity   `json:"attack_complexity"`
	PrivilegesRequired PrivilegesRequired `json:"privileges_required"`
	UserInteraction    UserInteraction    `json:"user_interaction"`
	Scope              Scope              `json:"scope"`

	// Impact Metrics (required)
	ConfidentialityImpact ConfidentialityImpact `json:"confidentiality_impact"`
	IntegrityImpact       IntegrityImpact       `json:"integrity_impact"`
	AvailabilityImpact    AvailabilityImpact    `json:"availability_impact"`

	// Temporal Metrics (optional)
	ExploitCodeMaturity ExploitCodeMaturity `json:"exploit_code_maturity,omitempty"`
	RemediationLevel    RemediationLevel    `json:"remediation_level,omitempty"`
	ReportConfidence    ReportConfidence    `json:"report_confidence,omitempty"`

	// Environmental Metrics (organizational customization)
	BusinessFunction      BusinessFunction      `json:"business_function,omitempty"`
	DataClassification    DataClassification    `json:"data_classification,omitempty"`
	ComplianceRequirement ComplianceRequirement `json:"compliance_requirement,omitempty"`
	BusinessContinuity    BusinessContinuity    `json:"business_continuity,omitempty"`
}

// Base Metric Enums
type AttackVector string

const (
	AttackVectorNetwork  AttackVector = "NETWORK"  // 0.85
	AttackVectorAdjacent AttackVector = "ADJACENT" // 0.62
	AttackVectorLocal    AttackVector = "LOCAL"    // 0.55
	AttackVectorPhysical AttackVector = "PHYSICAL" // 0.20
)

type AttackComplexity string

const (
	AttackComplexityLow  AttackComplexity = "LOW"  // 0.77
	AttackComplexityHigh AttackComplexity = "HIGH" // 0.44
)

type PrivilegesRequired string

const (
	PrivilegesRequiredNone PrivilegesRequired = "NONE" // 0.85
	PrivilegesRequiredLow  PrivilegesRequired = "LOW"  // 0.62
	PrivilegesRequiredHigh PrivilegesRequired = "HIGH" // 0.27
)

type UserInteraction string

const (
	UserInteractionNone     UserInteraction = "NONE"     // 0.85
	UserInteractionRequired UserInteraction = "REQUIRED" // 0.62
)

type Scope string

const (
	ScopeUnchanged Scope = "UNCHANGED" // 1.0
	ScopeChanged   Scope = "CHANGED"   // 1.08
)

// Impact Metrics
type ConfidentialityImpact string

const (
	ConfidentialityImpactNone ConfidentialityImpact = "NONE" // 0.0
	ConfidentialityImpactLow  ConfidentialityImpact = "LOW"  // 0.22
	ConfidentialityImpactHigh ConfidentialityImpact = "HIGH" // 0.56
)

type IntegrityImpact string

const (
	IntegrityImpactNone IntegrityImpact = "NONE" // 0.0
	IntegrityImpactLow  IntegrityImpact = "LOW"  // 0.22
	IntegrityImpactHigh IntegrityImpact = "HIGH" // 0.56
)

type AvailabilityImpact string

const (
	AvailabilityImpactNone AvailabilityImpact = "NONE" // 0.0
	AvailabilityImpactLow  AvailabilityImpact = "LOW"  // 0.22
	AvailabilityImpactHigh AvailabilityImpact = "HIGH" // 0.56
)

// Temporal Metrics
type ExploitCodeMaturity string

const (
	ExploitCodeMaturityNotDefined   ExploitCodeMaturity = "NOT_DEFINED"   // 1.0
	ExploitCodeMaturityUnproven     ExploitCodeMaturity = "UNPROVEN"      // 0.91
	ExploitCodeMaturityProofConcept ExploitCodeMaturity = "PROOF_CONCEPT" // 0.94
	ExploitCodeMaturityFunctional   ExploitCodeMaturity = "FUNCTIONAL"    // 0.97
	ExploitCodeMaturityHigh         ExploitCodeMaturity = "HIGH"          // 1.0
)

type RemediationLevel string

const (
	RemediationLevelNotDefined   RemediationLevel = "NOT_DEFINED"   // 1.0
	RemediationLevelOfficialFix  RemediationLevel = "OFFICIAL_FIX"  // 0.95
	RemediationLevelTemporaryFix RemediationLevel = "TEMPORARY_FIX" // 0.96
	RemediationLevelWorkaround   RemediationLevel = "WORKAROUND"    // 0.97
	RemediationLevelUnavailable  RemediationLevel = "UNAVAILABLE"   // 1.0
)

type ReportConfidence string

const (
	ReportConfidenceNotDefined ReportConfidence = "NOT_DEFINED" // 1.0
	ReportConfidenceUnknown    ReportConfidence = "UNKNOWN"     // 0.92
	ReportConfidenceReasonable ReportConfidence = "REASONABLE"  // 0.96
	ReportConfidenceConfirmed  ReportConfidence = "CONFIRMED"   // 1.0
)

// Environmental Metrics (Business-specific)
type BusinessFunction string

const (
	BusinessFunctionNotDefined      BusinessFunction = "NOT_DEFINED"      // 1.0
	BusinessFunctionSupporting      BusinessFunction = "SUPPORTING"       // 0.5
	BusinessFunctionOperational     BusinessFunction = "OPERATIONAL"      // 1.0
	BusinessFunctionCritical        BusinessFunction = "CRITICAL"         // 1.5
	BusinessFunctionMissionCritical BusinessFunction = "MISSION_CRITICAL" // 2.0
)

type DataClassification string

const (
	DataClassificationNotDefined   DataClassification = "NOT_DEFINED"  // 1.0
	DataClassificationPublic       DataClassification = "PUBLIC"       // 0.5
	DataClassificationInternal     DataClassification = "INTERNAL"     // 1.0
	DataClassificationConfidential DataClassification = "CONFIDENTIAL" // 1.5
	DataClassificationRestricted   DataClassification = "RESTRICTED"   // 2.0
)

type ComplianceRequirement string

const (
	ComplianceRequirementNotDefined ComplianceRequirement = "NOT_DEFINED" // 1.0
	ComplianceRequirementNone       ComplianceRequirement = "NONE"        // 1.0
	ComplianceRequirementStandard   ComplianceRequirement = "STANDARD"    // 1.2
	ComplianceRequirementRegulated  ComplianceRequirement = "REGULATED"   // 1.5
)

type BusinessContinuity string

const (
	BusinessContinuityNotDefined BusinessContinuity = "NOT_DEFINED" // 1.0
	BusinessContinuityLow        BusinessContinuity = "LOW"         // 0.8
	BusinessContinuityMedium     BusinessContinuity = "MEDIUM"      // 1.0
	BusinessContinuityHigh       BusinessContinuity = "HIGH"        // 1.3
	BusinessContinuityCritical   BusinessContinuity = "CRITICAL"    // 1.7
)

// BusinessImpactCalculator provides CVSS-style business impact calculation
type BusinessImpactCalculator struct {
	config *BusinessImpactConfig
}

// BusinessImpactConfig allows organizational customization
type BusinessImpactConfig struct {
	// Weight multipliers for different metric categories
	BaseWeight          float64 `json:"base_weight"`          // Default: 1.0
	TemporalWeight      float64 `json:"temporal_weight"`      // Default: 1.0
	EnvironmentalWeight float64 `json:"environmental_weight"` // Default: 1.0

	// Custom metric weights (overrides defaults)
	CustomWeights map[string]float64 `json:"custom_weights,omitempty"`

	// Scoring thresholds
	LowThreshold      float64 `json:"low_threshold"`      // Default: 3.9
	MediumThreshold   float64 `json:"medium_threshold"`   // Default: 6.9
	HighThreshold     float64 `json:"high_threshold"`     // Default: 8.9
	CriticalThreshold float64 `json:"critical_threshold"` // Default: 10.0
}

// NewBusinessImpactCalculator creates a new calculator with default config
func NewBusinessImpactCalculator() *BusinessImpactCalculator {
	return &BusinessImpactCalculator{
		config: &BusinessImpactConfig{
			BaseWeight:          1.0,
			TemporalWeight:      1.0,
			EnvironmentalWeight: 1.0,
			CustomWeights:       make(map[string]float64),
			LowThreshold:        3.9,
			MediumThreshold:     6.9,
			HighThreshold:       8.9,
			CriticalThreshold:   10.0,
		},
	}
}

// NewBusinessImpactCalculatorWithConfig creates calculator with custom config
func NewBusinessImpactCalculatorWithConfig(config *BusinessImpactConfig) *BusinessImpactCalculator {
	return &BusinessImpactCalculator{
		config: config,
	}
}

// LoadConfigFromJSON loads configuration from JSON
func (bic *BusinessImpactCalculator) LoadConfigFromJSON(jsonData []byte) error {
	return json.Unmarshal(jsonData, bic.config)
}

// CalculateScore computes the business impact score (0.0-10.0)
func (bic *BusinessImpactCalculator) CalculateScore(impact CVSSBusinessImpact) float64 {
	baseScore := bic.calculateBaseScore(impact)
	temporalScore := bic.calculateTemporalScore(baseScore, impact)
	environmentalScore := bic.calculateEnvironmentalScore(temporalScore, impact)

	return math.Min(10.0, environmentalScore)
}

// calculateBaseScore computes base CVSS score
func (bic *BusinessImpactCalculator) calculateBaseScore(impact CVSSBusinessImpact) float64 {
	// Get metric values
	av := bic.getAttackVectorValue(impact.AttackVector)
	ac := bic.getAttackComplexityValue(impact.AttackComplexity)
	pr := bic.getPrivilegesRequiredValue(impact.PrivilegesRequired, impact.Scope)
	ui := bic.getUserInteractionValue(impact.UserInteraction)

	c := bic.getConfidentialityImpactValue(impact.ConfidentialityImpact)
	i := bic.getIntegrityImpactValue(impact.IntegrityImpact)
	a := bic.getAvailabilityImpactValue(impact.AvailabilityImpact)

	// Calculate impact subscore
	impactSubScore := 1 - ((1 - c) * (1 - i) * (1 - a))

	// Calculate exploitability subscore
	exploitabilitySubScore := 8.22 * av * ac * pr * ui

	// Calculate base score
	var baseScore float64
	if impactSubScore <= 0 {
		baseScore = 0
	} else {
		scopeValue := bic.getScopeValue(impact.Scope)
		if impact.Scope == ScopeUnchanged {
			baseScore = math.Min(10.0, (impactSubScore + exploitabilitySubScore))
		} else {
			baseScore = math.Min(10.0, (impactSubScore*scopeValue + exploitabilitySubScore))
		}
		baseScore = math.Ceil(baseScore*10) / 10
	}

	return baseScore * bic.config.BaseWeight
}

// calculateTemporalScore applies temporal metrics
func (bic *BusinessImpactCalculator) calculateTemporalScore(baseScore float64, impact CVSSBusinessImpact) float64 {
	e := bic.getExploitCodeMaturityValue(impact.ExploitCodeMaturity)
	rl := bic.getRemediationLevelValue(impact.RemediationLevel)
	rc := bic.getReportConfidenceValue(impact.ReportConfidence)

	temporalScore := baseScore * e * rl * rc * bic.config.TemporalWeight
	return math.Ceil(temporalScore*10) / 10
}

// calculateEnvironmentalScore applies environmental (business) metrics
func (bic *BusinessImpactCalculator) calculateEnvironmentalScore(temporalScore float64, impact CVSSBusinessImpact) float64 {
	bf := bic.getBusinessFunctionValue(impact.BusinessFunction)
	dc := bic.getDataClassificationValue(impact.DataClassification)
	cr := bic.getComplianceRequirementValue(impact.ComplianceRequirement)
	bc := bic.getBusinessContinuityValue(impact.BusinessContinuity)

	// Combine environmental factors
	environmentalMultiplier := (bf + dc + cr + bc) / 4 * bic.config.EnvironmentalWeight

	environmentalScore := temporalScore * environmentalMultiplier
	return math.Ceil(environmentalScore*10) / 10
}

// GetSeverityLevel maps score to severity level
func (bic *BusinessImpactCalculator) GetSeverityLevel(score float64) types.BusinessImpactLevel {
	if score >= bic.config.CriticalThreshold {
		return types.BusinessImpactCritical
	} else if score >= bic.config.HighThreshold {
		return types.BusinessImpactHigh
	} else if score >= bic.config.MediumThreshold {
		return types.BusinessImpactMedium
	} else {
		return types.BusinessImpactLow
	}
}

// GenerateVectorString creates CVSS-style vector string
func (bic *BusinessImpactCalculator) GenerateVectorString(impact CVSSBusinessImpact) string {
	vector := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		string(impact.AttackVector),
		string(impact.AttackComplexity),
		string(impact.PrivilegesRequired),
		string(impact.UserInteraction),
		string(impact.Scope),
		string(impact.ConfidentialityImpact),
		string(impact.IntegrityImpact),
		string(impact.AvailabilityImpact),
	)

	// Add temporal metrics if specified
	if impact.ExploitCodeMaturity != "" {
		vector += fmt.Sprintf("/E:%s", string(impact.ExploitCodeMaturity))
	}
	if impact.RemediationLevel != "" {
		vector += fmt.Sprintf("/RL:%s", string(impact.RemediationLevel))
	}
	if impact.ReportConfidence != "" {
		vector += fmt.Sprintf("/RC:%s", string(impact.ReportConfidence))
	}

	// Add environmental metrics if specified
	if impact.BusinessFunction != "" {
		vector += fmt.Sprintf("/BF:%s", string(impact.BusinessFunction))
	}
	if impact.DataClassification != "" {
		vector += fmt.Sprintf("/DC:%s", string(impact.DataClassification))
	}
	if impact.ComplianceRequirement != "" {
		vector += fmt.Sprintf("/CR:%s", string(impact.ComplianceRequirement))
	}
	if impact.BusinessContinuity != "" {
		vector += fmt.Sprintf("/BC:%s", string(impact.BusinessContinuity))
	}

	return vector
}

// ParseVectorString parses CVSS-style vector string
func (bic *BusinessImpactCalculator) ParseVectorString(vectorString string) (*CVSSBusinessImpact, error) {
	impact := &CVSSBusinessImpact{}

	// Remove CVSS:3.1/ prefix if present
	vectorString = strings.TrimPrefix(vectorString, "CVSS:3.1/")

	// Split into components
	components := strings.Split(vectorString, "/")

	for _, component := range components {
		parts := strings.Split(component, ":")
		if len(parts) != 2 {
			continue
		}

		metric := parts[0]
		value := parts[1]

		switch metric {
		case "AV":
			impact.AttackVector = AttackVector(value)
		case "AC":
			impact.AttackComplexity = AttackComplexity(value)
		case "PR":
			impact.PrivilegesRequired = PrivilegesRequired(value)
		case "UI":
			impact.UserInteraction = UserInteraction(value)
		case "S":
			impact.Scope = Scope(value)
		case "C":
			impact.ConfidentialityImpact = ConfidentialityImpact(value)
		case "I":
			impact.IntegrityImpact = IntegrityImpact(value)
		case "A":
			impact.AvailabilityImpact = AvailabilityImpact(value)
		case "E":
			impact.ExploitCodeMaturity = ExploitCodeMaturity(value)
		case "RL":
			impact.RemediationLevel = RemediationLevel(value)
		case "RC":
			impact.ReportConfidence = ReportConfidence(value)
		case "BF":
			impact.BusinessFunction = BusinessFunction(value)
		case "DC":
			impact.DataClassification = DataClassification(value)
		case "CR":
			impact.ComplianceRequirement = ComplianceRequirement(value)
		case "BC":
			impact.BusinessContinuity = BusinessContinuity(value)
		}
	}

	return impact, nil
}

// Helper methods to get metric values with custom weight support
func (bic *BusinessImpactCalculator) getAttackVectorValue(av AttackVector) float64 {
	if custom, exists := bic.config.CustomWeights["AV:"+string(av)]; exists {
		return custom
	}

	switch av {
	case AttackVectorNetwork:
		return 0.85
	case AttackVectorAdjacent:
		return 0.62
	case AttackVectorLocal:
		return 0.55
	case AttackVectorPhysical:
		return 0.20
	default:
		return 0.85
	}
}

func (bic *BusinessImpactCalculator) getAttackComplexityValue(ac AttackComplexity) float64 {
	if custom, exists := bic.config.CustomWeights["AC:"+string(ac)]; exists {
		return custom
	}

	switch ac {
	case AttackComplexityLow:
		return 0.77
	case AttackComplexityHigh:
		return 0.44
	default:
		return 0.77
	}
}

func (bic *BusinessImpactCalculator) getPrivilegesRequiredValue(pr PrivilegesRequired, scope Scope) float64 {
	key := "PR:" + string(pr)
	if scope == ScopeChanged {
		key += ":CHANGED"
	}

	if custom, exists := bic.config.CustomWeights[key]; exists {
		return custom
	}

	switch pr {
	case PrivilegesRequiredNone:
		return 0.85
	case PrivilegesRequiredLow:
		if scope == ScopeChanged {
			return 0.68
		}
		return 0.62
	case PrivilegesRequiredHigh:
		if scope == ScopeChanged {
			return 0.50
		}
		return 0.27
	default:
		return 0.85
	}
}

func (bic *BusinessImpactCalculator) getUserInteractionValue(ui UserInteraction) float64 {
	if custom, exists := bic.config.CustomWeights["UI:"+string(ui)]; exists {
		return custom
	}

	switch ui {
	case UserInteractionNone:
		return 0.85
	case UserInteractionRequired:
		return 0.62
	default:
		return 0.85
	}
}

func (bic *BusinessImpactCalculator) getScopeValue(s Scope) float64 {
	if custom, exists := bic.config.CustomWeights["S:"+string(s)]; exists {
		return custom
	}

	switch s {
	case ScopeUnchanged:
		return 1.0
	case ScopeChanged:
		return 1.08
	default:
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getConfidentialityImpactValue(c ConfidentialityImpact) float64 {
	if custom, exists := bic.config.CustomWeights["C:"+string(c)]; exists {
		return custom
	}

	switch c {
	case ConfidentialityImpactNone:
		return 0.0
	case ConfidentialityImpactLow:
		return 0.22
	case ConfidentialityImpactHigh:
		return 0.56
	default:
		return 0.0
	}
}

func (bic *BusinessImpactCalculator) getIntegrityImpactValue(i IntegrityImpact) float64 {
	if custom, exists := bic.config.CustomWeights["I:"+string(i)]; exists {
		return custom
	}

	switch i {
	case IntegrityImpactNone:
		return 0.0
	case IntegrityImpactLow:
		return 0.22
	case IntegrityImpactHigh:
		return 0.56
	default:
		return 0.0
	}
}

func (bic *BusinessImpactCalculator) getAvailabilityImpactValue(a AvailabilityImpact) float64 {
	if custom, exists := bic.config.CustomWeights["A:"+string(a)]; exists {
		return custom
	}

	switch a {
	case AvailabilityImpactNone:
		return 0.0
	case AvailabilityImpactLow:
		return 0.22
	case AvailabilityImpactHigh:
		return 0.56
	default:
		return 0.0
	}
}

func (bic *BusinessImpactCalculator) getExploitCodeMaturityValue(e ExploitCodeMaturity) float64 {
	if custom, exists := bic.config.CustomWeights["E:"+string(e)]; exists {
		return custom
	}

	switch e {
	case ExploitCodeMaturityUnproven:
		return 0.91
	case ExploitCodeMaturityProofConcept:
		return 0.94
	case ExploitCodeMaturityFunctional:
		return 0.97
	case ExploitCodeMaturityHigh:
		return 1.0
	default: // NOT_DEFINED
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getRemediationLevelValue(rl RemediationLevel) float64 {
	if custom, exists := bic.config.CustomWeights["RL:"+string(rl)]; exists {
		return custom
	}

	switch rl {
	case RemediationLevelOfficialFix:
		return 0.95
	case RemediationLevelTemporaryFix:
		return 0.96
	case RemediationLevelWorkaround:
		return 0.97
	case RemediationLevelUnavailable:
		return 1.0
	default: // NOT_DEFINED
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getReportConfidenceValue(rc ReportConfidence) float64 {
	if custom, exists := bic.config.CustomWeights["RC:"+string(rc)]; exists {
		return custom
	}

	switch rc {
	case ReportConfidenceUnknown:
		return 0.92
	case ReportConfidenceReasonable:
		return 0.96
	case ReportConfidenceConfirmed:
		return 1.0
	default: // NOT_DEFINED
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getBusinessFunctionValue(bf BusinessFunction) float64 {
	if custom, exists := bic.config.CustomWeights["BF:"+string(bf)]; exists {
		return custom
	}

	switch bf {
	case BusinessFunctionSupporting:
		return 0.5
	case BusinessFunctionOperational:
		return 1.0
	case BusinessFunctionCritical:
		return 1.5
	case BusinessFunctionMissionCritical:
		return 2.0
	default: // NOT_DEFINED
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getDataClassificationValue(dc DataClassification) float64 {
	if custom, exists := bic.config.CustomWeights["DC:"+string(dc)]; exists {
		return custom
	}

	switch dc {
	case DataClassificationPublic:
		return 0.5
	case DataClassificationInternal:
		return 1.0
	case DataClassificationConfidential:
		return 1.5
	case DataClassificationRestricted:
		return 2.0
	default: // NOT_DEFINED
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getComplianceRequirementValue(cr ComplianceRequirement) float64 {
	if custom, exists := bic.config.CustomWeights["CR:"+string(cr)]; exists {
		return custom
	}

	switch cr {
	case ComplianceRequirementNone:
		return 1.0
	case ComplianceRequirementStandard:
		return 1.2
	case ComplianceRequirementRegulated:
		return 1.5
	default: // NOT_DEFINED
		return 1.0
	}
}

func (bic *BusinessImpactCalculator) getBusinessContinuityValue(bc BusinessContinuity) float64 {
	if custom, exists := bic.config.CustomWeights["BC:"+string(bc)]; exists {
		return custom
	}

	switch bc {
	case BusinessContinuityLow:
		return 0.8
	case BusinessContinuityMedium:
		return 1.0
	case BusinessContinuityHigh:
		return 1.3
	case BusinessContinuityCritical:
		return 1.7
	default: // NOT_DEFINED
		return 1.0
	}
}
