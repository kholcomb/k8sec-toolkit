package analysis

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

// RiskScorer provides advanced risk scoring algorithms for executive summaries
type RiskScorer struct {
	// Configuration for risk calculation
	SeverityWeights    map[string]float64
	TypeWeights        map[string]float64
	AssetWeights       map[string]float64
	ExposureMultiplier float64
	AgeDecayFactor     float64
}

// NewRiskScorer creates a new risk scorer with default weights
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		SeverityWeights: map[string]float64{
			"CRITICAL": 10.0,
			"HIGH":     7.5,
			"MEDIUM":   5.0,
			"LOW":      2.5,
			"INFO":     1.0,
		},
		TypeWeights: map[string]float64{
			"vulnerability":    1.0,
			"misconfiguration": 0.8,
			"compliance":       0.6,
			"rbac":             0.9,
			"best-practice":    0.4,
		},
		AssetWeights: map[string]float64{
			"Pod":              1.0,
			"Deployment":       1.2,
			"StatefulSet":      1.2,
			"DaemonSet":        1.1,
			"Service":          0.8,
			"Ingress":          1.3,
			"NetworkPolicy":    0.7,
			"ServiceAccount":   0.9,
			"Role":             0.8,
			"ClusterRole":      1.1,
			"PersistentVolume": 0.9,
			"ConfigMap":        0.6,
			"Secret":           1.4,
		},
		ExposureMultiplier: 1.5,  // Multiplier for internet-exposed resources
		AgeDecayFactor:     0.95, // Daily decay factor for finding age
	}
}

// CalculateOverallRiskScore computes the overall risk score (0-100) for a scan result
func (rs *RiskScorer) CalculateOverallRiskScore(scanResult *types.ScanResult) float64 {
	if len(scanResult.Findings) == 0 {
		return 0.0
	}

	totalRisk := 0.0
	maxPossibleRisk := 0.0

	for _, finding := range scanResult.Findings {
		risk := rs.calculateFindingRisk(finding)
		totalRisk += risk
		maxPossibleRisk += rs.SeverityWeights["CRITICAL"] * rs.TypeWeights["vulnerability"] * rs.AssetWeights["Secret"] * rs.ExposureMultiplier
	}

	if maxPossibleRisk == 0 {
		return 0.0
	}

	// Normalize to 0-100 scale with diminishing returns for very high counts
	normalizedScore := (totalRisk / maxPossibleRisk) * 100

	// Apply logarithmic scaling to prevent scores > 100 with many findings
	if normalizedScore > 50 {
		normalizedScore = 50 + (50 * math.Log10(1+(normalizedScore-50)/50))
	}

	return math.Min(100.0, normalizedScore)
}

// calculateFindingRisk calculates risk for a single finding
func (rs *RiskScorer) calculateFindingRisk(finding types.SecurityFinding) float64 {
	// Base severity weight
	severityWeight := rs.SeverityWeights[finding.Severity]
	if severityWeight == 0 {
		severityWeight = rs.SeverityWeights["INFO"]
	}

	// Finding type weight
	typeWeight := rs.TypeWeights[finding.Type]
	if typeWeight == 0 {
		typeWeight = 0.5 // Default for unknown types
	}

	// Asset criticality weight
	assetWeight := rs.AssetWeights[finding.Resource.Kind]
	if assetWeight == 0 {
		assetWeight = 1.0 // Default for unknown asset types
	}

	// Exposure multiplier (check if resource might be exposed)
	exposureMultiplier := 1.0
	if rs.isExposedResource(finding) {
		exposureMultiplier = rs.ExposureMultiplier
	}

	// CVSS bonus for vulnerabilities
	cvssBonus := 1.0
	if finding.CVSS > 0 {
		cvssBonus = 1.0 + (finding.CVSS / 100.0) // Slight bonus for higher CVSS scores
	}

	// Age decay (newer findings are more critical)
	ageMultiplier := rs.calculateAgeMultiplier(finding.Timestamp)

	return severityWeight * typeWeight * assetWeight * exposureMultiplier * cvssBonus * ageMultiplier
}

// isExposedResource determines if a resource might be internet-exposed
func (rs *RiskScorer) isExposedResource(finding types.SecurityFinding) bool {
	resourceKind := strings.ToLower(finding.Resource.Kind)

	// Resources that are commonly exposed
	exposedTypes := []string{"ingress", "service", "pod"}
	for _, exposedType := range exposedTypes {
		if strings.Contains(resourceKind, exposedType) {
			return true
		}
	}

	// Check for specific indicators in the finding
	description := strings.ToLower(finding.Description)
	title := strings.ToLower(finding.Title)

	exposureIndicators := []string{
		"exposed", "public", "internet", "external", "loadbalancer",
		"nodeport", "ingress", "0.0.0.0", "privileged", "hostnetwork",
	}

	for _, indicator := range exposureIndicators {
		if strings.Contains(description, indicator) || strings.Contains(title, indicator) {
			return true
		}
	}

	return false
}

// calculateAgeMultiplier applies decay based on finding age
func (rs *RiskScorer) calculateAgeMultiplier(timestamp time.Time) float64 {
	if timestamp.IsZero() {
		return 1.0 // No timestamp, assume current
	}

	daysSinceFound := time.Since(timestamp).Hours() / 24
	return math.Pow(rs.AgeDecayFactor, daysSinceFound)
}

// DetermineSecurityPosture determines overall security posture level
func (rs *RiskScorer) DetermineSecurityPosture(riskScore float64, findings []types.SecurityFinding) types.SecurityPostureLevel {
	criticalCount := 0
	highCount := 0

	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	// Critical conditions
	if criticalCount > 0 && riskScore > 80 {
		return types.SecurityPostureCritical
	}

	if riskScore >= 80 {
		return types.SecurityPosturePoor
	} else if riskScore >= 60 {
		return types.SecurityPostureFair
	} else if riskScore >= 30 {
		return types.SecurityPostureGood
	} else {
		return types.SecurityPostureExcellent
	}
}

// CalculateBusinessImpact assesses potential business impact
func (rs *RiskScorer) CalculateBusinessImpact(findings []types.SecurityFinding, clusterInfo *types.ClusterInfo) types.BusinessImpactLevel {
	criticalFindings := 0
	highFindings := 0
	exposedFindings := 0
	dataRelatedFindings := 0

	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			criticalFindings++
		case "HIGH":
			highFindings++
		}

		if rs.isExposedResource(finding) {
			exposedFindings++
		}

		if rs.isDataRelated(finding) {
			dataRelatedFindings++
		}
	}

	// Calculate cluster criticality factor
	clusterCriticalityFactor := 1.0
	if clusterInfo != nil {
		// Larger clusters or production environments increase impact
		if clusterInfo.NodeCount > 50 || strings.Contains(strings.ToLower(clusterInfo.Name), "prod") {
			clusterCriticalityFactor = 1.5
		}
	}

	// Weighted impact calculation
	impactScore := float64(criticalFindings)*10 + float64(highFindings)*5 +
		float64(exposedFindings)*3 + float64(dataRelatedFindings)*4
	impactScore *= clusterCriticalityFactor

	if impactScore >= 50 {
		return types.BusinessImpactCritical
	} else if impactScore >= 25 {
		return types.BusinessImpactHigh
	} else if impactScore >= 10 {
		return types.BusinessImpactMedium
	} else {
		return types.BusinessImpactLow
	}
}

// isDataRelated checks if finding relates to data security
func (rs *RiskScorer) isDataRelated(finding types.SecurityFinding) bool {
	text := strings.ToLower(finding.Description + " " + finding.Title)
	dataIndicators := []string{
		"secret", "password", "token", "key", "credential", "database",
		"pii", "pci", "gdpr", "encryption", "tls", "ssl", "cert",
	}

	for _, indicator := range dataIndicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}

	return finding.Resource.Kind == "Secret" || finding.Resource.Kind == "ConfigMap"
}

// CalculateRiskDistribution breaks down risk by category
func (rs *RiskScorer) CalculateRiskDistribution(findings []types.SecurityFinding) types.RiskDistribution {
	categoryRisks := map[string]float64{
		"infrastructure":   0,
		"applications":     0,
		"configuration":    0,
		"access_control":   0,
		"network_security": 0,
		"data_protection":  0,
	}

	totalRisk := 0.0

	for _, finding := range findings {
		risk := rs.calculateFindingRisk(finding)
		totalRisk += risk

		// Categorize the finding
		category := rs.categorizeFinding(finding)
		categoryRisks[category] += risk
	}

	// Convert to percentages
	dist := types.RiskDistribution{}
	if totalRisk > 0 {
		dist.Infrastructure = (categoryRisks["infrastructure"] / totalRisk) * 100
		dist.Applications = (categoryRisks["applications"] / totalRisk) * 100
		dist.Configuration = (categoryRisks["configuration"] / totalRisk) * 100
		dist.AccessControl = (categoryRisks["access_control"] / totalRisk) * 100
		dist.NetworkSecurity = (categoryRisks["network_security"] / totalRisk) * 100
		dist.DataProtection = (categoryRisks["data_protection"] / totalRisk) * 100
	}

	return dist
}

// categorizeFinding assigns a finding to a risk category
func (rs *RiskScorer) categorizeFinding(finding types.SecurityFinding) string {
	text := strings.ToLower(finding.Description + " " + finding.Title + " " + finding.Type)

	// Data protection indicators
	if strings.Contains(text, "secret") || strings.Contains(text, "encryption") ||
		strings.Contains(text, "tls") || finding.Resource.Kind == "Secret" {
		return "data_protection"
	}

	// Network security indicators
	if strings.Contains(text, "network") || strings.Contains(text, "ingress") ||
		strings.Contains(text, "service") || strings.Contains(text, "port") {
		return "network_security"
	}

	// Access control indicators
	if finding.Type == "rbac" || strings.Contains(text, "rbac") ||
		strings.Contains(text, "permission") || strings.Contains(text, "role") {
		return "access_control"
	}

	// Configuration indicators
	if finding.Type == "misconfiguration" || finding.Type == "best-practice" ||
		strings.Contains(text, "config") {
		return "configuration"
	}

	// Infrastructure indicators
	if strings.Contains(text, "node") || strings.Contains(text, "cluster") ||
		strings.Contains(text, "runtime") || strings.Contains(text, "kernel") {
		return "infrastructure"
	}

	// Default to applications
	return "applications"
}

// GenerateTopRisks identifies the top security risks requiring immediate attention
func (rs *RiskScorer) GenerateTopRisks(findings []types.SecurityFinding, limit int) []types.TopRisk {
	// Score all findings and sort by risk
	type scoredFinding struct {
		finding types.SecurityFinding
		risk    float64
	}

	var scoredFindings []scoredFinding
	for _, finding := range findings {
		risk := rs.calculateFindingRisk(finding)
		scoredFindings = append(scoredFindings, scoredFinding{finding, risk})
	}

	// Sort by risk (highest first)
	sort.Slice(scoredFindings, func(i, j int) bool {
		return scoredFindings[i].risk > scoredFindings[j].risk
	})

	// Generate top risks
	var topRisks []types.TopRisk
	for i := 0; i < len(scoredFindings) && i < limit; i++ {
		sf := scoredFindings[i]
		topRisk := rs.convertFindingToTopRisk(sf.finding, sf.risk)
		topRisks = append(topRisks, topRisk)
	}

	return topRisks
}

// convertFindingToTopRisk converts a finding to a TopRisk structure
func (rs *RiskScorer) convertFindingToTopRisk(finding types.SecurityFinding, risk float64) types.TopRisk {
	// Normalize risk to 0-100 scale
	normalizedRisk := math.Min(100.0, risk*5) // Scale factor for display

	// Determine probability based on exposure and type
	probability := "Medium"
	if rs.isExposedResource(finding) {
		probability = "High"
	} else if finding.Severity == "LOW" || finding.Severity == "INFO" {
		probability = "Low"
	}

	// Estimate cost based on severity and type
	estimatedCost := rs.estimateBreachCost(finding)

	// Time to exploit assessment
	timeToExploit := rs.assessTimeToExploit(finding)

	return types.TopRisk{
		ID:                finding.ID,
		Title:             finding.Title,
		Description:       finding.Description,
		Impact:            rs.mapSeverityToBusinessImpact(finding.Severity),
		Probability:       probability,
		RiskScore:         normalizedRisk,
		Category:          rs.categorizeFinding(finding),
		AffectedAssets:    1, // Could be enhanced to count multiple assets
		EstimatedCost:     estimatedCost,
		TimeToExploit:     timeToExploit,
		RecommendedAction: rs.generateRecommendedAction(finding),
	}
}

// mapSeverityToBusinessImpact maps finding severity to business impact
func (rs *RiskScorer) mapSeverityToBusinessImpact(severity string) types.BusinessImpactLevel {
	switch severity {
	case "CRITICAL":
		return types.BusinessImpactCritical
	case "HIGH":
		return types.BusinessImpactHigh
	case "MEDIUM":
		return types.BusinessImpactMedium
	default:
		return types.BusinessImpactLow
	}
}

// estimateBreachCost provides cost estimates for different types of findings
func (rs *RiskScorer) estimateBreachCost(finding types.SecurityFinding) string {
	if finding.Severity == "CRITICAL" {
		if rs.isDataRelated(finding) {
			return "$500K - $2M+"
		}
		return "$100K - $500K"
	} else if finding.Severity == "HIGH" {
		if rs.isExposedResource(finding) {
			return "$50K - $200K"
		}
		return "$10K - $100K"
	} else {
		return "< $10K"
	}
}

// assessTimeToExploit estimates how quickly a vulnerability could be exploited
func (rs *RiskScorer) assessTimeToExploit(finding types.SecurityFinding) string {
	if finding.Type == "vulnerability" && finding.CVSS >= 9.0 {
		return "Minutes to Hours"
	} else if finding.Severity == "CRITICAL" {
		return "Hours to Days"
	} else if finding.Severity == "HIGH" && rs.isExposedResource(finding) {
		return "Days to Weeks"
	} else {
		return "Weeks to Months"
	}
}

// generateRecommendedAction provides actionable remediation guidance
func (rs *RiskScorer) generateRecommendedAction(finding types.SecurityFinding) string {
	if finding.Type == "vulnerability" {
		if finding.FixedIn != "" {
			return "Update to version " + finding.FixedIn + " or apply security patches"
		}
		return "Apply available security patches or implement compensating controls"
	} else if finding.Type == "misconfiguration" {
		return "Review and correct configuration settings as per security best practices"
	} else if finding.Type == "rbac" {
		return "Review and restrict RBAC permissions following principle of least privilege"
	} else {
		return "Review finding details and implement recommended security controls"
	}
}
