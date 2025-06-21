package analysis

import (
	"testing"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestNewRiskScorer(t *testing.T) {
	rs := NewRiskScorer()

	// Verify default weights are set correctly
	if rs.SeverityWeights["CRITICAL"] != 10.0 {
		t.Errorf("Expected CRITICAL severity weight to be 10.0, got %f", rs.SeverityWeights["CRITICAL"])
	}

	if rs.TypeWeights["vulnerability"] != 1.0 {
		t.Errorf("Expected vulnerability type weight to be 1.0, got %f", rs.TypeWeights["vulnerability"])
	}

	if rs.AssetWeights["Secret"] != 1.4 {
		t.Errorf("Expected Secret asset weight to be 1.4, got %f", rs.AssetWeights["Secret"])
	}

	if rs.ExposureMultiplier != 1.5 {
		t.Errorf("Expected exposure multiplier to be 1.5, got %f", rs.ExposureMultiplier)
	}
}

func TestCalculateOverallRiskScore(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name        string
		findings    []types.SecurityFinding
		expectedMin float64
		expectedMax float64
	}{
		{
			name:        "No findings",
			findings:    []types.SecurityFinding{},
			expectedMin: 0.0,
			expectedMax: 0.0,
		},
		{
			name: "Single critical vulnerability",
			findings: []types.SecurityFinding{
				{
					ID:          "test-1",
					Type:        "vulnerability",
					Severity:    "CRITICAL",
					Title:       "Critical vulnerability",
					Description: "Remote code execution",
					CVE:         "CVE-2021-12345",
					CVSS:        9.8,
					Resource: types.ResourceReference{
						Kind:      "Pod",
						Name:      "test-pod",
						Namespace: "default",
					},
					Timestamp: time.Now(),
				},
			},
			expectedMin: 5.0,
			expectedMax: 25.0,
		},
		{
			name: "Multiple findings with varying severity",
			findings: []types.SecurityFinding{
				{
					ID:        "test-1",
					Type:      "vulnerability",
					Severity:  "CRITICAL",
					Resource:  types.ResourceReference{Kind: "Secret", Name: "secret1"},
					Timestamp: time.Now(),
				},
				{
					ID:        "test-2",
					Type:      "misconfiguration",
					Severity:  "HIGH",
					Resource:  types.ResourceReference{Kind: "Pod", Name: "pod1"},
					Timestamp: time.Now(),
				},
				{
					ID:        "test-3",
					Type:      "best-practice",
					Severity:  "LOW",
					Resource:  types.ResourceReference{Kind: "ConfigMap", Name: "config1"},
					Timestamp: time.Now(),
				},
			},
			expectedMin: 10.0,
			expectedMax: 50.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanResult := &types.ScanResult{
				Findings: tt.findings,
			}

			score := rs.CalculateOverallRiskScore(scanResult)

			if score < tt.expectedMin || score > tt.expectedMax {
				t.Errorf("Risk score %f not in expected range [%f, %f]", score, tt.expectedMin, tt.expectedMax)
			}

			// Ensure score is within valid range
			if score < 0 || score > 100 {
				t.Errorf("Risk score %f outside valid range [0, 100]", score)
			}
		})
	}
}

func TestCalculateFindingRisk(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name     string
		finding  types.SecurityFinding
		expected func(float64) bool // Function to validate the score
	}{
		{
			name: "Critical vulnerability in exposed service",
			finding: types.SecurityFinding{
				Type:        "vulnerability",
				Severity:    "CRITICAL",
				Description: "Remote code execution in exposed service",
				Resource:    types.ResourceReference{Kind: "Service", Name: "web-service"},
				CVSS:        9.8,
				Timestamp:   time.Now(),
			},
			expected: func(score float64) bool { return score > 10.0 && score < 20.0 },
		},
		{
			name: "Low severity config issue",
			finding: types.SecurityFinding{
				Type:      "misconfiguration",
				Severity:  "LOW",
				Resource:  types.ResourceReference{Kind: "ConfigMap", Name: "config"},
				Timestamp: time.Now(),
			},
			expected: func(score float64) bool { return score > 0.5 && score < 3.0 },
		},
		{
			name: "High severity secret exposure",
			finding: types.SecurityFinding{
				Type:        "vulnerability",
				Severity:    "HIGH",
				Description: "Secret exposed in public repository",
				Resource:    types.ResourceReference{Kind: "Secret", Name: "api-key"},
				Timestamp:   time.Now(),
			},
			expected: func(score float64) bool { return score > 8.0 && score < 20.0 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := rs.calculateFindingRisk(tt.finding)

			if !tt.expected(score) {
				t.Errorf("Finding risk score %f not in expected range for %s", score, tt.name)
			}
		})
	}
}

func TestIsExposedResource(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name     string
		finding  types.SecurityFinding
		expected bool
	}{
		{
			name: "Ingress resource",
			finding: types.SecurityFinding{
				Resource: types.ResourceReference{Kind: "Ingress"},
			},
			expected: true,
		},
		{
			name: "Service with exposure description",
			finding: types.SecurityFinding{
				Resource:    types.ResourceReference{Kind: "Service"},
				Description: "Service exposed to internet",
			},
			expected: true,
		},
		{
			name: "Pod with privileged access",
			finding: types.SecurityFinding{
				Resource: types.ResourceReference{Kind: "Pod"},
				Title:    "Privileged container detected",
			},
			expected: true,
		},
		{
			name: "ConfigMap without exposure",
			finding: types.SecurityFinding{
				Resource:    types.ResourceReference{Kind: "ConfigMap"},
				Description: "Invalid configuration parameter",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rs.isExposedResource(tt.finding)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.name, result)
			}
		})
	}
}

func TestCalculateAgeMultiplier(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name      string
		timestamp time.Time
		expected  func(float64) bool
	}{
		{
			name:      "Current timestamp",
			timestamp: time.Now(),
			expected:  func(m float64) bool { return m >= 0.95 && m <= 1.0 },
		},
		{
			name:      "One week old",
			timestamp: time.Now().AddDate(0, 0, -7),
			expected:  func(m float64) bool { return m >= 0.6 && m < 0.95 },
		},
		{
			name:      "One month old",
			timestamp: time.Now().AddDate(0, -1, 0),
			expected:  func(m float64) bool { return m >= 0.15 && m < 0.4 },
		},
		{
			name:      "Zero timestamp",
			timestamp: time.Time{},
			expected:  func(m float64) bool { return m == 1.0 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multiplier := rs.calculateAgeMultiplier(tt.timestamp)

			if !tt.expected(multiplier) {
				t.Errorf("Age multiplier %f not in expected range for %s", multiplier, tt.name)
			}
		})
	}
}

func TestDetermineSecurityPosture(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name      string
		riskScore float64
		findings  []types.SecurityFinding
		expected  types.SecurityPostureLevel
	}{
		{
			name:      "Critical with high score",
			riskScore: 85.0,
			findings: []types.SecurityFinding{
				{Severity: "CRITICAL"},
			},
			expected: types.SecurityPostureCritical,
		},
		{
			name:      "Poor security posture",
			riskScore: 85.0,
			findings:  []types.SecurityFinding{{Severity: "HIGH"}},
			expected:  types.SecurityPosturePoor,
		},
		{
			name:      "Fair security posture",
			riskScore: 65.0,
			findings:  []types.SecurityFinding{{Severity: "MEDIUM"}},
			expected:  types.SecurityPostureFair,
		},
		{
			name:      "Good security posture",
			riskScore: 45.0,
			findings:  []types.SecurityFinding{{Severity: "LOW"}},
			expected:  types.SecurityPostureGood,
		},
		{
			name:      "Excellent security posture",
			riskScore: 15.0,
			findings:  []types.SecurityFinding{{Severity: "INFO"}},
			expected:  types.SecurityPostureExcellent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rs.DetermineSecurityPosture(tt.riskScore, tt.findings)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.name, result)
			}
		})
	}
}

func TestCalculateBusinessImpact(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name        string
		findings    []types.SecurityFinding
		clusterInfo *types.ClusterInfo
		expected    types.BusinessImpactLevel
	}{
		{
			name: "Critical impact with production cluster",
			findings: []types.SecurityFinding{
				{Severity: "CRITICAL", Resource: types.ResourceReference{Kind: "Secret"}},
				{Severity: "CRITICAL", Description: "exposed service"},
				{Severity: "CRITICAL", Description: "secret exposed"},
				{Severity: "HIGH", Description: "network exposed"},
			},
			clusterInfo: &types.ClusterInfo{
				Name:      "prod-cluster",
				NodeCount: 100,
			},
			expected: types.BusinessImpactCritical,
		},
		{
			name: "High impact with multiple high findings",
			findings: []types.SecurityFinding{
				{Severity: "HIGH", Resource: types.ResourceReference{Kind: "Pod"}},
				{Severity: "HIGH", Description: "network exposed"},
				{Severity: "HIGH", Resource: types.ResourceReference{Kind: "Secret"}},
			},
			clusterInfo: &types.ClusterInfo{NodeCount: 10},
			expected:    types.BusinessImpactHigh,
		},
		{
			name: "Medium impact",
			findings: []types.SecurityFinding{
				{Severity: "HIGH", Resource: types.ResourceReference{Kind: "Pod"}},
				{Severity: "MEDIUM", Resource: types.ResourceReference{Kind: "Pod"}},
				{Severity: "MEDIUM", Description: "secret exposed"},
			},
			clusterInfo: nil,
			expected:    types.BusinessImpactMedium,
		},
		{
			name: "Low impact",
			findings: []types.SecurityFinding{
				{Severity: "LOW"},
				{Severity: "INFO"},
			},
			clusterInfo: nil,
			expected:    types.BusinessImpactLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rs.CalculateBusinessImpact(tt.findings, tt.clusterInfo)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.name, result)
			}
		})
	}
}

func TestCalculateRiskDistribution(t *testing.T) {
	rs := NewRiskScorer()

	findings := []types.SecurityFinding{
		{Type: "vulnerability", Resource: types.ResourceReference{Kind: "Secret"}, Severity: "HIGH"},
		{Type: "misconfiguration", Resource: types.ResourceReference{Kind: "Pod"}, Severity: "MEDIUM"},
		{Type: "rbac", Description: "excessive permissions", Severity: "HIGH"},
		{Type: "vulnerability", Resource: types.ResourceReference{Kind: "Service"}, Severity: "LOW"},
	}

	distribution := rs.CalculateRiskDistribution(findings)

	// Check that percentages add up to approximately 100%
	total := distribution.Infrastructure + distribution.Applications +
		distribution.Configuration + distribution.AccessControl +
		distribution.NetworkSecurity + distribution.DataProtection

	if total < 99.0 || total > 101.0 {
		t.Errorf("Risk distribution percentages should sum to ~100%%, got %f", total)
	}

	// Data protection should have some percentage due to Secret finding
	if distribution.DataProtection <= 0 {
		t.Error("Expected data protection risk > 0 due to Secret finding")
	}

	// Access control should have some percentage due to RBAC finding
	if distribution.AccessControl <= 0 {
		t.Error("Expected access control risk > 0 due to RBAC finding")
	}
}

func TestGenerateTopRisks(t *testing.T) {
	rs := NewRiskScorer()

	findings := []types.SecurityFinding{
		{
			ID:          "high-risk",
			Type:        "vulnerability",
			Severity:    "CRITICAL",
			Title:       "Critical vulnerability",
			Description: "Remote code execution",
			CVE:         "CVE-2021-12345",
			CVSS:        9.8,
			Resource:    types.ResourceReference{Kind: "Service", Name: "web-service"},
		},
		{
			ID:       "medium-risk",
			Type:     "misconfiguration",
			Severity: "HIGH",
			Title:    "Configuration issue",
			Resource: types.ResourceReference{Kind: "Pod", Name: "app-pod"},
		},
		{
			ID:       "low-risk",
			Type:     "best-practice",
			Severity: "LOW",
			Title:    "Best practice violation",
			Resource: types.ResourceReference{Kind: "ConfigMap", Name: "config"},
		},
	}

	topRisks := rs.GenerateTopRisks(findings, 2)

	if len(topRisks) != 2 {
		t.Errorf("Expected 2 top risks, got %d", len(topRisks))
	}

	// First risk should be the highest (critical vulnerability)
	if topRisks[0].ID != "high-risk" {
		t.Errorf("Expected first risk to be 'high-risk', got %s", topRisks[0].ID)
	}

	// Risk scores should be in descending order
	if len(topRisks) > 1 && topRisks[0].RiskScore < topRisks[1].RiskScore {
		t.Error("Top risks should be sorted by risk score in descending order")
	}

	// Verify fields are populated
	firstRisk := topRisks[0]
	if firstRisk.Impact == "" {
		t.Error("Top risk impact should be populated")
	}
	if firstRisk.Probability == "" {
		t.Error("Top risk probability should be populated")
	}
	if firstRisk.EstimatedCost == "" {
		t.Error("Top risk estimated cost should be populated")
	}
	if firstRisk.RecommendedAction == "" {
		t.Error("Top risk recommended action should be populated")
	}
}

func TestEstimateBreachCost(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name     string
		finding  types.SecurityFinding
		expected string
	}{
		{
			name: "Critical data-related finding",
			finding: types.SecurityFinding{
				Severity:    "CRITICAL",
				Description: "Secret exposure with PII data",
			},
			expected: "$500K - $2M+",
		},
		{
			name: "Critical non-data finding",
			finding: types.SecurityFinding{
				Severity: "CRITICAL",
				Title:    "Remote code execution",
			},
			expected: "$100K - $500K",
		},
		{
			name: "High severity exposed",
			finding: types.SecurityFinding{
				Severity:    "HIGH",
				Description: "Service exposed to internet",
			},
			expected: "$50K - $200K",
		},
		{
			name: "High severity not exposed",
			finding: types.SecurityFinding{
				Severity: "HIGH",
				Title:    "Configuration issue",
			},
			expected: "$10K - $100K",
		},
		{
			name: "Low severity",
			finding: types.SecurityFinding{
				Severity: "LOW",
			},
			expected: "< $10K",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rs.estimateBreachCost(tt.finding)
			if result != tt.expected {
				t.Errorf("Expected cost estimate '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestAssessTimeToExploit(t *testing.T) {
	rs := NewRiskScorer()

	tests := []struct {
		name     string
		finding  types.SecurityFinding
		expected string
	}{
		{
			name: "High CVSS vulnerability",
			finding: types.SecurityFinding{
				Type:     "vulnerability",
				CVSS:     9.5,
				Severity: "CRITICAL",
			},
			expected: "Minutes to Hours",
		},
		{
			name: "Critical severity",
			finding: types.SecurityFinding{
				Severity: "CRITICAL",
				CVSS:     7.0,
			},
			expected: "Hours to Days",
		},
		{
			name: "High severity exposed",
			finding: types.SecurityFinding{
				Severity:    "HIGH",
				Description: "exposed service",
			},
			expected: "Days to Weeks",
		},
		{
			name: "Medium severity",
			finding: types.SecurityFinding{
				Severity: "MEDIUM",
			},
			expected: "Weeks to Months",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rs.assessTimeToExploit(tt.finding)
			if result != tt.expected {
				t.Errorf("Expected time to exploit '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
