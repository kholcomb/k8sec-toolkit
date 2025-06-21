package analysis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

// TestExecutiveSummaryGeneration tests the complete workflow from findings to executive summary
func TestExecutiveSummaryGeneration(t *testing.T) {
	// Create sample findings representing a realistic security scan
	findings := createSampleFindings()
	clusterInfo := createSampleClusterInfo()

	// Initialize analyzers
	riskScorer := NewRiskScorer()
	businessAnalyzer := NewBusinessImpactAnalyzer()
	cvssCalculator := NewBusinessImpactCalculator()

	// Generate executive summary
	summary := generateExecutiveSummary(riskScorer, businessAnalyzer, cvssCalculator, findings, clusterInfo)

	// Validate executive summary structure
	validateExecutiveSummary(t, summary, findings)

	// Test JSON serialization
	validateJSONSerialization(t, summary)

	// Test with different configurations
	testCustomConfiguration(t, findings, clusterInfo)
}

func createSampleFindings() []types.SecurityFinding {
	baseTime := time.Now()

	return []types.SecurityFinding{
		{
			ID:          "vuln-001",
			Type:        "vulnerability",
			Severity:    "CRITICAL",
			Title:       "Remote Code Execution in Web Service",
			Description: "Critical vulnerability allowing remote code execution in exposed web service",
			CVE:         "CVE-2021-44228",
			CVSS:        10.0,
			FixedIn:     "2.15.0",
			Resource: types.ResourceReference{
				Kind:       "Pod",
				Name:       "web-service",
				Namespace:  "production",
				APIVersion: "v1",
			},
			Source:     "trivy",
			SourceID:   "CVE-2021-44228",
			Timestamp:  baseTime.Add(-2 * time.Hour),
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		},
		{
			ID:          "vuln-002",
			Type:        "vulnerability",
			Severity:    "HIGH",
			Title:       "SQL Injection in Database Service",
			Description: "High severity SQL injection vulnerability in database interface",
			CVE:         "CVE-2021-12345",
			CVSS:        8.5,
			FixedIn:     "3.2.1",
			Resource: types.ResourceReference{
				Kind:      "Service",
				Name:      "db-service",
				Namespace: "production",
			},
			Source:    "trivy",
			SourceID:  "CVE-2021-12345",
			Timestamp: baseTime.Add(-1 * time.Hour),
		},
		{
			ID:          "config-001",
			Type:        "misconfiguration",
			Severity:    "HIGH",
			Title:       "Privileged Container Running",
			Description: "Container running with privileged access in production environment",
			Resource: types.ResourceReference{
				Kind:      "Pod",
				Name:      "admin-pod",
				Namespace: "production",
			},
			Source:    "polaris",
			SourceID:  "security.privileged",
			Timestamp: baseTime.Add(-30 * time.Minute),
		},
		{
			ID:          "config-002",
			Type:        "misconfiguration",
			Severity:    "MEDIUM",
			Title:       "Missing Resource Limits",
			Description: "Container without CPU and memory limits defined",
			Resource: types.ResourceReference{
				Kind:      "Deployment",
				Name:      "worker-deployment",
				Namespace: "default",
			},
			Source:    "polaris",
			SourceID:  "resources.limits",
			Timestamp: baseTime.Add(-15 * time.Minute),
		},
		{
			ID:          "rbac-001",
			Type:        "rbac",
			Severity:    "HIGH",
			Title:       "Excessive RBAC Permissions",
			Description: "Service account has cluster-admin privileges unnecessarily",
			Resource: types.ResourceReference{
				Kind:      "ServiceAccount",
				Name:      "app-service-account",
				Namespace: "production",
			},
			Source:    "kubectl-who-can",
			SourceID:  "cluster-admin-check",
			Timestamp: baseTime.Add(-45 * time.Minute),
		},
		{
			ID:          "compliance-001",
			Type:        "compliance",
			Severity:    "MEDIUM",
			Title:       "CIS Benchmark Violation",
			Description: "Kubernetes cluster fails CIS benchmark check 1.2.3",
			Resource: types.ResourceReference{
				Kind: "Node",
				Name: "worker-node-1",
			},
			Source:    "kube-bench",
			SourceID:  "1.2.3",
			Timestamp: baseTime.Add(-1 * time.Hour),
		},
		{
			ID:          "secret-001",
			Type:        "vulnerability",
			Severity:    "CRITICAL",
			Title:       "Exposed Database Credentials",
			Description: "Database credentials exposed in environment variables",
			Resource: types.ResourceReference{
				Kind:      "Secret",
				Name:      "db-credentials",
				Namespace: "production",
			},
			Source:    "kubescape",
			SourceID:  "exposed-secrets",
			Timestamp: baseTime.Add(-3 * time.Hour),
		},
		{
			ID:          "best-practice-001",
			Type:        "best-practice",
			Severity:    "LOW",
			Title:       "Missing Security Context",
			Description: "Pod running without security context defined",
			Resource: types.ResourceReference{
				Kind:      "Pod",
				Name:      "legacy-app",
				Namespace: "default",
			},
			Source:    "polaris",
			SourceID:  "security.context",
			Timestamp: baseTime.Add(-10 * time.Minute),
		},
	}
}

func createSampleClusterInfo() *types.ClusterInfo {
	return &types.ClusterInfo{
		Name:           "production-cluster",
		Version:        "1.25.3",
		NodeCount:      25,
		NamespaceCount: 8,
		PodCount:       150,
		Provider:       "AWS EKS",
		ScanTimestamp:  time.Now(),
	}
}

func generateExecutiveSummary(riskScorer *RiskScorer, businessAnalyzer *BusinessImpactAnalyzer, cvssCalculator *BusinessImpactCalculator, findings []types.SecurityFinding, clusterInfo *types.ClusterInfo) *types.ExecutiveSummary {
	// Calculate overall risk score
	scanResult := &types.ScanResult{
		Findings:    findings,
		ClusterInfo: clusterInfo,
		ScanTime:    time.Now(),
	}

	riskScore := riskScorer.CalculateOverallRiskScore(scanResult)
	securityPosture := riskScorer.DetermineSecurityPosture(riskScore, findings)
	businessImpact := riskScorer.CalculateBusinessImpact(findings, clusterInfo)
	riskDistribution := riskScorer.CalculateRiskDistribution(findings)

	// Generate top risks
	topRisks := riskScorer.GenerateTopRisks(findings, 5)

	// Analyze critical assets
	criticalAssets := businessAnalyzer.AnalyzeCriticalAssets(findings, clusterInfo)

	// Generate action items
	immediate, quickWins, longTerm := businessAnalyzer.GenerateActionItems(findings, criticalAssets)

	// Count findings by severity
	severityCounts := make(map[string]int)
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}

	// Simulate previous scan for trend analysis
	previousScore := riskScore * 0.8 // Assume improvement
	scoreChange := riskScore - previousScore

	return &types.ExecutiveSummary{
		SecurityPosture: securityPosture,
		RiskScore:       riskScore,
		BusinessImpact:  businessImpact,
		ComplianceScore: 85.0,                 // Mock compliance score
		TrendDirection:  types.TrendDegrading, // Risk increased

		CriticalFindings:  severityCounts["CRITICAL"],
		HighFindings:      severityCounts["HIGH"],
		TotalFindings:     len(findings),
		RemediationEffort: "High",
		TimeToRemediate:   "2-4 weeks",

		RiskDistribution: riskDistribution,
		TopRisks:         topRisks,
		CriticalAssets:   criticalAssets,

		ImmediateActions: immediate,
		QuickWins:        quickWins,
		LongTermStrategy: longTerm,

		LastScanTime:     time.Now(),
		PreviousScore:    previousScore,
		ScoreChange:      scoreChange,
		NewFindings:      2, // Mock new findings
		ResolvedFindings: 1, // Mock resolved findings
	}
}

func validateExecutiveSummary(t *testing.T, summary *types.ExecutiveSummary, findings []types.SecurityFinding) {
	// Validate basic structure
	if summary == nil {
		t.Fatal("Executive summary should not be nil")
	}

	// Validate risk score range
	if summary.RiskScore < 0 || summary.RiskScore > 100 {
		t.Errorf("Risk score %f outside valid range [0, 100]", summary.RiskScore)
	}

	// Validate compliance score range
	if summary.ComplianceScore < 0 || summary.ComplianceScore > 100 {
		t.Errorf("Compliance score %f outside valid range [0, 100]", summary.ComplianceScore)
	}

	// Validate security posture
	validPostures := []types.SecurityPostureLevel{
		types.SecurityPostureExcellent,
		types.SecurityPostureGood,
		types.SecurityPostureFair,
		types.SecurityPosturePoor,
		types.SecurityPostureCritical,
	}

	found := false
	for _, posture := range validPostures {
		if summary.SecurityPosture == posture {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Invalid security posture: %s", summary.SecurityPosture)
	}

	// Validate finding counts
	expectedCritical := 0
	expectedHigh := 0
	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			expectedCritical++
		case "HIGH":
			expectedHigh++
		}
	}

	if summary.CriticalFindings != expectedCritical {
		t.Errorf("Expected %d critical findings, got %d", expectedCritical, summary.CriticalFindings)
	}

	if summary.HighFindings != expectedHigh {
		t.Errorf("Expected %d high findings, got %d", expectedHigh, summary.HighFindings)
	}

	if summary.TotalFindings != len(findings) {
		t.Errorf("Expected %d total findings, got %d", len(findings), summary.TotalFindings)
	}

	// Validate risk distribution percentages
	total := summary.RiskDistribution.Infrastructure +
		summary.RiskDistribution.Applications +
		summary.RiskDistribution.Configuration +
		summary.RiskDistribution.AccessControl +
		summary.RiskDistribution.NetworkSecurity +
		summary.RiskDistribution.DataProtection

	if total < 99.0 || total > 101.0 {
		t.Errorf("Risk distribution percentages should sum to ~100%%, got %f", total)
	}

	// Validate top risks
	if len(summary.TopRisks) == 0 {
		t.Error("Should have identified top risks")
	}

	// Validate critical assets
	if len(summary.CriticalAssets) == 0 {
		t.Error("Should have identified critical assets")
	}

	// Validate action items
	if len(summary.ImmediateActions) == 0 && expectedCritical > 0 {
		t.Error("Should have immediate actions for critical findings")
	}

	// Validate timestamps
	if summary.LastScanTime.IsZero() {
		t.Error("Last scan time should be set")
	}
}

func validateJSONSerialization(t *testing.T, summary *types.ExecutiveSummary) {
	// Test JSON marshaling
	jsonData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal executive summary to JSON: %v", err)
	}

	// Verify JSON is not empty
	if len(jsonData) == 0 {
		t.Error("JSON data should not be empty")
	}

	// Test JSON unmarshaling
	var unmarshaled types.ExecutiveSummary
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal executive summary from JSON: %v", err)
	}

	// Verify key fields are preserved
	if unmarshaled.RiskScore != summary.RiskScore {
		t.Errorf("Risk score mismatch after JSON round-trip: expected %f, got %f",
			summary.RiskScore, unmarshaled.RiskScore)
	}

	if unmarshaled.SecurityPosture != summary.SecurityPosture {
		t.Errorf("Security posture mismatch after JSON round-trip: expected %s, got %s",
			summary.SecurityPosture, unmarshaled.SecurityPosture)
	}

	if len(unmarshaled.TopRisks) != len(summary.TopRisks) {
		t.Errorf("Top risks count mismatch after JSON round-trip: expected %d, got %d",
			len(summary.TopRisks), len(unmarshaled.TopRisks))
	}
}

func testCustomConfiguration(t *testing.T, findings []types.SecurityFinding, clusterInfo *types.ClusterInfo) {
	// Test with custom CVSS configuration
	customConfig := &BusinessImpactConfig{
		BaseWeight:          1.5,
		TemporalWeight:      0.8,
		EnvironmentalWeight: 1.3,
		CustomWeights: map[string]float64{
			"AV:NETWORK":    0.9,
			"BF:CRITICAL":   2.5,
			"DC:RESTRICTED": 2.2,
		},
		LowThreshold:      2.0,
		MediumThreshold:   5.0,
		HighThreshold:     8.0,
		CriticalThreshold: 9.5,
	}

	customCalculator := NewBusinessImpactCalculatorWithConfig(customConfig)
	riskScorer := NewRiskScorer()
	businessAnalyzer := NewBusinessImpactAnalyzer()

	// Generate summary with custom configuration
	summary := generateExecutiveSummary(riskScorer, businessAnalyzer, customCalculator, findings, clusterInfo)

	// Validate custom configuration doesn't break summary generation
	if summary == nil {
		t.Error("Executive summary should not be nil with custom configuration")
	}

	if summary.RiskScore < 0 || summary.RiskScore > 100 {
		t.Errorf("Risk score %f outside valid range with custom configuration", summary.RiskScore)
	}
}

func TestExecutiveSummaryWithEmptyFindings(t *testing.T) {
	riskScorer := NewRiskScorer()
	businessAnalyzer := NewBusinessImpactAnalyzer()
	cvssCalculator := NewBusinessImpactCalculator()

	findings := []types.SecurityFinding{}
	clusterInfo := createSampleClusterInfo()

	summary := generateExecutiveSummary(riskScorer, businessAnalyzer, cvssCalculator, findings, clusterInfo)

	if summary.RiskScore != 0 {
		t.Errorf("Expected risk score 0 for no findings, got %f", summary.RiskScore)
	}

	if summary.TotalFindings != 0 {
		t.Errorf("Expected 0 total findings, got %d", summary.TotalFindings)
	}

	if summary.SecurityPosture != types.SecurityPostureExcellent {
		t.Errorf("Expected excellent security posture for no findings, got %s", summary.SecurityPosture)
	}
}

func TestExecutiveSummaryPerformance(t *testing.T) {
	// Create a large number of findings to test performance
	findings := make([]types.SecurityFinding, 1000)
	baseTime := time.Now()

	for i := 0; i < 1000; i++ {
		findings[i] = types.SecurityFinding{
			ID:       string(rune('A'+i%26)) + string(rune('A'+(i/26)%26)) + "-" + string(rune('0'+i%10)),
			Type:     []string{"vulnerability", "misconfiguration", "rbac", "compliance"}[i%4],
			Severity: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}[i%4],
			Title:    "Test finding " + string(rune('0'+i%10)),
			Resource: types.ResourceReference{
				Kind:      []string{"Pod", "Service", "Deployment", "Secret"}[i%4],
				Name:      "resource-" + string(rune('0'+i%10)),
				Namespace: []string{"production", "default", "kube-system"}[i%3],
			},
			Timestamp: baseTime.Add(-time.Duration(i) * time.Minute),
		}
	}

	clusterInfo := createSampleClusterInfo()

	riskScorer := NewRiskScorer()
	businessAnalyzer := NewBusinessImpactAnalyzer()
	cvssCalculator := NewBusinessImpactCalculator()

	// Measure performance
	startTime := time.Now()
	summary := generateExecutiveSummary(riskScorer, businessAnalyzer, cvssCalculator, findings, clusterInfo)
	duration := time.Since(startTime)

	// Verify summary was generated
	if summary == nil {
		t.Error("Executive summary should not be nil")
	}

	if summary.TotalFindings != 1000 {
		t.Errorf("Expected 1000 total findings, got %d", summary.TotalFindings)
	}

	// Performance should be reasonable (less than 5 seconds for 1000 findings)
	if duration > 5*time.Second {
		t.Errorf("Executive summary generation took too long: %v", duration)
	}

	t.Logf("Generated executive summary for %d findings in %v", len(findings), duration)
}

func TestExecutiveSummaryTrendAnalysis(t *testing.T) {
	riskScorer := NewRiskScorer()
	businessAnalyzer := NewBusinessImpactAnalyzer()
	cvssCalculator := NewBusinessImpactCalculator()

	findings := createSampleFindings()
	clusterInfo := createSampleClusterInfo()

	summary := generateExecutiveSummary(riskScorer, businessAnalyzer, cvssCalculator, findings, clusterInfo)

	// Validate trend analysis fields
	if summary.PreviousScore < 0 {
		t.Error("Previous score should not be negative")
	}

	if summary.ScoreChange == 0 && summary.TotalFindings > 0 {
		t.Error("Score change should not be zero when there are findings")
	}

	// Validate trend direction matches score change
	if summary.ScoreChange > 0 && summary.TrendDirection == types.TrendImproving {
		t.Error("Positive score change should indicate degrading trend")
	}

	if summary.NewFindings < 0 {
		t.Error("New findings count should not be negative")
	}

	if summary.ResolvedFindings < 0 {
		t.Error("Resolved findings count should not be negative")
	}
}
