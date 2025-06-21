package analysis

import (
	"testing"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestNewBusinessImpactAnalyzer(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	if bia == nil {
		t.Error("Business impact analyzer should not be nil")
	}

	if bia.riskScorer == nil {
		t.Error("Risk scorer should not be nil")
	}
}

func TestAnalyzeCriticalAssets(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	findings := []types.SecurityFinding{
		{
			ID:       "finding-1",
			Type:     "vulnerability",
			Severity: "CRITICAL",
			CVE:      "CVE-2021-12345",
			Resource: types.ResourceReference{
				Kind:      "Secret",
				Name:      "api-secret", // pragma: allowlist secret
				Namespace: "production",
			},
		},
		{
			ID:       "finding-2",
			Type:     "misconfiguration",
			Severity: "HIGH",
			Resource: types.ResourceReference{
				Kind:      "Pod",
				Name:      "web-pod",
				Namespace: "production",
			},
		},
		{
			ID:       "finding-3",
			Type:     "vulnerability",
			Severity: "MEDIUM",
			Resource: types.ResourceReference{
				Kind:      "Service",
				Name:      "api-service",
				Namespace: "default",
			},
		},
		{
			ID:       "finding-4",
			Type:     "best-practice",
			Severity: "LOW",
			Resource: types.ResourceReference{
				Kind:      "ConfigMap",
				Name:      "config",
				Namespace: "default",
			},
		},
	}

	clusterInfo := &types.ClusterInfo{
		Name:      "prod-cluster",
		NodeCount: 50,
	}

	criticalAssets := bia.AnalyzeCriticalAssets(findings, clusterInfo)

	// Should have identified critical assets (excluding low-risk ones)
	if len(criticalAssets) == 0 {
		t.Error("Should have identified at least one critical asset")
	}

	// Assets should be sorted by risk score (highest first)
	for i := 1; i < len(criticalAssets); i++ {
		if criticalAssets[i-1].RiskScore < criticalAssets[i].RiskScore {
			t.Error("Critical assets should be sorted by risk score in descending order")
		}
	}

	// Secret should be identified as critical // pragma: allowlist secret
	foundSecret := false // pragma: allowlist secret
	for _, asset := range criticalAssets {
		if asset.Type == "Secret" && asset.Name == "api-secret" { // pragma: allowlist secret
			foundSecret = true // pragma: allowlist secret
			if asset.VulnerabilityCount != 1 {
				t.Errorf("Expected 1 vulnerability for secret, got %d", asset.VulnerabilityCount) // pragma: allowlist secret
			}
			if asset.CriticalityLevel != "Critical" && asset.CriticalityLevel != "High" {
				t.Errorf("Expected Critical or High criticality for secret with critical finding, got %s", asset.CriticalityLevel) // pragma: allowlist secret
			}
		}
	}

	if !foundSecret { // pragma: allowlist secret
		t.Error("Should have identified the secret as a critical asset") // pragma: allowlist secret
	}
}

func TestCreateCriticalAsset(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	resource := types.ResourceReference{
		Kind:      "Deployment",
		Name:      "web-app",
		Namespace: "production",
	}

	findings := []types.SecurityFinding{
		{
			Type:     "vulnerability",
			Severity: "HIGH",
			CVE:      "CVE-2021-67890",
		},
		{
			Type:     "misconfiguration",
			Severity: "MEDIUM",
		},
	}

	asset := bia.createCriticalAsset(resource, findings)

	if asset.Name != "web-app" {
		t.Errorf("Expected asset name 'web-app', got %s", asset.Name)
	}

	if asset.Type != "Deployment" {
		t.Errorf("Expected asset type 'Deployment', got %s", asset.Type)
	}

	if asset.Namespace != "production" {
		t.Errorf("Expected asset namespace 'production', got %s", asset.Namespace)
	}

	if asset.VulnerabilityCount != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", asset.VulnerabilityCount)
	}

	if asset.MisconfigCount != 1 {
		t.Errorf("Expected 1 misconfiguration, got %d", asset.MisconfigCount)
	}

	if asset.BusinessFunction == "" {
		t.Error("Business function should be inferred")
	}

	if asset.DataClassification == "" {
		t.Error("Data classification should be inferred")
	}
}

func TestDetermineCriticalityLevel(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		name        string
		resource    types.ResourceReference
		findings    []types.SecurityFinding
		riskScore   float64
		expectedMin string
		expectedMax string
	}{
		{
			name:     "Critical secret with critical finding", // pragma: allowlist secret
			resource: types.ResourceReference{Kind: "Secret"},
			findings: []types.SecurityFinding{
				{Severity: "CRITICAL", Description: "exposed to internet"},
			},
			riskScore:   60.0,
			expectedMin: "Critical",
			expectedMax: "Critical",
		},
		{
			name:     "High severity with exposure",
			resource: types.ResourceReference{Kind: "Service"},
			findings: []types.SecurityFinding{
				{Severity: "HIGH", Description: "service exposed"},
			},
			riskScore:   40.0,
			expectedMin: "High",
			expectedMax: "High",
		},
		{
			name:     "Medium risk deployment",
			resource: types.ResourceReference{Kind: "Deployment"},
			findings: []types.SecurityFinding{
				{Severity: "MEDIUM"},
			},
			riskScore:   25.0,
			expectedMin: "Medium",
			expectedMax: "High",
		},
		{
			name:     "Low risk config",
			resource: types.ResourceReference{Kind: "ConfigMap"},
			findings: []types.SecurityFinding{
				{Severity: "LOW"},
			},
			riskScore:   10.0,
			expectedMin: "Low",
			expectedMax: "Medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criticality := bia.determineCriticalityLevel(tt.resource, tt.findings, tt.riskScore)

			validLevels := []string{"Low", "Medium", "High", "Critical"}
			found := false
			for _, level := range validLevels {
				if criticality == level {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Invalid criticality level: %s", criticality)
			}
		})
	}
}

func TestInferBusinessFunction(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		name     string
		resource types.ResourceReference
		expected string
	}{
		{
			name: "API Gateway",
			resource: types.ResourceReference{
				Name: "api-gateway",
			},
			expected: "API Services",
		},
		{
			name: "Database",
			resource: types.ResourceReference{
				Name: "mysql-database",
			},
			expected: "Data Storage",
		},
		{
			name: "Web Frontend",
			resource: types.ResourceReference{
				Name: "web-ui",
			},
			expected: "User Interface",
		},
		{
			name: "Authentication Service",
			resource: types.ResourceReference{
				Name: "auth-service",
			},
			expected: "Authentication",
		},
		{
			name: "Payment Service",
			resource: types.ResourceReference{
				Name: "payment-processor",
			},
			expected: "Financial Services",
		},
		{
			name: "Monitoring",
			resource: types.ResourceReference{
				Name: "monitoring-agent",
			},
			expected: "Observability",
		},
		{
			name: "Production Namespace",
			resource: types.ResourceReference{
				Name:      "some-service",
				Namespace: "production",
			},
			expected: "Production Services",
		},
		{
			name: "System Service",
			resource: types.ResourceReference{
				Name:      "some-service",
				Namespace: "kube-system",
			},
			expected: "System Infrastructure",
		},
		{
			name: "Generic Application",
			resource: types.ResourceReference{
				Name: "my-app",
			},
			expected: "Application Services",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bia.inferBusinessFunction(tt.resource, []types.SecurityFinding{})
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestInferDataClassification(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		name     string
		resource types.ResourceReference
		findings []types.SecurityFinding
		expected string
	}{
		{
			name: "PII Data",
			resource: types.ResourceReference{
				Name: "user-service",
			},
			findings: []types.SecurityFinding{
				{Description: "Contains PII data"},
			},
			expected: "PII",
		},
		{
			name: "PCI Data",
			resource: types.ResourceReference{
				Name: "payment-service",
			},
			findings: []types.SecurityFinding{
				{Title: "PCI compliance violation"},
			},
			expected: "PCI",
		},
		{
			name: "Health Data",
			resource: types.ResourceReference{
				Name: "health-records",
			},
			findings: []types.SecurityFinding{
				{Description: "PHI data exposure"},
			},
			expected: "PHI",
		},
		{
			name: "Secret Resource",
			resource: types.ResourceReference{
				Kind: "Secret",
				Name: "api-keys",
			},
			findings: []types.SecurityFinding{},
			expected: "Confidential",
		},
		{
			name: "Credential Finding",
			resource: types.ResourceReference{
				Name: "app-service",
			},
			findings: []types.SecurityFinding{
				{Description: "Hardcoded password detected"},
			},
			expected: "Confidential",
		},
		{
			name: "Production Resource",
			resource: types.ResourceReference{
				Name: "prod-service",
			},
			findings: []types.SecurityFinding{},
			expected: "Internal",
		},
		{
			name: "Public Demo",
			resource: types.ResourceReference{
				Name:      "demo-app",
				Namespace: "public",
			},
			findings: []types.SecurityFinding{},
			expected: "Public",
		},
		{
			name: "Default Internal",
			resource: types.ResourceReference{
				Name: "regular-service",
			},
			findings: []types.SecurityFinding{},
			expected: "Internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bia.inferDataClassification(tt.resource, tt.findings)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGenerateActionItems(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	findings := []types.SecurityFinding{
		{
			ID:          "critical-vuln",
			Type:        "vulnerability",
			Severity:    "CRITICAL",
			CVE:         "CVE-2021-12345",
			FixedIn:     "1.2.3",
			Title:       "Remote code execution",
			Description: "Critical vulnerability allowing RCE",
			Resource: types.ResourceReference{
				Kind:      "Pod",
				Name:      "web-pod",
				Namespace: "production",
			},
		},
		{
			ID:          "config-issue",
			Type:        "misconfiguration",
			Severity:    "HIGH",
			SourceID:    "CIS-1.2.3",
			Title:       "Insecure configuration",
			Description: "Configuration violates security best practices",
			Resource: types.ResourceReference{
				Kind:      "Deployment",
				Name:      "app-deploy",
				Namespace: "default",
			},
		},
		{
			ID:       "low-issue",
			Type:     "best-practice",
			Severity: "LOW",
			Title:    "Minor best practice violation",
			Resource: types.ResourceReference{
				Kind: "ConfigMap",
				Name: "config",
			},
		},
	}

	criticalAssets := []types.CriticalAsset{
		{
			Name:             "web-pod",
			Type:             "Pod",
			Namespace:        "production",
			CriticalityLevel: "Critical",
			BusinessFunction: "Web Services",
		},
	}

	immediate, quickWins, longTerm := bia.GenerateActionItems(findings, criticalAssets)

	// Should have at least one immediate action for critical finding
	if len(immediate) == 0 {
		t.Error("Should have at least one immediate action for critical finding")
	}

	// Verify immediate action is for critical vulnerability
	foundCritical := false
	for _, action := range immediate {
		if action.Priority == "Critical" {
			foundCritical = true
			if action.EstimatedEffort == "" {
				t.Error("Action should have estimated effort")
			}
			if action.BusinessValue == "" {
				t.Error("Action should have business value")
			}
			if len(action.ImplementationSteps) == 0 {
				t.Error("Action should have implementation steps")
			}
			if len(action.SuccessMetrics) == 0 {
				t.Error("Action should have success metrics")
			}
			if action.DueDate == nil {
				t.Error("Critical action should have due date")
			}
		}
	}

	if !foundCritical {
		t.Error("Should have critical action in immediate list")
	}

	// Should have some quick wins or long term actions
	totalActions := len(immediate) + len(quickWins) + len(longTerm)
	if totalActions < len(findings) {
		t.Error("Should have created actions for all significant findings")
	}
}

func TestGenerateActionID(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		name     string
		finding  types.SecurityFinding
		expected string
	}{
		{
			name: "Vulnerability with fix",
			finding: types.SecurityFinding{
				Type:     "vulnerability",
				FixedIn:  "1.2.3",
				Resource: types.ResourceReference{Kind: "Pod"},
			},
			expected: "patch-Pod-1-2-3",
		},
		{
			name: "Misconfiguration",
			finding: types.SecurityFinding{
				Type:     "misconfiguration",
				SourceID: "CIS-1.2.3",
				Resource: types.ResourceReference{Kind: "Deployment"},
			},
			expected: "config-Deployment-CIS-1.2.3",
		},
		{
			name: "RBAC issue",
			finding: types.SecurityFinding{
				Type:     "rbac",
				Source:   "kubectl-who-can",
				Resource: types.ResourceReference{Kind: "Role"},
			},
			expected: "rbac-Role-kubectl-who-can",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bia.generateActionID(tt.finding)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCreateActionItem(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	finding := types.SecurityFinding{
		ID:          "test-finding",
		Type:        "vulnerability",
		Severity:    "CRITICAL",
		CVE:         "CVE-2021-12345",
		FixedIn:     "1.2.3",
		Title:       "Critical vulnerability",
		Description: "Remote code execution vulnerability",
		Remediation: "Update to version 1.2.3",
		Resource: types.ResourceReference{
			Kind:      "Pod",
			Name:      "web-pod",
			Namespace: "production",
		},
	}

	action := bia.createActionItem(finding)

	if action.ID == "" {
		t.Error("Action ID should not be empty")
	}

	if action.Title == "" {
		t.Error("Action title should not be empty")
	}

	if action.Description == "" {
		t.Error("Action description should not be empty")
	}

	if action.Priority != "Critical" {
		t.Errorf("Expected priority 'Critical' for critical finding, got %s", action.Priority)
	}

	if action.Category != "Patch" {
		t.Errorf("Expected category 'Patch' for vulnerability, got %s", action.Category)
	}

	if action.EstimatedEffort == "" {
		t.Error("Estimated effort should not be empty")
	}

	if action.BusinessValue == "" {
		t.Error("Business value should not be empty")
	}

	if len(action.Prerequisites) == 0 {
		t.Error("Prerequisites should not be empty")
	}

	if len(action.AffectedSystems) == 0 {
		t.Error("Affected systems should not be empty")
	}

	if len(action.ImplementationSteps) == 0 {
		t.Error("Implementation steps should not be empty")
	}

	if len(action.SuccessMetrics) == 0 {
		t.Error("Success metrics should not be empty")
	}

	if len(action.RelatedFindings) != 1 || action.RelatedFindings[0] != finding.ID {
		t.Error("Related findings should contain the source finding ID")
	}

	// Critical findings should have due date
	if action.DueDate == nil {
		t.Error("Critical action should have due date")
	}

	// Due date should be within a week for critical
	expectedDue := time.Now().AddDate(0, 0, 7)
	if action.DueDate.After(expectedDue.AddDate(0, 0, 1)) { // Allow 1 day tolerance
		t.Error("Critical action due date should be within a week")
	}
}

func TestIsQuickWin(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		name     string
		action   types.ActionItem
		expected bool
	}{
		{
			name: "Short effort action",
			action: types.ActionItem{
				EstimatedEffort: "1-3 hours",
			},
			expected: true,
		},
		{
			name: "Config category action",
			action: types.ActionItem{
				Category: "Config",
			},
			expected: true,
		},
		{
			name: "Long effort action",
			action: types.ActionItem{
				EstimatedEffort: "8-16 hours",
			},
			expected: false,
		},
		{
			name: "Patch category with long effort",
			action: types.ActionItem{
				Category:        "Patch",
				EstimatedEffort: "4-8 hours",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bia.isQuickWin(&tt.action)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMapSeverityToPriority(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		severity string
		expected string
	}{
		{"CRITICAL", "Critical"},
		{"HIGH", "High"},
		{"MEDIUM", "Medium"},
		{"LOW", "Low"},
		{"INFO", "Low"},
		{"UNKNOWN", "Low"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := bia.mapSeverityToPriority(tt.severity)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetActionCategory(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		findingType string
		expected    string
	}{
		{"vulnerability", "Patch"},
		{"misconfiguration", "Config"},
		{"best-practice", "Config"},
		{"rbac", "Process"},
		{"compliance", "Process"},
	}

	for _, tt := range tests {
		t.Run(tt.findingType, func(t *testing.T) {
			finding := types.SecurityFinding{Type: tt.findingType}
			result := bia.getActionCategory(finding)
			if result != tt.expected {
				t.Errorf("Expected %s for type %s, got %s", tt.expected, tt.findingType, result)
			}
		})
	}
}

func TestEstimateEffort(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		name     string
		finding  types.SecurityFinding
		expected string
	}{
		{
			name: "Vulnerability with fix",
			finding: types.SecurityFinding{
				Type:    "vulnerability",
				FixedIn: "1.2.3",
			},
			expected: "2-4 hours",
		},
		{
			name: "Misconfiguration",
			finding: types.SecurityFinding{
				Type: "misconfiguration",
			},
			expected: "1-3 hours",
		},
		{
			name: "Other type",
			finding: types.SecurityFinding{
				Type: "rbac",
			},
			expected: "4-8 hours",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bia.estimateEffort(tt.finding)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCalculateBusinessValue(t *testing.T) {
	bia := NewBusinessImpactAnalyzer()

	tests := []struct {
		severity string
		expected string
	}{
		{"CRITICAL", "High - Prevents potential security breach"},
		{"HIGH", "Medium-High - Reduces significant security risk"},
		{"MEDIUM", "Medium - Improves overall security posture"},
		{"LOW", "Medium - Improves overall security posture"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			finding := types.SecurityFinding{Severity: tt.severity}
			result := bia.calculateBusinessValue(finding)
			if result != tt.expected {
				t.Errorf("Expected %s for severity %s, got %s", tt.expected, tt.severity, result)
			}
		})
	}
}
