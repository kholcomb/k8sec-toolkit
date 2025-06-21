package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestPolarisWrapper_GetInfo(t *testing.T) {
	cfg := config.PolarisConfig{
		ConfigFile:       "",
		OnlyShowFailures: false,
	}
	wrapper := NewPolarisWrapper(cfg)

	info := wrapper.GetInfo()

	if info.Name != "polaris" {
		t.Errorf("Expected name to be 'polaris', got %s", info.Name)
	}

	if info.Description == "" {
		t.Error("Description should not be empty")
	}

	if len(info.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}

	// Check for expected capabilities
	expectedCaps := []string{"Security best practices validation", "Resource efficiency checks"}
	for _, expected := range expectedCaps {
		found := false
		for _, cap := range info.Capabilities {
			if cap == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected capability '%s' not found", expected)
		}
	}
}

func TestValidateConfigPath(t *testing.T) {
	tests := []struct {
		path        string
		expectError bool
	}{
		{"", false},                                // Empty is allowed
		{"config.yaml", false},                     // Valid file
		{"configs/polaris.yml", false},             // Valid with directory
		{"/etc/polaris/config.yaml", false},        // Absolute path
		{"../../../etc/passwd", true},              // Path traversal
		{"config", true},                           // No extension
		{"config.txt", true},                       // Wrong extension
		{"invalid@file.yaml", true},                // Invalid characters
		{strings.Repeat("a", 300) + ".yaml", true}, // Too long
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := validateConfigPath(tt.path)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for path %s, but got none", tt.path)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for path %s, but got: %v", tt.path, err)
			}
		})
	}
}

func TestPolarisWrapper_buildAuditArgs(t *testing.T) {
	cfg := config.PolarisConfig{
		ConfigFile:       "test-config.yaml",
		OnlyShowFailures: true,
	}
	wrapper := NewPolarisWrapper(cfg)

	toolConfig := types.ToolConfig{
		KubeconfigPath: "/home/.kube/config",
		Context:        "test-cluster",
		Namespaces:     []string{"default", "kube-system"},
	}

	args, err := wrapper.buildAuditArgs(toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedArgs := []string{
		"audit",
		"--kubeconfig", "/home/.kube/config",
		"--context", "test-cluster",
		"--namespace", "default",
		"--namespace", "kube-system",
		"--format", "json",
		"--config", "test-config.yaml",
		"--only-show-failures",
		"--quiet",
	}

	if len(args) != len(expectedArgs) {
		t.Errorf("Expected %d args, got %d", len(expectedArgs), len(args))
	}

	for i, expected := range expectedArgs {
		if i >= len(args) || args[i] != expected {
			t.Errorf("Expected arg[%d] to be %s, got %s", i, expected, args[i])
		}
	}
}

func TestPolarisWrapper_buildAuditArgsMinimal(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	toolConfig := types.ToolConfig{}

	args, err := wrapper.buildAuditArgs(toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedArgs := []string{"audit", "--format", "json", "--quiet"}

	if len(args) != len(expectedArgs) {
		t.Errorf("Expected %d args, got %d", len(expectedArgs), len(args))
	}

	for i, expected := range expectedArgs {
		if i >= len(args) || args[i] != expected {
			t.Errorf("Expected arg[%d] to be %s, got %s", i, expected, args[i])
		}
	}
}

func TestPolarisWrapper_buildAuditArgsInvalidNamespace(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	toolConfig := types.ToolConfig{
		Namespaces: []string{"invalid_namespace"},
	}

	_, err := wrapper.buildAuditArgs(toolConfig)
	if err == nil {
		t.Error("Expected error for invalid namespace, got none")
	}
}

func TestPolarisWrapper_parseAuditResults(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	// Sample Polaris JSON output
	sampleOutput := PolarisReport{
		PolarisVersion: "4.2.0",
		AuditTime:      "2025-06-21T00:00:00Z",
		SourceType:     "Cluster",
		SourceName:     "test-cluster",
		Results: []PolarisResult{
			{
				Name:       "test-deployment",
				Namespace:  "default",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				Results: map[string]PolarisCheckResult{
					"cpuRequestsMissing": {
						ID:       "cpuRequestsMissing",
						Message:  "CPU requests are not set",
						Success:  false,
						Severity: "warning",
						Category: "Efficiency",
					},
				},
				PodResult: PolarisPodResult{
					Name: "test-pod",
					Results: map[string]PolarisCheckResult{
						"runAsNonRoot": {
							ID:       "runAsNonRoot",
							Message:  "Should run as non-root user",
							Success:  false,
							Severity: "error",
							Category: "Security",
						},
					},
					ContainerResults: []PolarisContainerResult{
						{
							Name: "app-container",
							Results: map[string]PolarisCheckResult{
								"readOnlyRootFilesystem": {
									ID:       "readOnlyRootFilesystem",
									Message:  "Root filesystem should be read-only",
									Success:  false,
									Severity: "error",
									Category: "Security",
								},
							},
						},
					},
				},
			},
		},
	}

	jsonOutput, err := json.Marshal(sampleOutput)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	findings, err := wrapper.parseAuditResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(findings))
	}

	// Check workload-level finding
	workloadFinding := findings[0]
	if workloadFinding.Type != string(types.FindingTypeBestPractice) {
		t.Errorf("Expected type to be %s, got %s", types.FindingTypeBestPractice, workloadFinding.Type)
	}
	if workloadFinding.Severity != string(types.SeverityMedium) {
		t.Errorf("Expected severity to be %s, got %s", types.SeverityMedium, workloadFinding.Severity)
	}
	if workloadFinding.Source != "polaris" {
		t.Errorf("Expected source to be 'polaris', got %s", workloadFinding.Source)
	}

	// Check pod-level finding
	podFinding := findings[1]
	if podFinding.Type != string(types.FindingTypeMisconfiguration) {
		t.Errorf("Expected type to be %s, got %s", types.FindingTypeMisconfiguration, podFinding.Type)
	}
	if podFinding.Severity != string(types.SeverityHigh) {
		t.Errorf("Expected severity to be %s, got %s", types.SeverityHigh, podFinding.Severity)
	}

	// Check container-level finding
	containerFinding := findings[2]
	if !strings.Contains(containerFinding.Title, "Container: app-container") {
		t.Error("Expected container finding to include container name in title")
	}

	// Check evidence
	evidence, ok := containerFinding.Evidence.(map[string]interface{})
	if !ok {
		t.Error("Expected evidence to be a map")
	} else {
		if evidence["container_name"] != "app-container" {
			t.Errorf("Expected container_name in evidence to be 'app-container', got %v", evidence["container_name"])
		}
		if evidence["level"] != "container" {
			t.Errorf("Expected level in evidence to be 'container', got %v", evidence["level"])
		}
	}
}

func TestPolarisWrapper_parseAuditResultsNoFailures(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	// Empty result - all checks passed
	sampleOutput := PolarisReport{
		PolarisVersion: "4.2.0",
		Results: []PolarisResult{
			{
				Name:      "healthy-deployment",
				Namespace: "default",
				Kind:      "Deployment",
				Results:   map[string]PolarisCheckResult{}, // No failures
				PodResult: PolarisPodResult{
					Results:          map[string]PolarisCheckResult{}, // No failures
					ContainerResults: []PolarisContainerResult{},      // No containers with failures
				},
			},
		},
	}

	jsonOutput, err := json.Marshal(sampleOutput)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	findings, err := wrapper.parseAuditResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should not create findings when all checks pass
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for healthy workload, got %d", len(findings))
	}
}

func TestPolarisWrapper_mapSeverity(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	tests := []struct {
		polarisSeverity string
		expected        string
	}{
		{"error", string(types.SeverityHigh)},
		{"Error", string(types.SeverityHigh)},
		{"warning", string(types.SeverityMedium)},
		{"Warning", string(types.SeverityMedium)},
		{"ignore", string(types.SeverityLow)},
		{"unknown", string(types.SeverityMedium)}, // default
	}

	for _, tt := range tests {
		t.Run(tt.polarisSeverity, func(t *testing.T) {
			severity := wrapper.mapSeverity(tt.polarisSeverity)
			if severity != tt.expected {
				t.Errorf("Expected severity %s for %s, got %s",
					tt.expected, tt.polarisSeverity, severity)
			}
		})
	}
}

func TestPolarisWrapper_mapCategory(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	tests := []struct {
		category string
		expected string
	}{
		{"Security", string(types.FindingTypeMisconfiguration)},
		{"security", string(types.FindingTypeMisconfiguration)},
		{"Efficiency", string(types.FindingTypeBestPractice)},
		{"efficiency", string(types.FindingTypeBestPractice)},
		{"Reliability", string(types.FindingTypeBestPractice)},
		{"reliability", string(types.FindingTypeBestPractice)},
		{"unknown", string(types.FindingTypeBestPractice)}, // default
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			findingType := wrapper.mapCategory(tt.category)
			if findingType != tt.expected {
				t.Errorf("Expected finding type %s for category %s, got %s",
					tt.expected, tt.category, findingType)
			}
		})
	}
}

func TestPolarisWrapper_buildDescription(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	result := PolarisResult{
		Name:      "test-deployment",
		Namespace: "default",
		Kind:      "Deployment",
	}

	checkResult := PolarisCheckResult{
		ID:       "cpuRequestsMissing",
		Message:  "CPU requests are not set",
		Category: "Efficiency",
	}

	description := wrapper.buildDescription(result, checkResult, "workload")

	expectedSubstrings := []string{
		"workload validation failed",
		"test-deployment",
		"default",
		"Deployment",
		"cpuRequestsMissing",
		"Efficiency",
		"CPU requests are not set",
	}

	for _, substring := range expectedSubstrings {
		if !strings.Contains(description, substring) {
			t.Errorf("Expected description to contain '%s', got: %s", substring, description)
		}
	}
}

func TestPolarisWrapper_buildTags(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	// Test security category tags
	securityCheck := PolarisCheckResult{
		Category: "Security",
		Severity: "error",
	}
	securityTags := wrapper.buildTags(securityCheck)

	expectedSecurityTags := []string{"polaris", "best-practices", "security", "configuration-security", "critical-issue"}
	for _, expected := range expectedSecurityTags {
		found := false
		for _, tag := range securityTags {
			if tag == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected tag '%s' not found in security tags", expected)
		}
	}

	// Test efficiency category tags
	efficiencyCheck := PolarisCheckResult{
		Category: "Efficiency",
		Severity: "warning",
	}
	efficiencyTags := wrapper.buildTags(efficiencyCheck)

	foundEfficiency := false
	for _, tag := range efficiencyTags {
		if tag == "efficiency" {
			foundEfficiency = true
			break
		}
	}
	if !foundEfficiency {
		t.Error("Expected 'efficiency' tag for efficiency category")
	}

	// Should not have critical-issue tag for warnings
	foundCritical := false
	for _, tag := range efficiencyTags {
		if tag == "critical-issue" {
			foundCritical = true
			break
		}
	}
	if foundCritical {
		t.Error("Did not expect 'critical-issue' tag for warning severity")
	}
}

func TestPolarisWrapper_buildRemediation(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	tests := []struct {
		checkID     string
		checkResult PolarisCheckResult
		expectText  string
	}{
		{
			"runAsNonRoot",
			PolarisCheckResult{Category: "Security", Message: "Should run as non-root"},
			"security configuration",
		},
		{
			"cpuRequestsMissing",
			PolarisCheckResult{Category: "Efficiency", Message: "CPU requests missing"},
			"resource allocation",
		},
		{
			"readinessProbe",
			PolarisCheckResult{Category: "Reliability", Message: "Readiness probe missing"},
			"reliability and availability",
		},
		{
			"customCheck",
			PolarisCheckResult{Category: "Unknown", Message: "Custom check failed"},
			"best practices documentation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.checkID, func(t *testing.T) {
			remediation := wrapper.buildRemediation(tt.checkID, tt.checkResult)
			if !strings.Contains(strings.ToLower(remediation), strings.ToLower(tt.expectText)) {
				t.Errorf("Expected remediation to contain '%s', got: %s", tt.expectText, remediation)
			}
		})
	}
}

func TestPolarisWrapper_parseAuditResultsInvalidJSON(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	invalidJSON := []byte(`{"invalid": json}`)

	_, err := wrapper.parseAuditResults(invalidJSON)
	if err == nil {
		t.Error("Expected error for invalid JSON, got none")
	}
}

func TestPolarisWrapper_createFinding(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	result := PolarisResult{
		Name:       "test-deployment",
		Namespace:  "default",
		Kind:       "Deployment",
		APIVersion: "apps/v1",
	}

	checkResult := PolarisCheckResult{
		ID:       "cpuRequestsMissing",
		Message:  "CPU requests are not set",
		Success:  false,
		Severity: "warning",
		Category: "Efficiency",
	}

	finding := wrapper.createFinding(result, "cpuRequestsMissing", checkResult, "workload")

	if finding.ID != "polaris-workload-cpurequestsmissing-test-deployment" {
		t.Errorf("Unexpected finding ID: %s", finding.ID)
	}

	if finding.Resource.Name != "test-deployment" {
		t.Errorf("Expected resource name 'test-deployment', got %s", finding.Resource.Name)
	}

	if finding.Resource.Namespace != "default" {
		t.Errorf("Expected resource namespace 'default', got %s", finding.Resource.Namespace)
	}

	if finding.Framework != "Polaris Best Practices" {
		t.Errorf("Expected framework 'Polaris Best Practices', got %s", finding.Framework)
	}
}

func TestPolarisWrapper_createFindingWithContainer(t *testing.T) {
	cfg := config.PolarisConfig{}
	wrapper := NewPolarisWrapper(cfg)

	result := PolarisResult{
		Name:      "test-deployment",
		Namespace: "default",
		Kind:      "Deployment",
	}

	containerResult := PolarisContainerResult{
		Name: "app-container",
	}

	checkResult := PolarisCheckResult{
		ID:       "readOnlyRootFilesystem",
		Message:  "Root filesystem should be read-only",
		Success:  false,
		Severity: "error",
		Category: "Security",
	}

	finding := wrapper.createFindingWithContainer(result, containerResult, "readOnlyRootFilesystem", checkResult)

	if !strings.Contains(finding.Title, "Container: app-container") {
		t.Error("Expected container finding to include container name in title")
	}

	if !strings.Contains(finding.ID, "app-container") {
		t.Error("Expected container finding ID to include container name")
	}

	// Check container-specific evidence
	evidence, ok := finding.Evidence.(map[string]interface{})
	if !ok {
		t.Error("Expected evidence to be a map")
	} else {
		if evidence["container_name"] != "app-container" {
			t.Errorf("Expected container_name in evidence, got %v", evidence["container_name"])
		}
		if evidence["level"] != "container" {
			t.Errorf("Expected level to be 'container', got %v", evidence["level"])
		}
	}
}
