package tools

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestTrivyWrapper_GetInfo(t *testing.T) {
	cfg := config.TrivyConfig{
		Severity:   []string{"CRITICAL", "HIGH"},
		IgnoreFile: "",
	}
	wrapper := NewTrivyWrapper(cfg)

	info := wrapper.GetInfo()

	if info.Name != "trivy" {
		t.Errorf("Expected name to be 'trivy', got %s", info.Name)
	}

	if info.Description == "" {
		t.Error("Description should not be empty")
	}

	if len(info.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}

	// Check for expected capabilities
	expectedCaps := []string{"Container image scanning", "CVE detection"}
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

func TestTrivyWrapper_buildKubernetesArgs(t *testing.T) {
	cfg := config.TrivyConfig{
		Severity:   []string{"CRITICAL", "HIGH"},
		IgnoreFile: "test.trivyignore",
	}
	wrapper := NewTrivyWrapper(cfg)

	toolConfig := types.ToolConfig{
		KubeconfigPath: "/home/.kube/config",
		Context:        "test-cluster",
		Namespaces:     []string{"default", "kube-system"},
	}

	args := wrapper.buildKubernetesArgs(toolConfig)

	expectedArgs := []string{
		"kubernetes",
		"--format", "json",
		"--kubeconfig", "/home/.kube/config",
		"--context", "test-cluster",
		"--severity", "CRITICAL,HIGH",
		"--include-namespaces", "default,kube-system",
		"--ignorefile", "test.trivyignore",
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

func TestTrivyWrapper_buildKubernetesArgsMinimal(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	toolConfig := types.ToolConfig{}

	args := wrapper.buildKubernetesArgs(toolConfig)

	expectedArgs := []string{"kubernetes", "--format", "json"}

	if len(args) != len(expectedArgs) {
		t.Errorf("Expected %d args, got %d", len(expectedArgs), len(args))
	}

	for i, expected := range expectedArgs {
		if i >= len(args) || args[i] != expected {
			t.Errorf("Expected arg[%d] to be %s, got %s", i, expected, args[i])
		}
	}
}

func TestTrivyWrapper_buildKubernetesArgsWithTimeout(t *testing.T) {
	cfg := config.TrivyConfig{
		Timeout: 5 * time.Minute,
	}
	wrapper := NewTrivyWrapper(cfg)

	toolConfig := types.ToolConfig{}

	args := wrapper.buildKubernetesArgs(toolConfig)

	found := false
	for i, arg := range args {
		if arg == "--timeout" && i+1 < len(args) {
			if strings.Contains(args[i+1], "5m") {
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("Expected timeout argument not found")
	}
}

func TestTrivyWrapper_parseResults(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	// Sample Trivy JSON output
	sampleOutput := TrivyKubernetesReport{
		ClusterName: "test-cluster",
		Resources: []TrivyResourceResult{
			{
				Namespace: "default",
				Kind:      "Pod",
				Name:      "test-pod",
				Results: []TrivyVulnResult{
					{
						Target: "nginx:1.20",
						Class:  "os-pkgs",
						Type:   "debian",
						Vulnerabilities: []TrivyVulnerability{
							{
								VulnerabilityID:  "CVE-2021-12345",
								PkgName:          "openssl",
								InstalledVersion: "1.1.1k-1",
								FixedVersion:     "1.1.1l-1",
								Severity:         "HIGH",
								Title:            "Test vulnerability",
								Description:      "This is a test vulnerability",
								References:       []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-12345"},
								CVSS: TrivyCVSS{
									Nvd: TrivyCVSSScore{
										V3Score: 7.5,
									},
								},
								CweIDs: []string{"CWE-79"},
							},
						},
					},
					{
						Target: "test-container",
						Class:  "config",
						Type:   "kubernetes",
						Misconfigurations: []TrivyMisconfig{
							{
								ID:          "KSV001",
								Type:        "Kubernetes Security Check",
								Title:       "Process can elevate its own privileges",
								Description: "A program inside the container can elevate its own privileges",
								Message:     "Container 'test-container' should set 'allowPrivilegeEscalation' to false",
								Severity:    "MEDIUM",
								Status:      "FAIL",
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

	findings, err := wrapper.parseResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Check vulnerability finding
	vulnFinding := findings[0]
	if vulnFinding.Type != string(types.FindingTypeVulnerability) {
		t.Errorf("Expected type to be %s, got %s", types.FindingTypeVulnerability, vulnFinding.Type)
	}
	if vulnFinding.Severity != string(types.SeverityHigh) {
		t.Errorf("Expected severity to be %s, got %s", types.SeverityHigh, vulnFinding.Severity)
	}
	if vulnFinding.CVE != "CVE-2021-12345" {
		t.Errorf("Expected CVE to be 'CVE-2021-12345', got %s", vulnFinding.CVE)
	}
	if vulnFinding.CVSS != 7.5 {
		t.Errorf("Expected CVSS to be 7.5, got %f", vulnFinding.CVSS)
	}
	if vulnFinding.Source != "trivy" {
		t.Errorf("Expected source to be 'trivy', got %s", vulnFinding.Source)
	}

	// Check misconfiguration finding
	misconfigFinding := findings[1]
	if misconfigFinding.Type != string(types.FindingTypeMisconfiguration) {
		t.Errorf("Expected type to be %s, got %s", types.FindingTypeMisconfiguration, misconfigFinding.Type)
	}
	if misconfigFinding.Severity != string(types.SeverityMedium) {
		t.Errorf("Expected severity to be %s, got %s", types.SeverityMedium, misconfigFinding.Severity)
	}
}

func TestTrivyWrapper_parseResultsEmpty(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	// Empty result
	sampleOutput := TrivyKubernetesReport{
		ClusterName: "empty-cluster",
		Resources:   []TrivyResourceResult{},
	}

	jsonOutput, err := json.Marshal(sampleOutput)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	findings, err := wrapper.parseResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty result, got %d", len(findings))
	}
}

func TestTrivyWrapper_normalizeSeverity(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	tests := []struct {
		trivySeverity string
		expected      string
	}{
		{"CRITICAL", string(types.SeverityCritical)},
		{"HIGH", string(types.SeverityHigh)},
		{"MEDIUM", string(types.SeverityMedium)},
		{"LOW", string(types.SeverityLow)},
		{"UNKNOWN", string(types.SeverityInfo)},
		{"unknown", string(types.SeverityInfo)}, // case insensitive
		{"INVALID", string(types.SeverityInfo)}, // default
	}

	for _, tt := range tests {
		t.Run(tt.trivySeverity, func(t *testing.T) {
			severity := wrapper.normalizeSeverity(tt.trivySeverity)
			if severity != tt.expected {
				t.Errorf("Expected severity %s for %s, got %s",
					tt.expected, tt.trivySeverity, severity)
			}
		})
	}
}

func TestTrivyWrapper_vulnerabilityToFinding(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	vuln := TrivyVulnerability{
		VulnerabilityID:  "CVE-2021-54321",
		PkgName:          "curl",
		InstalledVersion: "7.68.0-1ubuntu2.7",
		FixedVersion:     "7.68.0-1ubuntu2.8",
		Severity:         "CRITICAL",
		Title:            "Remote code execution in curl",
		Description:      "A critical vulnerability allowing remote code execution",
		References:       []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-54321"},
		CVSS: TrivyCVSS{
			Nvd: TrivyCVSSScore{
				V3Score: 9.8,
			},
		},
		CweIDs: []string{"CWE-787"},
	}

	resource := TrivyResourceResult{
		Namespace: "production",
		Kind:      "Deployment",
		Name:      "web-app",
	}

	finding := wrapper.vulnerabilityToFinding(vuln, resource)

	if finding.ID != "trivy-web-app-CVE-2021-54321" {
		t.Errorf("Unexpected finding ID: %s", finding.ID)
	}

	if finding.Type != string(types.FindingTypeVulnerability) {
		t.Errorf("Expected type %s, got %s", types.FindingTypeVulnerability, finding.Type)
	}

	if finding.Severity != string(types.SeverityCritical) {
		t.Errorf("Expected severity %s, got %s", types.SeverityCritical, finding.Severity)
	}

	if finding.CVE != "CVE-2021-54321" {
		t.Errorf("Expected CVE 'CVE-2021-54321', got %s", finding.CVE)
	}

	if finding.CVSS != 9.8 {
		t.Errorf("Expected CVSS 9.8, got %f", finding.CVSS)
	}

	if finding.FixedIn != "7.68.0-1ubuntu2.8" {
		t.Errorf("Expected FixedIn '7.68.0-1ubuntu2.8', got %s", finding.FixedIn)
	}

	if finding.Resource.Name != "web-app" {
		t.Errorf("Expected resource name 'web-app', got %s", finding.Resource.Name)
	}

	if finding.Resource.Namespace != "production" {
		t.Errorf("Expected resource namespace 'production', got %s", finding.Resource.Namespace)
	}

	// Check evidence
	evidence, ok := finding.Evidence.(map[string]interface{})
	if !ok {
		t.Error("Expected evidence to be a map")
	} else {
		if evidence["package"] != "curl" {
			t.Errorf("Expected package 'curl', got %v", evidence["package"])
		}
		if evidence["installed_version"] != "7.68.0-1ubuntu2.7" {
			t.Errorf("Expected installed_version '7.68.0-1ubuntu2.7', got %v", evidence["installed_version"])
		}
	}
}

func TestTrivyWrapper_vulnerabilityToFindingWithRedHatCVSS(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	vuln := TrivyVulnerability{
		VulnerabilityID: "CVE-2021-98765",
		Severity:        "HIGH",
		Title:           "Test with RedHat CVSS",
		CVSS: TrivyCVSS{
			RedHat: TrivyCVSSScore{
				V3Score: 8.2,
			},
		},
	}

	resource := TrivyResourceResult{
		Name: "test-resource",
	}

	finding := wrapper.vulnerabilityToFinding(vuln, resource)

	if finding.CVSS != 8.2 {
		t.Errorf("Expected CVSS 8.2 from RedHat, got %f", finding.CVSS)
	}
}

func TestTrivyWrapper_misconfigToFinding(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	misconfig := TrivyMisconfig{
		ID:          "KSV003",
		Type:        "Kubernetes Security Check",
		Title:       "Default capabilities not dropped",
		Description: "Container should drop default capabilities",
		Message:     "Container 'nginx' should drop ALL capabilities and add only required ones",
		Severity:    "HIGH",
		Status:      "FAIL",
	}

	resource := TrivyResourceResult{
		Namespace: "default",
		Kind:      "Pod",
		Name:      "nginx-pod",
	}

	finding := wrapper.misconfigToFinding(misconfig, resource)

	if finding.ID != "trivy-misconfig-nginx-pod-KSV003" {
		t.Errorf("Unexpected finding ID: %s", finding.ID)
	}

	if finding.Type != string(types.FindingTypeMisconfiguration) {
		t.Errorf("Expected type %s, got %s", types.FindingTypeMisconfiguration, finding.Type)
	}

	if finding.Severity != string(types.SeverityHigh) {
		t.Errorf("Expected severity %s, got %s", types.SeverityHigh, finding.Severity)
	}

	if finding.SourceID != "KSV003" {
		t.Errorf("Expected SourceID 'KSV003', got %s", finding.SourceID)
	}

	if finding.Resource.Name != "nginx-pod" {
		t.Errorf("Expected resource name 'nginx-pod', got %s", finding.Resource.Name)
	}

	// Check evidence
	evidence, ok := finding.Evidence.(map[string]interface{})
	if !ok {
		t.Error("Expected evidence to be a map")
	} else {
		if evidence["message"] != "Container 'nginx' should drop ALL capabilities and add only required ones" {
			t.Errorf("Expected specific message in evidence")
		}
		if evidence["status"] != "FAIL" {
			t.Errorf("Expected status 'FAIL', got %v", evidence["status"])
		}
	}
}

func TestTrivyWrapper_parseResultsInvalidJSON(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	invalidJSON := []byte(`{"invalid": json}`)

	_, err := wrapper.parseResults(invalidJSON)
	if err == nil {
		t.Error("Expected error for invalid JSON, got none")
	}
}

func TestTrivyWrapper_parseResultsMultipleResources(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	// Multiple resources with different types
	sampleOutput := TrivyKubernetesReport{
		Resources: []TrivyResourceResult{
			{
				Namespace: "default",
				Kind:      "Pod",
				Name:      "pod-1",
				Results: []TrivyVulnResult{
					{
						Vulnerabilities: []TrivyVulnerability{
							{
								VulnerabilityID: "CVE-2021-1",
								Severity:        "HIGH",
								Title:           "Test vuln 1",
								Description:     "Description 1",
							},
						},
					},
				},
			},
			{
				Namespace: "kube-system",
				Kind:      "Deployment",
				Name:      "deployment-1",
				Results: []TrivyVulnResult{
					{
						Target: "deployment-1",
						Class:  "config",
						Type:   "kubernetes",
						Misconfigurations: []TrivyMisconfig{
							{
								ID:       "KSV001",
								Severity: "MEDIUM",
								Title:    "Test misconfig",
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

	findings, err := wrapper.parseResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Check that we have findings from different namespaces and kinds
	namespaces := make(map[string]bool)
	kinds := make(map[string]bool)
	for _, finding := range findings {
		namespaces[finding.Resource.Namespace] = true
		kinds[finding.Resource.Kind] = true
	}

	if len(namespaces) != 2 {
		t.Errorf("Expected findings from 2 namespaces, got %d", len(namespaces))
	}
	if len(kinds) != 2 {
		t.Errorf("Expected findings from 2 resource kinds, got %d", len(kinds))
	}
}

func TestTrivyWrapper_parseResultsWithMultipleVulnerabilitiesPerResource(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	sampleOutput := TrivyKubernetesReport{
		Resources: []TrivyResourceResult{
			{
				Name: "multi-vuln-pod",
				Results: []TrivyVulnResult{
					{
						Vulnerabilities: []TrivyVulnerability{
							{VulnerabilityID: "CVE-2021-001", Severity: "CRITICAL"},
							{VulnerabilityID: "CVE-2021-002", Severity: "HIGH"},
							{VulnerabilityID: "CVE-2021-003", Severity: "MEDIUM"},
						},
					},
					{
						Vulnerabilities: []TrivyVulnerability{
							{VulnerabilityID: "CVE-2021-004", Severity: "LOW"},
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

	findings, err := wrapper.parseResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 4 {
		t.Errorf("Expected 4 findings, got %d", len(findings))
	}

	// Check severity distribution
	severities := make(map[string]int)
	for _, finding := range findings {
		severities[finding.Severity]++
	}

	expectedSeverities := map[string]int{
		string(types.SeverityCritical): 1,
		string(types.SeverityHigh):     1,
		string(types.SeverityMedium):   1,
		string(types.SeverityLow):      1,
	}

	for severity, expectedCount := range expectedSeverities {
		if severities[severity] != expectedCount {
			t.Errorf("Expected %d findings with severity %s, got %d",
				expectedCount, severity, severities[severity])
		}
	}
}

func TestTrivyWrapper_buildKubernetesArgsEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		config      config.TrivyConfig
		toolCfg     types.ToolConfig
		contains    []string
		notContains []string
	}{
		{
			name: "empty_severity",
			config: config.TrivyConfig{
				Severity: []string{},
			},
			toolCfg:     types.ToolConfig{},
			contains:    []string{"kubernetes", "--format", "json"},
			notContains: []string{"--severity"},
		},
		{
			name:   "single_namespace",
			config: config.TrivyConfig{},
			toolCfg: types.ToolConfig{
				Namespaces: []string{"production"},
			},
			contains: []string{"--include-namespaces", "production"},
		},
		{
			name: "no_timeout",
			config: config.TrivyConfig{
				Timeout: 0,
			},
			toolCfg:     types.ToolConfig{},
			notContains: []string{"--timeout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewTrivyWrapper(tt.config)
			args := wrapper.buildKubernetesArgs(tt.toolCfg)
			argsStr := strings.Join(args, " ")

			for _, should := range tt.contains {
				if !strings.Contains(argsStr, should) {
					t.Errorf("Expected args to contain '%s', got: %v", should, args)
				}
			}

			for _, shouldNot := range tt.notContains {
				if strings.Contains(argsStr, shouldNot) {
					t.Errorf("Expected args to NOT contain '%s', got: %v", shouldNot, args)
				}
			}
		})
	}
}

func TestTrivyWrapper_vulnerabilityToFindingNoCVSS(t *testing.T) {
	cfg := config.TrivyConfig{}
	wrapper := NewTrivyWrapper(cfg)

	vuln := TrivyVulnerability{
		VulnerabilityID: "CVE-2021-NOCVSS",
		Severity:        "MEDIUM",
		Title:           "No CVSS score available",
		// No CVSS data
	}

	resource := TrivyResourceResult{
		Name: "test-resource",
	}

	finding := wrapper.vulnerabilityToFinding(vuln, resource)

	if finding.CVSS != 0.0 {
		t.Errorf("Expected CVSS 0.0 when no score available, got %f", finding.CVSS)
	}
}
