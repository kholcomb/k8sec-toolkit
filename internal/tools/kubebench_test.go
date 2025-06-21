package tools

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestKubeBenchWrapper_GetInfo(t *testing.T) {
	cfg := config.KubeBenchConfig{
		Version: "1.0.0",
		Targets: []string{"master", "node"},
	}
	wrapper := NewKubeBenchWrapper(cfg)

	info := wrapper.GetInfo()

	if info.Name != "kube-bench" {
		t.Errorf("Expected name to be 'kube-bench', got %s", info.Name)
	}

	if info.Description == "" {
		t.Error("Description should not be empty")
	}

	if len(info.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}
}

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		target      string
		expectError bool
	}{
		{"master", false},
		{"node", false},
		{"etcd", false},
		{"policies", false},
		{"eks", false},
		{"gke", false},
		{"invalid-target", true},
		{"", true},
		{"../../../etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			err := validateTarget(tt.target)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for target %s, but got none", tt.target)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for target %s, but got: %v", tt.target, err)
			}
		})
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		version     string
		expectError bool
	}{
		{"", false},             // Empty version is allowed (auto-detect)
		{"v1.24", false},        // Valid version with v prefix
		{"1.25.0", false},       // Valid version without v prefix
		{"v1.26.1", false},      // Valid full version
		{"invalid", true},       // Invalid format
		{"v1", true},            // Incomplete version
		{"1.25.x", true},        // Invalid character
		{"../etc/passwd", true}, // Path injection attempt
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			err := validateVersion(tt.version)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for version %s, but got none", tt.version)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for version %s, but got: %v", tt.version, err)
			}
		})
	}
}

func TestKubeBenchWrapper_buildScanArgs(t *testing.T) {
	cfg := config.KubeBenchConfig{
		Version:   "v1.24",
		ConfigDir: "/etc/kube-bench",
		Targets:   []string{"master", "node"},
	}
	wrapper := NewKubeBenchWrapper(cfg)

	toolConfig := types.ToolConfig{
		KubeconfigPath: "/home/.kube/config",
		Context:        "test-cluster",
		Namespaces:     []string{"default"},
		OutputFormat:   "json",
		Timeout:        5 * time.Minute,
	}

	args, err := wrapper.buildScanArgs(toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedArgs := []string{
		"run",
		"--json",
		"--version", "v1.24",
		"--config-dir", "/etc/kube-bench",
		"--targets", "master",
		"--targets", "node",
		"--kubeconfig", "/home/.kube/config",
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

func TestKubeBenchWrapper_buildScanArgsWithDefaults(t *testing.T) {
	cfg := config.KubeBenchConfig{} // Empty config - should use defaults
	wrapper := NewKubeBenchWrapper(cfg)

	toolConfig := types.ToolConfig{
		OutputFormat: "json",
		Timeout:      5 * time.Minute,
	}

	args, err := wrapper.buildScanArgs(toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should contain default targets
	expectedTargets := []string{"master", "node", "etcd", "policies"}
	targetCount := 0
	for _, arg := range args {
		for _, target := range expectedTargets {
			if arg == target {
				targetCount++
			}
		}
	}

	if targetCount != len(expectedTargets) {
		t.Errorf("Expected %d default targets, found %d", len(expectedTargets), targetCount)
	}
}

func TestKubeBenchWrapper_parseResults(t *testing.T) {
	// Sample kube-bench JSON output
	sampleOutput := KubeBenchReport{
		Controls: []KubeBenchGroup{
			{
				ID:      "1",
				Version: "1.0",
				Text:    "Master Node Security Configuration",
				Type:    "master",
				Tests: []KubeBenchTest{
					{
						Section: "1.1",
						Desc:    "Master Node Configuration Files",
						Results: []KubeBenchResult{
							{
								TestNumber:     "1.1.1",
								TestDesc:       "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
								Status:         "FAIL",
								Scored:         true,
								Remediation:    "Run the below command (based on the file location on your system) on the master node.",
								ActualValue:    "600",
								ExpectedResult: "644",
								Reason:         "permissions too restrictive",
							},
							{
								TestNumber: "1.1.2",
								TestDesc:   "Ensure that the API server pod specification file ownership is set to root:root",
								Status:     "PASS",
								Scored:     true,
							},
							{
								TestNumber: "1.1.3",
								TestDesc:   "Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive",
								Status:     "WARN",
								Scored:     false,
								Reason:     "Test marked as manual",
							},
						},
					},
				},
			},
		},
		Totals: KubeBenchTotals{
			TotalPass: 1,
			TotalFail: 1,
			TotalWarn: 1,
			TotalInfo: 0,
		},
	}

	jsonOutput, err := json.Marshal(sampleOutput)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	cfg := config.KubeBenchConfig{}
	wrapper := NewKubeBenchWrapper(cfg)

	findings, err := wrapper.parseResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should only have findings for FAIL and WARN status (not PASS)
	expectedFindings := 2
	if len(findings) != expectedFindings {
		t.Errorf("Expected %d findings, got %d", expectedFindings, len(findings))
	}

	// Check the FAIL finding
	failFinding := findings[0]
	if failFinding.ID != "kube-bench-1.1.1" {
		t.Errorf("Expected ID to be 'kube-bench-1.1.1', got %s", failFinding.ID)
	}
	if failFinding.Severity != string(types.SeverityHigh) {
		t.Errorf("Expected severity to be %s for scored FAIL, got %s", types.SeverityHigh, failFinding.Severity)
	}
	if failFinding.Type != string(types.FindingTypeCompliance) {
		t.Errorf("Expected type to be %s, got %s", types.FindingTypeCompliance, failFinding.Type)
	}
	if failFinding.Source != "kube-bench" {
		t.Errorf("Expected source to be 'kube-bench', got %s", failFinding.Source)
	}

	// Check the WARN finding
	warnFinding := findings[1]
	if warnFinding.Severity != string(types.SeverityLow) {
		t.Errorf("Expected severity to be %s for WARN, got %s", types.SeverityLow, warnFinding.Severity)
	}
}

func TestKubeBenchWrapper_mapStatusToSeverity(t *testing.T) {
	cfg := config.KubeBenchConfig{}
	wrapper := NewKubeBenchWrapper(cfg)

	tests := []struct {
		status   string
		scored   bool
		expected string
	}{
		{"FAIL", true, string(types.SeverityHigh)},
		{"FAIL", false, string(types.SeverityMedium)},
		{"WARN", true, string(types.SeverityLow)},
		{"WARN", false, string(types.SeverityLow)},
		{"INFO", true, string(types.SeverityInfo)},
		{"PASS", true, string(types.SeverityInfo)},
		{"UNKNOWN", false, string(types.SeverityInfo)},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			severity := wrapper.mapStatusToSeverity(tt.status, tt.scored)
			if severity != tt.expected {
				t.Errorf("Expected severity %s for status %s (scored: %v), got %s",
					tt.expected, tt.status, tt.scored, severity)
			}
		})
	}
}

func TestKubeBenchWrapper_resultToFinding(t *testing.T) {
	cfg := config.KubeBenchConfig{}
	wrapper := NewKubeBenchWrapper(cfg)

	result := KubeBenchResult{
		TestNumber:     "1.1.1",
		TestDesc:       "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
		Status:         "FAIL",
		Scored:         true,
		Remediation:    "Run the below command on the master node",
		ActualValue:    "600",
		ExpectedResult: "644",
		Reason:         "permissions too restrictive",
		Audit:          "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
	}

	test := KubeBenchTest{
		Section: "1.1",
		Desc:    "Master Node Configuration Files",
	}

	group := KubeBenchGroup{
		ID:   "1",
		Text: "Master Node Security Configuration",
		Type: "master",
	}

	finding := wrapper.resultToFinding(result, test, group)

	if finding.ID != "kube-bench-1.1.1" {
		t.Errorf("Expected ID to be 'kube-bench-1.1.1', got %s", finding.ID)
	}

	if finding.Title != result.TestDesc {
		t.Errorf("Expected title to be %s, got %s", result.TestDesc, finding.Title)
	}

	if finding.Severity != string(types.SeverityHigh) {
		t.Errorf("Expected severity to be %s, got %s", types.SeverityHigh, finding.Severity)
	}

	if finding.Framework != "CIS Kubernetes Benchmark" {
		t.Errorf("Expected framework to be 'CIS Kubernetes Benchmark', got %s", finding.Framework)
	}

	// Check evidence
	evidence, ok := finding.Evidence.(map[string]interface{})
	if !ok {
		t.Error("Expected evidence to be a map")
	} else {
		if evidence["test_number"] != "1.1.1" {
			t.Errorf("Expected test_number in evidence to be '1.1.1', got %v", evidence["test_number"])
		}
		if evidence["actual_value"] != "600" {
			t.Errorf("Expected actual_value in evidence to be '600', got %v", evidence["actual_value"])
		}
	}

	// Check tags
	if len(finding.Tags) == 0 {
		t.Error("Expected tags to not be empty")
	}
	foundCISTag := false
	for _, tag := range finding.Tags {
		if tag == "CIS" {
			foundCISTag = true
			break
		}
	}
	if !foundCISTag {
		t.Error("Expected 'CIS' tag in finding tags")
	}
}

func TestKubeBenchWrapper_parseResultsWithInvalidJSON(t *testing.T) {
	cfg := config.KubeBenchConfig{}
	wrapper := NewKubeBenchWrapper(cfg)

	invalidJSON := []byte(`{"invalid": json}`)

	_, err := wrapper.parseResults(invalidJSON)
	if err == nil {
		t.Error("Expected error for invalid JSON, got none")
	}
}

func TestKubeBenchWrapper_parseResultsEmptyOutput(t *testing.T) {
	cfg := config.KubeBenchConfig{}
	wrapper := NewKubeBenchWrapper(cfg)

	emptyReport := KubeBenchReport{
		Controls: []KubeBenchGroup{},
		Totals: KubeBenchTotals{
			TotalPass: 0,
			TotalFail: 0,
			TotalWarn: 0,
			TotalInfo: 0,
		},
	}

	jsonOutput, err := json.Marshal(emptyReport)
	if err != nil {
		t.Fatalf("Failed to marshal empty report: %v", err)
	}

	findings, err := wrapper.parseResults(jsonOutput)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty report, got %d", len(findings))
	}
}

func TestKubeBenchWrapper_buildScanArgsInvalidTarget(t *testing.T) {
	cfg := config.KubeBenchConfig{
		Targets: []string{"invalid-target"},
	}
	wrapper := NewKubeBenchWrapper(cfg)

	toolConfig := types.ToolConfig{}

	_, err := wrapper.buildScanArgs(toolConfig)
	if err == nil {
		t.Error("Expected error for invalid target, got none")
	}
}

func TestKubeBenchWrapper_buildScanArgsInvalidVersion(t *testing.T) {
	cfg := config.KubeBenchConfig{
		Version: "invalid-version",
		Targets: []string{"master"},
	}
	wrapper := NewKubeBenchWrapper(cfg)

	toolConfig := types.ToolConfig{}

	_, err := wrapper.buildScanArgs(toolConfig)
	if err == nil {
		t.Error("Expected error for invalid version, got none")
	}
}
