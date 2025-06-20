package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kubesec-io/kubesec/internal/types"
)

func createTestScanResult() *types.ScanResult {
	return &types.ScanResult{
		Context:  "test-context",
		ScanTime: time.Now(),
		Duration: 5 * time.Minute,
		ToolsUsed: []string{"trivy", "kubescape"},
		ClusterInfo: &types.ClusterInfo{
			Name:           "test-cluster",
			Version:        "v1.28.0",
			NodeCount:      3,
			NamespaceCount: 10,
			PodCount:       50,
		},
		Findings: []types.SecurityFinding{
			{
				ID:          "test-finding-1",
				Type:        string(types.FindingTypeVulnerability),
				Severity:    string(types.SeverityCritical),
				Title:       "Critical Vulnerability",
				Description: "A critical security vulnerability",
				Source:      "trivy",
				Resource: types.ResourceReference{
					Kind:      "Pod",
					Name:      "nginx",
					Namespace: "default",
				},
				CVE:  "CVE-2023-1234",
				CVSS: 9.8,
			},
		},
		Summary: &types.FindingSummary{
			TotalFindings: 1,
			Critical:      1,
			High:          0,
			Medium:        0,
			Low:          0,
			RiskScore:    9.8,
		},
	}
}

func TestJSONFormatter(t *testing.T) {
	formatter := &JSONFormatter{}
	result := createTestScanResult()
	
	data, err := formatter.Format([]*types.ScanResult{result})
	if err != nil {
		t.Fatalf("JSON formatting failed: %v", err)
	}
	
	// Validate it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Generated JSON is invalid: %v", err)
	}
	
	// Check key fields
	if parsed["context"] != "test-context" {
		t.Error("JSON should contain context field")
	}
}

func TestTableFormatter(t *testing.T) {
	formatter := &TableFormatter{}
	result := createTestScanResult()
	
	data, err := formatter.Format([]*types.ScanResult{result})
	if err != nil {
		t.Fatalf("Table formatting failed: %v", err)
	}
	
	output := string(data)
	
	// Check for expected sections
	expectedSections := []string{
		"KubeSec Scan Results",
		"test-context",
		"test-cluster",
		"Summary:",
		"Total Findings: 1",
		"Critical: 1",
	}
	
	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("Table output should contain '%s'", section)
		}
	}
}

func TestSummaryFormatter(t *testing.T) {
	formatter := &SummaryFormatter{}
	result := createTestScanResult()
	
	data, err := formatter.Format([]*types.ScanResult{result})
	if err != nil {
		t.Fatalf("Summary formatting failed: %v", err)
	}
	
	output := string(data)
	
	// Check for expected content
	expectedContent := []string{
		"KubeSec Security Scan Summary",
		"Context: test-context",
		"Cluster: test-cluster",
		"Findings: 1",
		"Critical: 1",
	}
	
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("Summary output should contain '%s'", content)
		}
	}
}

func TestNewFormatter(t *testing.T) {
	testCases := []struct {
		format    string
		expectErr bool
	}{
		{"json", false},
		{"table", false},
		{"yaml", false},
		{"summary", false},
		{"invalid", true},
	}
	
	for _, tc := range testCases {
		formatter, err := NewFormatter(tc.format)
		
		if tc.expectErr {
			if err == nil {
				t.Errorf("Expected error for format '%s'", tc.format)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for format '%s': %v", tc.format, err)
			}
			if formatter == nil {
				t.Errorf("Formatter should not be nil for valid format '%s'", tc.format)
			}
		}
	}
}