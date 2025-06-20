package types

import (
	"testing"
	"time"
)

func TestSecurityFinding(t *testing.T) {
	finding := SecurityFinding{
		ID:          "test-finding-1",
		Type:        string(FindingTypeVulnerability),
		Severity:    string(SeverityCritical),
		Title:       "Test Vulnerability",
		Description: "A test vulnerability finding",
		Source:      "test",
		SourceID:    "CVE-2023-1234",
		Resource: ResourceReference{
			Kind:      "Pod",
			Name:      "test-pod",
			Namespace: "default",
		},
		CVE:       "CVE-2023-1234",
		CVSS:      9.8,
		Timestamp: time.Now(),
	}

	if finding.ID == "" {
		t.Error("SecurityFinding ID should not be empty")
	}

	if finding.Type != string(FindingTypeVulnerability) {
		t.Errorf("Expected finding type to be %s, got %s", FindingTypeVulnerability, finding.Type)
	}

	if finding.Severity != string(SeverityCritical) {
		t.Errorf("Expected severity to be %s, got %s", SeverityCritical, finding.Severity)
	}
}

func TestResourceReference(t *testing.T) {
	ref := ResourceReference{
		Kind:      "Deployment",
		Name:      "nginx",
		Namespace: "default",
	}

	if ref.Kind != "Deployment" {
		t.Errorf("Expected kind to be 'Deployment', got %s", ref.Kind)
	}

	if ref.Name != "nginx" {
		t.Errorf("Expected name to be 'nginx', got %s", ref.Name)
	}
}
