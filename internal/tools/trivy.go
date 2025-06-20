package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/kubesec-io/kubesec/internal/config"
	"github.com/kubesec-io/kubesec/internal/security"
	"github.com/kubesec-io/kubesec/internal/types"
)

// TrivyWrapper wraps the Trivy security scanner
type TrivyWrapper struct {
	config   config.TrivyConfig
	executor *security.SecureExecutor
	logger   *logrus.Logger
}

// TrivyKubernetesReport represents Trivy's Kubernetes scan output
type TrivyKubernetesReport struct {
	SchemaVersion int                    `json:"SchemaVersion"`
	ArtifactName  string                 `json:"ArtifactName"`
	ArtifactType  string                 `json:"ArtifactType"`
	Resources     []TrivyResourceResult  `json:"Resources"`
	Metadata      map[string]interface{} `json:"Metadata"`
}

// TrivyResourceResult represents a single resource scan result
type TrivyResourceResult struct {
	Namespace       string                 `json:"Namespace"`
	Kind            string                 `json:"Kind"`
	Name            string                 `json:"Name"`
	Results         []TrivyVulnResult     `json:"Results"`
	Misconfigurations []TrivyMisconfig     `json:"Misconfigurations"`
	Metadata        []interface{} `json:"Metadata"`
}

// TrivyVulnResult represents vulnerability scan results
type TrivyVulnResult struct {
	Target          string                `json:"Target"`
	Class           string                `json:"Class"`
	Type            string                `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyVulnerability represents a single vulnerability
type TrivyVulnerability struct {
	VulnerabilityID  string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	InstalledVersion string             `json:"InstalledVersion"`
	FixedVersion     string             `json:"FixedVersion"`
	Severity         string             `json:"Severity"`
	Title            string             `json:"Title"`
	Description      string             `json:"Description"`
	References       []string           `json:"References"`
	CVSS             TrivyCVSS          `json:"CVSS"`
	CweIDs           []string           `json:"CweIDs"`
	VendorSeverity   map[string]int     `json:"VendorSeverity"`
}

// TrivyCVSS represents CVSS scoring information
type TrivyCVSS struct {
	Nvd    TrivyCVSSScore `json:"nvd"`
	RedHat TrivyCVSSScore `json:"redhat"`
}

// TrivyCVSSScore represents a CVSS score
type TrivyCVSSScore struct {
	V2Vector string  `json:"V2Vector"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Score  float64 `json:"V3Score"`
}

// TrivyMisconfig represents a misconfiguration finding
type TrivyMisconfig struct {
	ID          string `json:"ID"`
	Type        string `json:"Type"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Message     string `json:"Message"`
	Severity    string `json:"Severity"`
	Status      string `json:"Status"`
}

// NewTrivyWrapper creates a new Trivy wrapper
func NewTrivyWrapper(config config.TrivyConfig) *TrivyWrapper {
	return &TrivyWrapper{
		config:   config,
		executor: security.NewSecureExecutor(),
		logger:   logrus.New(),
	}
}

// GetInfo returns information about the Trivy tool
func (t *TrivyWrapper) GetInfo() types.ToolInfo {
	return types.ToolInfo{
		Name:        "trivy",
		Version:     t.GetVersion(),
		Description: "Container vulnerability scanner",
		Website:     "https://trivy.dev/",
		License:     "Apache 2.0",
		Capabilities: []string{
			"Container image scanning",
			"CVE detection",
			"SBOM generation",
			"License detection",
			"Kubernetes resource scanning",
		},
	}
}

// Validate checks if Trivy is available and properly configured
func (t *TrivyWrapper) Validate() error {
	// Test basic execution using secure executor
	result, err := t.executor.Execute(context.Background(), "trivy-version", []string{"--version"})
	if err != nil {
		return fmt.Errorf("trivy validation failed: %w", err)
	}
	
	if result.ExitCode != 0 {
		return fmt.Errorf("trivy version check failed with exit code %d", result.ExitCode)
	}
	
	t.logger.Info("Trivy validation successful")
	return nil
}

// Execute runs Trivy with the given configuration
func (t *TrivyWrapper) Execute(ctx context.Context, config types.ToolConfig) (*types.ToolResult, error) {
	startTime := time.Now()
	
	t.logger.Info("Starting Trivy Kubernetes scan")

	// Build command arguments
	args := t.buildKubernetesArgs(config)

	// Execute command using secure executor
	execResult, err := t.executor.Execute(ctx, "trivy-kubernetes", args)
	duration := time.Since(startTime)

	result := &types.ToolResult{
		ToolName:   "trivy",
		ExecutedAt: startTime,
		Duration:   duration,
		ExitCode:   execResult.ExitCode,
		RawOutput:  execResult.Stdout,
		ErrorOutput: execResult.Stderr,
		Metadata:   map[string]interface{}{
			"audit_trail": execResult.AuditTrail,
		},
	}

	if err != nil {
		return result, fmt.Errorf("trivy execution failed: %w", err)
	}

	// Parse results
	findings, err := t.parseResults(execResult.Stdout)
	if err != nil {
		return result, fmt.Errorf("failed to parse trivy results: %w", err)
	}

	result.Findings = findings
	t.logger.Infof("Trivy scan completed with %d findings in %v", 
		len(findings), duration)

	return result, nil
}

// buildKubernetesArgs builds the command arguments for Kubernetes scanning
func (t *TrivyWrapper) buildKubernetesArgs(config types.ToolConfig) []string {
	args := []string{
		"kubernetes",
		"--format", "json",
	}

	// Add kubeconfig if specified
	if config.KubeconfigPath != "" {
		args = append(args, "--kubeconfig", config.KubeconfigPath)
	}

	// Add context if specified
	if config.Context != "" {
		args = append(args, "--context", config.Context)
	}

	// Add severity filters
	if len(t.config.Severity) > 0 {
		args = append(args, "--severity", strings.Join(t.config.Severity, ","))
	}

	// Add namespaces if specified
	if len(config.Namespaces) > 0 {
		args = append(args, "--include-namespaces", strings.Join(config.Namespaces, ","))
	}

	// Add timeout
	if t.config.Timeout > 0 {
		args = append(args, "--timeout", t.config.Timeout.String())
	}

	// Add ignore file if specified
	if t.config.IgnoreFile != "" {
		args = append(args, "--ignorefile", t.config.IgnoreFile)
	}

	// No additional args needed for cluster scanning
	return args
}

// parseResults parses Trivy JSON output into normalized findings
func (t *TrivyWrapper) parseResults(output []byte) ([]types.SecurityFinding, error) {
	var report TrivyKubernetesReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trivy output: %w", err)
	}

	var findings []types.SecurityFinding

	// Process each resource
	for _, resource := range report.Resources {
		// Process vulnerabilities
		for _, result := range resource.Results {
			for _, vuln := range result.Vulnerabilities {
				finding := t.vulnerabilityToFinding(vuln, resource)
				findings = append(findings, finding)
			}
		}

		// Process misconfigurations
		for _, misconfig := range resource.Misconfigurations {
			finding := t.misconfigToFinding(misconfig, resource)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// vulnerabilityToFinding converts a Trivy vulnerability to a SecurityFinding
func (t *TrivyWrapper) vulnerabilityToFinding(vuln TrivyVulnerability, resource TrivyResourceResult) types.SecurityFinding {
	// Get CVSS score (prefer NVD, fallback to RedHat)
	cvssScore := 0.0
	if vuln.CVSS.Nvd.V3Score > 0 {
		cvssScore = vuln.CVSS.Nvd.V3Score
	} else if vuln.CVSS.RedHat.V3Score > 0 {
		cvssScore = vuln.CVSS.RedHat.V3Score
	}

	return types.SecurityFinding{
		ID:          fmt.Sprintf("trivy-%s-%s", resource.Name, vuln.VulnerabilityID),
		Type:        string(types.FindingTypeVulnerability),
		Severity:    t.normalizeSeverity(vuln.Severity),
		Title:       vuln.Title,
		Description: vuln.Description,
		Source:      "trivy",
		SourceID:    vuln.VulnerabilityID,
		Resource: types.ResourceReference{
			Kind:      resource.Kind,
			Name:      resource.Name,
			Namespace: resource.Namespace,
		},
		CVE:         vuln.VulnerabilityID,
		CVSS:        cvssScore,
		FixedIn:     vuln.FixedVersion,
		Evidence: map[string]interface{}{
			"package":           vuln.PkgName,
			"installed_version": vuln.InstalledVersion,
			"fixed_version":     vuln.FixedVersion,
			"cwe_ids":          vuln.CweIDs,
		},
		References: vuln.References,
		Timestamp:  time.Now(),
	}
}

// misconfigToFinding converts a Trivy misconfiguration to a SecurityFinding
func (t *TrivyWrapper) misconfigToFinding(misconfig TrivyMisconfig, resource TrivyResourceResult) types.SecurityFinding {
	return types.SecurityFinding{
		ID:          fmt.Sprintf("trivy-misconfig-%s-%s", resource.Name, misconfig.ID),
		Type:        string(types.FindingTypeMisconfiguration),
		Severity:    t.normalizeSeverity(misconfig.Severity),
		Title:       misconfig.Title,
		Description: misconfig.Description,
		Source:      "trivy",
		SourceID:    misconfig.ID,
		Resource: types.ResourceReference{
			Kind:      resource.Kind,
			Name:      resource.Name,
			Namespace: resource.Namespace,
		},
		Evidence: map[string]interface{}{
			"message": misconfig.Message,
			"status":  misconfig.Status,
		},
		Timestamp: time.Now(),
	}
}

// normalizeSeverity converts Trivy severity to standard severity
func (t *TrivyWrapper) normalizeSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return string(types.SeverityCritical)
	case "HIGH":
		return string(types.SeverityHigh)
	case "MEDIUM":
		return string(types.SeverityMedium)
	case "LOW":
		return string(types.SeverityLow)
	default:
		return string(types.SeverityInfo)
	}
}

// UpdateDatabase updates Trivy's vulnerability database
func (t *TrivyWrapper) UpdateDatabase() error {
	t.logger.Info("Updating Trivy database")
	
	// Execute update using secure executor
	result, err := t.executor.Execute(context.Background(), "trivy-update", []string{"image", "--download-db-only"})
	if err != nil {
		return fmt.Errorf("failed to update trivy database: %w", err)
	}
	
	if result.ExitCode != 0 {
		return fmt.Errorf("trivy database update failed with exit code %d", result.ExitCode)
	}

	t.logger.Info("Trivy database updated successfully")
	return nil
}

// GetVersion returns the Trivy version
func (t *TrivyWrapper) GetVersion() string {
	// Execute version check using secure executor
	result, err := t.executor.Execute(context.Background(), "trivy-version", []string{"--version"})
	if err != nil {
		t.logger.Warnf("Version check failed: %v", err)
		return "unknown"
	}
	
	if result.ExitCode != 0 {
		return "unknown"
	}

	// Parse version from output
	lines := strings.Split(string(result.Stdout), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return "unknown"
}