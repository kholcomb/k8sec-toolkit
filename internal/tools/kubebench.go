package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/security"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

// KubeBenchWrapper wraps the kube-bench CIS Kubernetes Benchmark scanner
type KubeBenchWrapper struct {
	config   config.KubeBenchConfig
	executor *security.SecureExecutor
	logger   *logrus.Logger
}

// Security validation patterns
var (
	// Valid Kubernetes version pattern (e.g., v1.24, 1.25.0)
	validVersionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?$`)
	// Valid target names (allowlist)
	validTargets = map[string]bool{
		"master": true, "controlplane": true, "etcd": true, "node": true,
		"policies": true, "managedservices": true, "ack": true, "aks": true,
		"eks": true, "gke": true, "rh-0.7": true, "rh-1.0": true,
	}
)

// KubeBenchReport represents kube-bench's JSON output
type KubeBenchReport struct {
	Controls []KubeBenchGroup `json:"Controls"`
	Totals   KubeBenchTotals  `json:"Totals"`
}

// KubeBenchGroup represents a group of controls (e.g., Master Node Security)
type KubeBenchGroup struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	Text        string            `json:"text"`
	Type        string            `json:"type"`
	Tests       []KubeBenchTest   `json:"tests"`
	TotalFail   int               `json:"total_fail"`
	TotalPass   int               `json:"total_pass"`
	TotalWarn   int               `json:"total_warn"`
	TotalInfo   int               `json:"total_info"`
	TotalScore  int               `json:"total_score"`
	Remediation string            `json:"remediation"`
	Summary     map[string]string `json:"summary"`
}

// KubeBenchTest represents a single test within a group
type KubeBenchTest struct {
	Section     string            `json:"section"`
	Pass        int               `json:"pass"`
	Fail        int               `json:"fail"`
	Warn        int               `json:"warn"`
	Info        int               `json:"info"`
	Desc        string            `json:"desc"`
	Results     []KubeBenchResult `json:"results"`
	Summary     map[string]string `json:"summary"`
	Remediation string            `json:"remediation"`
}

// KubeBenchResult represents an individual check result
type KubeBenchResult struct {
	TestNumber     string `json:"test_number"`
	TestDesc       string `json:"test_desc"`
	Audit          string `json:"audit"`
	AuditEnv       string `json:"AuditEnv"`
	AuditConfig    string `json:"AuditConfig"`
	Type           string `json:"type"`
	Remediation    string `json:"remediation"`
	TestInfo       string `json:"test_info"`
	Status         string `json:"status"`
	ActualValue    string `json:"actual_value"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `json:"IsMultiple"`
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason"`
}

// KubeBenchTotals represents overall scan totals
type KubeBenchTotals struct {
	TotalPass int `json:"total_pass"`
	TotalFail int `json:"total_fail"`
	TotalWarn int `json:"total_warn"`
	TotalInfo int `json:"total_info"`
}

// NewKubeBenchWrapper creates a new kube-bench wrapper
func NewKubeBenchWrapper(config config.KubeBenchConfig) *KubeBenchWrapper {
	return &KubeBenchWrapper{
		config:   config,
		executor: security.NewSecureExecutor(),
		logger:   logrus.New(),
	}
}

// validateTarget validates target names against allowlist for security
func validateTarget(target string) error {
	if !validTargets[target] {
		return fmt.Errorf("invalid target: %s (allowed: %v)", target, getValidTargets())
	}
	return nil
}

// getValidTargets returns list of valid targets for error messages
func getValidTargets() []string {
	targets := make([]string, 0, len(validTargets))
	for t := range validTargets {
		targets = append(targets, t)
	}
	return targets
}

// validateVersion validates Kubernetes version format for security
func validateVersion(version string) error {
	if version == "" {
		return nil // Empty version is allowed (auto-detect)
	}
	if !validVersionPattern.MatchString(version) {
		return fmt.Errorf("invalid version format: %s (expected format: v1.24 or 1.25.0)", version)
	}
	return nil
}

// GetInfo returns information about the kube-bench tool
func (k *KubeBenchWrapper) GetInfo() types.ToolInfo {
	return types.ToolInfo{
		Name:        "kube-bench",
		Version:     k.GetVersion(),
		Description: "CIS Kubernetes Benchmark compliance scanner",
		Website:     "https://github.com/aquasecurity/kube-bench",
		License:     "Apache 2.0",
		Capabilities: []string{
			"CIS Kubernetes Benchmark compliance",
			"Control plane security assessment",
			"Node security validation",
			"etcd security checks",
			"Network policy validation",
			"RBAC configuration review",
		},
	}
}

// Validate checks if kube-bench is available and properly configured
func (k *KubeBenchWrapper) Validate() error {
	// Test basic execution using secure executor
	result, err := k.executor.Execute(context.Background(), "kube-bench-version", []string{"version"})
	if err != nil {
		return fmt.Errorf("kube-bench validation failed: %w", err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("kube-bench version check failed with exit code %d", result.ExitCode)
	}

	k.logger.Info("kube-bench validation successful")
	return nil
}

// Execute runs kube-bench with the given configuration
func (k *KubeBenchWrapper) Execute(ctx context.Context, config types.ToolConfig) (*types.ToolResult, error) {
	startTime := time.Now()

	k.logger.Info("Starting kube-bench CIS Kubernetes Benchmark scan")

	// Build command arguments with security validation
	args, err := k.buildScanArgs(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build secure command arguments: %w", err)
	}

	// Execute command using secure executor
	execResult, err := k.executor.Execute(ctx, "kube-bench-scan", args)
	duration := time.Since(startTime)

	result := &types.ToolResult{
		ToolName:    "kube-bench",
		ExecutedAt:  startTime,
		Duration:    duration,
		ExitCode:    execResult.ExitCode,
		RawOutput:   execResult.Stdout,
		ErrorOutput: execResult.Stderr,
		Metadata: map[string]interface{}{
			"audit_trail": execResult.AuditTrail,
		},
	}

	if err != nil {
		k.logger.Warnf("kube-bench stderr: %s", string(execResult.Stderr))
		// Check if it's just a warning exit code (kube-bench returns non-zero when failures exist)
		if execResult.ExitCode > 0 && len(execResult.Stdout) > 0 {
			k.logger.Info("kube-bench returned non-zero exit code but has output (likely due to failed checks)")
			// Continue processing - this is normal when security issues are found
		} else {
			return result, fmt.Errorf("kube-bench execution failed: %w", err)
		}
	}

	// Parse results
	findings, err := k.parseResults(execResult.Stdout)
	if err != nil {
		return result, fmt.Errorf("failed to parse kube-bench results: %w", err)
	}

	result.Findings = findings
	k.logger.Infof("kube-bench scan completed with %d findings in %v",
		len(findings), duration)

	return result, nil
}

// buildScanArgs builds the command arguments for scanning with security validation
func (k *KubeBenchWrapper) buildScanArgs(config types.ToolConfig) ([]string, error) {
	args := []string{
		"run",
		"--json",
	}

	// Add version if specified (validate format)
	version := k.config.Version
	if version != "" {
		if err := validateVersion(version); err != nil {
			return nil, err
		}
		args = append(args, "--version", version)
	}

	// Add custom config directory if specified (validate path)
	if k.config.ConfigDir != "" {
		cleanPath := filepath.Clean(k.config.ConfigDir)
		args = append(args, "--config-dir", cleanPath)
	}

	// Add targets if specified (validate each target)
	targets := k.config.Targets
	if len(targets) == 0 {
		// Default targets for comprehensive scan
		targets = []string{"master", "node", "etcd", "policies"}
	}

	for _, target := range targets {
		if err := validateTarget(target); err != nil {
			return nil, fmt.Errorf("invalid target %s: %w", target, err)
		}
	}

	// Add each target as separate argument (kube-bench expects this format)
	for _, target := range targets {
		args = append(args, "--targets", target)
	}

	// Add kubeconfig if specified (validate path)
	if config.KubeconfigPath != "" {
		cleanPath := filepath.Clean(config.KubeconfigPath)
		args = append(args, "--kubeconfig", cleanPath)
	}

	return args, nil
}

// parseResults parses kube-bench JSON output into normalized findings
func (k *KubeBenchWrapper) parseResults(output []byte) ([]types.SecurityFinding, error) {
	var report KubeBenchReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal kube-bench output: %w", err)
	}

	var findings []types.SecurityFinding

	// Process each control group
	for _, group := range report.Controls {
		// Process each test within the group
		for _, test := range group.Tests {
			// Process each individual result
			for _, result := range test.Results {
				// Only create findings for failed checks (FAIL or WARN)
				if result.Status == "FAIL" || result.Status == "WARN" {
					finding := k.resultToFinding(result, test, group)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

// resultToFinding converts a kube-bench result to a SecurityFinding
func (k *KubeBenchWrapper) resultToFinding(result KubeBenchResult, test KubeBenchTest, group KubeBenchGroup) types.SecurityFinding {
	// Determine severity based on status and scoring
	severity := k.mapStatusToSeverity(result.Status, result.Scored)

	// Determine finding type
	findingType := string(types.FindingTypeCompliance)

	// Build evidence
	evidence := map[string]interface{}{
		"test_number":     result.TestNumber,
		"audit_command":   result.Audit,
		"audit_env":       result.AuditEnv,
		"audit_config":    result.AuditConfig,
		"actual_value":    result.ActualValue,
		"expected_result": result.ExpectedResult,
		"reason":          result.Reason,
		"scored":          result.Scored,
		"group":           group.Text,
		"section":         test.Section,
	}

	// Create resource reference for cluster-level finding
	resourceRef := types.ResourceReference{
		Kind:       "Cluster",
		Name:       "kubernetes",
		APIVersion: "v1",
	}

	// Extract specific resource information from test description if available
	if strings.Contains(strings.ToLower(result.TestDesc), "pod") {
		resourceRef.Kind = "Pod"
	} else if strings.Contains(strings.ToLower(result.TestDesc), "service") {
		resourceRef.Kind = "Service"
	} else if strings.Contains(strings.ToLower(result.TestDesc), "configmap") {
		resourceRef.Kind = "ConfigMap"
	}

	return types.SecurityFinding{
		ID:          fmt.Sprintf("kube-bench-%s", result.TestNumber),
		Type:        findingType,
		Severity:    severity,
		Title:       result.TestDesc,
		Description: fmt.Sprintf("CIS Kubernetes Benchmark check %s failed. %s", result.TestNumber, result.TestInfo),
		Source:      "kube-bench",
		SourceID:    result.TestNumber,
		Framework:   "CIS Kubernetes Benchmark",
		Resource:    resourceRef,
		Remediation: result.Remediation,
		Evidence:    evidence,
		Tags:        []string{"CIS", "compliance", "benchmark", group.Type},
		Timestamp:   time.Now(),
	}
}

// mapStatusToSeverity maps kube-bench status to standard severity
func (k *KubeBenchWrapper) mapStatusToSeverity(status string, scored bool) string {
	switch status {
	case "FAIL":
		if scored {
			return string(types.SeverityHigh) // Scored failures are high severity
		}
		return string(types.SeverityMedium) // Unscored failures are medium
	case "WARN":
		return string(types.SeverityLow) // Warnings are low severity
	case "INFO":
		return string(types.SeverityInfo) // Info items are informational
	case "PASS":
		return string(types.SeverityInfo) // Passes are informational
	default:
		return string(types.SeverityInfo)
	}
}

// UpdateDatabase updates kube-bench's benchmark definitions
func (k *KubeBenchWrapper) UpdateDatabase() error {
	k.logger.Info("kube-bench database update not required (benchmarks are embedded)")
	return nil // kube-bench doesn't have a separate database to update
}

// GetVersion returns the kube-bench version
func (k *KubeBenchWrapper) GetVersion() string {
	// Execute version check using secure executor
	result, err := k.executor.Execute(context.Background(), "kube-bench-version", []string{"version"})
	if err != nil {
		k.logger.Warnf("Version check failed: %v", err)
		return "unknown"
	}

	if result.ExitCode != 0 {
		return "unknown"
	}

	// Parse version from output
	output := string(result.Stdout)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "kube-bench version") {
			// Extract version from "kube-bench version v0.6.10"
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return strings.TrimPrefix(parts[2], "v")
			}
		}
	}

	return "unknown"
}
