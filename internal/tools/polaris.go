package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/security"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

// PolarisWrapper wraps the Polaris workload best practices validator
type PolarisWrapper struct {
	config   config.PolarisConfig
	executor *security.SecureExecutor
	logger   *logrus.Logger
}

// Security validation patterns
var (
	// Valid config file path pattern (no path traversal)
	validConfigPathPattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+\.ya?ml$`)
	// Valid output format pattern
	validPolarisFormatPattern = regexp.MustCompile(`^(json|yaml|pretty|score)$`)
)

// PolarisReport represents Polaris audit JSON output
type PolarisReport struct {
	PolarisVersion string          `json:"PolarisVersion"`
	AuditTime      string          `json:"AuditTime"`
	SourceType     string          `json:"SourceType"`
	SourceName     string          `json:"SourceName"`
	DisplayName    string          `json:"DisplayName"`
	ClusterSummary PolarisCluster  `json:"ClusterSummary"`
	Results        []PolarisResult `json:"Results"`
}

// PolarisCluster represents cluster-level summary
type PolarisCluster struct {
	Version    string       `json:"Version"`
	Nodes      int          `json:"Nodes"`
	Pods       int          `json:"Pods"`
	Namespaces int          `json:"Namespaces"`
	Workloads  int          `json:"Workloads"`
	Results    PolarisScore `json:"Results"`
}

// PolarisScore represents scoring information
type PolarisScore struct {
	Totals            PolarisScoreTotals            `json:"Totals"`
	ResultsByCategory map[string]PolarisScoreTotals `json:"ResultsByCategory"`
}

// PolarisScoreTotals represents score totals
type PolarisScoreTotals struct {
	Successes int `json:"Successes"`
	Warnings  int `json:"Warnings"`
	Errors    int `json:"Errors"`
}

// PolarisResult represents a workload assessment result
type PolarisResult struct {
	Name       string                        `json:"Name"`
	Namespace  string                        `json:"Namespace"`
	Kind       string                        `json:"Kind"`
	APIVersion string                        `json:"APIVersion"`
	PodResult  PolarisPodResult              `json:"PodResult"`
	Results    map[string]PolarisCheckResult `json:"Results"`
}

// PolarisPodResult represents pod-level results
type PolarisPodResult struct {
	Name             string                        `json:"Name"`
	Results          map[string]PolarisCheckResult `json:"Results"`
	ContainerResults []PolarisContainerResult      `json:"ContainerResults"`
}

// PolarisContainerResult represents container-level results
type PolarisContainerResult struct {
	Name    string                        `json:"Name"`
	Results map[string]PolarisCheckResult `json:"Results"`
}

// PolarisCheckResult represents individual check result
type PolarisCheckResult struct {
	ID       string `json:"ID"`
	Message  string `json:"Message"`
	Success  bool   `json:"Success"`
	Severity string `json:"Severity"`
	Category string `json:"Category"`
}

// NewPolarisWrapper creates a new Polaris wrapper
func NewPolarisWrapper(config config.PolarisConfig) *PolarisWrapper {
	return &PolarisWrapper{
		config:   config,
		executor: security.NewSecureExecutor(),
		logger:   logrus.New(),
	}
}

// validateConfigPath validates configuration file path for security
func validateConfigPath(configPath string) error {
	if configPath == "" {
		return nil // Empty is allowed (uses default)
	}

	// Check for path traversal
	if strings.Contains(configPath, "..") {
		return fmt.Errorf("invalid config path: path traversal detected")
	}

	// Validate pattern
	if !validConfigPathPattern.MatchString(configPath) {
		return fmt.Errorf("invalid config path: %s (must be valid YAML file)", configPath)
	}

	// Additional length check
	if len(configPath) > 255 {
		return fmt.Errorf("config path too long: %d characters (max 255)", len(configPath))
	}

	return nil
}

// GetInfo returns information about the Polaris tool
func (p *PolarisWrapper) GetInfo() types.ToolInfo {
	return types.ToolInfo{
		Name:        "polaris",
		Version:     p.GetVersion(),
		Description: "Kubernetes workload best practices validator",
		Website:     "https://github.com/FairwindsOps/polaris",
		License:     "Apache 2.0",
		Capabilities: []string{
			"Security best practices validation",
			"Resource efficiency checks",
			"Reliability recommendations",
			"Custom policy configuration",
			"Workload health scoring",
			"Multi-category analysis (Security, Efficiency, Reliability)",
		},
	}
}

// Validate checks if Polaris is available and properly configured
func (p *PolarisWrapper) Validate() error {
	// Test basic execution using secure executor
	result, err := p.executor.Execute(context.Background(), "polaris-version", []string{"version"})
	if err != nil {
		return fmt.Errorf("polaris validation failed: %w", err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("polaris version check failed with exit code %d", result.ExitCode)
	}

	// Check if output contains expected content
	versionOutput := string(result.Stdout)
	if !strings.Contains(versionOutput, "polaris") {
		return fmt.Errorf("polaris does not appear to be properly installed")
	}

	p.logger.Info("polaris validation successful")
	return nil
}

// Execute runs Polaris with the given configuration
func (p *PolarisWrapper) Execute(ctx context.Context, config types.ToolConfig) (*types.ToolResult, error) {
	startTime := time.Now()

	p.logger.Info("Starting Polaris workload validation")

	// Build command arguments
	args, err := p.buildAuditArgs(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build audit arguments: %w", err)
	}

	// Execute Polaris audit using secure executor
	execResult, err := p.executor.Execute(ctx, "polaris", args)
	if err != nil {
		return nil, fmt.Errorf("polaris execution failed: %w", err)
	}

	// Polaris can return non-zero exit codes in normal operation when issues are found
	if execResult.ExitCode != 0 && len(execResult.Stdout) == 0 {
		return nil, fmt.Errorf("polaris audit failed with exit code %d: %s",
			execResult.ExitCode, string(execResult.Stderr))
	}

	// Parse results
	findings, err := p.parseAuditResults(execResult.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit results: %w", err)
	}

	duration := time.Since(startTime)
	result := &types.ToolResult{
		ToolName:   "polaris",
		ExecutedAt: startTime,
		Duration:   duration,
		ExitCode:   execResult.ExitCode,
		RawOutput:  execResult.Stdout,
		Findings:   findings,
		Metadata: map[string]interface{}{
			"total_findings": len(findings),
			"config_used":    p.config.ConfigFile,
		},
	}

	if len(execResult.Stderr) > 0 {
		result.ErrorOutput = execResult.Stderr
	}

	p.logger.Infof("Polaris validation completed with %d findings in %v",
		len(findings), duration)

	return result, nil
}

// buildAuditArgs builds command arguments for Polaris audit
func (p *PolarisWrapper) buildAuditArgs(config types.ToolConfig) ([]string, error) {
	args := []string{"audit"}

	// Add kubeconfig if specified
	if config.KubeconfigPath != "" {
		args = append(args, "--kubeconfig", config.KubeconfigPath)
	}

	// Add context if specified
	if config.Context != "" {
		args = append(args, "--context", config.Context)
	}

	// Add namespaces if specified
	if len(config.Namespaces) > 0 {
		for _, ns := range config.Namespaces {
			// Validate namespace name
			if !validNamespacePattern.MatchString(ns) {
				return nil, fmt.Errorf("invalid namespace: %s", ns)
			}
			args = append(args, "--namespace", ns)
		}
	}

	// Add output format
	args = append(args, "--format", "json")

	// Add config file if specified
	if p.config.ConfigFile != "" {
		if err := validateConfigPath(p.config.ConfigFile); err != nil {
			return nil, err
		}
		args = append(args, "--config", p.config.ConfigFile)
	}

	// Add only-show-failures if enabled
	if p.config.OnlyShowFailures {
		args = append(args, "--only-show-failures")
	}

	// Suppress Insights upload prompt
	args = append(args, "--quiet")

	return args, nil
}

// parseAuditResults parses Polaris JSON output into security findings
func (p *PolarisWrapper) parseAuditResults(output []byte) ([]types.SecurityFinding, error) {
	var report PolarisReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Polaris output: %w", err)
	}

	var findings []types.SecurityFinding

	// Process workload results
	for _, result := range report.Results {
		// Process workload-level checks
		for checkID, checkResult := range result.Results {
			if !checkResult.Success {
				finding := p.createFinding(result, checkID, checkResult, "workload")
				findings = append(findings, finding)
			}
		}

		// Process pod-level checks
		for checkID, checkResult := range result.PodResult.Results {
			if !checkResult.Success {
				finding := p.createFinding(result, checkID, checkResult, "pod")
				findings = append(findings, finding)
			}
		}

		// Process container-level checks
		for _, containerResult := range result.PodResult.ContainerResults {
			for checkID, checkResult := range containerResult.Results {
				if !checkResult.Success {
					finding := p.createFindingWithContainer(result, containerResult, checkID, checkResult)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

// createFinding creates a SecurityFinding from a Polaris check result
func (p *PolarisWrapper) createFinding(result PolarisResult, checkID string, checkResult PolarisCheckResult, level string) types.SecurityFinding {
	// Map Polaris severity to our severity levels
	severity := p.mapSeverity(checkResult.Severity)
	findingType := p.mapCategory(checkResult.Category)

	title := fmt.Sprintf("Polaris %s Check: %s", strings.Title(level), checkID)
	if checkResult.Message != "" {
		title = checkResult.Message
	}

	return types.SecurityFinding{
		ID:          fmt.Sprintf("polaris-%s-%s-%s", level, strings.ToLower(checkID), result.Name),
		Type:        findingType,
		Severity:    severity,
		Title:       title,
		Description: p.buildDescription(result, checkResult, level),
		Source:      "polaris",
		SourceID:    checkID,
		Framework:   "Polaris Best Practices",
		Resource: types.ResourceReference{
			APIVersion: result.APIVersion,
			Kind:       result.Kind,
			Name:       result.Name,
			Namespace:  result.Namespace,
		},
		Evidence: map[string]interface{}{
			"check_id": checkID,
			"category": checkResult.Category,
			"severity": checkResult.Severity,
			"message":  checkResult.Message,
			"level":    level,
			"success":  checkResult.Success,
		},
		Tags:        p.buildTags(checkResult),
		Remediation: p.buildRemediation(checkID, checkResult),
		Timestamp:   time.Now(),
	}
}

// createFindingWithContainer creates a SecurityFinding for container-level issues
func (p *PolarisWrapper) createFindingWithContainer(result PolarisResult, containerResult PolarisContainerResult, checkID string, checkResult PolarisCheckResult) types.SecurityFinding {
	finding := p.createFinding(result, checkID, checkResult, "container")

	// Update title and evidence for container context
	finding.Title = fmt.Sprintf("Polaris Container Check: %s (Container: %s)", checkID, containerResult.Name)
	finding.ID = fmt.Sprintf("polaris-container-%s-%s-%s", strings.ToLower(checkID), result.Name, containerResult.Name)

	// Add container information to evidence
	evidence := finding.Evidence.(map[string]interface{})
	evidence["container_name"] = containerResult.Name
	evidence["level"] = "container"

	return finding
}

// mapSeverity maps Polaris severity to our severity levels
func (p *PolarisWrapper) mapSeverity(polarisSeverity string) string {
	switch strings.ToLower(polarisSeverity) {
	case "error":
		return string(types.SeverityHigh)
	case "warning":
		return string(types.SeverityMedium)
	case "ignore":
		return string(types.SeverityLow)
	default:
		return string(types.SeverityMedium)
	}
}

// mapCategory maps Polaris category to finding type
func (p *PolarisWrapper) mapCategory(category string) string {
	switch strings.ToLower(category) {
	case "security":
		return string(types.FindingTypeMisconfiguration)
	case "efficiency":
		return string(types.FindingTypeBestPractice)
	case "reliability":
		return string(types.FindingTypeBestPractice)
	default:
		return string(types.FindingTypeBestPractice)
	}
}

// buildDescription creates a description for the finding
func (p *PolarisWrapper) buildDescription(result PolarisResult, checkResult PolarisCheckResult, level string) string {
	return fmt.Sprintf(
		"Polaris %s validation failed for %s '%s' in namespace '%s'. "+
			"Check '%s' in category '%s' reported: %s",
		level, result.Kind, result.Name, result.Namespace,
		checkResult.ID, checkResult.Category, checkResult.Message)
}

// buildTags creates tags for the finding
func (p *PolarisWrapper) buildTags(checkResult PolarisCheckResult) []string {
	tags := []string{"polaris", "best-practices", "workload-validation"}

	// Add category-specific tags
	switch strings.ToLower(checkResult.Category) {
	case "security":
		tags = append(tags, "security", "configuration-security")
	case "efficiency":
		tags = append(tags, "efficiency", "resource-optimization")
	case "reliability":
		tags = append(tags, "reliability", "availability")
	}

	// Add severity-based tags
	if strings.ToLower(checkResult.Severity) == "error" {
		tags = append(tags, "critical-issue")
	}

	return tags
}

// buildRemediation creates remediation advice
func (p *PolarisWrapper) buildRemediation(checkID string, checkResult PolarisCheckResult) string {
	baseRemediation := fmt.Sprintf("Address the '%s' check failure in category '%s'. %s",
		checkID, checkResult.Category, checkResult.Message)

	// Add category-specific guidance
	switch strings.ToLower(checkResult.Category) {
	case "security":
		return baseRemediation + " Review security configuration and apply recommended security settings."
	case "efficiency":
		return baseRemediation + " Optimize resource allocation and configuration for better efficiency."
	case "reliability":
		return baseRemediation + " Improve configuration for better reliability and availability."
	default:
		return baseRemediation + " Follow Polaris best practices documentation for detailed guidance."
	}
}

// UpdateDatabase updates Polaris configuration (no separate database to update)
func (p *PolarisWrapper) UpdateDatabase() error {
	p.logger.Info("Polaris database update not required (uses live cluster analysis)")
	return nil // Polaris doesn't have a separate database to update
}

// GetVersion returns the Polaris version
func (p *PolarisWrapper) GetVersion() string {
	// Execute version check using secure executor
	result, err := p.executor.Execute(context.Background(), "polaris-version", []string{"version"})
	if err != nil {
		p.logger.Warnf("Version check failed: %v", err)
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
		if strings.Contains(line, "polaris") && strings.Contains(line, "version") {
			// Extract version from output like "polaris version v4.2.0"
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "version" && i+1 < len(parts) {
					return strings.TrimPrefix(parts[i+1], "v")
				}
			}
		}
	}

	return "unknown"
}
