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

// KubescapeWrapper wraps the Kubescape security scanner
type KubescapeWrapper struct {
	config   config.KubescapeConfig
	executor *security.SecureExecutor
	logger   *logrus.Logger
}

// Security validation patterns (used by buildScanArgs)
var (
	// Valid namespace name pattern (RFC 1123 DNS label)
	validNamespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// Valid Kubernetes context pattern  
	validContextPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	// Valid framework names (allowlist)
	validFrameworks = map[string]bool{
		"AllControls": true, "ArmoBest": true, "DevOpsBest": true, "MITRE": true,
		"NSA": true, "SOC2": true, "cis-aks-t1.2.0": true, "cis-eks-t1.2.0": true,
		"cis-v1.10.0": true, "cis-v1.23-t1.0.1": true,
	}
)

// KubescapeReport represents Kubescape's scan output
type KubescapeReport struct {
	CustomerGUID     string                    `json:"customerGUID"`
	ClusterName      string                    `json:"clusterName"`
	ReportGeneratedTime string                 `json:"reportGeneratedTime"`
	Results          []KubescapeFrameworkResult `json:"results"`
	ClusterAPIServerInfo KubescapeClusterInfo  `json:"clusterAPIServerInfo"`
	SummaryDetails   KubescapeSummary          `json:"summaryDetails"`
}

// KubescapeFrameworkResult represents results for a specific framework
type KubescapeFrameworkResult struct {
	Framework    KubescapeFramework        `json:"framework"`
	Score        float64                   `json:"score"`
	Controls     []KubescapeControlResult  `json:"controls"`
}

// KubescapeFramework represents a compliance framework
type KubescapeFramework struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// KubescapeControlResult represents a single control result
type KubescapeControlResult struct {
	ControlID     string                     `json:"controlID"`
	Name          string                     `json:"name"`
	Description   string                     `json:"description"`
	Remediation   string                     `json:"remediation"`
	BaseScore     float64                    `json:"baseScore"`
	Score         float64                    `json:"score"`
	Status        KubescapeControlStatus     `json:"status"`
	ResourcesResult []KubescapeResourceResult `json:"resourcesResult"`
	Rules         []KubescapeRule            `json:"rules"`
}

// KubescapeControlStatus represents control status
type KubescapeControlStatus struct {
	Status      string `json:"status"`
	SubStatus   string `json:"subStatus"`
	Info        string `json:"info"`
}

// KubescapeResourceResult represents a resource that was evaluated
type KubescapeResourceResult struct {
	ResourceID   string                    `json:"resourceID"`
	Object       map[string]interface{}    `json:"object"`
	Configurations []KubescapeConfiguration `json:"configurations"`
}

// KubescapeConfiguration represents a configuration issue
type KubescapeConfiguration struct {
	Type        string                 `json:"type"`
	Path        string                 `json:"path"`
	Value       interface{}            `json:"value"`
	Expected    interface{}            `json:"expected"`
	Description string                 `json:"description"`
}

// KubescapeRule represents a compliance rule
type KubescapeRule struct {
	Name        string `json:"name"`
	RuleLanguage string `json:"ruleLanguage"`
	Match       []map[string]interface{} `json:"match"`
	Rule        string `json:"rule"`
}

// KubescapeClusterInfo represents cluster information
type KubescapeClusterInfo struct {
	ServerVersion string `json:"serverVersion"`
	GitVersion    string `json:"gitVersion"`
}

// KubescapeSummary represents scan summary
type KubescapeSummary struct {
	Score              float64            `json:"score"`
	TotalResources     int                `json:"totalResources"`
	TotalFailed        int                `json:"totalFailed"`
	ControlsSummary    map[string]int     `json:"controlsSummary"`
	ComplianceScore    float64            `json:"complianceScore"`
	FrameworksScores   map[string]float64 `json:"frameworksScores"`
}

// NewKubescapeWrapper creates a new Kubescape wrapper
func NewKubescapeWrapper(config config.KubescapeConfig) *KubescapeWrapper {
	return &KubescapeWrapper{
		config:   config,
		executor: security.NewSecureExecutor(),
		logger:   logrus.New(),
	}
}


// validateNamespace validates namespace names for security (used by buildScanArgs)
func validateNamespace(ns string) error {
	if ns == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if len(ns) > 63 {
		return fmt.Errorf("namespace name too long (max 63 characters)")
	}
	if !validNamespacePattern.MatchString(ns) {
		return fmt.Errorf("invalid namespace name: %s", ns)
	}
	return nil
}

// validateContext validates Kubernetes context names for security (used by buildScanArgs)
func validateContext(ctx string) error {
	if ctx == "" {
		return nil // Empty context is allowed
	}
	if len(ctx) > 253 {
		return fmt.Errorf("context name too long (max 253 characters)")
	}
	if !validContextPattern.MatchString(ctx) {
		return fmt.Errorf("invalid context name: %s", ctx)
	}
	return nil
}

// validateFramework validates framework names against allowlist (used by buildScanArgs)
func validateFramework(framework string) error {
	if !validFrameworks[framework] {
		return fmt.Errorf("invalid framework: %s (allowed: %v)", framework, getValidFrameworks())
	}
	return nil
}

// getValidFrameworks returns list of valid frameworks for error messages
func getValidFrameworks() []string {
	frameworks := make([]string, 0, len(validFrameworks))
	for f := range validFrameworks {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

// GetInfo returns information about the Kubescape tool
func (k *KubescapeWrapper) GetInfo() types.ToolInfo {
	return types.ToolInfo{
		Name:        "kubescape",
		Version:     k.GetVersion(),
		Description: "Kubernetes configuration security scanner",
		Website:     "https://kubescape.io/",
		License:     "Apache 2.0",
		Capabilities: []string{
			"Configuration security scanning",
			"CIS Kubernetes Benchmark",
			"NSA/CISA Guidelines",
			"MITRE ATT&CK framework",
			"Custom Resource scanning",
			"Operator security analysis",
		},
	}
}

// Validate checks if Kubescape is available and properly configured
func (k *KubescapeWrapper) Validate() error {
	// Test basic execution using secure executor
	result, err := k.executor.Execute(context.Background(), "kubescape-version", []string{"version"})
	if err != nil {
		return fmt.Errorf("kubescape validation failed: %w", err)
	}
	
	if result.ExitCode != 0 {
		return fmt.Errorf("kubescape version check failed with exit code %d", result.ExitCode)
	}
	
	k.logger.Info("Kubescape validation successful")
	return nil
}

// Execute runs Kubescape with the given configuration
func (k *KubescapeWrapper) Execute(ctx context.Context, config types.ToolConfig) (*types.ToolResult, error) {
	startTime := time.Now()
	
	k.logger.Info("Starting Kubescape configuration scan")

	// Build command arguments with security validation
	args, err := k.buildScanArgs(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build secure command arguments: %w", err)
	}

	// Execute command using secure executor
	execResult, err := k.executor.Execute(ctx, "kubescape-scan", args)
	duration := time.Since(startTime)

	result := &types.ToolResult{
		ToolName:   "kubescape",
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
		k.logger.Warnf("Kubescape stderr: %s", string(execResult.Stderr))
		// Check if it's just a warning exit code (kubescape returns 1 when findings exist)
		if execResult.ExitCode == 1 && len(execResult.Stdout) > 0 {
			k.logger.Info("Kubescape returned exit code 1 but has output (likely due to findings)")
			// Continue processing - this is normal when security issues are found
		} else {
			return result, fmt.Errorf("kubescape execution failed: %w", err)
		}
	}

	// Parse results
	findings, err := k.parseResults(execResult.Stdout)
	if err != nil {
		return result, fmt.Errorf("failed to parse kubescape results: %w", err)
	}

	result.Findings = findings
	k.logger.Infof("Kubescape scan completed with %d findings in %v", 
		len(findings), duration)

	return result, nil
}

// buildScanArgs builds the command arguments for scanning with security validation
func (k *KubescapeWrapper) buildScanArgs(config types.ToolConfig) ([]string, error) {
	// Start with scan framework subcommand instead of direct scan
	framework := "NSA" // Default framework (NSA is available)
	if len(k.config.Frameworks) > 0 {
		framework = k.config.Frameworks[0] // Use first framework
	}
	
	// Validate framework name for security
	if err := validateFramework(framework); err != nil {
		return nil, err
	}
	
	args := []string{
		"scan", "framework", framework,
		"--format", "json",
		"--verbose",
	}

	// Add kubeconfig if specified (validate path)
	if config.KubeconfigPath != "" {
		cleanPath := filepath.Clean(config.KubeconfigPath)
		args = append(args, "--kubeconfig", cleanPath)
	}

	// Add context if specified (validate name)
	if config.Context != "" {
		if err := validateContext(config.Context); err != nil {
			return nil, err
		}
		args = append(args, "--kube-context", config.Context)
	}

	// Add namespace filters (validate each namespace)
	if len(config.Namespaces) > 0 {
		for _, ns := range config.Namespaces {
			if err := validateNamespace(ns); err != nil {
				return nil, fmt.Errorf("invalid namespace %s: %w", ns, err)
			}
		}
		args = append(args, "--include-namespaces", strings.Join(config.Namespaces, ","))
	}

	// Add excluded namespaces (validate each namespace)
	if len(k.config.ExcludeNamespaces) > 0 {
		for _, ns := range k.config.ExcludeNamespaces {
			if err := validateNamespace(ns); err != nil {
				return nil, fmt.Errorf("invalid excluded namespace %s: %w", ns, err)
			}
		}
		args = append(args, "--exclude-namespaces", strings.Join(k.config.ExcludeNamespaces, ","))
	}

	// Don't submit results to cloud
	args = append(args, "--submit=false")

	return args, nil
}

// parseResults parses Kubescape JSON output into normalized findings
func (k *KubescapeWrapper) parseResults(output []byte) ([]types.SecurityFinding, error) {
	var report KubescapeReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal kubescape output: %w", err)
	}

	var findings []types.SecurityFinding

	// Process each framework result
	for _, frameworkResult := range report.Results {
		// Process each control
		for _, control := range frameworkResult.Controls {
			// Only process failed controls
			if control.Status.Status == "failed" {
				// Process each failed resource
				for _, resource := range control.ResourcesResult {
					finding := k.controlToFinding(control, resource, frameworkResult.Framework)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

// controlToFinding converts a Kubescape control failure to a SecurityFinding
func (k *KubescapeWrapper) controlToFinding(control KubescapeControlResult, resource KubescapeResourceResult, framework KubescapeFramework) types.SecurityFinding {
	// Extract resource information
	resourceRef := k.extractResourceReference(resource.Object)
	
	// Determine finding type based on framework
	findingType := string(types.FindingTypeMisconfiguration)
	if strings.Contains(strings.ToLower(framework.Name), "compliance") {
		findingType = string(types.FindingTypeCompliance)
	}

	// Map score to severity
	severity := k.mapScoreToSeverity(control.BaseScore)

	// Build evidence from configurations
	evidence := make(map[string]interface{})
	evidence["control_score"] = control.Score
	evidence["base_score"] = control.BaseScore
	evidence["status"] = control.Status
	
	if len(resource.Configurations) > 0 {
		evidence["configurations"] = resource.Configurations
	}

	return types.SecurityFinding{
		ID:          fmt.Sprintf("kubescape-%s-%s", control.ControlID, resourceRef.Name),
		Type:        findingType,
		Severity:    severity,
		Title:       control.Name,
		Description: control.Description,
		Source:      "kubescape",
		SourceID:    control.ControlID,
		Framework:   framework.Name,
		Resource:    resourceRef,
		Remediation: control.Remediation,
		Evidence:    evidence,
		Tags:        []string{framework.Name, "configuration"},
		Timestamp:   time.Now(),
	}
}

// extractResourceReference extracts resource information from Kubescape object
func (k *KubescapeWrapper) extractResourceReference(obj map[string]interface{}) types.ResourceReference {
	resourceRef := types.ResourceReference{}

	// Extract basic fields
	if kind, ok := obj["kind"].(string); ok {
		resourceRef.Kind = kind
	}
	
	if apiVersion, ok := obj["apiVersion"].(string); ok {
		resourceRef.APIVersion = apiVersion
	}

	// Extract metadata
	if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			resourceRef.Name = name
		}
		if namespace, ok := metadata["namespace"].(string); ok {
			resourceRef.Namespace = namespace
		}
		if uid, ok := metadata["uid"].(string); ok {
			resourceRef.UID = uid
		}
	}

	return resourceRef
}

// mapScoreToSeverity maps Kubescape score to standard severity
func (k *KubescapeWrapper) mapScoreToSeverity(score float64) string {
	// Kubescape uses 0-10 scale where 10 is most critical
	switch {
	case score >= 9.0:
		return string(types.SeverityCritical)
	case score >= 7.0:
		return string(types.SeverityHigh)
	case score >= 4.0:
		return string(types.SeverityMedium)
	case score >= 2.0:
		return string(types.SeverityLow)
	default:
		return string(types.SeverityInfo)
	}
}

// UpdateDatabase updates Kubescape's rule database
func (k *KubescapeWrapper) UpdateDatabase() error {
	k.logger.Info("Updating Kubescape database")
	
	// Execute update using secure executor
	result, err := k.executor.Execute(context.Background(), "kubescape-update", []string{"download", "artifacts"})
	if err != nil {
		return fmt.Errorf("failed to update kubescape database: %w", err)
	}
	
	if result.ExitCode != 0 {
		return fmt.Errorf("kubescape database update failed with exit code %d", result.ExitCode)
	}

	k.logger.Info("Kubescape database updated successfully")
	return nil
}

// GetVersion returns the Kubescape version
func (k *KubescapeWrapper) GetVersion() string {
	// Execute version check using secure executor
	result, err := k.executor.Execute(context.Background(), "kubescape-version", []string{"version"})
	if err != nil {
		k.logger.Warnf("Version check failed: %v", err)
		return "unknown"
	}
	
	if result.ExitCode != 0 {
		return "unknown"
	}

	// Parse version from output
	lines := strings.Split(string(result.Stdout), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Your current version is:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return "unknown"
}