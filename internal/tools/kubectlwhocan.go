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

// KubectlWhoCanWrapper wraps the kubectl-who-can RBAC analysis tool
type KubectlWhoCanWrapper struct {
	config   config.RBACConfig
	executor *security.SecureExecutor
	logger   *logrus.Logger
}

// Security validation patterns
var (
	// Valid verb patterns (Kubernetes RBAC verbs)
	validVerbPattern = regexp.MustCompile(`^(get|list|create|update|patch|delete|deletecollection|watch|\*)$`)
	// Valid resource patterns (Kubernetes resource names + subresources, no path traversal)
	validResourcePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*(/[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)?$|^\*$`)
	// Valid namespace pattern (DNS-1123 label) for RBAC
	validRBACNamespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// Dangerous RBAC permissions that warrant HIGH severity
var dangerousPermissions = map[string]map[string]bool{
	"*": {
		"*": true, // cluster-admin equivalent
	},
	"create": {
		"pods":                true, // Can create pods with any privileges
		"roles":               true, // Can escalate privileges
		"rolebindings":        true, // Can escalate privileges
		"clusterroles":        true, // Can escalate privileges
		"clusterrolebindings": true, // Can escalate privileges
		"serviceaccounts":     true, // Can create service accounts
		"persistentvolumes":   true, // Can access host filesystem
		"nodes":               true, // Node management
		"*":                   true, // Create anything
	},
	"update": {
		"pods":                true,
		"roles":               true,
		"rolebindings":        true,
		"clusterroles":        true,
		"clusterrolebindings": true,
		"nodes":               true,
		"*":                   true,
	},
	"patch": {
		"pods":                true,
		"roles":               true,
		"rolebindings":        true,
		"clusterroles":        true,
		"clusterrolebindings": true,
		"*":                   true,
	},
	"delete": {
		"pods":              true,
		"nodes":             true,
		"persistentvolumes": true,
		"*":                 true,
	},
	"get": {
		"secrets": true, // Can read secrets
		"*":       true, // Can read anything
	},
	"list": {
		"secrets": true,
		"*":       true,
	},
}

// WhoCanReport represents kubectl-who-can's JSON output
type WhoCanReport struct {
	Verb            string          `json:"verb"`
	Resource        string          `json:"resource"`
	Namespace       string          `json:"namespace,omitempty"`
	Subresource     string          `json:"subresource,omitempty"`
	ResourceName    string          `json:"resourceName,omitempty"`
	Users           []WhoCanSubject `json:"users,omitempty"`
	Groups          []WhoCanSubject `json:"groups,omitempty"`
	ServiceAccounts []WhoCanSubject `json:"serviceAccounts,omitempty"`
}

// WhoCanSubject represents a subject that can perform the action
type WhoCanSubject struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind"`
}

// NewKubectlWhoCanWrapper creates a new kubectl-who-can wrapper
func NewKubectlWhoCanWrapper(config config.RBACConfig) *KubectlWhoCanWrapper {
	return &KubectlWhoCanWrapper{
		config:   config,
		executor: security.NewSecureExecutor(),
		logger:   logrus.New(),
	}
}

// validateVerb validates RBAC verb for security
func validateVerb(verb string) error {
	if !validVerbPattern.MatchString(verb) {
		return fmt.Errorf("invalid verb: %s (allowed: get,list,create,update,patch,delete,deletecollection,watch,*)", verb)
	}
	return nil
}

// validateResource validates resource name for security
func validateResource(resource string) error {
	if !validResourcePattern.MatchString(resource) {
		return fmt.Errorf("invalid resource: %s (must be alphanumeric with hyphens, dots, slashes)", resource)
	}
	// Additional length check
	if len(resource) > 253 {
		return fmt.Errorf("resource name too long: %d characters (max 253)", len(resource))
	}
	return nil
}

// validateRBACNamespace validates namespace name for RBAC security
func validateRBACNamespace(namespace string) error {
	if namespace == "" {
		return nil // Empty namespace is allowed (cluster-wide)
	}
	if !validRBACNamespacePattern.MatchString(namespace) {
		return fmt.Errorf("invalid namespace: %s (must be valid DNS-1123 label)", namespace)
	}
	if len(namespace) > 63 {
		return fmt.Errorf("namespace name too long: %d characters (max 63)", len(namespace))
	}
	return nil
}

// GetInfo returns information about the kubectl-who-can tool
func (k *KubectlWhoCanWrapper) GetInfo() types.ToolInfo {
	return types.ToolInfo{
		Name:        "kubectl-who-can",
		Version:     k.GetVersion(),
		Description: "RBAC analysis tool for Kubernetes permissions audit",
		Website:     "https://github.com/aquasecurity/kubectl-who-can",
		License:     "Apache 2.0",
		Capabilities: []string{
			"RBAC permissions analysis",
			"Privilege escalation detection",
			"Service account enumeration",
			"Cluster-wide permission mapping",
			"Dangerous permissions identification",
			"Role and ClusterRole analysis",
		},
	}
}

// Validate checks if kubectl-who-can is available and properly configured
func (k *KubectlWhoCanWrapper) Validate() error {
	// Test basic execution using secure executor
	result, err := k.executor.Execute(context.Background(), "kubectl-who-can-version", []string{"--help"})
	if err != nil {
		return fmt.Errorf("kubectl-who-can validation failed: %w", err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("kubectl-who-can help check failed with exit code %d", result.ExitCode)
	}

	// Check if help output contains expected content
	helpOutput := string(result.Stdout)
	if !strings.Contains(helpOutput, "kubectl-who-can") {
		return fmt.Errorf("kubectl-who-can does not appear to be properly installed")
	}

	k.logger.Info("kubectl-who-can validation successful")
	return nil
}

// Execute runs kubectl-who-can with the given configuration
func (k *KubectlWhoCanWrapper) Execute(ctx context.Context, config types.ToolConfig) (*types.ToolResult, error) {
	startTime := time.Now()

	k.logger.Info("Starting kubectl-who-can RBAC analysis")

	// Build scan queries based on configuration
	queries, err := k.buildScanQueries(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build scan queries: %w", err)
	}

	var allFindings []types.SecurityFinding
	var allOutput []byte
	var totalErrors []string

	// Execute each query
	for _, query := range queries {
		k.logger.Infof("Analyzing permissions for %s %s", query.verb, query.resource)

		findings, output, err := k.executeQuery(ctx, query, config)
		if err != nil {
			k.logger.WithError(err).Warnf("Query failed for %s %s", query.verb, query.resource)
			totalErrors = append(totalErrors, fmt.Sprintf("%s %s: %v", query.verb, query.resource, err))
			continue
		}

		allFindings = append(allFindings, findings...)
		allOutput = append(allOutput, output...)
	}

	duration := time.Since(startTime)
	result := &types.ToolResult{
		ToolName:   "kubectl-who-can",
		ExecutedAt: startTime,
		Duration:   duration,
		ExitCode:   0, // Overall success if any queries succeeded
		RawOutput:  allOutput,
		Findings:   allFindings,
		Metadata: map[string]interface{}{
			"queries_executed": len(queries),
			"errors":           totalErrors,
		},
	}

	if len(totalErrors) > 0 {
		result.ErrorOutput = []byte(strings.Join(totalErrors, "\n"))
	}

	k.logger.Infof("kubectl-who-can analysis completed with %d findings in %v",
		len(allFindings), duration)

	return result, nil
}

// rbacQuery represents a single RBAC query to execute
type rbacQuery struct {
	verb         string
	resource     string
	namespace    string
	subresource  string
	resourceName string
}

// buildScanQueries builds the list of RBAC queries to execute
func (k *KubectlWhoCanWrapper) buildScanQueries(config types.ToolConfig) ([]rbacQuery, error) {
	var queries []rbacQuery

	// Define critical permissions to check based on configuration
	criticalQueries := []rbacQuery{
		// Cluster-admin equivalent checks
		{"*", "*", "", "", ""},
		{"create", "*", "", "", ""},
		{"delete", "*", "", "", ""},

		// Privilege escalation checks
		{"create", "roles", "", "", ""},
		{"create", "rolebindings", "", "", ""},
		{"create", "clusterroles", "", "", ""},
		{"create", "clusterrolebindings", "", "", ""},
		{"update", "roles", "", "", ""},
		{"update", "rolebindings", "", "", ""},
		{"update", "clusterroles", "", "", ""},
		{"update", "clusterrolebindings", "", "", ""},

		// Secret access checks
		{"get", "secrets", "", "", ""},
		{"list", "secrets", "", "", ""},

		// Pod manipulation (potential privilege escalation)
		{"create", "pods", "", "", ""},
		{"create", "pods", "", "exec", ""},
		{"create", "pods", "", "attach", ""},

		// Service account manipulation
		{"create", "serviceaccounts", "", "", ""},
		{"update", "serviceaccounts", "", "", ""},

		// Node access
		{"get", "nodes", "", "", ""},
		{"create", "nodes", "", "", ""},
		{"delete", "nodes", "", "", ""},

		// Persistent volume access
		{"create", "persistentvolumes", "", "", ""},
		{"delete", "persistentvolumes", "", "", ""},
	}

	// Add namespace-specific queries if namespaces are specified
	if len(config.Namespaces) > 0 {
		for _, ns := range config.Namespaces {
			if err := validateRBACNamespace(ns); err != nil {
				return nil, fmt.Errorf("invalid namespace %s: %w", ns, err)
			}

			// Add critical namespace-specific queries
			namespacedQueries := []rbacQuery{
				{"create", "pods", ns, "", ""},
				{"get", "secrets", ns, "", ""},
				{"list", "secrets", ns, "", ""},
				{"create", "roles", ns, "", ""},
				{"create", "rolebindings", ns, "", ""},
			}
			queries = append(queries, namespacedQueries...)
		}
	}

	// Add cluster-wide queries
	queries = append(queries, criticalQueries...)

	// Validate all queries
	for _, query := range queries {
		if err := validateVerb(query.verb); err != nil {
			return nil, err
		}
		if err := validateResource(query.resource); err != nil {
			return nil, err
		}
		if err := validateRBACNamespace(query.namespace); err != nil {
			return nil, err
		}
	}

	k.logger.Infof("Built %d RBAC queries for analysis", len(queries))
	return queries, nil
}

// executeQuery executes a single RBAC query
func (k *KubectlWhoCanWrapper) executeQuery(ctx context.Context, query rbacQuery, config types.ToolConfig) ([]types.SecurityFinding, []byte, error) {
	// Build command arguments
	args, err := k.buildQueryArgs(query, config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build query arguments: %w", err)
	}

	// Execute command using secure executor
	execResult, err := k.executor.Execute(ctx, "kubectl-who-can", args)
	if err != nil {
		return nil, nil, fmt.Errorf("kubectl-who-can execution failed: %w", err)
	}

	// kubectl-who-can can return non-zero exit codes in normal operation
	if execResult.ExitCode != 0 && len(execResult.Stdout) == 0 {
		return nil, execResult.Stderr, fmt.Errorf("query failed with exit code %d", execResult.ExitCode)
	}

	// Parse results
	findings, err := k.parseQueryResults(execResult.Stdout, query)
	if err != nil {
		return nil, execResult.Stdout, fmt.Errorf("failed to parse query results: %w", err)
	}

	return findings, execResult.Stdout, nil
}

// buildQueryArgs builds command arguments for a specific query
func (k *KubectlWhoCanWrapper) buildQueryArgs(query rbacQuery, config types.ToolConfig) ([]string, error) {
	args := []string{}

	// Add verb and resource
	args = append(args, query.verb)

	// Construct resource specification
	resource := query.resource
	if query.subresource != "" {
		resource += "/" + query.subresource
	}
	args = append(args, resource)

	// Add resource name if specified
	if query.resourceName != "" {
		args = append(args, query.resourceName)
	}

	// Add namespace if specified
	if query.namespace != "" {
		args = append(args, "--namespace", query.namespace)
	}

	// Add output format
	args = append(args, "--output", "json")

	// Add kubeconfig if specified
	if config.KubeconfigPath != "" {
		args = append(args, "--kubeconfig", config.KubeconfigPath)
	}

	// Add context if specified
	if config.Context != "" {
		args = append(args, "--context", config.Context)
	}

	return args, nil
}

// parseQueryResults parses kubectl-who-can JSON output into security findings
func (k *KubectlWhoCanWrapper) parseQueryResults(output []byte, query rbacQuery) ([]types.SecurityFinding, error) {
	var report WhoCanReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal kubectl-who-can output: %w", err)
	}

	var findings []types.SecurityFinding

	// Count total subjects with permission
	totalSubjects := len(report.Users) + len(report.Groups) + len(report.ServiceAccounts)

	// Only create findings if there are subjects with the permission
	if totalSubjects == 0 {
		return findings, nil
	}

	// Determine severity based on permission danger level
	severity := k.assessPermissionSeverity(query.verb, query.resource)
	findingType := string(types.FindingTypeRBAC)

	// Create finding for the permission
	finding := types.SecurityFinding{
		ID:          fmt.Sprintf("kubectl-who-can-%s-%s", query.verb, strings.ReplaceAll(query.resource, "/", "-")),
		Type:        findingType,
		Severity:    severity,
		Title:       fmt.Sprintf("RBAC Permission Analysis: %s %s", query.verb, query.resource),
		Description: k.buildPermissionDescription(query, totalSubjects),
		Source:      "kubectl-who-can",
		SourceID:    fmt.Sprintf("%s-%s", query.verb, query.resource),
		Framework:   "RBAC",
		Resource: types.ResourceReference{
			Kind:       "ClusterRole",
			Name:       "rbac-analysis",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		Evidence: map[string]interface{}{
			"verb":             query.verb,
			"resource":         query.resource,
			"namespace":        query.namespace,
			"subresource":      query.subresource,
			"resource_name":    query.resourceName,
			"total_subjects":   totalSubjects,
			"users":            report.Users,
			"groups":           report.Groups,
			"service_accounts": report.ServiceAccounts,
		},
		Tags:      k.buildPermissionTags(query, severity),
		Timestamp: time.Now(),
	}

	// Add remediation based on severity
	if severity == string(types.SeverityCritical) || severity == string(types.SeverityHigh) {
		finding.Remediation = k.buildPermissionRemediation(query)
	}

	findings = append(findings, finding)
	return findings, nil
}

// assessPermissionSeverity determines the severity level for a permission
func (k *KubectlWhoCanWrapper) assessPermissionSeverity(verb, resource string) string {
	// Check for critical permissions first
	if verb == "*" && resource == "*" {
		return string(types.SeverityCritical) // cluster-admin equivalent
	}

	// Check for privilege escalation permissions
	if strings.Contains(resource, "role") || strings.Contains(resource, "binding") {
		if verb == "create" || verb == "update" || verb == "patch" || verb == "*" {
			return string(types.SeverityCritical) // privilege escalation
		}
	}

	// Check for high-risk permissions based on specific verb-resource combinations
	if verbPerms, exists := dangerousPermissions[verb]; exists {
		if verbPerms[resource] {
			// Special cases for sensitive resources
			if resource == "secrets" && (verb == "get" || verb == "list") {
				return string(types.SeverityHigh) // secret access
			}
			if resource == "pods" && (verb == "create" || verb == "update" || verb == "patch") {
				return string(types.SeverityHigh) // pod manipulation
			}
			if verb == "create" || verb == "update" || verb == "patch" || verb == "delete" || verb == "*" {
				return string(types.SeverityHigh) // other dangerous write permissions
			}
		}
		// Check for wildcard permissions
		if verbPerms["*"] && (verb == "create" || verb == "update" || verb == "patch" || verb == "delete" || verb == "*") {
			return string(types.SeverityHigh) // wildcard dangerous permissions
		}
	}

	// Medium-risk: read access to regular resources
	if verb == "get" || verb == "list" || verb == "watch" {
		return string(types.SeverityMedium) // read access
	}

	// Default to low for other permissions
	return string(types.SeverityLow)
}

// buildPermissionDescription creates a description for the permission finding
func (k *KubectlWhoCanWrapper) buildPermissionDescription(query rbacQuery, subjectCount int) string {
	scope := "cluster-wide"
	if query.namespace != "" {
		scope = fmt.Sprintf("in namespace '%s'", query.namespace)
	}

	resource := query.resource
	if query.subresource != "" {
		resource += "/" + query.subresource
	}

	return fmt.Sprintf(
		"Found %d subject(s) with permission to '%s' on '%s' %s. "+
			"This permission should be reviewed to ensure it follows the principle of least privilege.",
		subjectCount, query.verb, resource, scope)
}

// buildPermissionTags creates tags for the permission finding
func (k *KubectlWhoCanWrapper) buildPermissionTags(query rbacQuery, severity string) []string {
	tags := []string{"RBAC", "permissions", "access-control"}

	if severity == string(types.SeverityCritical) || severity == string(types.SeverityHigh) {
		tags = append(tags, "privilege-escalation-risk")
	}

	if query.verb == "*" || query.resource == "*" {
		tags = append(tags, "wildcard-permissions")
	}

	if strings.Contains(query.resource, "secret") {
		tags = append(tags, "sensitive-data")
	}

	if strings.Contains(query.resource, "role") || strings.Contains(query.resource, "binding") {
		tags = append(tags, "rbac-management")
	}

	return tags
}

// buildPermissionRemediation creates remediation advice for dangerous permissions
func (k *KubectlWhoCanWrapper) buildPermissionRemediation(query rbacQuery) string {
	if query.verb == "*" && query.resource == "*" {
		return "Review cluster-admin permissions. Consider using more specific roles with minimal required permissions."
	}

	if strings.Contains(query.resource, "role") || strings.Contains(query.resource, "binding") {
		return "Review role management permissions. These can be used for privilege escalation. Consider restricting to specific roles or using admission controllers."
	}

	if query.resource == "secrets" {
		return "Review secret access permissions. Consider using service account token projection or external secret management."
	}

	if query.resource == "pods" && (query.verb == "create" || query.subresource == "exec") {
		return "Review pod creation/exec permissions. These can be used to gain access to node resources. Consider pod security standards."
	}

	return "Review this permission to ensure it follows the principle of least privilege."
}

// UpdateDatabase updates kubectl-who-can (no separate database to update)
func (k *KubectlWhoCanWrapper) UpdateDatabase() error {
	k.logger.Info("kubectl-who-can database update not required (uses live RBAC data)")
	return nil // kubectl-who-can doesn't have a separate database to update
}

// GetVersion returns the kubectl-who-can version
func (k *KubectlWhoCanWrapper) GetVersion() string {
	// Execute version check using secure executor
	result, err := k.executor.Execute(context.Background(), "kubectl-who-can-version", []string{"--version"})
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
		if strings.Contains(line, "kubectl-who-can") && strings.Contains(line, "version") {
			// Extract version from output like "kubectl-who-can version v0.4.0"
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
