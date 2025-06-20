package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/sirupsen/logrus"
)

// SecureExecutor provides secure command execution with comprehensive validation
type SecureExecutor struct {
	logger *logrus.Logger
}

// CommandTemplate defines a secure command template
type CommandTemplate struct {
	Name        string            // Human-readable name
	BinaryName  string            // Exact binary name (no paths)
	BinaryPaths []string          // Allowed absolute paths for the binary
	Arguments   []ArgumentPattern // Allowed argument patterns
	Timeout     time.Duration     // Maximum execution time
	Description string            // Description for audit logs
}

// ArgumentPattern defines validation for command arguments
type ArgumentPattern struct {
	Pattern     *regexp.Regexp // Regex pattern for validation
	Required    bool           // Whether this argument is required
	Description string         // Description for audit logs
}

// ExecutionContext contains context for secure command execution
type ExecutionContext struct {
	Command     string
	Arguments   []string
	WorkingDir  string
	Timeout     time.Duration
	Environment []string
}

// ExecutionResult contains the result of secure command execution
type ExecutionResult struct {
	Command     string
	Arguments   []string
	ExitCode    int
	Stdout      []byte
	Stderr      []byte
	Duration    time.Duration
	Error       error
	AuditTrail  string
}

// NewSecureExecutor creates a new secure executor instance
func NewSecureExecutor() *SecureExecutor {
	return &SecureExecutor{
		logger: logrus.New(),
	}
}

// Command registry with pre-approved command templates
var commandRegistry = map[string]CommandTemplate{
	"trivy-version": {
		Name:       "Trivy Version Check",
		BinaryName: "trivy",
		BinaryPaths: []string{
			"/usr/local/bin/trivy",
			"/opt/homebrew/bin/trivy",
			"/usr/bin/trivy",
		},
		Arguments: []ArgumentPattern{
			{Pattern: regexp.MustCompile(`^--version$`), Required: true, Description: "Version flag"},
		},
		Timeout:     30 * time.Second,
		Description: "Get Trivy version information",
	},
	"trivy-kubernetes": {
		Name:       "Trivy Kubernetes Scan",
		BinaryName: "trivy",
		BinaryPaths: []string{
			"/usr/local/bin/trivy",
			"/opt/homebrew/bin/trivy",
			"/usr/bin/trivy",
		},
		Arguments: []ArgumentPattern{
			{Pattern: regexp.MustCompile(`^kubernetes$`), Required: true, Description: "Kubernetes subcommand"},
			{Pattern: regexp.MustCompile(`^--format$`), Required: false, Description: "Output format flag"},
			{Pattern: regexp.MustCompile(`^json$`), Required: false, Description: "JSON format"},
			{Pattern: regexp.MustCompile(`^--kubeconfig$`), Required: false, Description: "Kubeconfig flag"},
			{Pattern: regexp.MustCompile(`^[/a-zA-Z0-9._-]+$`), Required: false, Description: "Kubeconfig path"},
			{Pattern: regexp.MustCompile(`^--context$`), Required: false, Description: "Context flag"},
			{Pattern: regexp.MustCompile(`^[a-zA-Z0-9._-]+$`), Required: false, Description: "Context name"},
			{Pattern: regexp.MustCompile(`^--severity$`), Required: false, Description: "Severity flag"},
			{Pattern: regexp.MustCompile(`^(CRITICAL|HIGH|MEDIUM|LOW|INFO)(,(CRITICAL|HIGH|MEDIUM|LOW|INFO))*$`), Required: false, Description: "Severity levels"},
			{Pattern: regexp.MustCompile(`^--include-namespaces$`), Required: false, Description: "Include namespaces flag"},
			{Pattern: regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(,[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`), Required: false, Description: "Namespace list"},
			{Pattern: regexp.MustCompile(`^--timeout$`), Required: false, Description: "Timeout flag"},
			{Pattern: regexp.MustCompile(`^[0-9]+[mhs]$`), Required: false, Description: "Timeout duration"},
			{Pattern: regexp.MustCompile(`^--ignorefile$`), Required: false, Description: "Ignore file flag"},
			{Pattern: regexp.MustCompile(`^[/a-zA-Z0-9._-]+$`), Required: false, Description: "Ignore file path"},
		},
		Timeout:     10 * time.Minute,
		Description: "Scan Kubernetes cluster for vulnerabilities",
	},
	"trivy-update": {
		Name:       "Trivy Database Update",
		BinaryName: "trivy",
		BinaryPaths: []string{
			"/usr/local/bin/trivy",
			"/opt/homebrew/bin/trivy",
			"/usr/bin/trivy",
		},
		Arguments: []ArgumentPattern{
			{Pattern: regexp.MustCompile(`^image$`), Required: true, Description: "Image subcommand"},
			{Pattern: regexp.MustCompile(`^--download-db-only$`), Required: true, Description: "Download DB only flag"},
		},
		Timeout:     5 * time.Minute,
		Description: "Update Trivy vulnerability database",
	},
	"kubescape-version": {
		Name:       "Kubescape Version Check",
		BinaryName: "kubescape",
		BinaryPaths: []string{
			"/usr/local/bin/kubescape",
			"/opt/homebrew/bin/kubescape",
			"/usr/bin/kubescape",
		},
		Arguments: []ArgumentPattern{
			{Pattern: regexp.MustCompile(`^version$`), Required: true, Description: "Version subcommand"},
		},
		Timeout:     30 * time.Second,
		Description: "Get Kubescape version information",
	},
	"kubescape-scan": {
		Name:       "Kubescape Framework Scan",
		BinaryName: "kubescape",
		BinaryPaths: []string{
			"/usr/local/bin/kubescape",
			"/opt/homebrew/bin/kubescape",
			"/usr/bin/kubescape",
		},
		Arguments: []ArgumentPattern{
			{Pattern: regexp.MustCompile(`^scan$`), Required: true, Description: "Scan subcommand"},
			{Pattern: regexp.MustCompile(`^framework$`), Required: true, Description: "Framework subcommand"},
			{Pattern: regexp.MustCompile(`^(AllControls|ArmoBest|DevOpsBest|MITRE|NSA|SOC2|cis-aks-t1\.2\.0|cis-eks-t1\.2\.0|cis-v1\.10\.0|cis-v1\.23-t1\.0\.1)$`), Required: true, Description: "Framework name"},
			{Pattern: regexp.MustCompile(`^--format$`), Required: false, Description: "Output format flag"},
			{Pattern: regexp.MustCompile(`^json$`), Required: false, Description: "JSON format"},
			{Pattern: regexp.MustCompile(`^--verbose$`), Required: false, Description: "Verbose flag"},
			{Pattern: regexp.MustCompile(`^--kubeconfig$`), Required: false, Description: "Kubeconfig flag"},
			{Pattern: regexp.MustCompile(`^[/a-zA-Z0-9._-]+$`), Required: false, Description: "Kubeconfig path"},
			{Pattern: regexp.MustCompile(`^--kube-context$`), Required: false, Description: "Context flag"},
			{Pattern: regexp.MustCompile(`^[a-zA-Z0-9._-]+$`), Required: false, Description: "Context name"},
			{Pattern: regexp.MustCompile(`^--include-namespaces$`), Required: false, Description: "Include namespaces flag"},
			{Pattern: regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(,[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`), Required: false, Description: "Namespace list"},
			{Pattern: regexp.MustCompile(`^--exclude-namespaces$`), Required: false, Description: "Exclude namespaces flag"},
			{Pattern: regexp.MustCompile(`^--submit=false$`), Required: false, Description: "Submit flag with value"},
		},
		Timeout:     10 * time.Minute,
		Description: "Scan Kubernetes cluster with compliance framework",
	},
	"kubescape-update": {
		Name:       "Kubescape Database Update",
		BinaryName: "kubescape",
		BinaryPaths: []string{
			"/usr/local/bin/kubescape",
			"/opt/homebrew/bin/kubescape",
			"/usr/bin/kubescape",
		},
		Arguments: []ArgumentPattern{
			{Pattern: regexp.MustCompile(`^download$`), Required: true, Description: "Download subcommand"},
			{Pattern: regexp.MustCompile(`^artifacts$`), Required: true, Description: "Artifacts argument"},
		},
		Timeout:     5 * time.Minute,
		Description: "Update Kubescape rule database",
	},
}

// Execute securely executes a pre-approved command with validation
func (se *SecureExecutor) Execute(ctx context.Context, commandKey string, args []string) (*ExecutionResult, error) {
	startTime := time.Now()
	
	// Audit log entry
	auditEntry := fmt.Sprintf("SECURITY_AUDIT: Command execution requested - Key: %s, Args: %v", commandKey, args)
	se.logger.Info(auditEntry)

	// Validate command key exists in registry
	template, exists := commandRegistry[commandKey]
	if !exists {
		err := fmt.Errorf("command not in allowlist: %s", commandKey)
		se.logger.Error(auditEntry + " - DENIED: " + err.Error())
		return &ExecutionResult{
			Command:    commandKey,
			Arguments:  args,
			Error:      err,
			AuditTrail: auditEntry + " - DENIED",
		}, err
	}

	// Validate binary path
	binaryPath, err := se.validateBinaryPath(template)
	if err != nil {
		se.logger.Error(auditEntry + " - DENIED: " + err.Error())
		return &ExecutionResult{
			Command:    commandKey,
			Arguments:  args,
			Error:      err,
			AuditTrail: auditEntry + " - DENIED: binary validation failed",
		}, err
	}

	// Validate arguments against patterns
	if err := se.validateArguments(args, template.Arguments); err != nil {
		se.logger.Error(auditEntry + " - DENIED: " + err.Error())
		return &ExecutionResult{
			Command:    commandKey,
			Arguments:  args,
			Error:      err,
			AuditTrail: auditEntry + " - DENIED: argument validation failed",
		}, err
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, template.Timeout)
	defer cancel()

	// Execute the command securely (no shell interpretation)
	cmd := exec.CommandContext(execCtx, binaryPath, args...)
	cmd.Env = []string{} // Empty environment for security

	se.logger.Infof("SECURITY_AUDIT: Executing validated command - %s %v", binaryPath, args)

	stdout, err := cmd.Output()
	duration := time.Since(startTime)

	result := &ExecutionResult{
		Command:   commandKey,
		Arguments: args,
		ExitCode:  cmd.ProcessState.ExitCode(),
		Stdout:    stdout,
		Duration:  duration,
		AuditTrail: fmt.Sprintf("%s - APPROVED and EXECUTED in %v", auditEntry, duration),
	}

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.Stderr = exitError.Stderr
		}
		result.Error = err
		se.logger.Warnf("SECURITY_AUDIT: Command completed with error - %v", err)
	} else {
		se.logger.Infof("SECURITY_AUDIT: Command completed successfully - Duration: %v", duration)
	}

	return result, err
}

// validateBinaryPath validates and returns the secure binary path
func (se *SecureExecutor) validateBinaryPath(template CommandTemplate) (string, error) {
	// Check each allowed path
	for _, allowedPath := range template.BinaryPaths {
		// Validate path structure
		if !filepath.IsAbs(allowedPath) {
			continue
		}
		
		// Check if file exists and is executable
		if info, err := os.Stat(allowedPath); err == nil {
			if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				// Verify the binary name matches
				if filepath.Base(allowedPath) == template.BinaryName {
					se.logger.Debugf("SECURITY_AUDIT: Binary validated - %s", allowedPath)
					return allowedPath, nil
				}
			}
		}
	}

	// If no direct path found, try PATH lookup with validation
	if pathBinary, err := exec.LookPath(template.BinaryName); err == nil {
		cleanPath := filepath.Clean(pathBinary)
		
		// Verify it's in our allowed paths or matches expected patterns
		for _, allowedPath := range template.BinaryPaths {
			if cleanPath == allowedPath {
				se.logger.Debugf("SECURITY_AUDIT: PATH binary validated - %s", cleanPath)
				return cleanPath, nil
			}
		}
		
		// Additional security check: verify binary signature/checksum in production
		// For now, we accept PATH lookups that match our naming requirements
		if filepath.Base(cleanPath) == template.BinaryName {
			se.logger.Warnf("SECURITY_AUDIT: Using PATH binary not in explicit allowlist - %s", cleanPath)
			return cleanPath, nil
		}
	}

	return "", fmt.Errorf("binary not found or not validated: %s", template.BinaryName)
}

// validateArguments validates command arguments against allowed patterns
func (se *SecureExecutor) validateArguments(args []string, patterns []ArgumentPattern) error {
	if len(args) == 0 && len(patterns) > 0 {
		// Check if any required patterns exist
		for _, pattern := range patterns {
			if pattern.Required {
				return fmt.Errorf("required arguments missing")
			}
		}
		return nil
	}

	// Validate each argument against patterns
	for i, arg := range args {
		validated := false
		
		for _, pattern := range patterns {
			if pattern.Pattern.MatchString(arg) {
				validated = true
				se.logger.Debugf("SECURITY_AUDIT: Argument validated - '%s' matches %s", arg, pattern.Description)
				break
			}
		}
		
		if !validated {
			return fmt.Errorf("argument %d ('%s') does not match any allowed pattern", i, arg)
		}
	}

	return nil
}

// GetAllowedCommands returns a list of all allowed command keys
func (se *SecureExecutor) GetAllowedCommands() []string {
	commands := make([]string, 0, len(commandRegistry))
	for key := range commandRegistry {
		commands = append(commands, key)
	}
	return commands
}

// GetCommandInfo returns information about a specific command
func (se *SecureExecutor) GetCommandInfo(commandKey string) (CommandTemplate, bool) {
	template, exists := commandRegistry[commandKey]
	return template, exists
}

// AuditLog returns recent audit log entries (placeholder for audit system)
func (se *SecureExecutor) AuditLog() []string {
	// In production, this would return entries from a persistent audit log
	return []string{"Audit logging would be implemented here"}
}