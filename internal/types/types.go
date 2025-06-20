package types

import (
	"context"
	"time"
)

// SecurityTool defines the interface for all security tools
type SecurityTool interface {
	// GetInfo returns basic information about the tool
	GetInfo() ToolInfo

	// Validate checks if the tool is properly configured and available
	Validate() error

	// Execute runs the tool with the given configuration
	Execute(ctx context.Context, config ToolConfig) (*ToolResult, error)

	// UpdateDatabase updates the tool's vulnerability/rule database
	UpdateDatabase() error

	// GetVersion returns the tool version
	GetVersion() string
}

// ToolInfo contains basic information about a security tool
type ToolInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Website      string   `json:"website"`
	License      string   `json:"license"`
	Capabilities []string `json:"capabilities"`
}

// ToolConfig contains configuration for tool execution
type ToolConfig struct {
	// Kubernetes configuration
	KubeconfigPath string `json:"kubeconfig_path"`
	Context        string `json:"context"`

	// Scanning scope
	Namespaces []string `json:"namespaces"`

	// Output configuration
	OutputFormat string `json:"output_format"`

	// Execution configuration
	Timeout time.Duration `json:"timeout"`

	// Tool-specific configuration
	CustomFlags map[string]interface{} `json:"custom_flags"`
}

// ToolResult contains the result of a tool execution
type ToolResult struct {
	// Execution metadata
	ToolName   string        `json:"tool_name"`
	ExecutedAt time.Time     `json:"executed_at"`
	Duration   time.Duration `json:"duration"`
	ExitCode   int           `json:"exit_code"`

	// Output data
	RawOutput   []byte `json:"raw_output,omitempty"`
	ErrorOutput []byte `json:"error_output,omitempty"`

	// Parsed findings
	Findings []SecurityFinding `json:"findings"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata"`
}

// SecurityFinding represents a normalized security finding
type SecurityFinding struct {
	// Core identification
	ID          string `json:"id"`
	Type        string `json:"type"`     // vulnerability, misconfiguration, compliance, rbac, best-practice
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Title       string `json:"title"`
	Description string `json:"description"`

	// Source information
	Source    string `json:"source"`              // trivy, kubescape, kube-bench, etc.
	SourceID  string `json:"source_id"`           // Original finding ID from source tool
	Framework string `json:"framework,omitempty"` // CIS, NSA, MITRE, etc.

	// Resource context
	Resource ResourceReference `json:"resource"`

	// Vulnerability-specific fields
	CVE     string  `json:"cve,omitempty"`
	CVSS    float64 `json:"cvss,omitempty"`
	FixedIn string  `json:"fixed_in,omitempty"`

	// Remediation and evidence
	Remediation string      `json:"remediation,omitempty"`
	Evidence    interface{} `json:"evidence,omitempty"`

	// Metadata
	Tags       []string  `json:"tags,omitempty"`
	References []string  `json:"references,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// ResourceReference identifies a Kubernetes resource
type ResourceReference struct {
	APIVersion string `json:"api_version,omitempty"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
	UID        string `json:"uid,omitempty"`
}

// ClusterInfo contains information about the scanned cluster
type ClusterInfo struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	NodeCount      int       `json:"node_count"`
	NamespaceCount int       `json:"namespace_count"`
	PodCount       int       `json:"pod_count"`
	Provider       string    `json:"provider,omitempty"`
	ScanTimestamp  time.Time `json:"scan_timestamp"`
}

// FindingSummary provides aggregate statistics about findings
type FindingSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByType        map[string]int `json:"by_type"`
	BySource      map[string]int `json:"by_source"`
	RiskScore     float64        `json:"risk_score"`
	Critical      int            `json:"critical"`
	High          int            `json:"high"`
	Medium        int            `json:"medium"`
	Low           int            `json:"low"`
	Info          int            `json:"info"`
}

// ScanResult represents the complete result of a security scan
type ScanResult struct {
	// Scan metadata
	Context   string        `json:"context"`
	ScanTime  time.Time     `json:"scan_time"`
	Duration  time.Duration `json:"duration"`
	ToolsUsed []string      `json:"tools_used"`

	// Cluster information
	ClusterInfo *ClusterInfo `json:"cluster_info"`

	// Findings and summary
	Findings []SecurityFinding `json:"findings"`
	Summary  *FindingSummary   `json:"summary"`

	// Tool-specific results
	ToolResults map[string]*ToolResult `json:"tool_results"`

	// Errors encountered during scan
	Errors map[string]error `json:"errors,omitempty"`
}

// SeverityLevel represents finding severity levels
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityLow      SeverityLevel = "LOW"
	SeverityInfo     SeverityLevel = "INFO"
)

// FindingType represents types of security findings
type FindingType string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeCompliance       FindingType = "compliance"
	FindingTypeRBAC             FindingType = "rbac"
	FindingTypeBestPractice     FindingType = "best-practice"
)
