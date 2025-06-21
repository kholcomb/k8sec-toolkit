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

// ExecutiveSummary provides high-level insights for dashboard consumption
type ExecutiveSummary struct {
	// Overall assessment
	SecurityPosture SecurityPostureLevel `json:"security_posture"`
	RiskScore       float64              `json:"risk_score"`       // 0-100 scale
	BusinessImpact  BusinessImpactLevel  `json:"business_impact"`  // Impact assessment
	ComplianceScore float64              `json:"compliance_score"` // 0-100 scale
	TrendDirection  TrendDirection       `json:"trend_direction"`  // Improving/Degrading/Stable

	// Key metrics
	CriticalFindings  int    `json:"critical_findings"`
	HighFindings      int    `json:"high_findings"`
	TotalFindings     int    `json:"total_findings"`
	RemediationEffort string `json:"remediation_effort"` // High/Medium/Low
	TimeToRemediate   string `json:"time_to_remediate"`  // Estimated time

	// Risk breakdown
	RiskDistribution RiskDistribution `json:"risk_distribution"`
	TopRisks         []TopRisk        `json:"top_risks"`
	CriticalAssets   []CriticalAsset  `json:"critical_assets"`

	// Actionable insights
	ImmediateActions []ActionItem `json:"immediate_actions"`
	QuickWins        []ActionItem `json:"quick_wins"`
	LongTermStrategy []ActionItem `json:"long_term_strategy"`

	// Progress tracking
	LastScanTime     time.Time `json:"last_scan_time"`
	PreviousScore    float64   `json:"previous_score"`
	ScoreChange      float64   `json:"score_change"`
	NewFindings      int       `json:"new_findings"`
	ResolvedFindings int       `json:"resolved_findings"`
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

	// Executive insights for dashboard consumption
	ExecutiveSummary *ExecutiveSummary `json:"executive_summary,omitempty"`

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

// SecurityPostureLevel represents overall security posture
type SecurityPostureLevel string

const (
	SecurityPostureExcellent SecurityPostureLevel = "excellent"
	SecurityPostureGood      SecurityPostureLevel = "good"
	SecurityPostureFair      SecurityPostureLevel = "fair"
	SecurityPosturePoor      SecurityPostureLevel = "poor"
	SecurityPostureCritical  SecurityPostureLevel = "critical"
)

// BusinessImpactLevel represents potential business impact
type BusinessImpactLevel string

const (
	BusinessImpactLow      BusinessImpactLevel = "low"
	BusinessImpactMedium   BusinessImpactLevel = "medium"
	BusinessImpactHigh     BusinessImpactLevel = "high"
	BusinessImpactCritical BusinessImpactLevel = "critical"
)

// TrendDirection represents security trend over time
type TrendDirection string

const (
	TrendImproving TrendDirection = "improving"
	TrendStable    TrendDirection = "stable"
	TrendDegrading TrendDirection = "degrading"
)

// RiskDistribution provides risk category breakdown
type RiskDistribution struct {
	Infrastructure  float64 `json:"infrastructure"`   // % of risk from infra
	Applications    float64 `json:"applications"`     // % of risk from apps
	Configuration   float64 `json:"configuration"`    // % of risk from config
	AccessControl   float64 `json:"access_control"`   // % of risk from RBAC
	NetworkSecurity float64 `json:"network_security"` // % of risk from network
	DataProtection  float64 `json:"data_protection"`  // % of risk from data
}

// TopRisk represents a high-priority security risk
type TopRisk struct {
	ID                string              `json:"id"`
	Title             string              `json:"title"`
	Description       string              `json:"description"`
	Impact            BusinessImpactLevel `json:"impact"`
	Probability       string              `json:"probability"` // High/Medium/Low
	RiskScore         float64             `json:"risk_score"`  // 0-100
	Category          string              `json:"category"`
	AffectedAssets    int                 `json:"affected_assets"`
	EstimatedCost     string              `json:"estimated_cost"`  // Cost of breach
	TimeToExploit     string              `json:"time_to_exploit"` // How quickly exploitable
	RecommendedAction string              `json:"recommended_action"`
}

// CriticalAsset represents a high-value asset requiring attention
type CriticalAsset struct {
	Name               string  `json:"name"`
	Type               string  `json:"type"` // Pod, Service, etc.
	Namespace          string  `json:"namespace"`
	CriticalityLevel   string  `json:"criticality_level"` // Critical/High/Medium
	VulnerabilityCount int     `json:"vulnerability_count"`
	MisconfigCount     int     `json:"misconfig_count"`
	RiskScore          float64 `json:"risk_score"`
	BusinessFunction   string  `json:"business_function"`   // What business function it serves
	DataClassification string  `json:"data_classification"` // PII, PCI, etc.
}

// ActionItem represents a recommended security action
type ActionItem struct {
	ID                  string     `json:"id"`
	Title               string     `json:"title"`
	Description         string     `json:"description"`
	Priority            string     `json:"priority"`         // Critical/High/Medium/Low
	Category            string     `json:"category"`         // Patch, Config, Process
	EstimatedEffort     string     `json:"estimated_effort"` // Hours or story points
	BusinessValue       string     `json:"business_value"`   // Risk reduction value
	Prerequisites       []string   `json:"prerequisites"`
	AffectedSystems     []string   `json:"affected_systems"`
	ImplementationSteps []string   `json:"implementation_steps"`
	SuccessMetrics      []string   `json:"success_metrics"`
	Owner               string     `json:"owner,omitempty"` // Team/person responsible
	DueDate             *time.Time `json:"due_date,omitempty"`
	RelatedFindings     []string   `json:"related_findings"` // Finding IDs
}
