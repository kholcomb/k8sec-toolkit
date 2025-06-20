package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config represents the KubeSec configuration
type Config struct {
	// Kubernetes configuration
	Kubeconfig string `mapstructure:"kubeconfig"`
	Context    string `mapstructure:"context"`

	// Tool configuration
	Tools ToolsConfig `mapstructure:"tools"`

	// Scan configuration
	Scan ScanConfig `mapstructure:"scan"`

	// Output configuration
	Output OutputConfig `mapstructure:"output"`

	// Security configuration
	Security SecurityConfig `mapstructure:"security"`
}

// ToolsConfig contains tool-specific configurations
type ToolsConfig struct {
	Enabled []string `mapstructure:"enabled"`

	Trivy     TrivyConfig     `mapstructure:"trivy"`
	Kubescape KubescapeConfig `mapstructure:"kubescape"`
	KubeBench KubeBenchConfig `mapstructure:"kube_bench"`
	RBAC      RBACConfig      `mapstructure:"rbac"`
	Polaris   PolarisConfig   `mapstructure:"polaris"`
}

// TrivyConfig contains Trivy-specific configuration
type TrivyConfig struct {
	Severity   []string      `mapstructure:"severity"`
	IgnoreFile string        `mapstructure:"ignore_file"`
	Timeout    time.Duration `mapstructure:"timeout"`
	Format     string        `mapstructure:"format"`
}

// KubescapeConfig contains Kubescape-specific configuration
type KubescapeConfig struct {
	Frameworks        []string `mapstructure:"frameworks"`
	Threshold         float64  `mapstructure:"threshold"`
	IncludeNamespaces []string `mapstructure:"include_namespaces"`
	ExcludeNamespaces []string `mapstructure:"exclude_namespaces"`
}

// KubeBenchConfig contains kube-bench specific configuration
type KubeBenchConfig struct {
	Version   string `mapstructure:"version"`
	ConfigDir string `mapstructure:"config_dir"`
	Targets   []string `mapstructure:"targets"`
}

// RBACConfig contains RBAC analysis configuration
type RBACConfig struct {
	CheckDangerousPermissions bool `mapstructure:"check_dangerous_permissions"`
	AnalyzeUnusedPermissions  bool `mapstructure:"analyze_unused_permissions"`
	GenerateLeastPrivilege    bool `mapstructure:"generate_least_privilege"`
}

// PolarisConfig contains Polaris-specific configuration
type PolarisConfig struct {
	ConfigFile        string `mapstructure:"config_file"`
	OnlyShowFailures  bool   `mapstructure:"only_show_failures"`
}

// ScanConfig contains scan execution configuration
type ScanConfig struct {
	Namespaces      []string      `mapstructure:"namespaces"`
	Tools           []string      `mapstructure:"tools"`
	Timeout         time.Duration `mapstructure:"timeout"`
	Parallel        bool          `mapstructure:"parallel"`
	MaxConcurrency  int           `mapstructure:"max_concurrency"`
	RetryAttempts   int           `mapstructure:"retry_attempts"`
	FailureThreshold float64      `mapstructure:"failure_threshold"`
}

// OutputConfig contains output formatting configuration
type OutputConfig struct {
	Format            string `mapstructure:"format"`
	File              string `mapstructure:"file"`
	IncludeRawResults bool   `mapstructure:"include_raw_results"`
	RedactSensitive   bool   `mapstructure:"redact_sensitive"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	TempDir             string `mapstructure:"temp_dir"`
	CleanupOnExit       bool   `mapstructure:"cleanup_on_exit"`
	VerifyToolChecksums bool   `mapstructure:"verify_tool_checksums"`
}

// Load loads the configuration from file and environment
func Load() (*Config, error) {
	// Set defaults
	setDefaults()

	// Create config instance
	cfg := &Config{}

	// Unmarshal configuration
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Tool defaults
	viper.SetDefault("tools.enabled", []string{"trivy", "kubescape"})
	
	// Trivy defaults
	viper.SetDefault("tools.trivy.severity", []string{"CRITICAL", "HIGH", "MEDIUM"})
	viper.SetDefault("tools.trivy.timeout", "5m")
	viper.SetDefault("tools.trivy.format", "json")

	// Kubescape defaults
	viper.SetDefault("tools.kubescape.frameworks", []string{"NSA", "MITRE"})
	viper.SetDefault("tools.kubescape.threshold", 7.0)

	// kube-bench defaults
	viper.SetDefault("tools.kube_bench.version", "auto")
	viper.SetDefault("tools.kube_bench.targets", []string{"master", "node", "etcd", "policies"})

	// RBAC defaults
	viper.SetDefault("tools.rbac.check_dangerous_permissions", true)
	viper.SetDefault("tools.rbac.analyze_unused_permissions", true)
	viper.SetDefault("tools.rbac.generate_least_privilege", false)

	// Polaris defaults
	viper.SetDefault("tools.polaris.only_show_failures", true)

	// Scan defaults
	viper.SetDefault("scan.timeout", "10m")
	viper.SetDefault("scan.parallel", true)
	viper.SetDefault("scan.max_concurrency", 3)
	viper.SetDefault("scan.retry_attempts", 2)
	viper.SetDefault("scan.failure_threshold", 0.5)

	// Output defaults
	viper.SetDefault("output.format", "table")
	viper.SetDefault("output.include_raw_results", false)
	viper.SetDefault("output.redact_sensitive", true)

	// Security defaults
	viper.SetDefault("security.temp_dir", "/tmp/kubesec")
	viper.SetDefault("security.cleanup_on_exit", true)
	viper.SetDefault("security.verify_tool_checksums", true)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate tool selection
	validTools := map[string]bool{
		"trivy":      true,
		"kubescape":  true,
		"kube-bench": true,
		"rbac":       true,
		"polaris":    true,
	}

	for _, tool := range c.Tools.Enabled {
		if !validTools[tool] {
			return fmt.Errorf("invalid tool: %s", tool)
		}
	}

	// Validate output format
	validFormats := map[string]bool{
		"table":   true,
		"json":    true,
		"yaml":    true,
		"summary": true,
		"sarif":   true,
	}

	if !validFormats[c.Output.Format] {
		return fmt.Errorf("invalid output format: %s", c.Output.Format)
	}

	// Validate scan configuration
	if c.Scan.MaxConcurrency < 1 {
		return fmt.Errorf("max_concurrency must be at least 1")
	}

	if c.Scan.FailureThreshold < 0 || c.Scan.FailureThreshold > 1 {
		return fmt.Errorf("failure_threshold must be between 0 and 1")
	}

	// Validate Kubescape threshold
	if c.Tools.Kubescape.Threshold < 0 || c.Tools.Kubescape.Threshold > 10 {
		return fmt.Errorf("kubescape threshold must be between 0 and 10")
	}

	return nil
}