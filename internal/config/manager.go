package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// ProfileType represents the configuration profile types
type ProfileType string

const (
	ProfileDev   ProfileType = "dev"
	ProfileProd  ProfileType = "prod"
	ProfileAudit ProfileType = "audit"
)

// Manager handles configuration operations
type Manager struct {
	configDir      string
	configFile     string
	currentProfile ProfileType
}

// NewManager creates a new configuration manager
func NewManager() (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".k8sec-toolkit")
	configFile := filepath.Join(configDir, "config.yaml")

	return &Manager{
		configDir:      configDir,
		configFile:     configFile,
		currentProfile: ProfileDev, // default profile
	}, nil
}

// Initialize creates the configuration directory and default config file
func (m *Manager) Initialize() error {
	// Create config directory if it doesn't exist
	if err := os.MkdirAll(m.configDir, 0700); err != nil {
		return fmt.Errorf("failed to create configuration directory: %w", err)
	}

	// Check if config file already exists
	if _, err := os.Stat(m.configFile); err == nil {
		return fmt.Errorf("configuration file already exists at %s", m.configFile)
	}

	// Create default configuration with all profiles
	defaultConfig := m.getDefaultConfig()

	// Write configuration file
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	if err := os.WriteFile(m.configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}

// SetProfile sets the current active profile
func (m *Manager) SetProfile(profile ProfileType) error {
	if !m.isValidProfile(profile) {
		return fmt.Errorf("invalid profile: %s (valid profiles: dev, prod, audit)", profile)
	}
	m.currentProfile = profile
	return nil
}

// GetCurrentProfile returns the current active profile
func (m *Manager) GetCurrentProfile() ProfileType {
	return m.currentProfile
}

// LoadConfig loads the configuration for the current profile
func (m *Manager) LoadConfig() (*Config, error) {
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found. Run 'k8sec-toolkit config init' to create one")
	}

	// Set up viper to read from our config file
	viper.SetConfigFile(m.configFile)
	viper.SetConfigType("yaml")

	// Read the configuration file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	// Load profile-specific configuration
	profileKey := fmt.Sprintf("profiles.%s", m.currentProfile)
	if !viper.IsSet(profileKey) {
		return nil, fmt.Errorf("profile '%s' not found in configuration", m.currentProfile)
	}

	// Create base config from profile
	cfg := &Config{}
	if err := viper.UnmarshalKey(profileKey, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile configuration: %w", err)
	}

	// Apply global overrides if they exist
	if viper.IsSet("global") {
		globalCfg := &Config{}
		if err := viper.UnmarshalKey("global", globalCfg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal global configuration: %w", err)
		}
		// Merge global config with profile config (global takes precedence)
		cfg = m.mergeConfigs(cfg, globalCfg)
	}

	// Ensure critical fields have defaults if not set
	m.applyDefaults(cfg)

	// Validate the final configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// GetValue retrieves a configuration value by key
func (m *Manager) GetValue(key string) (interface{}, error) {
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found")
	}

	viper.SetConfigFile(m.configFile)
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	// Look for the key in the current profile first
	profileKey := fmt.Sprintf("profiles.%s.%s", m.currentProfile, key)
	if viper.IsSet(profileKey) {
		return viper.Get(profileKey), nil
	}

	// Fall back to global configuration
	globalKey := fmt.Sprintf("global.%s", key)
	if viper.IsSet(globalKey) {
		return viper.Get(globalKey), nil
	}

	return nil, fmt.Errorf("configuration key '%s' not found", key)
}

// SetValue sets a configuration value by key
func (m *Manager) SetValue(key string, value interface{}, global bool) error {
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found")
	}

	// Read existing configuration
	viper.SetConfigFile(m.configFile)
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read configuration: %w", err)
	}

	// Set the value in appropriate section
	var targetKey string
	if global {
		targetKey = fmt.Sprintf("global.%s", key)
	} else {
		targetKey = fmt.Sprintf("profiles.%s.%s", m.currentProfile, key)
	}

	viper.Set(targetKey, value)

	// Write back to file
	return m.writeConfig()
}

// ViewConfig returns the current configuration as a formatted string
func (m *Manager) ViewConfig() (string, error) {
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		return "", fmt.Errorf("configuration file not found")
	}

	viper.SetConfigFile(m.configFile)
	if err := viper.ReadInConfig(); err != nil {
		return "", fmt.Errorf("failed to read configuration: %w", err)
	}

	settings := viper.AllSettings()
	data, err := yaml.Marshal(settings)
	if err != nil {
		return "", fmt.Errorf("failed to marshal configuration: %w", err)
	}

	return string(data), nil
}

// ValidateConfig validates the configuration file
func (m *Manager) ValidateConfig() error {
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found")
	}

	// Try to load each profile
	for _, profile := range []ProfileType{ProfileDev, ProfileProd, ProfileAudit} {
		originalProfile := m.currentProfile
		m.currentProfile = profile

		if _, err := m.LoadConfig(); err != nil {
			m.currentProfile = originalProfile
			return fmt.Errorf("validation failed for profile '%s': %w", profile, err)
		}

		m.currentProfile = originalProfile
	}

	return nil
}

// ListProfiles returns all available profiles
func (m *Manager) ListProfiles() []ProfileType {
	return []ProfileType{ProfileDev, ProfileProd, ProfileAudit}
}

// isValidProfile checks if the given profile is valid
func (m *Manager) isValidProfile(profile ProfileType) bool {
	validProfiles := []ProfileType{ProfileDev, ProfileProd, ProfileAudit}
	for _, p := range validProfiles {
		if p == profile {
			return true
		}
	}
	return false
}

// writeConfig writes the current viper configuration to file
func (m *Manager) writeConfig() error {
	settings := viper.AllSettings()
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	if err := os.WriteFile(m.configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}

// applyDefaults applies default values to configuration fields that are not set
func (m *Manager) applyDefaults(cfg *Config) {
	// Apply tool defaults
	if cfg.Tools.Enabled == nil {
		cfg.Tools.Enabled = []string{"trivy", "kubescape"}
	}

	// Apply Trivy defaults
	if cfg.Tools.Trivy.Severity == nil {
		cfg.Tools.Trivy.Severity = []string{"CRITICAL", "HIGH", "MEDIUM"}
	}
	if cfg.Tools.Trivy.Format == "" {
		cfg.Tools.Trivy.Format = "json"
	}
	if cfg.Tools.Trivy.Timeout == 0 {
		cfg.Tools.Trivy.Timeout = time.Minute * 5
	}

	// Apply Kubescape defaults
	if cfg.Tools.Kubescape.Frameworks == nil {
		cfg.Tools.Kubescape.Frameworks = []string{"NSA", "MITRE"}
	}
	if cfg.Tools.Kubescape.Threshold == 0 {
		cfg.Tools.Kubescape.Threshold = 7.0
	}

	// Apply scan defaults
	if cfg.Scan.Timeout == 0 {
		cfg.Scan.Timeout = time.Minute * 10
	}
	if cfg.Scan.MaxConcurrency == 0 {
		cfg.Scan.MaxConcurrency = 3
	}
	if cfg.Scan.RetryAttempts == 0 {
		cfg.Scan.RetryAttempts = 2
	}

	// Apply output defaults
	if cfg.Output.Format == "" {
		cfg.Output.Format = "table"
	}

	// Apply security defaults
	if cfg.Security.TempDir == "" {
		cfg.Security.TempDir = "/tmp/k8sec-toolkit"
	}
}

// mergeConfigs merges two configurations with the second taking precedence
func (m *Manager) mergeConfigs(base, override *Config) *Config {
	result := *base // Copy base config

	// Merge tools configuration
	if override.Tools.Enabled != nil {
		result.Tools.Enabled = override.Tools.Enabled
	}

	// Merge individual tool configs
	if override.Tools.Trivy.Severity != nil {
		result.Tools.Trivy.Severity = override.Tools.Trivy.Severity
	}
	if override.Tools.Trivy.Timeout != 0 {
		result.Tools.Trivy.Timeout = override.Tools.Trivy.Timeout
	}
	if override.Tools.Trivy.Format != "" {
		result.Tools.Trivy.Format = override.Tools.Trivy.Format
	}

	// Merge kubescape config
	if override.Tools.Kubescape.Frameworks != nil {
		result.Tools.Kubescape.Frameworks = override.Tools.Kubescape.Frameworks
	}
	if override.Tools.Kubescape.Threshold != 0 {
		result.Tools.Kubescape.Threshold = override.Tools.Kubescape.Threshold
	}

	// Merge scan configuration
	if override.Scan.Timeout != 0 {
		result.Scan.Timeout = override.Scan.Timeout
	}
	if override.Scan.MaxConcurrency != 0 {
		result.Scan.MaxConcurrency = override.Scan.MaxConcurrency
	}

	// Merge output configuration
	if override.Output.Format != "" {
		result.Output.Format = override.Output.Format
	}

	// Merge kubeconfig and context
	if override.Kubeconfig != "" {
		result.Kubeconfig = override.Kubeconfig
	}
	if override.Context != "" {
		result.Context = override.Context
	}

	return &result
}

// getDefaultConfig returns the default configuration with all profiles
func (m *Manager) getDefaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"profiles": map[string]interface{}{
			"dev": map[string]interface{}{
				"tools": map[string]interface{}{
					"enabled": []string{"trivy", "kubescape"},
					"trivy": map[string]interface{}{
						"severity": []string{"CRITICAL", "HIGH"},
						"timeout":  "3m",
						"format":   "json",
					},
					"kubescape": map[string]interface{}{
						"frameworks": []string{"NSA"},
						"threshold":  8.0,
					},
					"kube_bench": map[string]interface{}{
						"version": "auto",
						"targets": []string{"master", "node"},
					},
					"rbac": map[string]interface{}{
						"check_dangerous_permissions": true,
						"analyze_unused_permissions":  false,
						"generate_least_privilege":    false,
					},
					"polaris": map[string]interface{}{
						"only_show_failures": true,
					},
				},
				"scan": map[string]interface{}{
					"timeout":           "5m",
					"parallel":          true,
					"max_concurrency":   2,
					"retry_attempts":    1,
					"failure_threshold": 0.7,
				},
				"output": map[string]interface{}{
					"format":              "table",
					"include_raw_results": false,
					"redact_sensitive":    true,
				},
				"security": map[string]interface{}{
					"temp_dir":              "/tmp/k8sec-toolkit",
					"cleanup_on_exit":       true,
					"verify_tool_checksums": false,
				},
			},
			"prod": map[string]interface{}{
				"tools": map[string]interface{}{
					"enabled": []string{"trivy", "kubescape", "kube-bench", "rbac", "polaris"},
					"trivy": map[string]interface{}{
						"severity": []string{"CRITICAL", "HIGH", "MEDIUM"},
						"timeout":  "10m",
						"format":   "json",
					},
					"kubescape": map[string]interface{}{
						"frameworks": []string{"NSA", "MITRE", "CIS"},
						"threshold":  6.0,
					},
					"kube_bench": map[string]interface{}{
						"version": "auto",
						"targets": []string{"master", "node", "etcd", "policies"},
					},
					"rbac": map[string]interface{}{
						"check_dangerous_permissions": true,
						"analyze_unused_permissions":  true,
						"generate_least_privilege":    true,
					},
					"polaris": map[string]interface{}{
						"only_show_failures": false,
					},
				},
				"scan": map[string]interface{}{
					"timeout":           "15m",
					"parallel":          true,
					"max_concurrency":   4,
					"retry_attempts":    3,
					"failure_threshold": 0.3,
				},
				"output": map[string]interface{}{
					"format":              "json",
					"include_raw_results": true,
					"redact_sensitive":    true,
				},
				"security": map[string]interface{}{
					"temp_dir":              "/tmp/k8sec-toolkit",
					"cleanup_on_exit":       true,
					"verify_tool_checksums": true,
				},
			},
			"audit": map[string]interface{}{
				"tools": map[string]interface{}{
					"enabled": []string{"trivy", "kubescape", "kube-bench", "rbac", "polaris"},
					"trivy": map[string]interface{}{
						"severity": []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
						"timeout":  "20m",
						"format":   "json",
					},
					"kubescape": map[string]interface{}{
						"frameworks": []string{"NSA", "MITRE", "CIS", "SOC2", "PCI"},
						"threshold":  4.0,
					},
					"kube_bench": map[string]interface{}{
						"version": "auto",
						"targets": []string{"master", "node", "etcd", "policies"},
					},
					"rbac": map[string]interface{}{
						"check_dangerous_permissions": true,
						"analyze_unused_permissions":  true,
						"generate_least_privilege":    true,
					},
					"polaris": map[string]interface{}{
						"only_show_failures": false,
					},
				},
				"scan": map[string]interface{}{
					"timeout":           "30m",
					"parallel":          true,
					"max_concurrency":   6,
					"retry_attempts":    3,
					"failure_threshold": 0.1,
				},
				"output": map[string]interface{}{
					"format":              "json",
					"include_raw_results": true,
					"redact_sensitive":    false,
				},
				"security": map[string]interface{}{
					"temp_dir":              "/tmp/k8sec-toolkit",
					"cleanup_on_exit":       false,
					"verify_tool_checksums": true,
				},
			},
		},
		"global": map[string]interface{}{
			"kubeconfig": "", // Will use default kubectl config
			"context":    "", // Will use current context
		},
	}
}

// GetConfigPath returns the path to the configuration file
func (m *Manager) GetConfigPath() string {
	return m.configFile
}

// ParseProfileFromString converts a string to ProfileType
func ParseProfileFromString(s string) (ProfileType, error) {
	switch strings.ToLower(s) {
	case "dev", "development":
		return ProfileDev, nil
	case "prod", "production":
		return ProfileProd, nil
	case "audit", "compliance":
		return ProfileAudit, nil
	default:
		return "", fmt.Errorf("invalid profile: %s (valid profiles: dev, prod, audit)", s)
	}
}
