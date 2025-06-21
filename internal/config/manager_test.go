package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.Equal(t, ProfileDev, manager.GetCurrentProfile())
}

func TestSetProfile(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)

	// Test valid profiles
	err = manager.SetProfile(ProfileProd)
	assert.NoError(t, err)
	assert.Equal(t, ProfileProd, manager.GetCurrentProfile())

	err = manager.SetProfile(ProfileAudit)
	assert.NoError(t, err)
	assert.Equal(t, ProfileAudit, manager.GetCurrentProfile())

	// Test invalid profile
	err = manager.SetProfile("invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile")
}

func TestParseProfileFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected ProfileType
		hasError bool
	}{
		{"dev", ProfileDev, false},
		{"development", ProfileDev, false},
		{"prod", ProfileProd, false},
		{"production", ProfileProd, false},
		{"audit", ProfileAudit, false},
		{"compliance", ProfileAudit, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseProfileFromString(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "k8sec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create manager with custom config path
	manager := &Manager{
		configDir:      tempDir,
		configFile:     filepath.Join(tempDir, "config.yaml"),
		currentProfile: ProfileDev,
	}

	// Test initialization
	err = manager.Initialize()
	assert.NoError(t, err)

	// Verify config file was created
	_, err = os.Stat(manager.configFile)
	assert.NoError(t, err)

	// Test that initialization fails when file already exists
	err = manager.Initialize()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestLoadConfig(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "k8sec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create manager with custom config path
	manager := &Manager{
		configDir:      tempDir,
		configFile:     filepath.Join(tempDir, "config.yaml"),
		currentProfile: ProfileDev,
	}

	// Test loading non-existent config
	_, err = manager.LoadConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Initialize config and test loading
	err = manager.Initialize()
	require.NoError(t, err)

	// Test loading dev profile
	cfg, err := manager.LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Contains(t, cfg.Tools.Enabled, "trivy")
	assert.Contains(t, cfg.Tools.Enabled, "kubescape")

	// Test loading prod profile
	err = manager.SetProfile(ProfileProd)
	require.NoError(t, err)

	cfg, err = manager.LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Contains(t, cfg.Tools.Enabled, "trivy")
	assert.Contains(t, cfg.Tools.Enabled, "kubescape")
	assert.Contains(t, cfg.Tools.Enabled, "kube-bench")
	assert.Contains(t, cfg.Tools.Enabled, "rbac")
	assert.Contains(t, cfg.Tools.Enabled, "polaris")

	// Test loading audit profile
	err = manager.SetProfile(ProfileAudit)
	require.NoError(t, err)

	cfg, err = manager.LoadConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, 4.0, cfg.Tools.Kubescape.Threshold) // Audit profile has stricter threshold
}

func TestGetSetValue(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "k8sec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create manager with custom config path
	manager := &Manager{
		configDir:      tempDir,
		configFile:     filepath.Join(tempDir, "config.yaml"),
		currentProfile: ProfileDev,
	}

	// Initialize config
	err = manager.Initialize()
	require.NoError(t, err)

	// Test setting and getting profile-specific value
	err = manager.SetValue("tools.trivy.timeout", "7m", false)
	assert.NoError(t, err)

	value, err := manager.GetValue("tools.trivy.timeout")
	assert.NoError(t, err)
	assert.Equal(t, "7m", value)

	// Test setting and getting global value
	err = manager.SetValue("kubeconfig", "/custom/kubeconfig", true)
	assert.NoError(t, err)

	value, err = manager.GetValue("kubeconfig")
	assert.NoError(t, err)
	assert.Equal(t, "/custom/kubeconfig", value)

	// Test getting non-existent value
	_, err = manager.GetValue("non.existent.key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestValidateConfig(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "k8sec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create manager with custom config path
	manager := &Manager{
		configDir:      tempDir,
		configFile:     filepath.Join(tempDir, "config.yaml"),
		currentProfile: ProfileDev,
	}

	// Test validation of non-existent config
	err = manager.ValidateConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Initialize config and test validation
	err = manager.Initialize()
	require.NoError(t, err)

	err = manager.ValidateConfig()
	assert.NoError(t, err)
}

func TestListProfiles(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)

	profiles := manager.ListProfiles()
	assert.Len(t, profiles, 3)
	assert.Contains(t, profiles, ProfileDev)
	assert.Contains(t, profiles, ProfileProd)
	assert.Contains(t, profiles, ProfileAudit)
}

func TestViewConfig(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "k8sec-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create manager with custom config path
	manager := &Manager{
		configDir:      tempDir,
		configFile:     filepath.Join(tempDir, "config.yaml"),
		currentProfile: ProfileDev,
	}

	// Test viewing non-existent config
	_, err = manager.ViewConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Initialize config and test viewing
	err = manager.Initialize()
	require.NoError(t, err)

	configData, err := manager.ViewConfig()
	assert.NoError(t, err)
	assert.NotEmpty(t, configData)
	assert.Contains(t, configData, "profiles")
	assert.Contains(t, configData, "dev")
	assert.Contains(t, configData, "prod")
	assert.Contains(t, configData, "audit")
}

func TestMergeConfigs(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)

	base := &Config{
		Tools: ToolsConfig{
			Enabled: []string{"trivy"},
			Trivy: TrivyConfig{
				Severity: []string{"HIGH"},
				Timeout:  time.Minute * 5,
				Format:   "json",
			},
		},
		Scan: ScanConfig{
			Timeout:        time.Minute * 10,
			MaxConcurrency: 2,
		},
	}

	override := &Config{
		Tools: ToolsConfig{
			Enabled: []string{"trivy", "kubescape"},
			Trivy: TrivyConfig{
				Severity: []string{"CRITICAL", "HIGH"},
				Timeout:  time.Minute * 7,
			},
		},
		Scan: ScanConfig{
			MaxConcurrency: 4,
		},
	}

	result := manager.mergeConfigs(base, override)

	// Check that override values took precedence
	assert.Equal(t, []string{"trivy", "kubescape"}, result.Tools.Enabled)
	assert.Equal(t, []string{"CRITICAL", "HIGH"}, result.Tools.Trivy.Severity)
	assert.Equal(t, time.Minute*7, result.Tools.Trivy.Timeout)
	assert.Equal(t, 4, result.Scan.MaxConcurrency)

	// Check that non-overridden values remained
	assert.Equal(t, "json", result.Tools.Trivy.Format)
	assert.Equal(t, time.Minute*10, result.Scan.Timeout)
}

func TestGetDefaultConfig(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)

	defaultConfig := manager.getDefaultConfig()
	assert.NotNil(t, defaultConfig)

	// Check structure
	assert.Contains(t, defaultConfig, "profiles")
	assert.Contains(t, defaultConfig, "global")

	profiles := defaultConfig["profiles"].(map[string]interface{})
	assert.Contains(t, profiles, "dev")
	assert.Contains(t, profiles, "prod")
	assert.Contains(t, profiles, "audit")

	// Check dev profile
	devProfile := profiles["dev"].(map[string]interface{})
	assert.Contains(t, devProfile, "tools")
	assert.Contains(t, devProfile, "scan")
	assert.Contains(t, devProfile, "output")
	assert.Contains(t, devProfile, "security")

	// Check prod profile has more tools enabled
	prodProfile := profiles["prod"].(map[string]interface{})
	prodTools := prodProfile["tools"].(map[string]interface{})
	prodEnabled := prodTools["enabled"].([]string)
	assert.Len(t, prodEnabled, 5) // All tools enabled in prod

	// Check audit profile has strictest settings
	auditProfile := profiles["audit"].(map[string]interface{})
	auditTools := auditProfile["tools"].(map[string]interface{})
	auditKubescape := auditTools["kubescape"].(map[string]interface{})
	assert.Equal(t, 4.0, auditKubescape["threshold"]) // Strictest threshold
}

func TestGetConfigPath(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)

	path := manager.GetConfigPath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, ".k8sec-toolkit")
	assert.Contains(t, path, "config.yaml")
}
