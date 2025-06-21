package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigBasicFunctionality(t *testing.T) {
	// Create temporary directory for home
	tempDir, err := os.MkdirTemp("", "k8sec-test-home-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Set HOME environment variable temporarily
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)
	os.Setenv("HOME", tempDir)

	t.Run("command structure", func(t *testing.T) {
		cmd := newConfigCommand()
		assert.NotNil(t, cmd)
		assert.Equal(t, "config", cmd.Use)
		assert.NotEmpty(t, cmd.Short)
		assert.NotEmpty(t, cmd.Long)

		// Check that all subcommands are present
		subcommands := cmd.Commands()
		assert.Len(t, subcommands, 6) // init, view, set, get, validate, list

		// Check profile flag exists
		flag := cmd.PersistentFlags().Lookup("profile")
		assert.NotNil(t, flag)
		assert.Equal(t, "dev", flag.DefValue)
	})

	t.Run("init command functionality", func(t *testing.T) {
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"init"})
		err := configCmd.Execute()
		assert.NoError(t, err)

		// Check that config file was created
		configPath := filepath.Join(tempDir, ".k8sec-toolkit", "config.yaml")
		_, err = os.Stat(configPath)
		assert.NoError(t, err)

		// Check that file has expected content
		data, err := os.ReadFile(configPath)
		assert.NoError(t, err)
		content := string(data)
		assert.Contains(t, content, "profiles:")
		assert.Contains(t, content, "dev:")
		assert.Contains(t, content, "prod:")
		assert.Contains(t, content, "audit:")
	})

	t.Run("view command functionality", func(t *testing.T) {
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"view"})
		err := configCmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("set and get functionality", func(t *testing.T) {
		// Set a value
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"set", "tools.trivy.format", "table"})
		err := configCmd.Execute()
		assert.NoError(t, err)

		// Get the value
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"get", "tools.trivy.format"})
		err = configCmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("validate functionality", func(t *testing.T) {
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"validate"})
		err := configCmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("profile switching", func(t *testing.T) {
		// Test different profiles
		profiles := []string{"dev", "prod", "audit"}
		for _, profile := range profiles {
			configCmd := newConfigCommand()
			configCmd.SetArgs([]string{"--profile", profile, "view"})
			err := configCmd.Execute()
			assert.NoError(t, err, "Profile %s should work", profile)
		}

		// Test invalid profile
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"--profile", "invalid", "view"})
		err := configCmd.Execute()
		assert.Error(t, err)
	})
}

func TestConfigErrorHandling(t *testing.T) {
	// Create temporary directory for home
	tempDir, err := os.MkdirTemp("", "k8sec-test-home-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Set HOME environment variable temporarily
	originalHome := os.Getenv("HOME")
	defer os.Setenv("HOME", originalHome)
	os.Setenv("HOME", tempDir)

	t.Run("operations without config file", func(t *testing.T) {
		// View should fail without config
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"view"})
		err := configCmd.Execute()
		assert.Error(t, err)

		// Get should fail without config
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"get", "some.key"})
		err = configCmd.Execute()
		assert.Error(t, err)

		// Set should fail without config
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"set", "some.key", "value"})
		err = configCmd.Execute()
		assert.Error(t, err)

		// Validate should fail without config
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"validate"})
		err = configCmd.Execute()
		assert.Error(t, err)
	})

	t.Run("invalid arguments", func(t *testing.T) {
		// Initialize config first
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"init"})
		err := configCmd.Execute()
		require.NoError(t, err)

		// Set with wrong number of arguments
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"set", "key"})
		err = configCmd.Execute()
		assert.Error(t, err)

		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"set", "key", "value", "extra"})
		err = configCmd.Execute()
		assert.Error(t, err)

		// Get with wrong number of arguments
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"get"})
		err = configCmd.Execute()
		assert.Error(t, err)

		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"get", "key", "extra"})
		err = configCmd.Execute()
		assert.Error(t, err)
	})

	t.Run("force flag with init", func(t *testing.T) {
		// Create a fresh temp directory for this subtest
		freshTempDir, err := os.MkdirTemp("", "k8sec-test-force-*")
		require.NoError(t, err)
		defer os.RemoveAll(freshTempDir)

		// Temporarily override HOME for this test
		os.Setenv("HOME", freshTempDir)
		defer os.Setenv("HOME", tempDir) // Restore original temp dir

		// First init should succeed
		configCmd := newConfigCommand()
		configCmd.SetArgs([]string{"init"})
		err = configCmd.Execute()
		assert.NoError(t, err)

		// Second init should fail
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"init"})
		err = configCmd.Execute()
		assert.Error(t, err)

		// Init with force should succeed
		configCmd = newConfigCommand()
		configCmd.SetArgs([]string{"init", "--force"})
		err = configCmd.Execute()
		assert.NoError(t, err)
	})
}
