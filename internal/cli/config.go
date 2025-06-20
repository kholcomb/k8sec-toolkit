package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// newConfigCommand creates the config subcommand
func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage KubeSec configuration",
		Long:  "Initialize, validate, and manage KubeSec configuration files",
	}

	cmd.AddCommand(newConfigInitCommand())
	cmd.AddCommand(newConfigListCommand())
	cmd.AddCommand(newConfigValidateCommand())

	return cmd
}

// newConfigInitCommand creates the config init subcommand
func newConfigInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize a new configuration file",
		Long:  "Create a new KubeSec configuration file with default settings",
		RunE:  runConfigInit,
	}
}

// newConfigListCommand creates the config list subcommand
func newConfigListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List current configuration",
		Long:  "Display the current configuration settings",
		RunE:  runConfigList,
	}
}

// newConfigValidateCommand creates the config validate subcommand
func newConfigValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		Long:  "Validate the syntax and settings of the configuration file",
		RunE:  runConfigValidate,
	}
}

// runConfigInit initializes a new configuration file
func runConfigInit(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".k8sec-toolkit.yaml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("configuration file already exists at %s", configPath)
	}

	// Create default configuration
	defaultConfig := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled": []string{"trivy", "kubescape"},
			"trivy": map[string]interface{}{
				"severity": []string{"CRITICAL", "HIGH", "MEDIUM"},
				"timeout":  "5m",
			},
			"kubescape": map[string]interface{}{
				"frameworks": []string{"cis", "nsa"},
				"threshold":  7.0,
			},
		},
		"scan": map[string]interface{}{
			"timeout":         "10m",
			"parallel":        true,
			"max_concurrency": 3,
		},
		"output": map[string]interface{}{
			"format":              "table",
			"include_raw_results": false,
			"redact_sensitive":    true,
		},
	}

	// Write configuration file
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	fmt.Printf("Configuration file created at: %s\n", configPath)
	return nil
}

// runConfigList displays the current configuration
func runConfigList(cmd *cobra.Command, args []string) error {
	fmt.Printf("Configuration file: %s\n", viper.ConfigFileUsed())
	fmt.Printf("\nCurrent settings:\n")

	settings := viper.AllSettings()
	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	fmt.Printf("%s", data)
	return nil
}

// runConfigValidate validates the configuration file
func runConfigValidate(cmd *cobra.Command, args []string) error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		return fmt.Errorf("no configuration file found")
	}

	fmt.Printf("Validating configuration file: %s\n", configFile)

	// TODO: Implement proper configuration validation
	// For now, just check if it can be read
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	fmt.Printf("Configuration is valid\n")
	return nil
}
