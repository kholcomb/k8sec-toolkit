package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
)

// newConfigCommand creates the config subcommand
func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage k8sec-toolkit configuration",
		Long:  "Initialize, view, set, get, and validate k8sec-toolkit configuration with support for multiple profiles",
	}

	// Add profile flag to the parent command
	cmd.PersistentFlags().StringP("profile", "p", "dev", "Configuration profile to use (dev, prod, audit)")

	cmd.AddCommand(newConfigInitCommand())
	cmd.AddCommand(newConfigViewCommand())
	cmd.AddCommand(newConfigSetCommand())
	cmd.AddCommand(newConfigGetCommand())
	cmd.AddCommand(newConfigValidateCommand())
	cmd.AddCommand(newConfigListCommand()) // Keep for backward compatibility

	return cmd
}

// getConfigManager creates and returns a configuration manager with the specified profile
func getConfigManager(cmd *cobra.Command) (*config.Manager, error) {
	manager, err := config.NewManager()
	if err != nil {
		return nil, err
	}

	// Get profile from flag
	profileStr, err := cmd.Flags().GetString("profile")
	if err != nil {
		return nil, fmt.Errorf("failed to get profile flag: %w", err)
	}

	profile, err := config.ParseProfileFromString(profileStr)
	if err != nil {
		return nil, err
	}

	if err := manager.SetProfile(profile); err != nil {
		return nil, err
	}

	return manager, nil
}

// newConfigInitCommand creates the config init subcommand
func newConfigInitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new configuration file",
		Long:  "Create a new k8sec-toolkit configuration file with default settings for dev, prod, and audit profiles",
		RunE:  runConfigInit,
	}

	cmd.Flags().BoolP("force", "f", false, "Overwrite existing configuration file")
	return cmd
}

// newConfigViewCommand creates the config view subcommand
func newConfigViewCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "View current configuration",
		Long:  "Display the current configuration settings for the specified profile",
		RunE:  runConfigView,
	}
}

// newConfigSetCommand creates the config set subcommand
func newConfigSetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long:  "Set a configuration value for the specified profile or globally",
		Args:  cobra.ExactArgs(2),
		RunE:  runConfigSet,
	}

	cmd.Flags().BoolP("global", "g", false, "Set value globally instead of for current profile")
	return cmd
}

// newConfigGetCommand creates the config get subcommand
func newConfigGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Long:  "Get a configuration value from the specified profile",
		Args:  cobra.ExactArgs(1),
		RunE:  runConfigGet,
	}
}

// newConfigValidateCommand creates the config validate subcommand
func newConfigValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration file",
		Long:  "Validate the syntax and settings of the configuration file for all profiles",
		RunE:  runConfigValidate,
	}
}

// newConfigListCommand creates the config list subcommand (backward compatibility)
func newConfigListCommand() *cobra.Command {
	return &cobra.Command{
		Use:        "list",
		Short:      "List current configuration (alias for view)",
		Long:       "Display the current configuration settings (deprecated: use 'view' instead)",
		RunE:       runConfigView,
		Deprecated: "use 'k8sec-toolkit config view' instead",
	}
}

// runConfigInit initializes a new configuration file
func runConfigInit(cmd *cobra.Command, args []string) error {
	manager, err := getConfigManager(cmd)
	if err != nil {
		return err
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("failed to get force flag: %w", err)
	}

	// Check if config exists and handle force flag
	if _, err := os.Stat(manager.GetConfigPath()); err == nil && !force {
		return fmt.Errorf("configuration file already exists at %s. Use --force to overwrite", manager.GetConfigPath())
	}

	if force {
		// Remove existing file if force is specified
		if err := os.Remove(manager.GetConfigPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing configuration file: %w", err)
		}
	}

	if err := manager.Initialize(); err != nil {
		return err
	}

	fmt.Printf("Configuration file created at: %s\n", manager.GetConfigPath())
	fmt.Printf("Available profiles: dev, prod, audit\n")
	fmt.Printf("Use 'k8sec-toolkit config view --profile <profile>' to view profile-specific settings\n")
	return nil
}

// runConfigView displays the current configuration
func runConfigView(cmd *cobra.Command, args []string) error {
	manager, err := getConfigManager(cmd)
	if err != nil {
		return err
	}

	configData, err := manager.ViewConfig()
	if err != nil {
		return err
	}

	fmt.Printf("Configuration file: %s\n", manager.GetConfigPath())
	fmt.Printf("Current profile: %s\n\n", manager.GetCurrentProfile())
	fmt.Printf("%s", configData)
	return nil
}

// runConfigSet sets a configuration value
func runConfigSet(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("exactly two arguments required: key and value")
	}

	manager, err := getConfigManager(cmd)
	if err != nil {
		return err
	}

	key := args[0]
	value := args[1]

	global, err := cmd.Flags().GetBool("global")
	if err != nil {
		return fmt.Errorf("failed to get global flag: %w", err)
	}

	// Parse value based on type hints in the key
	var parsedValue interface{}
	if strings.Contains(strings.ToLower(key), "enabled") || strings.Contains(strings.ToLower(key), "severity") || strings.Contains(strings.ToLower(key), "frameworks") || strings.Contains(strings.ToLower(key), "targets") {
		// Array values - split by comma
		parsedValue = strings.Split(value, ",")
		// Trim whitespace from each element
		arr := parsedValue.([]string)
		for i, v := range arr {
			arr[i] = strings.TrimSpace(v)
		}
		parsedValue = arr
	} else if strings.Contains(strings.ToLower(key), "parallel") || strings.Contains(strings.ToLower(key), "redact") || strings.Contains(strings.ToLower(key), "cleanup") || strings.Contains(strings.ToLower(key), "verify") {
		// Boolean values
		parsedValue = strings.ToLower(value) == "true"
	} else if strings.Contains(strings.ToLower(key), "threshold") || strings.Contains(strings.ToLower(key), "failure_threshold") {
		// Float values
		var f float64
		if _, err := fmt.Sscanf(value, "%f", &f); err != nil {
			return fmt.Errorf("invalid float value for %s: %s", key, value)
		}
		parsedValue = f
	} else if strings.Contains(strings.ToLower(key), "concurrency") || strings.Contains(strings.ToLower(key), "attempts") {
		// Integer values
		var i int
		if _, err := fmt.Sscanf(value, "%d", &i); err != nil {
			return fmt.Errorf("invalid integer value for %s: %s", key, value)
		}
		parsedValue = i
	} else {
		// String values
		parsedValue = value
	}

	if err := manager.SetValue(key, parsedValue, global); err != nil {
		return err
	}

	scope := "profile"
	if global {
		scope = "global"
	}

	fmt.Printf("Successfully set %s configuration: %s = %v\n", scope, key, parsedValue)
	return nil
}

// runConfigGet gets a configuration value
func runConfigGet(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("exactly one argument required: key")
	}

	manager, err := getConfigManager(cmd)
	if err != nil {
		return err
	}

	key := args[0]
	value, err := manager.GetValue(key)
	if err != nil {
		return err
	}

	fmt.Printf("%s = %v\n", key, value)
	return nil
}

// runConfigValidate validates the configuration file
func runConfigValidate(cmd *cobra.Command, args []string) error {
	manager, err := getConfigManager(cmd)
	if err != nil {
		return err
	}

	fmt.Printf("Validating configuration file: %s\n", manager.GetConfigPath())

	if err := manager.ValidateConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	fmt.Printf("✓ Configuration is valid for all profiles\n")

	// Show available profiles
	profiles := manager.ListProfiles()
	fmt.Printf("\nAvailable profiles: %v\n", profiles)
	fmt.Printf("Current profile: %s\n", manager.GetCurrentProfile())

	return nil
}
