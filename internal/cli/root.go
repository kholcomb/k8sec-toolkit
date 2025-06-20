package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/sirupsen/logrus"
)

var (
	cfgFile     string
	kubeconfig  string
	kubeContext string
	verbose     bool
	outputFormat string
)

// NewRootCommand creates the root cobra command
func NewRootCommand(version, gitCommit, buildTime string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "k8sec-toolkit",
		Short: "K8Sec Toolkit - Kubernetes Security Scanner",
		Long: `K8Sec Toolkit is a comprehensive Kubernetes security scanner that orchestrates
best-in-class open source security tools to provide unified security assessment.

K8Sec Toolkit integrates:
- Trivy: Container vulnerability scanning
- Kubescape: Configuration security and compliance
- kube-bench: CIS Kubernetes Benchmark
- kubectl-who-can: RBAC analysis
- Polaris: Workload best practices

All tools are free, open source, and Apache 2.0 licensed.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initLogging()
			initConfig()
		},
		Version: formatVersion(version, gitCommit, buildTime),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.k8sec-toolkit.yaml)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "path to the kubeconfig file (default is ~/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubernetes context to use")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "output format (table, json, yaml, summary)")

	// Bind flags to viper
	viper.BindPFlag("kubeconfig", rootCmd.PersistentFlags().Lookup("kubeconfig"))
	viper.BindPFlag("context", rootCmd.PersistentFlags().Lookup("context"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("output.format", rootCmd.PersistentFlags().Lookup("output"))

	// Add subcommands
	rootCmd.AddCommand(newScanCommand())
	rootCmd.AddCommand(newVersionCommand(version, gitCommit, buildTime))
	rootCmd.AddCommand(newConfigCommand())
	rootCmd.AddCommand(newToolsCommand())

	return rootCmd
}

// initLogging sets up the logging configuration
func initLogging() {
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
}

// initConfig reads in config file and ENV variables
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			logrus.WithError(err).Fatal("Failed to get user home directory")
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".k8sec-toolkit")
	}

	viper.SetEnvPrefix("K8SEC_TOOLKIT")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		logrus.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}
}

// formatVersion formats the version information
func formatVersion(version, gitCommit, buildTime string) string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", version, gitCommit, buildTime)
}