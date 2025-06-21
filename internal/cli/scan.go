package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/scanner"
	"github.com/kholcomb/k8sec-toolkit/pkg/output"
)

var (
	scanNamespaces []string
	scanTools      []string
	scanTimeout    time.Duration
)

// newScanCommand creates the scan subcommand
func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [context...]",
		Short: "Scan Kubernetes clusters for security issues",
		Long: `Scan one or more Kubernetes clusters for security vulnerabilities,
misconfigurations, and compliance issues using integrated security tools.

Examples:
  # Scan current cluster with all tools
  k8sec-toolkit scan

  # Scan specific context with selected tools
  k8sec-toolkit scan --context prod --tools trivy,kubescape

  # Scan multiple namespaces
  k8sec-toolkit scan --namespaces kube-system,default,app-prod

  # Output results in JSON format
  k8sec-toolkit scan --output json

  # Scan with extended timeout
  k8sec-toolkit scan --timeout 15m`,
		RunE: runScan,
	}

	// Scan-specific flags
	cmd.Flags().StringSliceVarP(&scanNamespaces, "namespaces", "n", []string{}, "namespaces to scan (default: all accessible)")
	cmd.Flags().StringSliceVar(&scanTools, "tools", []string{"trivy", "kubescape", "kube-bench"}, "tools to run (trivy,kubescape,kube-bench,rbac,polaris)")
	cmd.Flags().DurationVar(&scanTimeout, "timeout", 10*time.Minute, "scan timeout")

	return cmd
}

// runScan executes the security scan
func runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	logrus.Info("Starting K8Sec Toolkit security scan...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override config with command-line flags
	if len(scanNamespaces) > 0 {
		cfg.Scan.Namespaces = scanNamespaces
	}
	if len(scanTools) > 0 {
		cfg.Scan.Tools = scanTools
	}
	if scanTimeout > 0 {
		cfg.Scan.Timeout = scanTimeout
	}

	// Set kubeconfig and context from flags/config
	if kubeconfig != "" {
		cfg.Kubeconfig = kubeconfig
	} else if viper.GetString("kubeconfig") != "" {
		cfg.Kubeconfig = viper.GetString("kubeconfig")
	}

	if kubeContext != "" {
		cfg.Context = kubeContext
	} else if viper.GetString("context") != "" {
		cfg.Context = viper.GetString("context")
	}

	// Determine contexts to scan
	contexts := args
	if len(contexts) == 0 && cfg.Context != "" {
		contexts = []string{cfg.Context}
	}
	if len(contexts) == 0 {
		contexts = []string{""} // Use default context
	}

	logrus.Infof("Scanning %d context(s) with tools: %s",
		len(contexts), strings.Join(cfg.Scan.Tools, ", "))

	// Create scanner
	scannerInstance := scanner.New(cfg)

	// Scan each context
	allResults := make([]*scanner.ScanResult, 0, len(contexts))
	for _, contextName := range contexts {
		logrus.Infof("Scanning context: %s", contextName)

		scanCtx, cancel := context.WithTimeout(ctx, cfg.Scan.Timeout)
		defer cancel()

		result, err := scannerInstance.ScanContext(scanCtx, contextName)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to scan context %s", contextName)
			continue
		}

		allResults = append(allResults, result)
	}

	if len(allResults) == 0 {
		return fmt.Errorf("no contexts were successfully scanned")
	}

	// Output results
	return outputResults(allResults, outputFormat)
}

// outputResults outputs the scan results in the specified format
func outputResults(results []*scanner.ScanResult, format string) error {
	return output.FormatAndOutput(results, format, "")
}
