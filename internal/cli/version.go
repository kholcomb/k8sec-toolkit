package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// newVersionCommand creates the version subcommand
func newVersionCommand(version, gitCommit, buildTime string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  "Display detailed version information for KubeSec and its components",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion(version, gitCommit, buildTime)
		},
	}
}

// showVersion displays version information
func showVersion(version, gitCommit, buildTime string) {
	fmt.Printf("KubeSec version %s\n", version)
	fmt.Printf("Git commit: %s\n", gitCommit)
	fmt.Printf("Built: %s\n", buildTime)
	fmt.Printf("Go version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	
	// TODO: Add embedded tool versions
	fmt.Printf("\nEmbedded Tools:\n")
	fmt.Printf("  Trivy: (version will be detected)\n")
	fmt.Printf("  Kubescape: (version will be detected)\n")
	fmt.Printf("  kube-bench: (version will be detected)\n")
	fmt.Printf("  kubectl-who-can: (version will be detected)\n")
	fmt.Printf("  Polaris: (version will be detected)\n")
}