package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kholcomb/k8sec-toolkit/internal/cli"
	"github.com/sirupsen/logrus"
)

var (
	// Version information - set during build
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logrus.Info("Received shutdown signal")
		cancel()
	}()

	// Create and execute root command
	rootCmd := cli.NewRootCommand(Version, GitCommit, BuildTime)
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		logrus.WithError(err).Fatal("Command execution failed")
	}
}
