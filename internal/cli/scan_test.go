package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"
)

func TestScanCommand(t *testing.T) {
	// Test that the scan command can be created without errors
	cmd := newScanCommand()
	
	if cmd == nil {
		t.Fatal("newScanCommand() returned nil")
	}
	
	if cmd.Use != "scan [context...]" {
		t.Errorf("Expected command use to be 'scan [context...]', got %s", cmd.Use)
	}
	
	if cmd.Short == "" {
		t.Error("Command should have a short description")
	}
}

func TestScanCommandHelp(t *testing.T) {
	// Test that help can be displayed without errors
	rootCmd := &cobra.Command{Use: "kubesec"}
	rootCmd.AddCommand(newScanCommand())
	
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"scan", "--help"})
	
	err := rootCmd.ExecuteContext(context.Background())
	if err != nil {
		t.Fatalf("Failed to execute help command: %v", err)
	}
	
	output := buf.String()
	if output == "" {
		t.Error("Help command should produce output")
	}
	
	// Check for key help sections
	expectedSections := []string{"Usage:", "Examples:", "Flags:"}
	for _, section := range expectedSections {
		if !bytes.Contains(buf.Bytes(), []byte(section)) {
			t.Errorf("Help output should contain '%s' section", section)
		}
	}
}