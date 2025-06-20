package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"gopkg.in/yaml.v3"

	"github.com/kubesec-io/kubesec/internal/types"
)

// Formatter handles different output formats
type Formatter interface {
	Format(results []*types.ScanResult) ([]byte, error)
}

// JSONFormatter formats output as JSON
type JSONFormatter struct{}

// TableFormatter formats output as a human-readable table
type TableFormatter struct{}

// YAMLFormatter formats output as YAML
type YAMLFormatter struct{}

// SummaryFormatter formats output as a brief summary
type SummaryFormatter struct{}

// NewFormatter creates a formatter based on the format string
func NewFormatter(format string) (Formatter, error) {
	switch strings.ToLower(format) {
	case "json":
		return &JSONFormatter{}, nil
	case "table":
		return &TableFormatter{}, nil
	case "yaml":
		return &YAMLFormatter{}, nil
	case "summary":
		return &SummaryFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

// Format implements Formatter for JSON output
func (f *JSONFormatter) Format(results []*types.ScanResult) ([]byte, error) {
	if len(results) == 1 {
		return json.MarshalIndent(results[0], "", "  ")
	}
	return json.MarshalIndent(results, "", "  ")
}

// Format implements Formatter for table output
func (f *TableFormatter) Format(results []*types.ScanResult) ([]byte, error) {
	var output strings.Builder

	for _, result := range results {
		output.WriteString(f.formatScanResult(result))
		output.WriteString("\n")
	}

	return []byte(output.String()), nil
}

func (f *TableFormatter) formatScanResult(result *types.ScanResult) string {
	var output strings.Builder

	// Header
	output.WriteString(fmt.Sprintf("=== KubeSec Scan Results: %s ===\n", result.Context))
	
	// Cluster info
	if result.ClusterInfo != nil {
		output.WriteString(fmt.Sprintf("Cluster: %s (v%s)\n", 
			result.ClusterInfo.Name, result.ClusterInfo.Version))
		output.WriteString(fmt.Sprintf("Nodes: %d, Namespaces: %d, Pods: %d\n",
			result.ClusterInfo.NodeCount, result.ClusterInfo.NamespaceCount, result.ClusterInfo.PodCount))
	}
	
	output.WriteString(fmt.Sprintf("Scan Time: %s\n", result.ScanTime.Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
	output.WriteString(fmt.Sprintf("Tools: %s\n", strings.Join(result.ToolsUsed, ", ")))

	// Summary
	if result.Summary != nil {
		output.WriteString(fmt.Sprintf("\nSummary:\n"))
		output.WriteString(fmt.Sprintf("  Total Findings: %d\n", result.Summary.TotalFindings))
		output.WriteString(fmt.Sprintf("  Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n",
			result.Summary.Critical, result.Summary.High, result.Summary.Medium, 
			result.Summary.Low, result.Summary.Info))
		output.WriteString(fmt.Sprintf("  Risk Score: %.1f\n", result.Summary.RiskScore))
	}

	// Findings table
	if len(result.Findings) > 0 {
		output.WriteString(f.formatFindingsTable(result.Findings))
	}

	// Errors
	if len(result.Errors) > 0 {
		output.WriteString("\nErrors:\n")
		for tool, err := range result.Errors {
			output.WriteString(fmt.Sprintf("  %s: %v\n", tool, err))
		}
	}

	return output.String()
}

func (f *TableFormatter) formatFindingsTable(findings []types.SecurityFinding) string {
	var output strings.Builder
	
	output.WriteString("\nFindings:\n")
	
	// Create table
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Severity", "Type", "Resource", "Title", "Source"})
	table.SetBorder(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	// Add findings (limit to first 20 for readability)
	count := len(findings)
	if count > 20 {
		count = 20
	}

	for i := 0; i < count; i++ {
		finding := findings[i]
		resourceName := fmt.Sprintf("%s/%s", finding.Resource.Kind, finding.Resource.Name)
		if finding.Resource.Namespace != "" {
			resourceName = fmt.Sprintf("%s/%s", finding.Resource.Namespace, resourceName)
		}
		
		// Truncate title if too long
		title := finding.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}

		table.Append([]string{
			finding.Severity,
			finding.Type,
			resourceName,
			title,
			finding.Source,
		})
	}

	table.Render()
	output.WriteString(tableString.String())

	if len(findings) > 20 {
		output.WriteString(fmt.Sprintf("... and %d more findings (use --output json for full results)\n", len(findings)-20))
	}

	return output.String()
}

// Format implements Formatter for YAML output
func (f *YAMLFormatter) Format(results []*types.ScanResult) ([]byte, error) {
	if len(results) == 1 {
		return yaml.Marshal(results[0])
	}
	return yaml.Marshal(results)
}

// Format implements Formatter for summary output
func (f *SummaryFormatter) Format(results []*types.ScanResult) ([]byte, error) {
	var output strings.Builder

	totalFindings := 0
	totalCritical := 0
	totalHigh := 0
	totalMedium := 0
	totalLow := 0
	avgRiskScore := 0.0

	output.WriteString("KubeSec Security Scan Summary\n")
	output.WriteString("============================\n\n")

	for _, result := range results {
		if result.Summary != nil {
			totalFindings += result.Summary.TotalFindings
			totalCritical += result.Summary.Critical
			totalHigh += result.Summary.High
			totalMedium += result.Summary.Medium
			totalLow += result.Summary.Low
			avgRiskScore += result.Summary.RiskScore
		}

		output.WriteString(fmt.Sprintf("Context: %s\n", result.Context))
		if result.ClusterInfo != nil {
			output.WriteString(fmt.Sprintf("  Cluster: %s (v%s)\n", 
				result.ClusterInfo.Name, result.ClusterInfo.Version))
		}
		if result.Summary != nil {
			output.WriteString(fmt.Sprintf("  Findings: %d (Critical: %d, High: %d)\n",
				result.Summary.TotalFindings, result.Summary.Critical, result.Summary.High))
			output.WriteString(fmt.Sprintf("  Risk Score: %.1f\n", result.Summary.RiskScore))
		}
		output.WriteString(fmt.Sprintf("  Tools: %s\n", strings.Join(result.ToolsUsed, ", ")))
		
		if len(result.Errors) > 0 {
			output.WriteString(fmt.Sprintf("  Errors: %d tool(s) failed\n", len(result.Errors)))
		}
		
		output.WriteString("\n")
	}

	// Overall summary
	if len(results) > 1 {
		avgRiskScore /= float64(len(results))
		output.WriteString("Overall Summary:\n")
		output.WriteString(fmt.Sprintf("  Total Findings: %d\n", totalFindings))
		output.WriteString(fmt.Sprintf("  Critical: %d, High: %d, Medium: %d, Low: %d\n",
			totalCritical, totalHigh, totalMedium, totalLow))
		output.WriteString(fmt.Sprintf("  Average Risk Score: %.1f\n", avgRiskScore))
	}

	return []byte(output.String()), nil
}

// FormatAndOutput formats results and writes them to the specified output
func FormatAndOutput(results []*types.ScanResult, format, outputFile string) error {
	formatter, err := NewFormatter(format)
	if err != nil {
		return err
	}

	data, err := formatter.Format(results)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if outputFile == "" || outputFile == "-" {
		fmt.Print(string(data))
		return nil
	}

	return os.WriteFile(outputFile, data, 0644)
}