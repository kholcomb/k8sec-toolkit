package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
	"github.com/kholcomb/k8sec-toolkit/internal/tools"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
)

// Scanner orchestrates multiple security tools
type Scanner struct {
	config *config.Config
	tools  map[string]types.SecurityTool
	logger *logrus.Logger
}

// ScanResult represents the result of scanning a context
type ScanResult = types.ScanResult

// New creates a new scanner instance
func New(cfg *config.Config) *Scanner {
	logger := logrus.New()
	if cfg != nil {
		// Configure logger based on config
		logger.SetLevel(logrus.InfoLevel)
	}

	scanner := &Scanner{
		config: cfg,
		tools:  make(map[string]types.SecurityTool),
		logger: logger,
	}

	// Initialize available tools
	scanner.initializeTools()

	return scanner
}

// initializeTools initializes the available security tools
func (s *Scanner) initializeTools() {
	// Initialize Trivy
	if s.isToolEnabled("trivy") {
		trivyTool := tools.NewTrivyWrapper(s.config.Tools.Trivy)
		s.tools["trivy"] = trivyTool
	}

	// Initialize Kubescape
	if s.isToolEnabled("kubescape") {
		kubescapeTool := tools.NewKubescapeWrapper(s.config.Tools.Kubescape)
		s.tools["kubescape"] = kubescapeTool
	}

	// TODO: Initialize other tools (kube-bench, rbac, polaris)
	// For MVP, we focus on Trivy + Kubescape
	
	s.logger.Infof("Initialized %d security tools", len(s.tools))
}

// isToolEnabled checks if a tool is enabled in configuration
func (s *Scanner) isToolEnabled(toolName string) bool {
	for _, enabled := range s.config.Tools.Enabled {
		if enabled == toolName {
			return true
		}
	}
	return false
}

// ScanContext scans a specific Kubernetes context
func (s *Scanner) ScanContext(ctx context.Context, contextName string) (*ScanResult, error) {
	startTime := time.Now()
	
	s.logger.Infof("Starting scan of context: %s", contextName)

	// Create Kubernetes client
	client, clusterInfo, err := s.createKubernetesClient(contextName)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Validate cluster access
	if err := s.validateClusterAccess(client); err != nil {
		return nil, fmt.Errorf("cluster access validation failed: %w", err)
	}

	// Discover CRDs
	crds, err := s.discoverCRDs(ctx, client)
	if err != nil {
		s.logger.WithError(err).Warn("Failed to discover CRDs")
		crds = []CRDInfo{} // Continue without CRD info
	} else {
		s.logger.Infof("Discovered %d CRDs (%d security-relevant)", 
			len(crds), s.countSecurityRelevantCRDs(crds))
	}

	// Prepare tool configuration
	toolConfig := s.prepareToolConfig(contextName)

	// Execute tools
	toolResults, errors := s.executeTools(ctx, toolConfig)

	// Aggregate results
	findings := s.aggregateFindings(toolResults)
	summary := s.generateSummary(findings)

	// Determine which tools were used
	toolsUsed := make([]string, 0, len(toolResults))
	for toolName := range toolResults {
		toolsUsed = append(toolsUsed, toolName)
	}

	result := &ScanResult{
		Context:     contextName,
		ScanTime:    startTime,
		Duration:    time.Since(startTime),
		ToolsUsed:   toolsUsed,
		ClusterInfo: clusterInfo,
		Findings:    findings,
		Summary:     summary,
		ToolResults: toolResults,
		Errors:      errors,
	}

	s.logger.Infof("Scan completed in %v with %d findings", 
		result.Duration, len(result.Findings))

	return result, nil
}

// createKubernetesClient creates a Kubernetes client for the given context
func (s *Scanner) createKubernetesClient(contextName string) (kubernetes.Interface, *types.ClusterInfo, error) {
	// Load kubeconfig
	kubeconfigPath := s.config.Kubeconfig
	if kubeconfigPath == "" {
		kubeconfigPath = clientcmd.RecommendedHomeFile
	}

	// Build config
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath

	configOverrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		configOverrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, configOverrides)

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// Create client
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Get cluster info
	clusterInfo, err := s.getClusterInfo(client)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cluster info: %w", err)
	}

	return client, clusterInfo, nil
}

// validateClusterAccess validates that we have the required permissions
func (s *Scanner) validateClusterAccess(client kubernetes.Interface) error {
	// Test basic access by getting server version
	_, err := client.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %w", err)
	}

	// TODO: Check specific RBAC permissions required for scanning
	return nil
}

// getClusterInfo retrieves basic information about the cluster
func (s *Scanner) getClusterInfo(client kubernetes.Interface) (*types.ClusterInfo, error) {
	// Get server version
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get server version: %w", err)
	}

	// Get basic resource counts
	namespaces, err := client.CoreV1().Namespaces().List(context.TODO(), 
		metav1.ListOptions{})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to get namespace count")
	}

	pods, err := client.CoreV1().Pods("").List(context.TODO(), 
		metav1.ListOptions{})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to get pod count")
	}

	nodes, err := client.CoreV1().Nodes().List(context.TODO(), 
		metav1.ListOptions{})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to get node count")
	}

	clusterInfo := &types.ClusterInfo{
		Name:          "kubernetes", // TODO: Get actual cluster name
		Version:       version.GitVersion,
		ScanTimestamp: time.Now(),
	}

	if namespaces != nil {
		clusterInfo.NamespaceCount = len(namespaces.Items)
	}
	if pods != nil {
		clusterInfo.PodCount = len(pods.Items)
	}
	if nodes != nil {
		clusterInfo.NodeCount = len(nodes.Items)
	}

	return clusterInfo, nil
}

// prepareToolConfig prepares the tool configuration
func (s *Scanner) prepareToolConfig(contextName string) types.ToolConfig {
	return types.ToolConfig{
		KubeconfigPath: s.config.Kubeconfig,
		Context:        contextName,
		Namespaces:     s.config.Scan.Namespaces,
		OutputFormat:   "json",
		Timeout:        s.config.Scan.Timeout,
		CustomFlags:    make(map[string]interface{}),
	}
}

// executeTools executes all configured security tools
func (s *Scanner) executeTools(ctx context.Context, toolConfig types.ToolConfig) (
	map[string]*types.ToolResult, map[string]error) {
	
	if s.config.Scan.Parallel {
		return s.executeToolsParallel(ctx, toolConfig)
	}
	
	return s.executeToolsSequential(ctx, toolConfig)
}

// executeToolsParallel executes tools in parallel
func (s *Scanner) executeToolsParallel(ctx context.Context, toolConfig types.ToolConfig) (
	map[string]*types.ToolResult, map[string]error) {
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	toolResults := make(map[string]*types.ToolResult)
	errors := make(map[string]error)
	
	// Create semaphore for concurrency control
	semaphore := make(chan struct{}, s.config.Scan.MaxConcurrency)
	
	for toolName, tool := range s.tools {
		wg.Add(1)
		go func(name string, t types.SecurityTool) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			s.logger.Infof("Executing tool: %s", name)
			result, err := t.Execute(ctx, toolConfig)
			
			mu.Lock()
			if err != nil {
				errors[name] = err
				s.logger.WithError(err).Errorf("Tool %s failed", name)
			} else {
				toolResults[name] = result
				s.logger.Infof("Tool %s completed with %d findings", 
					name, len(result.Findings))
			}
			mu.Unlock()
		}(toolName, tool)
	}
	
	wg.Wait()
	return toolResults, errors
}

// executeToolsSequential executes tools sequentially
func (s *Scanner) executeToolsSequential(ctx context.Context, toolConfig types.ToolConfig) (
	map[string]*types.ToolResult, map[string]error) {
	
	toolResults := make(map[string]*types.ToolResult)
	errors := make(map[string]error)
	
	for toolName, tool := range s.tools {
		s.logger.Infof("Executing tool: %s", toolName)
		result, err := tool.Execute(ctx, toolConfig)
		
		if err != nil {
			errors[toolName] = err
			s.logger.WithError(err).Errorf("Tool %s failed", toolName)
		} else {
			toolResults[toolName] = result
			s.logger.Infof("Tool %s completed with %d findings", 
				toolName, len(result.Findings))
		}
	}
	
	return toolResults, errors
}

// aggregateFindings combines findings from all tools
func (s *Scanner) aggregateFindings(toolResults map[string]*types.ToolResult) []types.SecurityFinding {
	var allFindings []types.SecurityFinding
	
	for _, result := range toolResults {
		allFindings = append(allFindings, result.Findings...)
	}
	
	// TODO: Implement deduplication logic
	
	return allFindings
}

// generateSummary generates a summary of the findings
func (s *Scanner) generateSummary(findings []types.SecurityFinding) *types.FindingSummary {
	summary := &types.FindingSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByType:        make(map[string]int),
		BySource:      make(map[string]int),
	}
	
	for _, finding := range findings {
		// Count by severity
		summary.BySeverity[finding.Severity]++
		switch finding.Severity {
		case string(types.SeverityCritical):
			summary.Critical++
		case string(types.SeverityHigh):
			summary.High++
		case string(types.SeverityMedium):
			summary.Medium++
		case string(types.SeverityLow):
			summary.Low++
		case string(types.SeverityInfo):
			summary.Info++
		}
		
		// Count by type
		summary.ByType[finding.Type]++
		
		// Count by source
		summary.BySource[finding.Source]++
	}
	
	// Calculate risk score (simple algorithm for now)
	summary.RiskScore = float64(summary.Critical*10 + summary.High*5 + summary.Medium*2 + summary.Low*1) / 10.0
	
	return summary
}

// discoverCRDs discovers and analyzes Custom Resource Definitions in the cluster
func (s *Scanner) discoverCRDs(ctx context.Context, client kubernetes.Interface) ([]CRDInfo, error) {
	// Get the rest config from the client
	config, err := s.getRestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get rest config: %w", err)
	}

	// Create API extensions client
	apiextClient, err := apiextensionsclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create API extensions client: %w", err)
	}

	// Create CRD discovery service
	crdDiscovery := &CRDDiscovery{
		client:       client,
		apiextClient: apiextClient,
		logger:       s.logger,
	}

	return crdDiscovery.DiscoverCRDs(ctx)
}

// countSecurityRelevantCRDs counts how many CRDs are security-relevant
func (s *Scanner) countSecurityRelevantCRDs(crds []CRDInfo) int {
	count := 0
	for _, crd := range crds {
		if crd.SecurityRelevant {
			count++
		}
	}
	return count
}

// getRestConfig gets the REST config for creating additional clients
func (s *Scanner) getRestConfig() (*rest.Config, error) {
	kubeconfigPath := s.config.Kubeconfig
	if kubeconfigPath == "" {
		kubeconfigPath = clientcmd.RecommendedHomeFile
	}

	// Build config
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath

	configOverrides := &clientcmd.ConfigOverrides{}
	if s.config.Context != "" {
		configOverrides.CurrentContext = s.config.Context
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, configOverrides)

	return clientConfig.ClientConfig()
}