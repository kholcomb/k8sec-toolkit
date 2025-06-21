package analysis

import (
	"sort"
	"strings"
	"time"

	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

// BusinessImpactAnalyzer provides business-focused analysis of security findings
type BusinessImpactAnalyzer struct {
	riskScorer *RiskScorer
}

// NewBusinessImpactAnalyzer creates a new business impact analyzer
func NewBusinessImpactAnalyzer() *BusinessImpactAnalyzer {
	return &BusinessImpactAnalyzer{
		riskScorer: NewRiskScorer(),
	}
}

// AnalyzeCriticalAssets identifies and analyzes critical assets in the cluster
func (bia *BusinessImpactAnalyzer) AnalyzeCriticalAssets(findings []types.SecurityFinding, clusterInfo *types.ClusterInfo) []types.CriticalAsset {
	// Group findings by resource
	assetFindings := make(map[string][]types.SecurityFinding)
	for _, finding := range findings {
		assetKey := finding.Resource.Namespace + "/" + finding.Resource.Kind + "/" + finding.Resource.Name
		assetFindings[assetKey] = append(assetFindings[assetKey], finding)
	}

	var criticalAssets []types.CriticalAsset
	for _, assetFindingsList := range assetFindings {
		if len(assetFindingsList) == 0 {
			continue
		}

		firstFinding := assetFindingsList[0]
		asset := bia.createCriticalAsset(firstFinding.Resource, assetFindingsList)

		// Only include assets that meet criticality threshold
		if asset.CriticalityLevel != "Low" || asset.RiskScore >= 25.0 {
			criticalAssets = append(criticalAssets, asset)
		}
	}

	// Sort by risk score (highest first)
	sort.Slice(criticalAssets, func(i, j int) bool {
		return criticalAssets[i].RiskScore > criticalAssets[j].RiskScore
	})

	// Limit to top 20 for executive summary
	if len(criticalAssets) > 20 {
		criticalAssets = criticalAssets[:20]
	}

	return criticalAssets
}

// createCriticalAsset creates a CriticalAsset from resource and its findings
func (bia *BusinessImpactAnalyzer) createCriticalAsset(resource types.ResourceReference, findings []types.SecurityFinding) types.CriticalAsset {
	vulnCount := 0
	misconfigCount := 0
	totalRisk := 0.0

	for _, finding := range findings {
		switch finding.Type {
		case "vulnerability":
			vulnCount++
		case "misconfiguration", "best-practice":
			misconfigCount++
		}
		totalRisk += bia.riskScorer.calculateFindingRisk(finding)
	}

	return types.CriticalAsset{
		Name:               resource.Name,
		Type:               resource.Kind,
		Namespace:          resource.Namespace,
		CriticalityLevel:   bia.determineCriticalityLevel(resource, findings, totalRisk),
		VulnerabilityCount: vulnCount,
		MisconfigCount:     misconfigCount,
		RiskScore:          totalRisk,
		BusinessFunction:   bia.inferBusinessFunction(resource, findings),
		DataClassification: bia.inferDataClassification(resource, findings),
	}
}

// determineCriticalityLevel assesses asset criticality based on various factors
func (bia *BusinessImpactAnalyzer) determineCriticalityLevel(resource types.ResourceReference, findings []types.SecurityFinding, riskScore float64) string {
	// Base criticality on resource type
	baseCriticality := bia.getResourceCriticality(resource.Kind)

	// Adjust based on findings severity
	hasCritical := false
	hasHigh := false
	for _, finding := range findings {
		if finding.Severity == "CRITICAL" {
			hasCritical = true
		} else if finding.Severity == "HIGH" {
			hasHigh = true
		}
	}

	// Adjust based on exposure
	isExposed := false
	for _, finding := range findings {
		if bia.riskScorer.isExposedResource(finding) {
			isExposed = true
			break
		}
	}

	// Determine final criticality
	if hasCritical && isExposed && baseCriticality >= 3 {
		return "Critical"
	} else if (hasHigh && isExposed) || (hasCritical && baseCriticality >= 2) || riskScore > 50 {
		return "High"
	} else if baseCriticality >= 2 || riskScore > 20 {
		return "Medium"
	} else {
		return "Low"
	}
}

// getResourceCriticality returns base criticality for resource types (1-4 scale)
func (bia *BusinessImpactAnalyzer) getResourceCriticality(kind string) int {
	criticalityMap := map[string]int{
		"Secret":           4,
		"Ingress":          4,
		"ClusterRole":      4,
		"Deployment":       3,
		"StatefulSet":      3,
		"DaemonSet":        3,
		"Service":          3,
		"Pod":              2,
		"ServiceAccount":   2,
		"Role":             2,
		"ConfigMap":        2,
		"PersistentVolume": 2,
		"NetworkPolicy":    1,
	}

	if criticality, exists := criticalityMap[kind]; exists {
		return criticality
	}
	return 2 // Default to medium
}

// inferBusinessFunction attempts to determine business function from context
func (bia *BusinessImpactAnalyzer) inferBusinessFunction(resource types.ResourceReference, findings []types.SecurityFinding) string {
	name := strings.ToLower(resource.Name)
	namespace := strings.ToLower(resource.Namespace)

	// Common business function indicators
	if containsAny(name, []string{"api", "gateway", "proxy"}) {
		return "API Services"
	} else if containsAny(name, []string{"db", "database", "mysql", "postgres", "mongo"}) {
		return "Data Storage"
	} else if containsAny(name, []string{"web", "frontend", "ui", "portal"}) {
		return "User Interface"
	} else if containsAny(name, []string{"auth", "login", "oauth", "identity"}) {
		return "Authentication"
	} else if containsAny(name, []string{"payment", "billing", "order", "commerce"}) {
		return "Financial Services"
	} else if containsAny(name, []string{"log", "monitor", "metric", "observ"}) {
		return "Observability"
	} else if containsAny(name, []string{"backup", "storage", "archive"}) {
		return "Data Management"
	} else if containsAny(namespace, []string{"prod", "production"}) {
		return "Production Services"
	} else if containsAny(namespace, []string{"kube-system", "system"}) {
		return "System Infrastructure"
	} else {
		return "Application Services"
	}
}

// inferDataClassification determines data sensitivity level
func (bia *BusinessImpactAnalyzer) inferDataClassification(resource types.ResourceReference, findings []types.SecurityFinding) string {
	name := strings.ToLower(resource.Name)
	namespace := strings.ToLower(resource.Namespace)

	// Check findings for data classification hints
	for _, finding := range findings {
		text := strings.ToLower(finding.Description + " " + finding.Title)
		if containsAny(text, []string{"pii", "personal", "gdpr", "privacy"}) {
			return "PII"
		} else if containsAny(text, []string{"pci", "payment", "card", "financial"}) {
			return "PCI"
		} else if containsAny(text, []string{"phi", "health", "medical", "hipaa"}) {
			return "PHI"
		} else if containsAny(text, []string{"secret", "password", "token", "credential"}) {
			return "Confidential"
		}
	}

	// Check resource type and name
	if resource.Kind == "Secret" {
		return "Confidential"
	} else if containsAny(name, []string{"prod", "production"}) {
		return "Internal"
	} else if containsAny(namespace, []string{"public", "demo", "test"}) {
		return "Public"
	} else {
		return "Internal"
	}
}

// GenerateActionItems creates prioritized action items for remediation
func (bia *BusinessImpactAnalyzer) GenerateActionItems(findings []types.SecurityFinding, criticalAssets []types.CriticalAsset) (immediate, quickWins, longTerm []types.ActionItem) {
	// Process findings to generate actions
	actionMap := make(map[string]*types.ActionItem)

	for _, finding := range findings {
		actionID := bia.generateActionID(finding)

		if existingAction, exists := actionMap[actionID]; exists {
			// Merge related findings
			existingAction.RelatedFindings = append(existingAction.RelatedFindings, finding.ID)
			existingAction.AffectedSystems = append(existingAction.AffectedSystems,
				finding.Resource.Namespace+"/"+finding.Resource.Name)
		} else {
			// Create new action item
			action := bia.createActionItem(finding)
			actionMap[actionID] = &action
		}
	}

	// Convert map to slices and categorize
	for _, action := range actionMap {
		bia.enhanceActionWithBusinessContext(action, criticalAssets)

		switch action.Priority {
		case "Critical":
			immediate = append(immediate, *action)
		case "High":
			if bia.isQuickWin(action) {
				quickWins = append(quickWins, *action)
			} else {
				longTerm = append(longTerm, *action)
			}
		case "Medium":
			if bia.isQuickWin(action) {
				quickWins = append(quickWins, *action)
			} else {
				longTerm = append(longTerm, *action)
			}
		default:
			longTerm = append(longTerm, *action)
		}
	}

	// Sort each category by business value
	sortByBusinessValue := func(actions []types.ActionItem) {
		sort.Slice(actions, func(i, j int) bool {
			return bia.compareBusinessValue(actions[i], actions[j])
		})
	}

	sortByBusinessValue(immediate)
	sortByBusinessValue(quickWins)
	sortByBusinessValue(longTerm)

	// Limit results for executive summary
	immediate = limitActionItems(immediate, 5)
	quickWins = limitActionItems(quickWins, 8)
	longTerm = limitActionItems(longTerm, 10)

	return immediate, quickWins, longTerm
}

// generateActionID creates a unique ID for grouping related actions
func (bia *BusinessImpactAnalyzer) generateActionID(finding types.SecurityFinding) string {
	if finding.Type == "vulnerability" && finding.FixedIn != "" {
		return "patch-" + finding.Resource.Kind + "-" + strings.ReplaceAll(finding.FixedIn, ".", "-")
	} else if finding.Type == "misconfiguration" {
		return "config-" + finding.Resource.Kind + "-" + finding.SourceID
	} else {
		return finding.Type + "-" + finding.Resource.Kind + "-" + finding.Source
	}
}

// createActionItem creates an action item from a finding
func (bia *BusinessImpactAnalyzer) createActionItem(finding types.SecurityFinding) types.ActionItem {
	priority := bia.mapSeverityToPriority(finding.Severity)
	category := bia.getActionCategory(finding)

	action := types.ActionItem{
		ID:                  bia.generateActionID(finding),
		Title:               bia.generateActionTitle(finding),
		Description:         bia.generateActionDescription(finding),
		Priority:            priority,
		Category:            category,
		EstimatedEffort:     bia.estimateEffort(finding),
		BusinessValue:       bia.calculateBusinessValue(finding),
		Prerequisites:       bia.getPrerequisites(finding),
		AffectedSystems:     []string{finding.Resource.Namespace + "/" + finding.Resource.Name},
		ImplementationSteps: bia.generateImplementationSteps(finding),
		SuccessMetrics:      bia.generateSuccessMetrics(finding),
		RelatedFindings:     []string{finding.ID},
	}

	// Set due date for critical items
	if priority == "Critical" {
		dueDate := time.Now().AddDate(0, 0, 7) // 1 week for critical
		action.DueDate = &dueDate
	} else if priority == "High" {
		dueDate := time.Now().AddDate(0, 1, 0) // 1 month for high
		action.DueDate = &dueDate
	}

	return action
}

// Helper functions

func containsAny(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func (bia *BusinessImpactAnalyzer) mapSeverityToPriority(severity string) string {
	switch severity {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	default:
		return "Low"
	}
}

func (bia *BusinessImpactAnalyzer) getActionCategory(finding types.SecurityFinding) string {
	if finding.Type == "vulnerability" {
		return "Patch"
	} else if finding.Type == "misconfiguration" || finding.Type == "best-practice" {
		return "Config"
	} else {
		return "Process"
	}
}

func (bia *BusinessImpactAnalyzer) generateActionTitle(finding types.SecurityFinding) string {
	if finding.Type == "vulnerability" {
		return "Update " + finding.Resource.Kind + " to resolve " + finding.CVE
	} else {
		return "Fix " + finding.Resource.Kind + " configuration: " + finding.Title
	}
}

func (bia *BusinessImpactAnalyzer) generateActionDescription(finding types.SecurityFinding) string {
	return finding.Description + "\n\nRemediation: " + finding.Remediation
}

func (bia *BusinessImpactAnalyzer) estimateEffort(finding types.SecurityFinding) string {
	if finding.Type == "vulnerability" && finding.FixedIn != "" {
		return "2-4 hours" // Standard patching effort
	} else if finding.Type == "misconfiguration" {
		return "1-3 hours" // Configuration change
	} else {
		return "4-8 hours" // More complex changes
	}
}

func (bia *BusinessImpactAnalyzer) calculateBusinessValue(finding types.SecurityFinding) string {
	if finding.Severity == "CRITICAL" {
		return "High - Prevents potential security breach"
	} else if finding.Severity == "HIGH" {
		return "Medium-High - Reduces significant security risk"
	} else {
		return "Medium - Improves overall security posture"
	}
}

func (bia *BusinessImpactAnalyzer) getPrerequisites(finding types.SecurityFinding) []string {
	prerequisites := []string{"Security team approval"}

	if finding.Type == "vulnerability" {
		prerequisites = append(prerequisites, "Test environment validation", "Maintenance window")
	} else if finding.Type == "misconfiguration" {
		prerequisites = append(prerequisites, "Configuration backup")
	}

	return prerequisites
}

func (bia *BusinessImpactAnalyzer) generateImplementationSteps(finding types.SecurityFinding) []string {
	if finding.Type == "vulnerability" {
		return []string{
			"1. Create maintenance window",
			"2. Backup current configuration",
			"3. Update to fixed version: " + finding.FixedIn,
			"4. Validate functionality",
			"5. Confirm vulnerability resolution",
		}
	} else {
		return []string{
			"1. Review current configuration",
			"2. Backup existing settings",
			"3. Apply recommended configuration",
			"4. Test system functionality",
			"5. Monitor for issues",
		}
	}
}

func (bia *BusinessImpactAnalyzer) generateSuccessMetrics(finding types.SecurityFinding) []string {
	return []string{
		"Vulnerability scan confirms issue resolved",
		"No degradation in system performance",
		"Security compliance score improved",
	}
}

func (bia *BusinessImpactAnalyzer) enhanceActionWithBusinessContext(action *types.ActionItem, criticalAssets []types.CriticalAsset) {
	// Find if any affected systems are critical assets
	for _, system := range action.AffectedSystems {
		for _, asset := range criticalAssets {
			assetPath := asset.Namespace + "/" + asset.Name
			if strings.Contains(system, assetPath) {
				action.BusinessValue = "High - Affects critical business asset: " + asset.BusinessFunction
				break
			}
		}
	}
}

func (bia *BusinessImpactAnalyzer) isQuickWin(action *types.ActionItem) bool {
	effort := strings.ToLower(action.EstimatedEffort)
	return strings.Contains(effort, "1-3") || strings.Contains(effort, "1-2") ||
		action.Category == "Config"
}

func (bia *BusinessImpactAnalyzer) compareBusinessValue(a, b types.ActionItem) bool {
	valueA := bia.getBusinessValueScore(a.BusinessValue)
	valueB := bia.getBusinessValueScore(b.BusinessValue)
	return valueA > valueB
}

func (bia *BusinessImpactAnalyzer) getBusinessValueScore(value string) int {
	if strings.Contains(value, "High") {
		return 3
	} else if strings.Contains(value, "Medium-High") {
		return 2
	} else if strings.Contains(value, "Medium") {
		return 1
	} else {
		return 0
	}
}

func limitActionItems(items []types.ActionItem, limit int) []types.ActionItem {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}
