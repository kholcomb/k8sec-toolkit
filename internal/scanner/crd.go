package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// CRDDiscovery handles Custom Resource Definition discovery and analysis
type CRDDiscovery struct {
	client       kubernetes.Interface
	apiextClient apiextensionsclientset.Interface
	logger       *logrus.Logger
}

// CRDInfo contains information about a discovered CRD
type CRDInfo struct {
	Name             string            `json:"name"`
	Group            string            `json:"group"`
	Version          string            `json:"version"`
	Kind             string            `json:"kind"`
	Scope            string            `json:"scope"`
	SecurityRelevant bool              `json:"security_relevant"`
	OperatorManaged  bool              `json:"operator_managed"`
	Description      string            `json:"description"`
	ResourceCount    int               `json:"resource_count"`
	Annotations      map[string]string `json:"annotations"`
	Labels           map[string]string `json:"labels"`
}

// SecurityRelevantCRDs contains patterns for identifying security-relevant CRDs
var SecurityRelevantCRDs = []string{
	// Service Mesh
	"virtualservices", "destinationrules", "gateways", "serviceentries",
	"authorizationpolicies", "peerauthentications", "requestauthentications",

	// Security Tools
	"networkpolicies", "podsecuritypolicies", "securitycontextconstraints",
	"certificates", "issuers", "clusterissuers", "certificaterequests",
	"constrainttemplates", "configs", "constraints",

	// Policy Engines
	"policies", "clusterpolicies", "policyreports", "clusterpolicyreports",
	"admissionpolicies", "validatingadmissionpolicies",

	// Secret Management
	"secretstores", "externalsecrets", "secretproviderclasses",
	"vaultconnections", "vaultauths", "vaultdynamicsecrets",

	// Monitoring & Security
	"prometheusrules", "servicemonitors", "podmonitors",
	"falcoevents", "falcorules", "falcosidekicks",

	// Identity & Access
	"serviceaccounts", "clusterroles", "roles", "rolebindings", "clusterrolebindings",
	"oidcidentityproviders", "ldapidentityproviders",

	// Container Security
	"imagestreams", "images", "vulnerabilityreports", "configauditreports",
	"rbacassessmentreports", "infraassessmentreports",
}

// OperatorPatterns contains patterns for identifying operator-managed CRDs
var OperatorPatterns = []string{
	"operators", "subscriptions", "installplans", "catalogsources",
	"olmconfigs", "operatorgroups", "clusterserviceversions",
}

// NewCRDDiscovery creates a new CRD discovery instance
func NewCRDDiscovery(config *rest.Config, client kubernetes.Interface) (*CRDDiscovery, error) {
	apiextClient, err := apiextensionsclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create apiextensions client: %w", err)
	}

	return &CRDDiscovery{
		client:       client,
		apiextClient: apiextClient,
		logger:       logrus.New(),
	}, nil
}

// DiscoverCRDs discovers all CRDs in the cluster and identifies security-relevant ones
func (c *CRDDiscovery) DiscoverCRDs(ctx context.Context) ([]CRDInfo, error) {
	c.logger.Info("Discovering Custom Resource Definitions")

	// List all CRDs
	crdList, err := c.apiextClient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CRDs: %w", err)
	}

	var crdInfos []CRDInfo
	for _, crd := range crdList.Items {
		info := c.analyzeCRD(&crd)
		crdInfos = append(crdInfos, info)
	}

	c.logger.Infof("Discovered %d CRDs (%d security-relevant)",
		len(crdInfos), c.countSecurityRelevant(crdInfos))

	return crdInfos, nil
}

// analyzeCRD analyzes a single CRD for security relevance
func (c *CRDDiscovery) analyzeCRD(crd *apiextensionsv1.CustomResourceDefinition) CRDInfo {
	// Get the latest version
	var latestVersion string
	for _, version := range crd.Spec.Versions {
		if version.Served && version.Storage {
			latestVersion = version.Name
			break
		}
	}
	if latestVersion == "" && len(crd.Spec.Versions) > 0 {
		latestVersion = crd.Spec.Versions[0].Name
	}

	info := CRDInfo{
		Name:        crd.Name,
		Group:       crd.Spec.Group,
		Version:     latestVersion,
		Kind:        crd.Spec.Names.Kind,
		Scope:       string(crd.Spec.Scope),
		Annotations: crd.Annotations,
		Labels:      crd.Labels,
	}

	// Check if security relevant
	info.SecurityRelevant = c.isSecurityRelevant(crd)

	// Check if operator managed
	info.OperatorManaged = c.isOperatorManaged(crd)

	// Get description from annotations
	if desc, ok := crd.Annotations["description"]; ok {
		info.Description = desc
	}

	// Count resources (if accessible)
	info.ResourceCount = c.countCustomResources(crd)

	return info
}

// isSecurityRelevant determines if a CRD is security-relevant
func (c *CRDDiscovery) isSecurityRelevant(crd *apiextensionsv1.CustomResourceDefinition) bool {
	crdName := strings.ToLower(crd.Name)
	kind := strings.ToLower(crd.Spec.Names.Kind)
	group := strings.ToLower(crd.Spec.Group)

	// Check against known security-relevant patterns
	for _, pattern := range SecurityRelevantCRDs {
		if strings.Contains(crdName, pattern) ||
			strings.Contains(kind, pattern) ||
			strings.Contains(group, pattern) {
			return true
		}
	}

	// Check for security-related keywords in annotations
	if annotations := crd.Annotations; annotations != nil {
		for key, value := range annotations {
			keyLower := strings.ToLower(key)
			valueLower := strings.ToLower(value)

			securityKeywords := []string{"security", "policy", "rbac", "auth", "cert", "secret", "vulnerability"}
			for _, keyword := range securityKeywords {
				if strings.Contains(keyLower, keyword) || strings.Contains(valueLower, keyword) {
					return true
				}
			}
		}
	}

	// Check for security-related categories
	if categories := crd.Spec.Names.Categories; categories != nil {
		for _, category := range categories {
			categoryLower := strings.ToLower(category)
			if strings.Contains(categoryLower, "security") ||
				strings.Contains(categoryLower, "policy") ||
				strings.Contains(categoryLower, "auth") {
				return true
			}
		}
	}

	return false
}

// isOperatorManaged determines if a CRD is managed by an operator
func (c *CRDDiscovery) isOperatorManaged(crd *apiextensionsv1.CustomResourceDefinition) bool {
	crdName := strings.ToLower(crd.Name)

	// Check against operator patterns
	for _, pattern := range OperatorPatterns {
		if strings.Contains(crdName, pattern) {
			return true
		}
	}

	// Check for operator-related annotations
	if annotations := crd.Annotations; annotations != nil {
		operatorAnnotations := []string{
			"operators.coreos.com",
			"olm.operatorframework.io",
			"operator.openshift.io",
			"charts.helm.sh",
		}

		for _, opAnnotation := range operatorAnnotations {
			for key := range annotations {
				if strings.Contains(key, opAnnotation) {
					return true
				}
			}
		}
	}

	// Check labels
	if labels := crd.Labels; labels != nil {
		operatorLabels := []string{
			"operators.coreos.com",
			"olm.operatorframework.io",
			"app.kubernetes.io/managed-by",
		}

		for _, opLabel := range operatorLabels {
			for key, value := range labels {
				if strings.Contains(key, opLabel) || strings.Contains(value, "operator") {
					return true
				}
			}
		}
	}

	return false
}

// countCustomResources attempts to count instances of the custom resource
func (c *CRDDiscovery) countCustomResources(crd *apiextensionsv1.CustomResourceDefinition) int {
	// This is a basic implementation - in practice, we'd need to use dynamic client
	// to properly enumerate custom resources

	// For now, return 0 as placeholder
	// TODO: Implement dynamic client-based resource counting
	return 0
}

// countSecurityRelevant counts security-relevant CRDs
func (c *CRDDiscovery) countSecurityRelevant(crdInfos []CRDInfo) int {
	count := 0
	for _, info := range crdInfos {
		if info.SecurityRelevant {
			count++
		}
	}
	return count
}

// GetSecurityRelevantCRDs filters CRDs to only security-relevant ones
func (c *CRDDiscovery) GetSecurityRelevantCRDs(crdInfos []CRDInfo) []CRDInfo {
	var securityCRDs []CRDInfo
	for _, info := range crdInfos {
		if info.SecurityRelevant {
			securityCRDs = append(securityCRDs, info)
		}
	}
	return securityCRDs
}

// GetOperatorManagedCRDs filters CRDs to only operator-managed ones
func (c *CRDDiscovery) GetOperatorManagedCRDs(crdInfos []CRDInfo) []CRDInfo {
	var operatorCRDs []CRDInfo
	for _, info := range crdInfos {
		if info.OperatorManaged {
			operatorCRDs = append(operatorCRDs, info)
		}
	}
	return operatorCRDs
}

// GenerateCRDSecurityReport generates a security report for discovered CRDs
func (c *CRDDiscovery) GenerateCRDSecurityReport(crdInfos []CRDInfo) map[string]interface{} {
	report := make(map[string]interface{})

	total := len(crdInfos)
	securityRelevant := len(c.GetSecurityRelevantCRDs(crdInfos))
	operatorManaged := len(c.GetOperatorManagedCRDs(crdInfos))

	report["total_crds"] = total
	report["security_relevant"] = securityRelevant
	report["operator_managed"] = operatorManaged
	report["security_coverage"] = float64(securityRelevant) / float64(total) * 100

	// Group by category
	groupCounts := make(map[string]int)
	for _, info := range crdInfos {
		groupCounts[info.Group]++
	}
	report["groups"] = groupCounts

	// Identify high-priority security CRDs
	highPriorityCRDs := make([]string, 0)
	for _, info := range crdInfos {
		if info.SecurityRelevant {
			crdName := strings.ToLower(info.Name)
			// Check for critical security CRDs
			criticalPatterns := []string{"networkpolicy", "certificate", "secret", "auth", "rbac"}
			for _, pattern := range criticalPatterns {
				if strings.Contains(crdName, pattern) {
					highPriorityCRDs = append(highPriorityCRDs, info.Name)
					break
				}
			}
		}
	}
	report["high_priority_security_crds"] = highPriorityCRDs

	return report
}
