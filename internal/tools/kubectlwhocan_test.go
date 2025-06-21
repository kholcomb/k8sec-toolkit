package tools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kholcomb/k8sec-toolkit/internal/config"
	"github.com/kholcomb/k8sec-toolkit/internal/types"
)

func TestKubectlWhoCanWrapper_GetInfo(t *testing.T) {
	cfg := config.RBACConfig{
		CheckDangerousPermissions: true,
		AnalyzeUnusedPermissions:  true,
		GenerateLeastPrivilege:    false,
	}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	info := wrapper.GetInfo()

	if info.Name != "kubectl-who-can" {
		t.Errorf("Expected name to be 'kubectl-who-can', got %s", info.Name)
	}

	if info.Description == "" {
		t.Error("Description should not be empty")
	}

	if len(info.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}

	// Check for expected capabilities
	expectedCaps := []string{"RBAC permissions analysis", "Privilege escalation detection"}
	for _, expected := range expectedCaps {
		found := false
		for _, cap := range info.Capabilities {
			if cap == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected capability '%s' not found", expected)
		}
	}
}

func TestValidateVerb(t *testing.T) {
	tests := []struct {
		verb        string
		expectError bool
	}{
		{"get", false},
		{"list", false},
		{"create", false},
		{"update", false},
		{"patch", false},
		{"delete", false},
		{"deletecollection", false},
		{"watch", false},
		{"*", false},
		{"invalid-verb", true},
		{"", true},
		{"../../../etc/passwd", true},
		{"exec", true}, // exec is not a valid RBAC verb
	}

	for _, tt := range tests {
		t.Run(tt.verb, func(t *testing.T) {
			err := validateVerb(tt.verb)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for verb %s, but got none", tt.verb)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for verb %s, but got: %v", tt.verb, err)
			}
		})
	}
}

func TestValidateResource(t *testing.T) {
	tests := []struct {
		resource    string
		expectError bool
	}{
		{"pods", false},
		{"services", false},
		{"secrets", false},
		{"roles", false},
		{"rolebindings", false},
		{"clusterroles", false},
		{"clusterrolebindings", false},
		{"*", false},
		{"pods/exec", false},          // Subresource
		{"pods/attach", false},        // Subresource
		{"apps/deployments", false},   // API group resource
		{"", true},                    // Empty resource
		{"invalid@resource", true},    // Invalid characters
		{"../../../etc/passwd", true}, // Path injection
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			err := validateResource(tt.resource)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for resource %s, but got none", tt.resource)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for resource %s, but got: %v", tt.resource, err)
			}
		})
	}
}

func TestValidateRBACNamespace(t *testing.T) {
	tests := []struct {
		namespace   string
		expectError bool
	}{
		{"", false},                   // Empty namespace is allowed (cluster-wide)
		{"default", false},            // Valid namespace
		{"kube-system", false},        // Valid namespace with hyphen
		{"my-app-ns", false},          // Valid namespace
		{"123", false},                // Numeric namespace
		{"INVALID", true},             // Uppercase not allowed
		{"invalid_ns", true},          // Underscore not allowed
		{"invalid..ns", true},         // Double dot not allowed
		{"invalid-", true},            // Ending with hyphen
		{"-invalid", true},            // Starting with hyphen
		{"../../../etc/passwd", true}, // Path injection
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			err := validateRBACNamespace(tt.namespace)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for namespace %s, but got none", tt.namespace)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for namespace %s, but got: %v", tt.namespace, err)
			}
		})
	}
}

func TestKubectlWhoCanWrapper_buildScanQueries(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	toolConfig := types.ToolConfig{
		Namespaces: []string{"default", "kube-system"},
	}

	queries, err := wrapper.buildScanQueries(toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(queries) == 0 {
		t.Error("Expected some queries to be built")
	}

	// Check for critical queries
	foundClusterAdmin := false
	foundSecretAccess := false // pragma: allowlist secret
	foundPrivilegeEscalation := false

	for _, query := range queries {
		if query.verb == "*" && query.resource == "*" {
			foundClusterAdmin = true
		}
		if query.verb == "get" && query.resource == "secrets" { // pragma: allowlist secret
			foundSecretAccess = true // pragma: allowlist secret
		}
		if query.verb == "create" && query.resource == "clusterroles" {
			foundPrivilegeEscalation = true
		}
	}

	if !foundClusterAdmin {
		t.Error("Expected cluster-admin check query")
	}
	if !foundSecretAccess { // pragma: allowlist secret
		t.Error("Expected secret access check query") // pragma: allowlist secret
	}
	if !foundPrivilegeEscalation {
		t.Error("Expected privilege escalation check query")
	}
}

func TestKubectlWhoCanWrapper_buildQueryArgs(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	query := rbacQuery{
		verb:         "get",
		resource:     "secrets",
		namespace:    "default",
		subresource:  "",
		resourceName: "my-secret",
	}

	toolConfig := types.ToolConfig{
		KubeconfigPath: "/home/.kube/config",
		Context:        "my-cluster",
	}

	args, err := wrapper.buildQueryArgs(query, toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedArgs := []string{
		"get",
		"secrets",
		"my-secret",
		"--namespace", "default",
		"--output", "json",
		"--kubeconfig", "/home/.kube/config",
		"--context", "my-cluster",
	}

	if len(args) != len(expectedArgs) {
		t.Errorf("Expected %d args, got %d", len(expectedArgs), len(args))
	}

	for i, expected := range expectedArgs {
		if i >= len(args) || args[i] != expected {
			t.Errorf("Expected arg[%d] to be %s, got %s", i, expected, args[i])
		}
	}
}

func TestKubectlWhoCanWrapper_buildQueryArgsWithSubresource(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	query := rbacQuery{
		verb:        "create",
		resource:    "pods",
		namespace:   "",
		subresource: "exec",
	}

	toolConfig := types.ToolConfig{}

	args, err := wrapper.buildQueryArgs(query, toolConfig)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should contain "pods/exec"
	found := false
	for _, arg := range args {
		if arg == "pods/exec" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected 'pods/exec' in arguments for subresource query")
	}
}

func TestKubectlWhoCanWrapper_parseQueryResults(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	// Sample kubectl-who-can JSON output
	sampleOutput := WhoCanReport{
		Verb:      "create",
		Resource:  "clusterroles",
		Namespace: "",
		Users: []WhoCanSubject{
			{
				Name: "system:admin",
				Kind: "User",
			},
		},
		Groups: []WhoCanSubject{
			{
				Name: "system:masters",
				Kind: "Group",
			},
		},
		ServiceAccounts: []WhoCanSubject{
			{
				Name:      "cluster-admin",
				Namespace: "kube-system",
				Kind:      "ServiceAccount",
			},
		},
	}

	jsonOutput, err := json.Marshal(sampleOutput)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	query := rbacQuery{
		verb:     "create",
		resource: "clusterroles",
	}

	findings, err := wrapper.parseQueryResults(jsonOutput, query)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Type != string(types.FindingTypeRBAC) {
		t.Errorf("Expected type to be %s, got %s", types.FindingTypeRBAC, finding.Type)
	}

	if finding.Source != "kubectl-who-can" {
		t.Errorf("Expected source to be 'kubectl-who-can', got %s", finding.Source)
	}

	// Check evidence
	evidence, ok := finding.Evidence.(map[string]interface{})
	if !ok {
		t.Error("Expected evidence to be a map")
	} else {
		if evidence["verb"] != "create" {
			t.Errorf("Expected verb in evidence to be 'create', got %v", evidence["verb"])
		}
		if evidence["resource"] != "clusterroles" {
			t.Errorf("Expected resource in evidence to be 'clusterroles', got %v", evidence["resource"])
		}
		if evidence["total_subjects"] != 3 {
			t.Errorf("Expected total_subjects in evidence to be 3, got %v", evidence["total_subjects"])
		}
	}
}

func TestKubectlWhoCanWrapper_parseQueryResultsNoSubjects(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	// Empty result - no subjects have the permission
	sampleOutput := WhoCanReport{
		Verb:            "delete",
		Resource:        "persistentvolumes",
		Users:           []WhoCanSubject{},
		Groups:          []WhoCanSubject{},
		ServiceAccounts: []WhoCanSubject{},
	}

	jsonOutput, err := json.Marshal(sampleOutput)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	query := rbacQuery{
		verb:     "delete",
		resource: "persistentvolumes",
	}

	findings, err := wrapper.parseQueryResults(jsonOutput, query)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should not create findings when no subjects have permission
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for no subjects, got %d", len(findings))
	}
}

func TestKubectlWhoCanWrapper_assessPermissionSeverity(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	tests := []struct {
		verb     string
		resource string
		expected string
	}{
		{"*", "*", string(types.SeverityCritical)},                 // cluster-admin
		{"create", "clusterroles", string(types.SeverityCritical)}, // privilege escalation
		{"create", "rolebindings", string(types.SeverityCritical)}, // privilege escalation
		{"get", "secrets", string(types.SeverityHigh)},             // sensitive data // pragma: allowlist secret
		{"create", "pods", string(types.SeverityHigh)},             // pod manipulation
		{"get", "configmaps", string(types.SeverityMedium)},        // read access
		{"list", "services", string(types.SeverityMedium)},         // read access
		{"watch", "events", string(types.SeverityMedium)},          // watch is read access
	}

	for _, tt := range tests {
		t.Run(tt.verb+"-"+tt.resource, func(t *testing.T) {
			severity := wrapper.assessPermissionSeverity(tt.verb, tt.resource)
			if severity != tt.expected {
				t.Errorf("Expected severity %s for %s %s, got %s",
					tt.expected, tt.verb, tt.resource, severity)
			}
		})
	}
}

func TestKubectlWhoCanWrapper_buildPermissionDescription(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	// Test cluster-wide permission
	query1 := rbacQuery{
		verb:     "create",
		resource: "pods",
	}
	desc1 := wrapper.buildPermissionDescription(query1, 5)
	if !strings.Contains(desc1, "cluster-wide") {
		t.Error("Expected description to mention 'cluster-wide' for cluster-scoped query")
	}
	if !strings.Contains(desc1, "5 subject(s)") {
		t.Error("Expected description to mention subject count")
	}

	// Test namespaced permission
	query2 := rbacQuery{
		verb:      "get",
		resource:  "secrets",
		namespace: "default",
	}
	desc2 := wrapper.buildPermissionDescription(query2, 2)
	if !strings.Contains(desc2, "in namespace 'default'") {
		t.Error("Expected description to mention namespace for namespaced query")
	}

	// Test subresource
	query3 := rbacQuery{
		verb:        "create",
		resource:    "pods",
		subresource: "exec",
	}
	desc3 := wrapper.buildPermissionDescription(query3, 1)
	if !strings.Contains(desc3, "pods/exec") {
		t.Error("Expected description to include subresource")
	}
}

func TestKubectlWhoCanWrapper_buildPermissionTags(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	// Test high severity tags
	query1 := rbacQuery{
		verb:     "*",
		resource: "*",
	}
	tags1 := wrapper.buildPermissionTags(query1, string(types.SeverityCritical))

	expectedTags := []string{"RBAC", "permissions", "access-control", "privilege-escalation-risk", "wildcard-permissions"}
	for _, expected := range expectedTags {
		found := false
		for _, tag := range tags1 {
			if tag == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected tag '%s' not found in high severity tags", expected)
		}
	}

	// Test secret-specific tags // pragma: allowlist secret
	query2 := rbacQuery{
		verb:     "get",
		resource: "secrets", // pragma: allowlist secret
	}
	tags2 := wrapper.buildPermissionTags(query2, string(types.SeverityHigh))

	foundSensitiveData := false
	for _, tag := range tags2 {
		if tag == "sensitive-data" {
			foundSensitiveData = true
			break
		}
	}
	if !foundSensitiveData {
		t.Error("Expected 'sensitive-data' tag for secrets permission")
	}
}

func TestKubectlWhoCanWrapper_buildPermissionRemediation(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	tests := []struct {
		verb        string
		resource    string
		subresource string
		expectText  string
	}{
		{"*", "*", "", "cluster-admin permissions"},
		{"create", "roles", "", "role management permissions"},
		{"get", "secrets", "", "secret access permissions"},
		{"create", "pods", "exec", "pod creation/exec permissions"},
		{"update", "configmaps", "", "principle of least privilege"},
	}

	for _, tt := range tests {
		t.Run(tt.verb+"-"+tt.resource, func(t *testing.T) {
			query := rbacQuery{
				verb:        tt.verb,
				resource:    tt.resource,
				subresource: tt.subresource,
			}
			remediation := wrapper.buildPermissionRemediation(query)
			if !strings.Contains(strings.ToLower(remediation), strings.ToLower(tt.expectText)) {
				t.Errorf("Expected remediation to contain '%s', got: %s", tt.expectText, remediation)
			}
		})
	}
}

func TestKubectlWhoCanWrapper_parseQueryResultsInvalidJSON(t *testing.T) {
	cfg := config.RBACConfig{}
	wrapper := NewKubectlWhoCanWrapper(cfg)

	invalidJSON := []byte(`{"invalid": json}`)
	query := rbacQuery{verb: "get", resource: "pods"}

	_, err := wrapper.parseQueryResults(invalidJSON, query)
	if err == nil {
		t.Error("Expected error for invalid JSON, got none")
	}
}

func TestRbacQuery(t *testing.T) {
	// Test the rbacQuery struct
	query := rbacQuery{
		verb:         "create",
		resource:     "pods",
		namespace:    "default",
		subresource:  "exec",
		resourceName: "my-pod",
	}

	if query.verb != "create" {
		t.Errorf("Expected verb 'create', got %s", query.verb)
	}
	if query.resource != "pods" {
		t.Errorf("Expected resource 'pods', got %s", query.resource)
	}
	if query.namespace != "default" {
		t.Errorf("Expected namespace 'default', got %s", query.namespace)
	}
}
