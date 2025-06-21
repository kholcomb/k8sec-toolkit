# K8Sec Toolkit

[![Security Status](https://img.shields.io/badge/security-hardened-green.svg)](SECURITY.md)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A comprehensive Kubernetes security scanner that orchestrates best-in-class open source security tools
with enterprise-grade security controls.

## 🔒 Security-First Architecture

K8Sec Toolkit implements **defense-in-depth security** with:

- **Secure Command Execution**: Built-in command validation and allowlisting
- **Input Validation**: Comprehensive sanitization and allowlisting
- **Binary Integrity**: Path validation and integrity verification
- **Audit Logging**: Complete security audit trail
- **Privilege Minimization**: Least-privilege execution model

See [SECURITY.md](SECURITY.md) for complete security documentation.

## ✨ Features

- **🛡️ Multi-Tool Integration**: Trivy, Kubescape, kube-bench, kubectl-who-can, Polaris
- **📊 Unified Output**: Consistent JSON/YAML/Table formats across all tools
- **🔍 CRD Discovery**: Automated Custom Resource Definition security analysis
- **🎯 Context-Aware**: Scan multiple Kubernetes contexts with intelligent filtering
- **⚡ Performance**: Parallel tool execution with timeout controls
- **🏭 Production Ready**: Comprehensive error handling, logging, and monitoring
- **🔐 Secure by Design**: Enterprise-grade command execution framework

## 🚀 Quick Start

### Installation

```bash
# Build from source
go build -o k8sec-toolkit cmd/k8sec-toolkit/main.go

# Or use make
make build

# Install dependencies (macOS with Homebrew)
brew install trivy kubescape kube-bench kubectl-who-can polaris
```

### Basic Usage

```bash
# Scan current context with default tools
k8sec-toolkit scan

# Scan specific context with selected tools
k8sec-toolkit scan --context my-cluster --tools trivy,kubescape,kube-bench,rbac,polaris

# Output in different formats
k8sec-toolkit scan --output json
k8sec-toolkit scan --output yaml
k8sec-toolkit scan --output table

# Scan specific namespaces
k8sec-toolkit scan --namespaces kube-system,default

# Verbose security audit logging
k8sec-toolkit scan --verbose
```

### Example Output

```bash
$ k8sec-toolkit scan --output table

=== K8Sec Toolkit Scan Results: kubernetes ===
Cluster: kubernetes (v1.32.2)
Nodes: 3, Namespaces: 12, Pods: 45
Scan Time: 2023-12-24T10:00:00Z
Duration: 2m15s
Tools: trivy, kubescape, kube-bench, rbac, polaris

Summary:
  Total Findings: 25
  Critical: 2, High: 8, Medium: 10, Low: 5, Info: 0
  Risk Score: 75.2

Findings:
+----------+----------------+------------------+---------------------+----------+
| SEVERITY | TYPE           | RESOURCE         | TITLE               | SOURCE   |
+----------+----------------+------------------+---------------------+----------+
| CRITICAL | vulnerability  | default/nginx    | CVE-2023-12345      | trivy    |
| HIGH     | misconfiguration| kube-system/pod  | Privileged container| polaris  |
+----------+----------------+------------------+---------------------+----------+
```

## 🔧 Tools Integrated

All tools are free, open source, and Apache 2.0 licensed:

| Tool | Purpose | Website |
|------|---------|---------|
| **[Trivy](https://trivy.dev/)** | Container vulnerability scanning | <https://trivy.dev/> |
| **[Kubescape](https://kubescape.io/)** | Configuration security & compliance | <https://kubescape.io/> |
| **[kube-bench](https://github.com/aquasecurity/kube-bench)** | CIS Kubernetes Benchmark | <https://github.com/aquasecurity/kube-bench> |
| **[kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can)** | RBAC analysis | <https://github.com/aquasecurity/kubectl-who-can> |
| **[Polaris](https://polaris.docs.fairwinds.com/)** | Workload best practices | <https://polaris.docs.fairwinds.com/> |

## 🏗️ Architecture

K8Sec Toolkit follows a **secure tool orchestration** architecture:

```text
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Interface │───▶│ SecureExecutor   │───▶│ Security Tools  │
│                 │    │                  │    │                 │
│ • Input Validation   │ • Command Allow- │    │ • Trivy         │
│ • Output Formatting  │   listing        │    │ • Kubescape     │
│ • Error Handling     │ • Arg Validation │    │ • kube-bench    │
└─────────────────┘    │ • Binary Verif.  │    │ • kubectl-who-can│
                       │ • Audit Logging  │    │ • Polaris       │
                       └──────────────────┘    └─────────────────┘
```

### Key Principles

✅ **Secure by Default**: All commands go through security validation
✅ **Defense in Depth**: Multiple security layers prevent attacks
✅ **Fail Safe**: Security failures block execution
✅ **Audit Everything**: Complete command execution audit trail
✅ **Zero Trust**: No user input is trusted without validation

## 📋 Commands

### Current Commands

```bash
# Scan commands
k8sec-toolkit scan [context...]              # Scan clusters for security issues
k8sec-toolkit scan --tools trivy,rbac        # Use specific tools only
k8sec-toolkit scan --namespaces ns1,ns2      # Scan specific namespaces

# Tool management
k8sec-toolkit tools status                   # Check tool availability and versions
k8sec-toolkit tools list                     # List all available tools

# Utilities
k8sec-toolkit version                        # Show version information
k8sec-toolkit completion bash                # Generate shell completion
```

### Planned Commands

```bash
# Configuration (planned)
k8sec-toolkit config view                    # Show current configuration
k8sec-toolkit config set <key> <value>       # Set configuration values

# Tool updates (planned)
k8sec-toolkit tools update                   # Update tool databases
```

## ⚙️ Configuration

### Configuration File

Create `~/.k8sec-toolkit.yaml`:

```yaml
# Tool selection
tools:
  enabled: ["trivy", "kubescape", "kube-bench", "rbac", "polaris"]

  trivy:
    severity: ["CRITICAL", "HIGH", "MEDIUM"]
    timeout: "5m"

  kubescape:
    frameworks: ["NSA", "MITRE"]
    threshold: 7.0

  kube_bench:
    version: "auto"
    targets: ["master", "node", "etcd", "policies"]

  rbac:
    check_dangerous_permissions: true
    analyze_unused_permissions: true
    generate_least_privilege: false

  polaris:
    config_path: ""  # Use default built-in config
    only_show_failed_tests: true
    output_format: "json"

# Scan settings
scan:
  timeout: "10m"
  parallel: true
  max_concurrency: 3

# Output settings
output:
  format: "table"
  include_raw_results: false
  redact_sensitive: true

# Security settings
security:
  verify_tool_checksums: true
  cleanup_on_exit: true
```

### Environment Variables

```bash
export K8SEC_TOOLKIT_CONFIG=/path/to/config.yaml
export K8SEC_TOOLKIT_KUBECONFIG=/path/to/kubeconfig
export K8SEC_TOOLKIT_CONTEXT=my-cluster
export K8SEC_TOOLKIT_OUTPUT=json
```

## 🧪 Development

### Prerequisites

- Go 1.21+
- kubectl configured with cluster access
- Security tools installed (trivy, kubescape, etc.)

### Building

```bash
# Build binary
make build

# Run tests
make test

# Run security checks
make security-check

# Run linting
make lint

# Generate code coverage
make coverage
```

### Testing

```bash
# Unit tests
go test ./...

# Integration tests
make test-integration

# Security tests
make test-security

# End-to-end tests
make test-e2e
```

### GitFlow Workflow

This project uses GitFlow for version control:

```bash
# Feature development
git flow feature start new-feature
git flow feature finish new-feature

# Release preparation
git flow release start v1.0.0
git flow release finish v1.0.0

# Hotfix for production
git flow hotfix start critical-fix
git flow hotfix finish critical-fix
```

## 📊 Security Metrics

K8Sec Toolkit provides comprehensive security metrics:

- **Vulnerability Count**: Total CVEs discovered
- **Risk Score**: Weighted security score (0-100)
- **Compliance Score**: Framework compliance percentage
- **Coverage Score**: Percentage of resources scanned
- **Remediation Time**: Estimated fix effort

## 🔬 Advanced Analysis Capabilities

### Executive Summary Data Models

K8Sec Toolkit includes sophisticated data models for executive-level security reporting:

- **Risk Scoring Algorithm**: Multi-factor calculation considering severity, exposure, asset criticality
- **CVSS Business Impact**: Industry-standard scoring with organizational customization
- **Critical Asset Analysis**: Identification of high-value assets requiring attention
- **Actionable Remediation Plans**: Structured recommendations with effort estimation

These capabilities are designed for integration with dashboard platforms and executive reporting systems.

**Note**: API server and CLI integration for these features are planned for future releases.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Security Contributions

For security-related contributions:

1. Review [SECURITY.md](SECURITY.md) first
2. All security changes require security review
3. Security tests must pass
4. Include security impact assessment

## 📄 License

Apache 2.0 - see [LICENSE](LICENSE) for details.

## 🔒 Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

**DO NOT** create public issues for security vulnerabilities.

## 🎯 Roadmap

### Current Phase (Phase 3 Complete)

- ✅ All 5 security tools integrated and validated (Trivy, Kubescape, kube-bench, kubectl-who-can, Polaris)
- ✅ Advanced risk scoring and business impact analysis data models
- ✅ Comprehensive test coverage (90%+ for analysis modules)
- ✅ Executive summary capabilities for dashboard integration
- ✅ Security command execution framework with validation and audit logging
- ✅ Tool integration issues resolved (trivy exit codes, polaris execution, secure executor fixes)
- ✅ Comprehensive tool validation test suite implemented

### Recent Fixes (Current Session)

- ✅ Fixed trivy execution handling for non-zero exit codes when vulnerabilities are found
- ✅ Resolved polaris tool integration issues and namespace validation
- ✅ Enhanced secure executor stderr capture for better error diagnostics
- ✅ Fixed tool selection logic to properly honor CLI flags
- ✅ Created comprehensive validation script for all tool integrations

### Planned Features

- [ ] Enhanced CLI output formats (executive summary, detailed reports)
- [ ] Configuration management commands
- [ ] API server for dashboard integration
- [ ] Webhook notifications for critical findings
- [ ] Binary signature verification
- [ ] Container-based tool isolation
- [ ] Real-time security monitoring
- [ ] Machine learning anomaly detection
- [ ] Cloud provider integrations
- [ ] Policy as Code engine

---

**Built with ❤️ for Kubernetes Security**
