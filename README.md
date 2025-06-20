# KubeSec - Kubernetes Security Scanner

A comprehensive CLI tool that orchestrates best-in-class open source security tools to provide unified Kubernetes security assessment.

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Access to a Kubernetes cluster
- `trivy` and `kubescape` binaries in PATH (for now)

### Build and Run

```bash
# Build the binary
make build

# Run a basic scan
./build/kubesec scan

# Scan with specific output format
./build/kubesec scan --output json

# Scan specific namespaces
./build/kubesec scan --namespaces kube-system,default

# Get help
./build/kubesec --help
```

## 📋 Current Status (MVP)

### ✅ Implemented
- CLI framework with full command structure
- Configuration management system
- Trivy integration for vulnerability scanning
- Kubescape integration for configuration security
- CRD discovery and security analysis
- Output formatters (JSON, table, YAML, summary)
- Basic error handling

### ⚠️ Known Limitations (MVP)
- Requires external `trivy` and `kubescape` binaries
- No embedded tools yet (planned for v1.0)
- Limited to Trivy + Kubescape (additional tools coming)
- Basic error handling only

## 🛠 Commands

### Scan Commands
```bash
# Scan current cluster context
kubesec scan

# Scan specific context
kubesec scan --context production

# Scan with specific tools
kubesec scan --tools trivy,kubescape

# Scan with timeout
kubesec scan --timeout 15m
```

### Configuration Commands
```bash
# Initialize configuration
kubesec config init

# View current configuration
kubesec config list

# Validate configuration
kubesec config validate
```

### Tool Management
```bash
# List available tools
kubesec tools list

# Check tool status
kubesec tools status

# Update tool databases
kubesec tools update
```

## 📊 Output Formats

### Table (Default)
Human-readable table format with summary and top findings.

### JSON
Structured output for automation and integration:
```bash
kubesec scan --output json
```

### Summary
High-level overview perfect for dashboards:
```bash
kubesec scan --output summary
```

## ⚙️ Configuration

KubeSec uses a YAML configuration file (`~/.kubesec.yaml`):

```yaml
tools:
  enabled: ["trivy", "kubescape"]
  trivy:
    severity: ["CRITICAL", "HIGH", "MEDIUM"]
    timeout: "5m"
  kubescape:
    frameworks: ["cis", "nsa"]
    threshold: 7.0

scan:
  timeout: "10m"
  parallel: true
  max_concurrency: 3

output:
  format: "table"
  redact_sensitive: true
```

## 🔧 Development

### Build Commands
```bash
# Build for development (with debug symbols)
make dev

# Run tests
make test

# Validate code
make validate

# Clean build artifacts
make clean
```

### Project Structure
```
kubesec/
├── cmd/kubesec/          # Main entry point
├── internal/
│   ├── cli/              # CLI commands
│   ├── config/           # Configuration management
│   ├── scanner/          # Scanner orchestration
│   ├── tools/            # Tool wrappers
│   └── types/            # Type definitions
├── pkg/
│   └── output/           # Output formatters
└── Makefile              # Build automation
```

## 🎯 MVP Goals

This MVP demonstrates:
1. **Working CLI** that scans real Kubernetes clusters
2. **Tool Integration** with Trivy and Kubescape
3. **Unified Output** in multiple formats
4. **CRD Support** for modern Kubernetes environments
5. **Foundation** for full tool ecosystem

## 🔮 Roadmap

### v1.0 (Next)
- [ ] Embedded tool binaries (no external dependencies)
- [ ] kube-bench integration (CIS compliance)
- [ ] RBAC analysis tools
- [ ] Polaris integration (best practices)
- [ ] SARIF output format
- [ ] Comprehensive test suite

### v1.1
- [ ] Runtime security (Falco integration)
- [ ] Policy enforcement analysis (OPA/Gatekeeper)
- [ ] Advanced CRD security rules
- [ ] Performance optimizations

### v2.0
- [ ] MCP server implementation
- [ ] Web UI for report viewing
- [ ] Historical trend analysis
- [ ] Custom rule engine

## 🤝 Contributing

This is an MVP implementation. Focus areas for contribution:
1. Testing against diverse cluster environments
2. Additional tool integrations
3. Output format improvements
4. Performance optimizations

## 📄 License

Apache 2.0 License - see LICENSE file for details.

---

**Note**: This is a proof-of-concept implementation demonstrating the KubeSec architecture and core functionality. Production use requires additional hardening and testing.