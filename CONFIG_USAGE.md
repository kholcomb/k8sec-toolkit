# k8sec-toolkit Configuration Management

The `k8sec-toolkit config` command provides comprehensive configuration management with support for multiple profiles and hierarchical configuration.

## Features

- **Multi-profile support**: dev, prod, and audit profiles with different security settings
- **Hierarchical configuration**: Global settings and profile-specific overrides
- **Type-aware value setting**: Automatic detection of arrays, booleans, numbers, and strings
- **Validation**: Comprehensive validation of all configuration values
- **Secure defaults**: Appropriate security settings for each profile

## Configuration File Location

Configuration is stored in `~/.k8sec-toolkit/config.yaml`

## Available Commands

### Initialize Configuration

```bash
# Create a new configuration file with default profiles
k8sec-toolkit config init

# Overwrite existing configuration
k8sec-toolkit config init --force
```

### View Configuration

```bash
# View current configuration (default profile: dev)
k8sec-toolkit config view

# View specific profile
k8sec-toolkit config view --profile prod
k8sec-toolkit config view --profile audit
```

### Set Configuration Values

```bash
# Set profile-specific values
k8sec-toolkit config set tools.trivy.format table
k8sec-toolkit config set scan.max_concurrency 5
k8sec-toolkit config set scan.parallel false
k8sec-toolkit config set tools.kubescape.threshold 8.5

# Set array values (comma-separated)
k8sec-toolkit config set tools.enabled "trivy,kubescape,polaris"
k8sec-toolkit config set tools.trivy.severity "CRITICAL,HIGH"

# Set global values (applies to all profiles)
k8sec-toolkit config set --global context production-cluster
k8sec-toolkit config set --global kubeconfig /path/to/kubeconfig
```

### Get Configuration Values

```bash
# Get profile-specific values
k8sec-toolkit config get tools.trivy.format
k8sec-toolkit config get scan.max_concurrency

# Get global values
k8sec-toolkit config get context
```

### Validate Configuration

```bash
# Validate all profiles
k8sec-toolkit config validate
```

## Profile Descriptions

### Development Profile (`dev`)

- **Purpose**: Local development and testing
- **Security Level**: Relaxed
- **Tools**: Basic set (trivy, kubescape)
- **Timeouts**: Shorter for faster feedback
- **Concurrency**: Lower to avoid resource conflicts

### Production Profile (`prod`)

- **Purpose**: Production environment scanning
- **Security Level**: Comprehensive
- **Tools**: All security tools enabled
- **Timeouts**: Longer for thorough analysis
- **Verification**: Tool checksum verification enabled

### Audit Profile (`audit`)

- **Purpose**: Compliance and audit requirements
- **Security Level**: Maximum
- **Tools**: All tools with strictest settings
- **Thresholds**: Lowest tolerance for issues
- **Compliance**: Includes SOC2, PCI frameworks

## Configuration Hierarchy

Configuration values are resolved in this order (highest to lowest priority):

1. Command-line flags
2. Environment variables
3. Global configuration section
4. Profile-specific configuration
5. Built-in defaults

## Example Configuration Structure

```yaml
global:
  context: ""
  kubeconfig: ""

profiles:
  dev:
    tools:
      enabled: ["trivy", "kubescape"]
      trivy:
        severity: ["CRITICAL", "HIGH"]
        timeout: "3m"
        format: "json"
      kubescape:
        frameworks: ["NSA"]
        threshold: 8.0
    scan:
      timeout: "5m"
      max_concurrency: 2
      parallel: true
    output:
      format: "table"
      redact_sensitive: true
    security:
      verify_tool_checksums: false
      cleanup_on_exit: true

  prod:
    tools:
      enabled: ["trivy", "kubescape", "kube-bench", "rbac", "polaris"]
      kubescape:
        threshold: 6.0
        frameworks: ["NSA", "MITRE", "CIS"]
    scan:
      timeout: "15m"
      max_concurrency: 4
    security:
      verify_tool_checksums: true

  audit:
    tools:
      kubescape:
        threshold: 4.0
        frameworks: ["NSA", "MITRE", "CIS", "SOC2", "PCI"]
    scan:
      timeout: "30m"
      max_concurrency: 6
      failure_threshold: 0.1
    output:
      format: "json"
      include_raw_results: true
      redact_sensitive: false
```

## Common Configuration Keys

### Tool Configuration

- `tools.enabled`: Array of enabled tools
- `tools.trivy.severity`: Array of severity levels to report
- `tools.trivy.timeout`: Scan timeout duration
- `tools.kubescape.threshold`: Risk score threshold (0-10)
- `tools.kubescape.frameworks`: Compliance frameworks to check

### Scan Configuration

- `scan.timeout`: Overall scan timeout
- `scan.max_concurrency`: Maximum concurrent tool executions
- `scan.parallel`: Enable/disable parallel scanning
- `scan.retry_attempts`: Number of retry attempts for failed scans

### Output Configuration

- `output.format`: Output format (table, json, yaml, summary)
- `output.include_raw_results`: Include raw tool outputs
- `output.redact_sensitive`: Redact sensitive information

### Security Configuration

- `security.verify_tool_checksums`: Verify tool binary checksums
- `security.cleanup_on_exit`: Clean up temporary files
- `security.temp_dir`: Temporary directory for tool operations

## Security Considerations

1. **File Permissions**: Configuration file is created with 0600 permissions (owner read/write only)
2. **Input Validation**: All configuration values are validated before use
3. **Path Sanitization**: File paths are validated to prevent directory traversal
4. **Tool Verification**: Optional checksum verification for tool binaries
5. **Sensitive Data**: Option to redact sensitive information from outputs

## Troubleshooting

### Configuration Not Found

```bash
Error: configuration file not found. Run 'k8sec-toolkit config init' to create one
```

**Solution**: Initialize configuration with `k8sec-toolkit config init`

### Invalid Profile

```bash
Error: invalid profile: xyz (valid profiles: dev, prod, audit)
```

**Solution**: Use a valid profile name: `dev`, `prod`, or `audit`

### Validation Errors

```bash
Error: configuration validation failed: invalid output format: xyz
```

**Solution**: Check configuration values against valid options and fix invalid entries

### Permission Errors

```bash
Error: failed to write configuration file: permission denied
```

**Solution**: Ensure you have write permissions to `~/.k8sec-toolkit/` directory
