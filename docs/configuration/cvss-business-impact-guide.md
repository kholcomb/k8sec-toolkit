# CVSS Business Impact Configuration Guide

## Overview

The K8Sec Toolkit implements a CVSS-style business impact scoring system that allows organizations to customize risk assessment based on their specific business context, compliance requirements, and risk tolerance.

**Current Status**: The CVSS business impact data structures and scoring algorithms are fully implemented. Configuration management via CLI commands is planned for future releases.

This guide provides comprehensive instructions for configuring and optimizing the scoring system for your organization.

## Table of Contents

- [Quick Start](#quick-start)
- [Understanding CVSS Business Impact](#understanding-cvss-business-impact)
- [Configuration Options](#configuration-options)
- [Organizational Templates](#organizational-templates)
- [Best Practices](#best-practices)
- [Validation and Testing](#validation-and-testing)
- [Migration Guide](#migration-guide)

## Quick Start

### Default Configuration

The system comes with sensible defaults that work for most organizations:

```json
{
  "base_weight": 1.0,
  "temporal_weight": 1.0,
  "environmental_weight": 1.0,
  "custom_weights": {},
  "low_threshold": 3.9,
  "medium_threshold": 6.9,
  "high_threshold": 8.9,
  "critical_threshold": 10.0
}
```

### Basic Customization

To get started with customization, create a configuration file:

```bash
# Create configuration directory
mkdir -p ~/.k8sec/config

# Create basic configuration
cat > ~/.k8sec/config/business-impact.json << EOF
{
  "environmental_weight": 1.2,
  "custom_weights": {
    "BF:CRITICAL": 1.8,
    "DC:CONFIDENTIAL": 1.6
  },
  "critical_threshold": 9.0
}
EOF

# Apply configuration (PLANNED - CLI config management not yet implemented)
k8sec-toolkit config set business-impact ~/.k8sec/config/business-impact.json
```

**Note**: CLI configuration commands are planned for future releases. Currently, CVSS configurations can be applied programmatically using the Go API.

## Understanding CVSS Business Impact

### Scoring Formula

The business impact score is calculated using a three-layer approach:

```
Final Score = Base Score × Temporal Multiplier × Environmental Multiplier

Where:
- Base Score: Standard CVSS 3.1 calculation (0-10)
- Temporal Multiplier: Product of temporal metrics (0.91-1.0)
- Environmental Multiplier: Average of business metrics (0.5-2.0)
```

### Score Components

#### 1. Base Score (Technical Risk)

Calculated using standard CVSS 3.1 methodology:

- Attack Vector (Network, Adjacent, Local, Physical)
- Attack Complexity (Low, High)
- Privileges Required (None, Low, High)
- User Interaction (None, Required)
- Scope (Unchanged, Changed)
- Impact on Confidentiality, Integrity, Availability

#### 2. Temporal Score (Exploit Context)

Adjusts base score based on exploit maturity and remediation:

- Exploit Code Maturity
- Remediation Level
- Report Confidence

#### 3. Environmental Score (Business Context)

Customizes score based on organizational factors:

- Business Function Criticality
- Data Classification Level
- Compliance Requirements
- Business Continuity Impact

## Configuration Options

### Weight Multipliers

#### Base Weight

Controls the influence of technical CVSS factors.

```json
{
  "base_weight": 1.5  // Increase technical risk importance
}
```

**Recommended Values:**

- `0.8`: De-emphasize technical factors
- `1.0`: Default balanced approach
- `1.2`: Emphasize technical factors
- `1.5+`: High-security environments

#### Temporal Weight

Controls the influence of exploit maturity and remediation factors.

```json
{
  "temporal_weight": 0.9  // Slightly reduce temporal influence
}
```

**Use Cases:**

- `0.8`: Focus on inherent risk over exploit status
- `1.0`: Balanced approach (default)
- `1.2`: Emphasize current exploit landscape

#### Environmental Weight

Controls the influence of business context factors.

```json
{
  "environmental_weight": 1.3  // Increase business context importance
}
```

**Recommended Values:**

- `0.8`: Technical-focused assessment
- `1.0`: Balanced assessment (default)
- `1.5`: Business-focused assessment
- `2.0`: Maximum business context emphasis

### Custom Metric Weights

Override default values for specific metrics:

```json
{
  "custom_weights": {
    // Base metrics
    "AV:NETWORK": 0.9,
    "AC:LOW": 0.8,
    "PR:NONE": 0.95,

    // Environmental metrics
    "BF:MISSION_CRITICAL": 2.5,
    "DC:RESTRICTED": 2.2,
    "CR:REGULATED": 1.8,
    "BC:CRITICAL": 2.0
  }
}
```

### Threshold Configuration

Customize severity level boundaries:

```json
{
  "low_threshold": 2.5,      // 0.0-2.5 = Low
  "medium_threshold": 5.5,   // 2.6-5.5 = Medium
  "high_threshold": 7.5,     // 5.6-7.5 = High
  "critical_threshold": 9.0  // 7.6-10.0 = Critical
}
```

## Organizational Templates

### Financial Services

Optimized for financial institutions with strict compliance requirements:

```json
{
  "base_weight": 1.2,
  "temporal_weight": 1.1,
  "environmental_weight": 1.8,
  "custom_weights": {
    "AV:NETWORK": 0.95,
    "S:CHANGED": 1.15,
    "C:HIGH": 0.7,
    "I:HIGH": 0.7,
    "A:HIGH": 0.5,
    "BF:MISSION_CRITICAL": 2.5,
    "BF:CRITICAL": 2.0,
    "DC:RESTRICTED": 2.5,
    "DC:CONFIDENTIAL": 2.0,
    "CR:REGULATED": 2.0,
    "BC:CRITICAL": 2.2
  },
  "low_threshold": 2.0,
  "medium_threshold": 4.5,
  "high_threshold": 7.0,
  "critical_threshold": 8.5
}
```

### Healthcare (HIPAA)

Configured for healthcare organizations handling PHI:

```json
{
  "base_weight": 1.0,
  "temporal_weight": 1.0,
  "environmental_weight": 2.0,
  "custom_weights": {
    "C:HIGH": 0.8,
    "C:LOW": 0.3,
    "I:HIGH": 0.7,
    "A:HIGH": 0.4,
    "BF:CRITICAL": 2.2,
    "DC:RESTRICTED": 2.8,
    "DC:CONFIDENTIAL": 2.0,
    "CR:REGULATED": 2.2,
    "BC:HIGH": 1.5,
    "BC:CRITICAL": 2.0
  },
  "low_threshold": 2.5,
  "medium_threshold": 5.0,
  "high_threshold": 7.0,
  "critical_threshold": 8.5
}
```

### Technology Startup

Balanced approach for agile development environments:

```json
{
  "base_weight": 1.1,
  "temporal_weight": 1.2,
  "environmental_weight": 1.0,
  "custom_weights": {
    "E:HIGH": 1.1,
    "RL:UNAVAILABLE": 1.2,
    "BF:CRITICAL": 1.8,
    "DC:CONFIDENTIAL": 1.5,
    "CR:STANDARD": 1.1,
    "BC:HIGH": 1.4
  },
  "low_threshold": 4.0,
  "medium_threshold": 7.0,
  "high_threshold": 8.5,
  "critical_threshold": 9.5
}
```

### Government/Defense

High-security configuration for sensitive environments:

```json
{
  "base_weight": 1.3,
  "temporal_weight": 1.1,
  "environmental_weight": 1.5,
  "custom_weights": {
    "AV:NETWORK": 1.0,
    "PR:NONE": 1.0,
    "S:CHANGED": 1.2,
    "C:HIGH": 0.8,
    "I:HIGH": 0.8,
    "A:HIGH": 0.6,
    "E:HIGH": 1.1,
    "BF:MISSION_CRITICAL": 2.8,
    "BF:CRITICAL": 2.3,
    "DC:RESTRICTED": 3.0,
    "DC:CONFIDENTIAL": 2.5,
    "CR:REGULATED": 2.5,
    "BC:CRITICAL": 2.5
  },
  "low_threshold": 1.5,
  "medium_threshold": 4.0,
  "high_threshold": 6.5,
  "critical_threshold": 8.0
}
```

### E-commerce/Retail

Optimized for customer-facing applications with PCI requirements:

```json
{
  "base_weight": 1.0,
  "temporal_weight": 1.1,
  "environmental_weight": 1.4,
  "custom_weights": {
    "AV:NETWORK": 0.95,
    "A:HIGH": 0.7,
    "BF:CRITICAL": 2.0,
    "BF:OPERATIONAL": 1.2,
    "DC:CONFIDENTIAL": 2.2,
    "DC:INTERNAL": 1.1,
    "CR:REGULATED": 1.8,
    "BC:HIGH": 1.6,
    "BC:CRITICAL": 2.0
  },
  "low_threshold": 3.5,
  "medium_threshold": 6.5,
  "high_threshold": 8.0,
  "critical_threshold": 9.0
}
```

## Best Practices

### 1. Start with Industry Template

Begin with a template closest to your industry rather than the default configuration.

### 2. Gradual Customization

Implement changes incrementally:

1. **Week 1**: Apply industry template
2. **Week 2**: Adjust environmental weight based on initial results
3. **Week 3**: Customize business function weights
4. **Week 4**: Fine-tune thresholds based on alert volume

### 3. Validation Against Known Scenarios

Test configuration against known security incidents:

```bash
# Test with historical findings (PLANNED)
k8sec-toolkit analyze --config custom-config.json --findings historical-findings.json

# Compare scores with expected business impact (PLANNED)
k8sec-toolkit validate-config --config custom-config.json --test-cases validation-cases.json
```

**Note**: CLI validation commands are planned for future releases. Currently, validation can be performed using the Go API with test data.

### 4. Regular Review and Adjustment

Schedule quarterly reviews:

- Analyze score distribution vs. actual business impact
- Adjust weights based on incident response data
- Update thresholds based on security team capacity

### 5. Document Rationale

Maintain documentation for all customizations:

```json
{
  "_metadata": {
    "organization": "Acme Corp",
    "industry": "Financial Services",
    "compliance_frameworks": ["SOX", "PCI-DSS"],
    "last_updated": "2023-12-24",
    "rationale": {
      "environmental_weight": "Increased to 1.8 due to strict compliance requirements",
      "critical_threshold": "Lowered to 8.5 to increase sensitivity for regulatory findings"
    }
  },
  "base_weight": 1.2,
  "environmental_weight": 1.8,
  "critical_threshold": 8.5
}
```

## Validation and Testing

### Configuration Validation

```bash
# Validate configuration syntax and ranges (PLANNED)
k8sec-toolkit config validate business-impact.json

# Test against sample findings (PLANNED)
k8sec-toolkit config test business-impact.json --sample-findings sample.json

# Generate score distribution report (PLANNED)
k8sec-toolkit config analyze business-impact.json --historical-data findings-30days.json
```

**Note**: All CLI configuration commands are planned for future releases. Currently implemented:

- CVSS scoring algorithms and data structures
- Programmatic configuration via Go API
- Business impact analysis logic

### A/B Testing

Compare configurations with historical data:

```bash
# Compare default vs. custom configuration
k8sec-toolkit compare-configs \
  --config-a default \
  --config-b custom-config.json \
  --findings historical-findings.json \
  --output comparison-report.json
```

### Score Distribution Analysis

```bash
# Analyze score distribution
k8sec-toolkit analyze-distribution \
  --config custom-config.json \
  --findings findings.json \
  --output distribution-analysis.json
```

Expected output:

```json
{
  "score_distribution": {
    "low": 45,
    "medium": 32,
    "high": 18,
    "critical": 5
  },
  "recommendations": [
    "Consider lowering high_threshold to 7.0 to better distribute findings",
    "Environmental weight may be too high - 23% of findings are critical"
  ]
}
```

## Migration Guide

### From Basic to CVSS Business Impact

1. **Export Current Configuration**:

```bash
k8sec-toolkit config export --format json > current-config.json
```

2. **Create CVSS Configuration**:

```bash
k8sec-toolkit config migrate \
  --from current-config.json \
  --to cvss-business-impact \
  --output migrated-config.json
```

3. **Test Migration**:

```bash
k8sec-toolkit config test migrated-config.json \
  --compare-with current-config.json \
  --findings test-findings.json
```

4. **Gradual Rollout**:

```bash
# Phase 1: Test environment
k8sec-toolkit config apply migrated-config.json --environment test

# Phase 2: Staging environment
k8sec-toolkit config apply migrated-config.json --environment staging

# Phase 3: Production environment
k8sec-toolkit config apply migrated-config.json --environment production
```

### Backward Compatibility

Maintain backward compatibility during transition:

```json
{
  "version": "2.0",
  "backward_compatibility": {
    "enabled": true,
    "fallback_to_simple_scoring": true,
    "migration_period_days": 30
  },
  "cvss_business_impact": {
    "base_weight": 1.2,
    "environmental_weight": 1.5
  }
}
```

## Troubleshooting

### Common Issues

#### Issue: All scores are too high/low

**Solution**: Adjust base thresholds rather than weights:

```json
{
  "low_threshold": 4.5,      // Increase if scores too high
  "medium_threshold": 7.0,
  "high_threshold": 8.5,
  "critical_threshold": 9.5
}
```

#### Issue: Business context not reflected in scores

**Solution**: Increase environmental weight and customize business metrics:

```json
{
  "environmental_weight": 1.8,
  "custom_weights": {
    "BF:MISSION_CRITICAL": 2.5,
    "DC:RESTRICTED": 2.2
  }
}
```

#### Issue: Too many critical alerts

**Solution**: Raise critical threshold or adjust weights:

```json
{
  "critical_threshold": 9.2,
  "custom_weights": {
    "BF:CRITICAL": 1.8  // Reduce from default 2.0
  }
}
```

### Debug Mode

Enable detailed scoring information:

```bash
k8sec-toolkit scan --debug-scoring --output-format detailed-json
```

Output includes:

- Individual metric values
- Intermediate score calculations
- Weight applications
- Final score breakdown

### Logging Configuration

```json
{
  "logging": {
    "level": "debug",
    "include_scoring_details": true,
    "log_file": "/var/log/k8sec/scoring.log"
  }
}
```

## Advanced Configuration

### Dynamic Weight Adjustment

Implement time-based weight adjustments:

```json
{
  "dynamic_weights": {
    "enabled": true,
    "rules": [
      {
        "condition": "time_of_day >= 18:00 OR time_of_day <= 06:00",
        "weight_multiplier": 0.8,
        "reason": "Reduced impact during off-hours"
      },
      {
        "condition": "day_of_week IN ['Saturday', 'Sunday']",
        "weight_multiplier": 0.7,
        "reason": "Lower business impact on weekends"
      }
    ]
  }
}
```

### Context-Aware Scoring

Adjust scores based on deployment context:

```json
{
  "context_rules": [
    {
      "condition": "namespace == 'production'",
      "weight_multiplier": 1.5
    },
    {
      "condition": "labels.contains('public-facing')",
      "custom_weights": {
        "AV:NETWORK": 1.0,
        "BF:CRITICAL": 2.0
      }
    }
  ]
}
```

### Integration with External Systems

```json
{
  "external_integrations": {
    "cmdb": {
      "enabled": true,
      "endpoint": "https://cmdb.company.com/api/v1/assets",
      "asset_criticality_mapping": true
    },
    "threat_intelligence": {
      "enabled": true,
      "providers": ["vendor1", "vendor2"],
      "exploit_maturity_updates": true
    }
  }
}
```

## Support and Resources

### Documentation

- [CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [NIST Risk Management Framework](https://csrc.nist.gov/projects/risk-management)
- [K8Sec Toolkit API Reference](../api/executive-summary.md)

### Community

- GitHub Issues: Report configuration problems
- Slack Channel: #k8sec-toolkit-config
- Monthly Office Hours: Configuration best practices

### Professional Services

- Configuration audit and optimization
- Custom industry template development
- Training and workshops

For additional support, contact: <support@k8sec-toolkit.com>
