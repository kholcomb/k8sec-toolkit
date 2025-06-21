# Executive Summary API Documentation

## Overview

The K8Sec Toolkit provides comprehensive executive summary capabilities designed for dashboard integration and executive reporting. This API documentation covers the data structures, scoring algorithms, and integration patterns for consuming executive-level security insights.

## Table of Contents

- [Data Structures](#data-structures)
- [Risk Scoring](#risk-scoring)
- [CVSS Business Impact](#cvss-business-impact)
- [API Endpoints](#api-endpoints)
- [Integration Examples](#integration-examples)
- [Configuration](#configuration)

## Data Structures

### ExecutiveSummary

The core executive summary data structure optimized for dashboard consumption.

```json
{
  "security_posture": "fair",
  "risk_score": 67.5,
  "business_impact": "high",
  "compliance_score": 82.3,
  "trend_direction": "degrading",

  "critical_findings": 3,
  "high_findings": 12,
  "total_findings": 45,
  "remediation_effort": "High",
  "time_to_remediate": "2-4 weeks",

  "risk_distribution": {
    "infrastructure": 25.5,
    "applications": 35.2,
    "configuration": 18.7,
    "access_control": 12.1,
    "network_security": 5.8,
    "data_protection": 2.7
  },

  "top_risks": [
    {
      "id": "risk-001",
      "title": "Critical Remote Code Execution Vulnerability",
      "description": "Log4j vulnerability allowing remote code execution",
      "impact": "critical",
      "probability": "high",
      "risk_score": 95.2,
      "category": "applications",
      "affected_assets": 8,
      "estimated_cost": "$500K - $2M+",
      "time_to_exploit": "Minutes to Hours",
      "recommended_action": "Update to Log4j 2.15.0 immediately"
    }
  ],

  "critical_assets": [
    {
      "name": "payment-service",
      "type": "Deployment",
      "namespace": "production",
      "criticality_level": "Critical",
      "vulnerability_count": 2,
      "misconfig_count": 1,
      "risk_score": 87.3,
      "business_function": "Financial Services",
      "data_classification": "PCI"
    }
  ],

  "immediate_actions": [
    {
      "id": "action-001",
      "title": "Update Log4j to 2.15.0",
      "description": "Critical security update for Log4j vulnerability",
      "priority": "Critical",
      "category": "Patch",
      "estimated_effort": "2-4 hours",
      "business_value": "High - Prevents potential security breach",
      "due_date": "2023-12-25T00:00:00Z",
      "implementation_steps": [
        "1. Create maintenance window",
        "2. Backup current configuration",
        "3. Update to Log4j 2.15.0",
        "4. Validate functionality",
        "5. Confirm vulnerability resolution"
      ]
    }
  ],

  "quick_wins": [],
  "long_term_strategy": [],

  "last_scan_time": "2023-12-24T10:00:00Z",
  "previous_score": 62.1,
  "score_change": 5.4,
  "new_findings": 3,
  "resolved_findings": 1
}
```

### Field Descriptions

#### Security Metrics

- `security_posture`: Overall security assessment (`excellent`, `good`, `fair`, `poor`, `critical`)
- `risk_score`: Numerical risk score (0-100 scale)
- `business_impact`: Business impact level (`low`, `medium`, `high`, `critical`)
- `compliance_score`: Compliance assessment score (0-100 scale)
- `trend_direction`: Security trend (`improving`, `stable`, `degrading`)

#### Finding Counts

- `critical_findings`: Number of critical severity findings
- `high_findings`: Number of high severity findings
- `total_findings`: Total number of security findings
- `remediation_effort`: Overall effort required (`Low`, `Medium`, `High`)
- `time_to_remediate`: Estimated time to address critical issues

#### Risk Analysis

- `risk_distribution`: Percentage breakdown of risk by category
- `top_risks`: Array of highest priority risks (max 10)
- `critical_assets`: Array of most critical assets requiring attention (max 20)

#### Action Planning

- `immediate_actions`: Critical actions requiring immediate attention (max 5)
- `quick_wins`: Actions with high value and low effort (max 8)
- `long_term_strategy`: Strategic improvements for long-term security (max 10)

#### Trend Analysis

- `last_scan_time`: Timestamp of current scan
- `previous_score`: Risk score from previous scan
- `score_change`: Change in risk score (positive = worse)
- `new_findings`: Count of new findings since last scan
- `resolved_findings`: Count of findings resolved since last scan

## Risk Scoring

### Risk Score Calculation

The risk scoring algorithm considers multiple factors:

```
Risk Score = Σ(finding_risk) / max_possible_risk * 100

Where finding_risk = severity_weight × type_weight × asset_weight × exposure_multiplier × cvss_bonus × age_multiplier
```

#### Weight Factors

**Severity Weights:**

- `CRITICAL`: 10.0
- `HIGH`: 7.5
- `MEDIUM`: 5.0
- `LOW`: 2.5
- `INFO`: 1.0

**Type Weights:**

- `vulnerability`: 1.0
- `rbac`: 0.9
- `misconfiguration`: 0.8
- `compliance`: 0.6
- `best-practice`: 0.4

**Asset Weights:**

- `Secret`: 1.4
- `Ingress`: 1.3
- `Deployment`: 1.2
- `StatefulSet`: 1.2
- `ClusterRole`: 1.1
- `DaemonSet`: 1.1
- `Pod`: 1.0
- `ServiceAccount`: 0.9
- `PersistentVolume`: 0.9
- `Service`: 0.8
- `Role`: 0.8
- `NetworkPolicy`: 0.7
- `ConfigMap`: 0.6

**Exposure Multiplier:** 1.5x for internet-exposed resources

**Age Decay Factor:** 0.95 daily decay (newer findings weighted higher)

### Security Posture Mapping

| Risk Score Range | Security Posture | Description |
|------------------|------------------|-------------|
| 0-29            | `excellent`      | Strong security posture |
| 30-59           | `good`           | Generally secure with minor issues |
| 60-79           | `fair`           | Moderate security concerns |
| 80-89           | `poor`           | Significant security risks |
| 90-100          | `critical`       | Immediate action required |

## CVSS Business Impact

### Overview

The CVSS Business Impact system provides industry-standard risk assessment with organizational customization, similar to the NIST Common Vulnerability Scoring System (CVSS) but adapted for business impact analysis.

### Vector String Format

```
CVSS:3.1/AV:NETWORK/AC:LOW/PR:NONE/UI:NONE/S:CHANGED/C:HIGH/I:HIGH/A:HIGH/E:HIGH/RL:OFFICIAL_FIX/RC:CONFIRMED/BF:CRITICAL/DC:CONFIDENTIAL/CR:REGULATED/BC:CRITICAL
```

### Metric Categories

#### Base Metrics (Required)

- **AV (Attack Vector)**: `NETWORK`, `ADJACENT`, `LOCAL`, `PHYSICAL`
- **AC (Attack Complexity)**: `LOW`, `HIGH`
- **PR (Privileges Required)**: `NONE`, `LOW`, `HIGH`
- **UI (User Interaction)**: `NONE`, `REQUIRED`
- **S (Scope)**: `UNCHANGED`, `CHANGED`
- **C (Confidentiality Impact)**: `NONE`, `LOW`, `HIGH`
- **I (Integrity Impact)**: `NONE`, `LOW`, `HIGH`
- **A (Availability Impact)**: `NONE`, `LOW`, `HIGH`

#### Temporal Metrics (Optional)

- **E (Exploit Code Maturity)**: `NOT_DEFINED`, `UNPROVEN`, `PROOF_CONCEPT`, `FUNCTIONAL`, `HIGH`
- **RL (Remediation Level)**: `NOT_DEFINED`, `OFFICIAL_FIX`, `TEMPORARY_FIX`, `WORKAROUND`, `UNAVAILABLE`
- **RC (Report Confidence)**: `NOT_DEFINED`, `UNKNOWN`, `REASONABLE`, `CONFIRMED`

#### Environmental Metrics (Business Context)

- **BF (Business Function)**: `NOT_DEFINED`, `SUPPORTING`, `OPERATIONAL`, `CRITICAL`, `MISSION_CRITICAL`
- **DC (Data Classification)**: `NOT_DEFINED`, `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`
- **CR (Compliance Requirement)**: `NOT_DEFINED`, `NONE`, `STANDARD`, `REGULATED`
- **BC (Business Continuity)**: `NOT_DEFINED`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### Score Calculation

```
Environmental Score = Base Score × Temporal Multiplier × Environmental Multiplier

Where:
- Base Score: CVSS 3.1 base score calculation
- Temporal Multiplier: Product of temporal metric values
- Environmental Multiplier: Average of environmental metric values
```

### Business Impact Levels

| Score Range | Business Impact | Description |
|-------------|----------------|-------------|
| 0.0-3.9     | `low`          | Minimal business impact |
| 4.0-6.9     | `medium`       | Moderate business impact |
| 7.0-8.9     | `high`         | Significant business impact |
| 9.0-10.0    | `critical`     | Severe business impact |

## API Endpoints

**Note**: The API endpoints described below represent the planned API server integration. Currently, the executive summary capabilities are implemented as Go packages and data structures for integration with external systems. The HTTP API server is planned for future releases.

### Planned: GET /api/v1/scan/{scan-id}/executive-summary

Returns the executive summary for a specific scan.

**Response:**

```json
{
  "scan_id": "scan-12345",
  "cluster_context": "production-cluster",
  "executive_summary": {
    // ExecutiveSummary object
  }
}
```

### Planned: GET /api/v1/clusters/{cluster-id}/executive-summary

Returns the latest executive summary for a cluster.

**Query Parameters:**

- `include_history`: Include trend data from previous scans
- `risk_threshold`: Filter findings above specified risk threshold

### Planned: POST /api/v1/executive-summary/custom

Generate executive summary with custom CVSS configuration.

**Request Body:**

```json
{
  "findings": [],
  "cluster_info": {},
  "cvss_config": {
    "base_weight": 1.5,
    "environmental_weight": 1.2,
    "custom_weights": {
      "BF:CRITICAL": 2.5,
      "DC:RESTRICTED": 2.0
    }
  }
}
```

## Integration Examples

### Grafana Dashboard Integration

```javascript
// Grafana JSON Data Source Query
{
  "targets": [
    {
      "url": "/api/v1/clusters/prod/executive-summary",
      "method": "GET"
    }
  ],
  "dashboard": {
    "panels": [
      {
        "title": "Security Posture",
        "type": "stat",
        "targets": [
          {
            "expr": "executive_summary.security_posture"
          }
        ]
      },
      {
        "title": "Risk Score Trend",
        "type": "timeseries",
        "targets": [
          {
            "expr": "executive_summary.risk_score"
          }
        ]
      }
    ]
  }
}
```

### Power BI Integration

```json
{
  "dataSource": {
    "type": "web",
    "url": "https://k8sec-api.company.com/api/v1/executive-summary",
    "headers": {
      "Authorization": "Bearer ${token}"
    }
  },
  "transformations": [
    {
      "type": "expand",
      "column": "executive_summary.risk_distribution"
    }
  ]
}
```

### Tableau Integration

```sql
-- Custom SQL Connector
SELECT
  scan_time,
  risk_score,
  security_posture,
  critical_findings,
  high_findings,
  total_findings
FROM k8sec_executive_summaries
WHERE cluster_id = 'production'
ORDER BY scan_time DESC
```

### Generic HTTP API Consumer

```python
import requests
import json

def get_executive_summary(cluster_id, api_key):
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }

    response = requests.get(
        f'https://api.k8sec.company.com/v1/clusters/{cluster_id}/executive-summary',
        headers=headers
    )

    if response.status_code == 200:
        return response.json()['executive_summary']
    else:
        raise Exception(f'API Error: {response.status_code}')

# Usage
summary = get_executive_summary('production-cluster', 'your-api-key')
print(f"Risk Score: {summary['risk_score']}")
print(f"Security Posture: {summary['security_posture']}")
```

## Configuration

### Default CVSS Configuration

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

### Organizational Customization Example

```json
{
  "base_weight": 1.2,
  "temporal_weight": 0.9,
  "environmental_weight": 1.5,
  "custom_weights": {
    "AV:NETWORK": 0.9,
    "BF:MISSION_CRITICAL": 2.5,
    "DC:RESTRICTED": 2.2,
    "CR:REGULATED": 1.8,
    "BC:CRITICAL": 2.0
  },
  "low_threshold": 2.5,
  "medium_threshold": 5.5,
  "high_threshold": 7.5,
  "critical_threshold": 9.0
}
```

### Risk Scorer Configuration

```json
{
  "severity_weights": {
    "CRITICAL": 12.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 1.0
  },
  "exposure_multiplier": 2.0,
  "age_decay_factor": 0.92
}
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_CONFIGURATION",
    "message": "Custom weight values must be between 0.0 and 10.0",
    "details": {
      "field": "custom_weights.BF:CRITICAL",
      "value": 15.0,
      "max_allowed": 10.0
    }
  }
}
```

### Common Error Codes

- `INVALID_CONFIGURATION`: Configuration validation failed
- `SCAN_NOT_FOUND`: Requested scan ID does not exist
- `CLUSTER_NOT_FOUND`: Requested cluster ID does not exist
- `INSUFFICIENT_DATA`: Not enough data for trend analysis
- `CALCULATION_ERROR`: Error during risk score calculation

## Performance Considerations

### Response Times

- Executive summary generation: < 2 seconds for 1000 findings
- API response time: < 500ms for cached results
- Dashboard refresh rate: Recommended 5-15 minutes

### Data Retention

- Executive summaries: 90 days default retention
- Trend data: 1 year for compliance reporting
- Raw findings: 30 days unless configured otherwise

### Rate Limiting

- API calls: 100 requests per minute per API key
- Bulk operations: 10 requests per minute
- Dashboard integrations: Recommended caching for 5+ minutes

## Security Considerations

### Authentication

- API key authentication required for all endpoints
- JWT tokens supported for interactive access
- Service account authentication for automated integrations

### Data Privacy

- Executive summaries may contain sensitive security information
- Implement appropriate access controls in consuming systems
- Consider data residency requirements for multi-region deployments

### Audit Logging

- All API access logged with timestamp and caller identity
- Executive summary access tracked for compliance
- Retention period configurable (default 1 year)
