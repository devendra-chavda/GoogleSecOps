# Google Chronicle Security Analytic Rules

This directory contains Azure Sentinel Analytic Rules for Google Chronicle Security detections. These rules are designed following Azure Security best practices and create automated incidents for threat detection and response.

## Files

### Analytic Rules

1. **Chronicle-HighSeverityDetectionAlert.yaml**
   - **Severity:** High
   - **Frequency:** Every 5 minutes
   - **Purpose:** Catch-all rule for HIGH/CRITICAL detections
   - **Incident Grouping:** By detection ID (6-hour regroup)
   - **Key Fields:** Risk Score, IP Count, Host Count
   - **Use Case:** General visibility into critical threats

2. **Chronicle-BruteForceAttackDetection.yaml**
   - **Severity:** High
   - **Frequency:** Every 10 minutes
   - **Purpose:** Detect coordinated brute force attacks
   - **Trigger:** Rule contains "brute_force" or "greynoise" + severity HIGH/CRITICAL
   - **Incident Grouping:** By attacking IP (4-hour regroup)
   - **Key Fields:** Attack count, target hosts, affected users
   - **Use Case:** Credential compromise prevention

3. **Chronicle-CredentialAccessAttack.yaml**
   - **Severity:** High
   - **Frequency:** Every 15 minutes
   - **Purpose:** Detect MITRE T1110 (Brute Force) attacks
   - **Trigger:** Credential Access tactic + severity HIGH/CRITICAL
   - **Incident Grouping:** By source IP (6-hour regroup)
   - **Key Fields:** Failure count, target users, attack timeline
   - **Use Case:** Account security monitoring

4. **Chronicle-MultiSourceAttackDetection.yaml**
   - **Severity:** Medium
   - **Frequency:** Every 30 minutes
   - **Purpose:** Detect coordinated multi-source attacks
   - **Trigger:** >3 source IPs OR >2 source hosts
   - **Incident Grouping:** By target hostname (8-hour regroup)
   - **Key Fields:** Attack pattern, source count, risk score
   - **Use Case:** Advanced threat and lateral movement detection

### Documentation

- **ANALYTIC_RULES_GUIDE.md** - Comprehensive guide with:
  - Rule strategy and design rationale
  - Entity mapping and custom details
  - Investigation workflow
  - Alert thresholds and tuning
  - SOAR integration examples
  - Monitoring and metrics

## Quick Start

### 1. Deploy Rules to Azure Sentinel

```bash
# Copy rule files to Sentinel Analytics Rules
# Menu: Analytics > Rule templates
# Search for "Chronicle"
# Import each YAML file
```

Or use Azure CLI:

```powershell
az sentinel analytics-rule create \
  --resource-group <rg-name> \
  --workspace-name <workspace-name> \
  --rule-id <rule-id> \
  --name <rule-name> \
  --properties @rule-file.yaml
```

### 2. Verify Parser Dependency

Ensure the `chronicle_detection` parser is deployed:

```kusto
chronicle_detection
| take 1
```

Should return successful results.

### 3. Enable Rules

1. Go to Azure Sentinel > Analytics
2. Filter by "Chronicle"
3. Enable all 4 rules
4. Review and customize thresholds as needed

### 4. Configure Notifications

For each rule, set up:
- Email notifications
- Slack/Teams alerts
- ITSM ticketing
- Automated response playbooks

---

## Parser Dependency

These rules depend on the Chronicle Detection parser:
- **Parser Name:** `chronicle_detection`
- **Parser File:** `../parsers/chronicle_detection.yaml`
- **Data Source:** `DetectionAlerts_CL`

**Key Parser Fields Used:**

| Field | Type | Used In Rules |
|-------|------|---------------|
| `id` | string | All (incident grouping) |
| `severity` | string | All (filtering) |
| `alertState` | string | All (filtering) |
| `ruleName` | string | Rule 2, 3 |
| `var_correlation_ip` | string | All (entity mapping) |
| `var_principal_ip` | string | All (entity mapping) |
| `var_target_hostname` | string | All (entity mapping) |
| `var_target_user_userid` | string | All (entity mapping) |
| `var_principal_ip_count` | int | Rule 1, 3 |
| `var_source_ip_count` | int | Rule 1, 3 |
| `risk_score` | int | All (custom details) |
| `detectionTime` | datetime | All (custom details) |

---

## Incident Entity Mapping

### IP Address Entities

```
var_correlation_ip     → Malicious IP (from threat intel)
var_principal_ip       → Source IP (attacker)
var_target_ip          → Target IP (victim)
```

### Host Entities

```
var_principal_hostname → Source hostname
var_target_hostname    → Target hostname
```

### Account Entities

```
var_target_user_userid → Targeted user account
```

### URL Entities

```
urlBackToProduct       → Link to Chronicle console
```

---

## Customization Guide

### Adjust Query Frequency

**For high-volume environments:**
```yaml
queryFrequency: 15m  # Increase from 5m
queryPeriod: 15m      # Match frequency
```

**For low-volume environments:**
```yaml
queryFrequency: 30m   # Increase to reduce queries
queryPeriod: 2h       # Keep lookback window
```

### Adjust Thresholds

**Example: Brute Force Rule**

Current: `TotalDetections > 1`

More sensitive:
```kusto
| where TotalDetections > 0  # Catch first attempt
```

Less sensitive:
```kusto
| where TotalDetections > 5  # Only major campaigns
```

### Add Custom Filters

**Example: Exclude internal IPs**

```kusto
| where not(var_correlation_ip startswith "10.")
| where not(var_correlation_ip startswith "172.")
| where not(var_correlation_ip startswith "192.")
```

**Example: Focus on specific rules**

```kusto
| where ruleName has "ransomware" 
   or ruleName has "c2_communication"
```

---

## Monitoring and Tuning

### Key Metrics to Monitor

1. **Alert Volume**
   - Expected: 5-20 alerts per day
   - If >100: Too sensitive, increase thresholds
   - If <1: May miss threats, decrease thresholds

2. **False Positive Rate**
   - Target: <10%
   - Review trend monthly
   - Adjust filters as needed

3. **Time to Detection**
   - Current: 5-30 minutes depending on rule
   - Faster = more query cost
   - Balance cost vs responsiveness

### Health Check Queries

Check rule execution:

```kusto
AzureDiagnostics
| where OperationName == "Analytics Rule Execution"
| where Resource like "*/analytics/*"
| summarize
    ExecutionCount = count(),
    AvgDuration = avg(DurationMs),
    MaxDuration = max(DurationMs)
    by Resource, ResultType
```

---

## SOAR Integration

### Automated Playbook Example

**Trigger:** Chronicle Brute Force Incident Created

**Actions:**
1. Get entity data (IP, hostname, user)
2. Query GreyNoise for IP reputation
3. Check Azure AD for risky sign-ins
4. If confirmed threat:
   - Auto-isolate host
   - Reset compromised passwords
   - Create security incident ticket
   - Notify security team

**Resources:**
- Azure Logic Apps
- Power Automate
- Sentinel Automation Rules

---

## Troubleshooting

### Rule Not Triggering

1. **Check parser dependency**
   ```kusto
   chronicle_detection
   | take 1
   ```

2. **Verify data ingestion**
   ```kusto
   DetectionAlerts_CL
   | where TimeGenerated > ago(1h)
   | count
   ```

3. **Test rule query manually**
   - Copy query from rule
   - Run in Log Analytics
   - Verify results

### Too Many False Positives

1. Increase `triggerThreshold`
2. Add filters: `where risk_score > 50`
3. Exclude known benign IPs
4. Adjust `queryPeriod` to reduce noise

### Alert Fatigue

1. Increase `queryFrequency` (run less often)
2. Adjust grouping periods
3. Use `aggregationKind: SingleAlert` for deduplication
4. Disable low-confidence rules during off-hours

---

## Best Practices

### For SOC Analysts

- ✅ Always verify threat intel before escalating
- ✅ Check detection timeline for context
- ✅ Correlate with other data sources
- ✅ Document investigation findings
- ✅ Update incident status regularly

### For SOC Managers

- ✅ Monitor rule effectiveness monthly
- ✅ Track MTTR (mean time to resolution)
- ✅ Review false positive trends
- ✅ Adjust thresholds quarterly
- ✅ Plan capacity based on alert volume

### For Security Engineers

- ✅ Keep threat intel feeds updated
- ✅ Maintain IP blocklists
- ✅ Review MITRE mappings annually
- ✅ Update detection logic as threats evolve
- ✅ Document custom modifications

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-27 | Initial release |

---

## Support and Feedback

For issues or improvements:
1. Check ANALYTIC_RULES_GUIDE.md for detailed info
2. Review parser configuration
3. Test queries in Log Analytics
4. Contact security team for tuning
