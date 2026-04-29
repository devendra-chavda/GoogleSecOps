# Google Chronicle Security Analytic Rules Guide

## Overview

This guide explains the Analytic Rules created for Google Chronicle Security detections in Azure Sentinel. These rules follow Azure Security best practices and create actionable incidents for security analysts.

---

## Rules Summary

### 1. Chronicle - High Severity Detection Alert
**File:** `Chronicle-HighSeverityDetectionAlert.yaml`

**Purpose:** Catch-all rule for all HIGH and CRITICAL severity detections

**Trigger Condition:**
- Severity: HIGH or CRITICAL
- Alert State: ALERTING

**Frequency:** Every 5 minutes

**Key Metrics:**
- Risk Score
- Principal IP Count
- Source IP Count

**Incident Details:**
- Entity Mapping: IP, Host, Account, URL
- Custom Details: Rule Name, Rule Type, Detection Time
- Grouping: By Detection ID (6-hour regroup period)
- Re-open: Yes (ensures tracking of persistent threats)

**Use Case:**
- General incident creation for all critical threats
- Baseline rule for comprehensive threat visibility

---

### 2. Chronicle - Brute Force Attack Detection
**File:** `Chronicle-BruteForceAttackDetection.yaml`

**Purpose:** Detect coordinated brute force attacks targeting authentication systems

**Trigger Condition:**
- Rule contains "brute_force" or "greynoise"
- Severity: HIGH or CRITICAL
- Alert State: ALERTING
- Multiple detections required (TotalDetections > 1)

**Frequency:** Every 10 minutes (lookback 30 minutes)

**Aggregation:**
- Groups by attacking IP + rule name + severity
- Counts total detections
- Tracks unique target hosts and users
- Calculates max risk score

**Incident Details:**
- Entity Mapping: IP, Host
- Custom Details:
  - Attack Count
  - Unique Targets
  - Risk Score
  - First/Last Detection Time
  - Affected Users/Hosts

**Use Case:**
- Focused incident for coordinated authentication attacks
- Helps identify persistent attackers
- Tracks campaign progression

---

### 3. Chronicle - Credential Access Attack Detection
**File:** `Chronicle-CredentialAccessAttack.yaml`

**Purpose:** Detect credential access attacks (MITRE T1110)

**Trigger Condition:**
- Rule labels contain "Credential Access" tactic
- Severity: HIGH or CRITICAL
- DetectionCount > 1 OR FailureCount > 5

**Frequency:** Every 15 minutes (lookback 1 hour)

**Aggregation:**
- Groups by source IP + source hostname
- Counts by target users and hosts
- Tracks failure count

**Incident Details:**
- Entity Mapping: IP, Host, Account
- Custom Details:
  - Attacking IP
  - Source Host
  - Target Users
  - Target Hosts
  - Failure Count
  - Risk Score

**Use Case:**
- MITRE-tactic based detection
- Tracks compromised accounts
- Identifies internal vs external threats

---

### 4. Chronicle - Multi-Source Attack Detection
**File:** `Chronicle-MultiSourceAttackDetection.yaml`

**Purpose:** Detect coordinated attacks from multiple sources

**Trigger Condition:**
- Source IP Count > 3 OR Source Host Count > 2
- Severity: HIGH or CRITICAL
- Multiple detections required

**Frequency:** Every 30 minutes (lookback 2 hours)

**Aggregation:**
- Groups by target host + target user
- Calculates attack score
- Identifies attack pattern (Distributed, Coordinated, Multi-Source)

**Attack Patterns:**
- **Distributed Attack:** > 5 unique source IPs
- **Coordinated Multi-Host:** > 2 unique source hosts
- **Multi-Source Single Target:** Other cases

**Incident Details:**
- Entity Mapping: Host, Account, IP
- Custom Details:
  - Source IP Count
  - Attack Pattern
  - Risk Score
  - Timeline of attacks

**Use Case:**
- Detect advanced persistent threats
- Identify lateral movement
- Track campaign-style attacks

---

## Incident Configuration Strategy

### Field Mapping (Entity Enrichment)

**IP Address Mapping:**
- `var_correlation_ip` - The malicious IP from threat intel
- `var_principal_ip` - Source of the attack
- `var_target_ip` - Target of the attack

**Host Mapping:**
- `var_principal_hostname` - Source host
- `var_target_hostname` - Target host

**Account Mapping:**
- `var_target_user_userid` - Targeted user accounts

**URL Mapping:**
- `urlBackToProduct` - Link back to Chronicle console

### Custom Details Strategy

**Rule Identification:**
- `ruleName` - Which rule triggered the alert
- `ruleId` - Unique identifier for the rule
- `ruleType` - Detection type (MULTI_EVENT, etc.)

**Risk Assessment:**
- `risk_score` - Quantified risk (0-100)
- `severity` - Alert severity level

**Timeline Context:**
- `createdTime` - When alert was created
- `detectionTime` - When threat was detected
- `FirstDetectionTime` - Start of attack campaign
- `LastDetectionTime` - Most recent activity

**Attack Metrics:**
- `var_principal_ip_count` - Number of failed attempts
- `var_source_ip_count` - Count of source IPs
- `AttackCount` - Total attack events

**Targets:**
- `var_target_user_userid` - Compromised accounts
- `var_target_hostname` - Affected systems

---

## Grouping Strategy

### Rule 1: High Severity Detection Alert
```
Match Attribute: id (unique detection)
Regroup Period: 6 hours
Reopen Closed: Yes
Effect: Creates separate incident per detection, regroups within 6 hours
```

### Rule 2: Brute Force Attack Detection
```
Match Attribute: var_correlation_ip (attacking IP)
Regroup Period: 4 hours
Reopen Closed: No
Effect: Groups all attacks from same IP, prevents noise
```

### Rule 3: Credential Access Attack Detection
```
Match Attribute: var_principal_ip (source IP)
Regroup Period: 6 hours
Reopen Closed: Yes
Effect: Groups credential attacks by source, reopens if new activity
```

### Rule 4: Multi-Source Attack Detection
```
Match Attribute: var_target_hostname (target host)
Regroup Period: 8 hours
Reopen Closed: Yes
Effect: Groups multi-source attacks targeting same host
```

---

## Recommended Alert Thresholds

### By Severity

| Severity | Threshold | Reason |
|----------|-----------|--------|
| CRITICAL | All events (>0) | Immediate investigation required |
| HIGH | Aggregated (>1) | Indicates active threat |
| MEDIUM | Aggregated (>3) | Possible coordinated activity |
| LOW | Aggregated (>5) | May indicate false positives |

### By Attack Pattern

| Pattern | Threshold | Response Time |
|---------|-----------|----------------|
| Brute Force | >1 occurrence | 30 minutes |
| Credential Access | >1 occurrence + >5 failures | 1 hour |
| Multi-Source | >3 sources | 15 minutes |
| Distributed | >5 sources | Immediate |

---

## Investigation Workflow

### Step 1: Incident Review
1. Review rule that triggered the incident
2. Check severity level and risk score
3. Identify affected hosts/users
4. Note first and last detection times

### Step 2: Threat Actor Identification
1. Analyze `var_correlation_ip` (malicious IP)
2. Check `var_principal_ip` (source of attack)
3. Review threat intelligence data in `risk_score`
4. Assess reputation via `urlBackToProduct` link

### Step 3: Target Analysis
1. Identify `var_target_hostname` (affected hosts)
2. List `var_target_user_userid` (targeted accounts)
3. Review `var_principal_ip_count` (attempt count)
4. Check for successful compromise

### Step 4: Scope Assessment
1. Review `UniqueTargetHosts` (breadth)
2. Check `UniqueTargetUsers` (scope)
3. Analyze `SourceIPCount` (coordination level)
4. Determine if lateral movement occurred

### Step 5: Response Actions
- **Brute Force**: Reset passwords, enable MFA
- **Credential Access**: Revoke tokens, audit logs
- **Multi-Source**: Isolate hosts, check lateral movement
- **All Attacks**: Review firewall rules, patch systems

---

## Performance Tuning

### Query Optimization

**Current Complexity:**
- Rule 1: O(n) - Simple filtering
- Rule 2: O(n log n) - Single summarize
- Rule 3: O(n log n) - Single summarize
- Rule 4: O(n log n) - Single summarize

**Optimization Tips:**
1. Adjust `queryPeriod` based on data volume
2. Increase `triggerThreshold` to reduce noise
3. Use `queryFrequency` to balance latency vs cost
4. Consider date filtering for large datasets

### Cost Considerations

**Per Rule Cost (estimated):**
- Rule 1 (5m frequency): ~2,000 queries/month
- Rule 2 (10m frequency): ~4,500 queries/month
- Rule 3 (15m frequency): ~3,000 queries/month
- Rule 4 (30m frequency): ~1,500 queries/month

**Optimization:**
- Disable low-value rules during testing
- Increase frequency to 30+ minutes for stable environments
- Use time-based filters to reduce data scanned

---

## Integration with SOAR

### Incident Enrichment Playbook

When incident is created:

1. **Obtain Threat Intel**
   - Query GreyNoise for IP reputation
   - Check AbuseIPDB for abuse history
   - Lookup WHOIS information

2. **Assess Internal Impact**
   - Query Active Directory for user accounts
   - Check Azure AD for risky sign-ins
   - Review Office 365 activity

3. **Isolation Decision**
   - Auto-isolate if HIGH + brute force
   - Tag for manual review if MEDIUM
   - Create task for forensics if CRITICAL

4. **Notification**
   - Email security team
   - Post to Slack/Teams channel
   - Create ticket in ITSM system

---

## Monitoring Dashboard

### Key Metrics to Track

```
1. Detection Rate
   - Detections per hour
   - Trending analysis (↑ indicates new threats)

2. Severity Distribution
   - % CRITICAL vs HIGH vs MEDIUM
   - Helps assess threat landscape

3. Top Attacking IPs
   - Most frequent sources
   - Geo-location analysis

4. Top Targeted Hosts/Users
   - Most attacked assets
   - Helps prioritize hardening

5. Rule Effectiveness
   - False positive rate
   - Time-to-detection
   - Incident grouping success
```

---

## Best Practices

### For Incident Analysts

1. **Always check the timeline**
   - Compare `FirstDetectionTime` vs `LastDetectionTime`
   - Identify if active or historical

2. **Verify entity mappings**
   - Confirm IPs are from threat intel
   - Validate hostnames exist in environment
   - Check if accounts are real users

3. **Prioritize by risk score**
   - Risk score > 70 requires immediate action
   - Risk score 40-70 requires investigation
   - Risk score < 40 may be false positives

4. **Track incident progression**
   - Monitor if attacker escalates
   - Watch for lateral movement
   - Track access attempts over time

### For SOC Managers

1. **Tune thresholds regularly**
   - Review false positive rate monthly
   - Adjust triggers based on patterns
   - Disable ineffective rules

2. **Monitor rule health**
   - Ensure queries don't timeout
   - Track execution time
   - Monitor alert volume

3. **Update threat intel**
   - Keep IP blocklists current
   - Review MITRE tactics quarterly
   - Align with emerging threats

4. **Incident metrics**
   - Track mean time to resolution (MTTR)
   - Monitor escalation rate
   - Measure threat impact

---

## Related Resources

- **Parser:** `chronicle_detection.yaml`
- **Data Connector:** Google Chronicle Security
- **MITRE ATT&CK:** https://attack.mitre.org/
- **GreyNoise Intel:** https://www.greynoise.io/
- **Azure Sentinel Docs:** https://docs.microsoft.com/azure/sentinel/
