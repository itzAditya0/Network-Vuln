# 🎯 Network Vulnerability Scanner - Complete Walkthrough

This document provides a comprehensive walkthrough of the Network Vulnerability Scanner, demonstrating all features, security controls, and verification capabilities.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Installation & Setup](#2-installation--setup)
3. [Running Scans](#3-running-scans)
4. [Understanding Reports](#4-understanding-reports)
5. [Security Features](#5-security-features)
6. [Audit Chain Verification](#6-audit-chain-verification)
7. [Testing Suite](#7-testing-suite)
8. [Performance Metrics](#8-performance-metrics)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Project Overview

### What It Does

The Network Vulnerability Scanner automates the vulnerability assessment workflow:

```
Target Discovery → Port Scanning → Service Detection → CVE Mapping → 
Exploit Validation → Threat Scoring → Report Generation
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **CLI** | `main.py` | Command-line interface |
| **Endpoint Manager** | `src/endpoint_manager.py` | Target loading & validation |
| **Nmap Controller** | `src/nmap_controller.py` | Scanning with retries |
| **CVE Mapper** | `src/cve_mapper.py` | Map services to known exploits |
| **Metasploit Validator** | `src/msf_validator.py` | Verify exploitability |
| **Safe Mode** | `src/safe_mode.py` | Security controls |
| **Scoring Engine** | `src/scoring_engine.py` | Threat prioritization |
| **Report Generator** | `src/report_generator.py` | Output in JSON/CSV/HTML |
| **Audit Logger** | `src/logger.py` | HMAC chain logging |

---

## 2. Installation & Setup

### Step 1: Clone & Environment

```bash
cd Network_Vuln
python -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation

```bash
python main.py --help
```

Expected output:
```
usage: vulnscanner [-h] [--config CONFIG] [--log-level {DEBUG,INFO,WARNING,ERROR}]
                   [--metrics-port METRICS_PORT]
                   {scan,validate,report,status} ...

Network Vulnerability Scanner with Exploit Validation
```

### Step 4: Install Test Dependencies (Optional)

```bash
pip install pytest pytest-asyncio
```

---

## 3. Running Scans

### Quick Scan (No Root Required)

```bash
python main.py scan \
  --target scanme.nmap.org \
  --user-id operator1 \
  --ticket-id VULN-0001 \
  --scan-type quick
```

**Output:**
```json
{"event":"hostname_resolved","hostname":"scanme.nmap.org","ip":"45.33.32.156",...}
{"event":"nmap_scan_complete","ports_found":3,"target":"45.33.32.156",...}
{"event":"pipeline_completed","vulnerabilities":0,"duration":16.8,...}

============================================================
Scan Complete: 54a7939a
============================================================
Targets Scanned:    1
Vulnerabilities:    0
Exploitable:        0
Duration:           16.8s

Reports:
  json: reports/scan_54a7939a_20251211_231255.json
  csv: reports/scan_54a7939a_20251211_231255.csv
  html: reports/scan_54a7939a_20251211_231255.html
```

### Full Scan (Root Required)

```bash
sudo python main.py scan \
  --target 192.168.1.100 \
  --user-id operator1 \
  --ticket-id VULN-0001 \
  --scan-type full
```

The `full` scan includes:
- OS fingerprinting (`-O` flag)
- Vulnerability scripts (`--script vuln`)
- Version detection (`-sV`)

### Scan Types Comparison

| Type | Speed | Root | Use Case |
|------|-------|------|----------|
| `quick` | ~20s | No | Rapid reconnaissance |
| `full` | ~2-5min | Yes | Complete assessment |
| `stealth` | ~5min | Yes | Evade IDS detection |
| `vuln` | ~1-3min | No | Vuln scripts only |

---

## 4. Understanding Reports

### JSON Report

```json
{
  "scan_id": "54a7939a",
  "targets_scanned": 1,
  "vulnerabilities_found": 0,
  "metadata": {
    "user_id": "operator1",
    "ticket_id": "VULN-0001"
  },
  "vulnerabilities": []
}
```

### CSV Report

```csv
target,port,service,cve,severity,score,validation_result
192.168.1.100,445,smb,CVE-2017-0143,critical,9.8,vulnerable
```

### HTML Report

Opens in browser with:
- Executive summary
- Vulnerability table with sorting
- Remediation recommendations
- Scan metadata

---

## 5. Security Features

### 5.1 Two-Person Approval

Destructive exploits require approval from two different people:

```
Operator (operator1) ──────► Request Approval
                                    │
                                    ▼
Admin (admin1) ────────────► Approve (different user + device)
                                    │
                                    ▼
                              Exploit Executed
```

**Security Checks:**
- ✅ Approver ≠ Operator
- ✅ Approver device fingerprint ≠ Operator device fingerprint
- ✅ Approver has Admin role with MFA verified
- ✅ Valid ticket ID (JIRA format or signed hash)

### 5.2 Kill Switch

Any user can activate an emergency stop:

```python
safe_mode.activate_kill_switch(user_id="responder", reason="Incident detected")
```

Only admins can deactivate:

```python
safe_mode.deactivate_kill_switch(user_id="admin1")
```

### 5.3 Scope Authorization

Scans are restricted to authorized IP ranges:

```python
ScopeAuthorization(
    id="prod-scope",
    cidr=IPv4Network("10.0.0.0/24"),
    ticket_id="VULN-001",
    approved_by=["admin1", "admin2"],
    valid_from=datetime.now(),
    valid_until=datetime.now() + timedelta(hours=24),
)
```

### 5.4 Log Scrubbing

Sensitive data is automatically redacted:

```python
# Input
{"username": "admin", "password": "secret123", "api_key": "AKIAIOSFODNN7EXAMPLE"}

# Logged output
{"username": "admin", "password": "[REDACTED]", "api_key": "[REDACTED]"}
```

**Scrubbed patterns:** password, secret, token, key, credential, ssn, credit_card, email, phone

---

## 6. Audit Chain Verification

### How It Works

Each audit record contains an HMAC computed over:
1. The previous record's HMAC
2. The current record's payload

```
Record 1: HMAC(key, "" + payload1) = hash1
Record 2: HMAC(key, hash1 + payload2) = hash2
Record 3: HMAC(key, hash2 + payload3) = hash3
```

### Running the Demo

```bash
python ops/demo_audit_chain.py
```

**Output:**

```
╔══════════════════════════════════════════════════════════╗
║        HMAC Audit Chain Verification Demo                ║
║       Network Vulnerability Scanner Project              ║
╚══════════════════════════════════════════════════════════╝

============================================================
Phase 1: Creating Audit Chain
============================================================

Creating 5 chained audit records...

Record #1:
  Action:    scan_started
  User:      operator1
  HMAC:      c55931fb483d9899...

Record #2:
  Action:    vulnerability_found
  Prev HMAC: c55931fb483d9899...
  HMAC:      a477769531728f68...

✓ Created 5 records with chained HMACs

============================================================
Phase 2: Verifying Audit Chain
============================================================

✓ All 5 records verified
✓ Chain integrity CONFIRMED

============================================================
Phase 3: Tamper Detection Demo
============================================================

Simulating attacker modifying record #3:
  Original action: 'validation_requested'
  Tampered action: 'exploit_executed'

✗ TAMPERING DETECTED!
✓ System successfully detected the modification

============================================================
Phase 4: Original Chain Still Valid
============================================================

✓ Original chain integrity CONFIRMED
✓ Demo complete - tamper-evident audit logging verified

Summary:
 • Each audit record contains an HMAC of its contents + prev HMAC
 • Any modification breaks the cryptographic chain
 • Attackers cannot forge valid HMACs without the secret key
 • Key is stored in Vault and rotated according to policy
```

### Verifying Production Audit Chain

```bash
python ops/verify_audit.py
```

---

## 7. Testing Suite

### Run All Tests

```bash
./venv/bin/pytest tests/ -v
```

### Test Categories

#### Security Tests (18 tests)

```bash
./venv/bin/pytest tests/test_security.py -v
```

Tests:
- ✅ Password fields redacted
- ✅ Token fields redacted
- ✅ Nested sensitive fields redacted
- ✅ Case-insensitive matching
- ✅ No AWS keys in source
- ✅ No private keys in source
- ✅ No hardcoded passwords
- ✅ .env in .gitignore

#### Audit Chain Tests (15 tests)

```bash
./venv/bin/pytest tests/test_audit_demo.py -v
```

Tests:
- ✅ Single record has HMAC
- ✅ Chained records link correctly
- ✅ Valid chain verifies
- ✅ Tampered action detected
- ✅ Tampered user_id detected
- ✅ Broken chain link detected
- ✅ Forged HMAC detected
- ✅ Wrong key fails verification
- ✅ Deleted record detected
- ✅ Reordered records detected

#### Performance Tests (4 tests)

```bash
./venv/bin/pytest tests/perf/test_performance.py -v
```

Tests:
- ✅ 100 endpoints latency < 30s
- ✅ Peak memory delta < 500MB
- ✅ CPU time recorded
- ✅ Full benchmark with CSV output

### Test Results Summary

```
============================== 37 passed in 4.29s ==============================
```

---

## 8. Performance Metrics

### Benchmark Results

Running 100 mock endpoints:

| Metric | Value |
|--------|-------|
| **Latency** | ~1-2s (mocked) |
| **Peak Memory** | ~50MB delta |
| **CPU Time** | ~0.5s |

Results are saved to `reports/performance_metrics.csv`:

```csv
timestamp,endpoint_count,latency_seconds,peak_memory_mb,cpu_time_seconds
2025-12-11T17:34:00+00:00,100,1.234,48.56,0.456
```

### Running Performance Tests

```bash
./venv/bin/pytest tests/perf/test_performance.py -v
```

---

## 9. Troubleshooting

### Common Issues

#### "Expected 4 octets" Error

**Problem:** Using hostname instead of IP address

**Solution:** The scanner now auto-resolves hostnames. Make sure you're using the latest `main.py`.

```bash
python main.py scan --target scanme.nmap.org ...  # ✅ Works now
```

#### "TCP/IP fingerprinting requires root"

**Problem:** Full scan requires sudo

**Solution:**
```bash
# Option 1: Use sudo
sudo python main.py scan --target ... --scan-type full

# Option 2: Use quick scan (no root needed)
python main.py scan --target ... --scan-type quick
```

#### "No module named 'src'"

**Problem:** Running script from wrong directory

**Solution:**
```bash
cd /path/to/Network_Vuln
python main.py ...
```

#### Tests Failing

**Problem:** Missing dependencies

**Solution:**
```bash
./venv/bin/pip install pytest pytest-asyncio structlog
```

---

## 📚 Additional Resources

- **README.md** - Quick start and feature overview
- **ops/runbook.md** - Operational procedures
- **Implementation Plan** - Technical design decisions

---

<div align="center">

**End of Walkthrough**

For questions or issues, please open a GitHub issue.

</div>
