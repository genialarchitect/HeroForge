# Stub Elimination Master Plan

## Overview

**Total Items:** 307 TODO/placeholder comments across 135 files
**Goal:** Replace all placeholder implementations with functional code

---

## Phase 1: Quick Wins (Low Complexity)
**Estimated: 2-3 hours**

These are simple database lookups, calculations, or field population that can be done with existing infrastructure.

### Sprint 1.1: Context API Field Population (27 items)
**File:** `src/web/api/context.rs`

All TODO items are fetching data from existing database tables. Replace with actual queries:

| Line | Current | Fix |
|------|---------|-----|
| 85-87 | `training_modules_completed: 0` | Query `orange_team` training tables |
| 93-94 | `last_incident: None` | Query `green_team` incident tables |
| 100-102 | `vulnerabilities_introduced: 0` | Query `yellow_team` SAST results |
| 110-112 | `compliance_status: Vec::new()` | Query `white_team` compliance tables |
| 174-180 | `medium_vuln_count: 0` | Query scan_results for vuln counts |
| 186-188 | `siem_integrated: false` | Query integration settings |
| 193-195 | `mean_time_to_detect: None` | Calculate from incident data |
| 200-202 | `detection_effectiveness: 0.0` | Calculate from purple_team exercises |
| 207-208 | `compliance_violations: 0` | Query white_team findings |

### Sprint 1.2: Database Calculations (8 items)
**Files:** `src/db/ot_ics.rs`, `src/db/yara.rs`, `src/db/iot.rs`, `src/db/quotas.rs`

| File | Item | Fix |
|------|------|-----|
| `db/ot_ics.rs:601` | `total_vulnerabilities: 0` | COUNT query on vulnerabilities |
| `db/ot_ics.rs:604` | `protocols_detected: Vec::new()` | DISTINCT query on protocols |
| `db/yara.rs:2577` | `trend: 0.0` | Calculate from match history |
| `db/yara.rs:2579` | `last_match_at: None` | MAX query on match timestamps |
| `db/iot.rs:675` | `protocol_usage: Vec::new()` | GROUP BY query on protocols |
| `db/quotas.rs:675` | Storage calculation | Query file sizes from assets |

### Sprint 1.3: SIEM/UEBA Calculations (5 items)
**Files:** `src/siem/ueba/*.rs`

| File | Item | Fix |
|------|------|-----|
| `ueba/advanced_detection.rs:454` | Holiday detection | Add holiday calendar check |
| `ueba/advanced_detection.rs:989` | Peer comparison | Implement group baseline comparison |
| `ueba/engine.rs:908` | Activity trend | Calculate trend from historical data |

---

## Phase 2: Internal Logic Completion
**Estimated: 4-5 hours**

These are algorithm completions that don't require external dependencies.

### Sprint 2.1: Investigation & Timeline (4 items)
**File:** `src/investigation/timeline/reconstruction.rs`

| Line | Item | Implementation |
|------|------|----------------|
| 14 | ML-based event correlation | Implement similarity scoring between events |
| 55 | Technique mapping | Map event types to MITRE ATT&CK techniques |

### Sprint 2.2: Threat Intel Processing (20 items)
**Files:** `src/threat_intel/aggregation.rs`, `correlation.rs`, `dissemination.rs`

| Area | Items | Implementation |
|------|-------|----------------|
| Aggregation | 9 | Implement feed normalization, deduplication |
| Correlation | 5 | Implement IOC correlation algorithms |
| Dissemination | 6 | Implement TLP-based distribution logic |

### Sprint 2.3: Jobs Executor (11 items)
**File:** `src/jobs/executor.rs`

Implement actual job execution logic for scheduled tasks.

### Sprint 2.4: Permissions & Sharing (6 items)
**File:** `src/web/api/permissions.rs`

| Line | Item | Fix |
|------|------|-----|
| 630 | Verify share permission | Check resource ownership/permissions |
| 667 | Verify view permission | Validate share access |
| 696 | Verify manage permission | Validate admin rights |

---

## Phase 3: Compliance Frameworks
**Estimated: 3-4 hours**

### Sprint 3.1: Compliance Automation (17 items)
**Files:** `src/compliance_automation/*.rs`

| File | Items | Implementation |
|------|-------|----------------|
| `iso27001.rs` | 5 | Implement ISO 27001 control mappings |
| `soc2.rs` | 4 | Implement SOC 2 trust principles |
| `fedramp.rs` | 4 | Implement FedRAMP control baselines |
| `evidence.rs` | 4 | Implement evidence collection automation |

---

## Phase 4: External API Integrations
**Estimated: 8-10 hours**

These require actual API calls to external services.

### Sprint 4.1: Analytics Warehouse Connectors (4 items)
**File:** `src/analytics_engine/warehouse.rs`

| Line | Provider | Implementation |
|------|----------|----------------|
| 143 | Snowflake | Use `snowflake-api` crate or REST API |
| 152 | BigQuery | Use `google-cloud-bigquery` crate |
| 161 | Redshift | Use `sqlx` with PostgreSQL driver |
| 170 | Azure Synapse | Use `tiberius` crate for SQL Server |

### Sprint 4.2: SIEM Integrations (4 items)
**Files:** `src/siem/qradar.rs`, `src/purple_team/detection_check.rs`

| System | Items | Implementation |
|--------|-------|----------------|
| QRadar | 2 | REST API calls for offense/event creation |
| Splunk | 1 | HEC (HTTP Event Collector) integration |
| Elasticsearch | 1 | Direct ES client queries |

### Sprint 4.3: Communication Channels (6 items)
**Files:** `src/communications/*.rs`

| Platform | Items | Implementation |
|----------|-------|----------------|
| Discord | 2 | Webhook API calls |
| Telegram | 1 | Bot API integration |
| WhatsApp | 1 | Business API (or Twilio) |

### Sprint 4.4: Threat Intel Enrichment (8 items)
**File:** `src/cti_automation/enrichment.rs`

Implement actual API calls to:
- VirusTotal
- AbuseIPDB
- Shodan
- OTX (AlienVault)
- MISP

### Sprint 4.5: Integration Connectors (4 items)
**Files:** `src/integrations/pagerduty.rs`, `github.rs`

| Platform | Items | Implementation |
|----------|-------|----------------|
| PagerDuty | 2 | Events API v2 |
| GitHub | 2 | REST/GraphQL API |

---

## Phase 5: Web3/Blockchain Integration
**Estimated: 6-8 hours**

### Sprint 5.1: Ethereum RPC Integration (8 items)
**Files:** `src/web3/wallet.rs`, `smart_contracts.rs`

| Area | Items | Implementation |
|------|-------|----------------|
| Wallet analysis | 5 | ethers-rs for RPC calls |
| Contract analysis | 3 | Bytecode fetching, Etherscan API |

Add support for:
- `eth_getCode` for contract detection
- `eth_getLogs` for approval events
- Etherscan API for verification status

---

## Phase 6: Data Lake & Streaming
**Estimated: 4-5 hours**

### Sprint 6.1: Data Lake Storage (9 items)
**File:** `src/data_lake/storage.rs`

Implement actual storage backends:
- S3/MinIO integration
- Parquet file handling
- Query optimization

### Sprint 6.2: Stream Processing (8 items)
**File:** `src/data_lake/processing.rs`

Implement streaming connectors:
- Kafka consumer/producer
- Event processing pipeline

### Sprint 6.3: Stream Connectors (1 item)
**File:** `src/analytics_engine/stream.rs`

Connect to actual streaming sources.

---

## Phase 7: Security Tool Integrations
**Estimated: 5-6 hours**

### Sprint 7.1: Cracking Engine (2 items)
**File:** `src/cracking/engine.rs`

| Item | Implementation |
|------|----------------|
| John the Ripper support | Implement JtR process spawning |
| Duration calculation | Track actual execution time |

### Sprint 7.2: YARA Engine (1 item)
**File:** `src/malware_analysis/yara_engine.rs`

Implement proper YARA rule syntax parsing.

### Sprint 7.3: Purple Team Engine (4 items)
**File:** `src/purple_team/engine.rs`

Implement actual attack execution framework.

### Sprint 7.4: Exploit Sandbox (2 items)
**File:** `src/exploit_research/sandbox.rs`

Implement sandboxed execution environment.

---

## Phase 8: Kubernetes & Cloud
**Estimated: 4-5 hours**

### Sprint 8.1: K8s Security (13 items)
**Files:** `src/k8s_security/*.rs`

| File | Items | Implementation |
|------|-------|----------------|
| `cluster.rs` | 4 | K8s API client integration |
| `workloads.rs` | 3 | Pod/Deployment analysis |
| `runtime.rs` | 2 | Runtime security checks |
| `network.rs` | 2 | NetworkPolicy analysis |
| `compliance.rs` | 2 | CIS benchmark checks |

### Sprint 8.2: Multi-Cloud Orchestration (3 items)
**File:** `src/orchestration/multi_cloud.rs`

Implement cross-cloud resource management.

### Sprint 8.3: Auto-Scaling (5 items)
**File:** `src/orchestration/scale.rs`

Implement scaling decision logic.

---

## Phase 9: IoT & Emerging Tech
**Estimated: 3-4 hours**

### Sprint 9.1: IoT Lifecycle (6 items)
**File:** `src/iot/lifecycle.rs`

Implement device lifecycle management.

### Sprint 9.2: IoT Vulnerability (3 items)
**File:** `src/iot/vulnerability.rs`

Implement IoT-specific vulnerability checks.

### Sprint 9.3: Emerging Technologies (6 items)
**Files:** `src/emerging_tech/*.rs`

| File | Items | Implementation |
|------|-------|----------------|
| `quantum.rs` | 2 | Quantum-safe crypto checks |
| Others | 4 | 5G, XR, Adversarial ML |

---

## Phase 10: Auth & Security Hardening
**Estimated: 3-4 hours**

### Sprint 10.1: WebAuthn Completion (3 items)
**File:** `src/web/auth/webauthn.rs`

| Line | Item | Implementation |
|------|------|----------------|
| 325 | CBOR parsing | Use `ciborium` crate for COSE key extraction |
| 349 | Attestation parsing | Proper CBOR attestation object parsing |
| 482 | Signature verification | Implement actual cryptographic verification |

### Sprint 10.2: SAML Verification (3 items)
**File:** `src/web/auth/sso/saml.rs`

Implement proper XML signature verification.

### Sprint 10.3: Device Trust (2 items)
**File:** `src/web/auth/device_trust.rs`

Complete device fingerprint verification.

### Sprint 10.4: Input Validation (4 items)
**File:** `src/hardening/input_validation.rs`

Complete input sanitization rules.

---

## Phase 11: BI & Reporting
**Estimated: 2-3 hours**

### Sprint 11.1: BI Export (3 items)
**File:** `src/bi/export.rs`

Implement export to various formats.

### Sprint 11.2: BI Reports (2 items)
**File:** `src/bi/reports.rs`

Complete report generation logic.

### Sprint 11.3: BI Metrics (2 items)
**File:** `src/bi/metrics.rs`

Implement metric calculations.

---

## Phase 12: Incident Response & Playbooks
**Estimated: 4-5 hours**

### Sprint 12.1: Green Team Playbooks (2 items)
**File:** `src/green_team/playbooks/actions.rs`

| Line | Item | Implementation |
|------|------|----------------|
| 553 | Script execution | Sandboxed script runner |
| 654 | Approval workflow | Implement approval request system |

### Sprint 12.2: Orchestration (1 item)
**File:** `src/green_team/orchestration/mod.rs`

Implement integration callbacks.

### Sprint 12.3: Threat Hunting API (4 items)
**File:** `src/web/api/threat_hunting_api.rs`

Complete campaign and execution endpoints.

---

## Phase 13: Predictive & ML
**Estimated: 3-4 hours**

### Sprint 13.1: Predictive Security (5 items)
**File:** `src/predictive_security/proactive_defense.rs`

Implement predictive algorithms.

### Sprint 13.2: ML Explainability (2 items)
**File:** `src/ml/xai.rs`

Implement model explanation features.

### Sprint 13.3: ML Core (2 items)
**File:** `src/ml/mod.rs`

Complete ML pipeline integration.

---

## Phase 14: Patch Management
**Estimated: 2-3 hours**

### Sprint 14.1: Patch Prioritization (5 items)
**File:** `src/patch_management/prioritization.rs`

Implement patch priority scoring.

### Sprint 14.2: Patch Deployment (2 items)
**File:** `src/patch_management/deployment.rs`

Implement deployment orchestration.

---

## Phase 15: API Governance
**Estimated: 2-3 hours**

### Sprint 15.1: API Governance Core (5 items)
**File:** `src/api_governance/mod.rs`

Implement API policy enforcement.

### Sprint 15.2: Rate Limiting (2 items)
**File:** `src/api_governance/rate_limiting.rs`

Complete rate limiting implementation.

---

## Phase 16: Mesh & Agents
**Estimated: 2-3 hours**

### Sprint 16.1: Agent Discovery (1 item)
**File:** `src/agents/mesh/discovery.rs`

Implement mDNS announcements.

### Sprint 16.2: Agent Scheduler (2 items)
**File:** `src/agents/mesh/scheduler.rs`

Complete task scheduling.

---

## Phase 17: Miscellaneous
**Estimated: 2-3 hours**

### Sprint 17.1: DNS Template Engine (1 item)
**File:** `src/scanner/template_engine/protocols/dns.rs`

Implement custom resolver support.

### Sprint 17.2: DNS Reputation (1 item)
**File:** `src/scanner/dns_analysis/reputation.rs`

Use `idna` crate for proper decoding.

### Sprint 17.3: Region Routing (2 items)
**File:** `src/web/middleware/region_routing.rs`

Implement geo-based routing.

### Sprint 17.4: Evidence Collection (2 items)
**File:** `src/web/api/evidence.rs`

Complete evidence upload/management.

---

## Execution Summary

| Phase | Description | Items | Est. Hours |
|-------|-------------|-------|------------|
| 1 | Quick Wins | 40 | 2-3 |
| 2 | Internal Logic | 41 | 4-5 |
| 3 | Compliance | 17 | 3-4 |
| 4 | External APIs | 26 | 8-10 |
| 5 | Web3/Blockchain | 8 | 6-8 |
| 6 | Data Lake | 18 | 4-5 |
| 7 | Security Tools | 9 | 5-6 |
| 8 | K8s & Cloud | 21 | 4-5 |
| 9 | IoT & Emerging | 15 | 3-4 |
| 10 | Auth & Hardening | 12 | 3-4 |
| 11 | BI & Reporting | 7 | 2-3 |
| 12 | IR & Playbooks | 7 | 4-5 |
| 13 | Predictive & ML | 9 | 3-4 |
| 14 | Patch Management | 7 | 2-3 |
| 15 | API Governance | 7 | 2-3 |
| 16 | Mesh & Agents | 3 | 2-3 |
| 17 | Miscellaneous | 6 | 2-3 |
| **TOTAL** | | **307** | **~60-75 hrs** |

---

## Dependencies

### External Crates Needed
```toml
# Web3
ethers = "2.0"

# Data Warehouses
snowflake-connector = "0.1"
google-cloud-bigquery = "0.1"
tiberius = "0.12"  # SQL Server

# Streaming
rdkafka = "0.36"
apache-pulsar = "6.0"

# Auth
ciborium = "0.2"  # CBOR parsing

# Internationalization
idna = "0.5"

# Cloud APIs
aws-sdk-* = "1.0"
azure_* = "0.20"
google-cloud-* = "0.1"
```

### Environment Variables Needed
```bash
# Web3
ETHEREUM_RPC_URL=
ETHERSCAN_API_KEY=

# Data Warehouses
SNOWFLAKE_ACCOUNT=
SNOWFLAKE_USER=
SNOWFLAKE_PASSWORD=
BIGQUERY_PROJECT_ID=
GOOGLE_APPLICATION_CREDENTIALS=

# SIEM
QRADAR_URL=
QRADAR_API_KEY=
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=

# Communications
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=

# Threat Intel
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
```

---

## Recommended Execution Order

1. **Phase 1** - Quick database lookups (immediate value, no dependencies)
2. **Phase 2** - Internal logic (foundation for other features)
3. **Phase 10** - Auth hardening (security critical)
4. **Phase 3** - Compliance (enables audit capabilities)
5. **Phase 4** - External APIs (core integrations)
6. **Phases 5-17** - Remaining features in parallel where possible

---

## Notes

- All "In production, would..." comments become actual implementations
- Mock implementations in `incident_response/automation.rs` remain as opt-in features with real integration options
- External API calls should include proper error handling, retries, and rate limiting
- Add feature flags for optional integrations (e.g., `#[cfg(feature = "snowflake")]`)
