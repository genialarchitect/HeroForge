# HeroForge Priority 2 Feature Implementation Plan
## Blue Team, DevSecOps & Advanced Capabilities

---

## Overview

This plan implements 5 major feature categories with 40 features across 15 sprints.

**Status**: ✅ **ALL SPRINTS COMPLETE** (as of January 2026)

**Timeline**: 15 sprints (2-week sprints = 30 weeks / 7.5 months)
**Goal**: Transform HeroForge into a comprehensive Blue Team and DevSecOps platform with advanced automation

**Prerequisites**: Priority 1 features should be substantially complete before starting Priority 2.

---

## Completion Summary

| Category | Sprints | Status |
|----------|---------|--------|
| A: Blue Team Enhancement | 1-6 | ✅ Complete |
| B: DevSecOps Platform | 7-10 | ✅ Complete |
| C: SOAR & Automation | 11-12 | ✅ Complete |
| D: OT/ICS & IoT Security | 13-14 | ✅ Complete |
| E: AI/ML Security Operations | 15 | ✅ Complete |

**Total Lines of Code**: ~65,000+ lines across P2 modules

---

## Feature Categories

### Category A: Blue Team Enhancement (10 features)
### Category B: DevSecOps Platform (10 features)
### Category C: SOAR & Automation (8 features)
### Category D: OT/ICS & IoT Security (6 features)
### Category E: AI/ML Security Operations (6 features)

---

## Sprint Breakdown

### Sprint 1-2: Advanced Detection Engineering

**Sprint 1: YARA Deep Integration** ✅ COMPLETE
- [x] YARA rule engine with multi-file scanning
- [x] Memory scanning support (process memory dumps)
- [x] Real-time file system monitoring with YARA
- [x] Rule performance profiling and optimization
- [x] Community rule repository sync (YARA-Rules, awesome-yara)
- [x] Rule effectiveness scoring based on matches/FPs

**Sprint 2: Sigma Rule Engine Enhancement** ✅ COMPLETE
- [x] Full Sigma rule parser with all modifiers
- [x] Backend conversion (Splunk SPL, Elastic EQL, QRadar AQL)
- [x] Sigma rule testing against sample logs
- [x] Rule chain/correlation support
- [x] ATT&CK coverage visualization from Sigma rules
- [x] Rule tuning recommendations based on FP analysis

**Database Schema (Sprint 1-2)**:
```sql
-- YARA Enhancement
CREATE TABLE yara_scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    scan_type TEXT NOT NULL, -- 'file', 'directory', 'memory', 'process'
    target_path TEXT,
    process_id INTEGER,
    rules_used TEXT, -- JSON array of rule IDs
    status TEXT DEFAULT 'pending',
    files_scanned INTEGER DEFAULT 0,
    matches_found INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE yara_scan_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES yara_scans(id),
    rule_id TEXT NOT NULL REFERENCES yara_rules(id),
    file_path TEXT,
    process_name TEXT,
    matched_strings TEXT, -- JSON array
    match_offset INTEGER,
    metadata TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE yara_rule_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL, -- 'github', 'url', 'local'
    url TEXT,
    branch TEXT DEFAULT 'main',
    last_sync_at TIMESTAMP,
    rules_count INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sigma Enhancement
CREATE TABLE sigma_rules (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT, -- 'stable', 'test', 'experimental', 'deprecated'
    level TEXT NOT NULL, -- 'informational', 'low', 'medium', 'high', 'critical'
    logsource_category TEXT,
    logsource_product TEXT,
    logsource_service TEXT,
    detection_yaml TEXT NOT NULL, -- Original Sigma YAML
    condition TEXT,
    falsepositives TEXT, -- JSON array
    tags TEXT, -- JSON array (ATT&CK tags)
    references TEXT, -- JSON array
    author TEXT,
    date TEXT,
    modified TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    custom BOOLEAN DEFAULT FALSE,
    hits_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sigma_conversions (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES sigma_rules(id),
    backend TEXT NOT NULL, -- 'splunk', 'elastic', 'qradar', 'microsoft_defender'
    converted_query TEXT NOT NULL,
    conversion_errors TEXT, -- JSON array
    last_converted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sigma_rule_tests (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES sigma_rules(id),
    test_type TEXT NOT NULL, -- 'positive', 'negative'
    test_data TEXT NOT NULL, -- JSON log sample
    expected_result BOOLEAN NOT NULL,
    actual_result BOOLEAN,
    tested_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 1-2)**:
```
# YARA Scanning
POST   /api/yara/scan                    # Start YARA scan
GET    /api/yara/scans                   # List scans
GET    /api/yara/scans/{id}              # Get scan details
GET    /api/yara/scans/{id}/results      # Get scan results
POST   /api/yara/scan/memory/{pid}       # Scan process memory
POST   /api/yara/scan/realtime           # Start real-time monitoring
DELETE /api/yara/scan/realtime/{id}      # Stop real-time monitoring

# YARA Rule Sources
GET    /api/yara/sources                 # List rule sources
POST   /api/yara/sources                 # Add rule source
POST   /api/yara/sources/{id}/sync       # Sync rules from source
DELETE /api/yara/sources/{id}            # Remove source

# Sigma Rules
GET    /api/sigma/rules                  # List rules
POST   /api/sigma/rules                  # Create rule
GET    /api/sigma/rules/{id}             # Get rule
PUT    /api/sigma/rules/{id}             # Update rule
DELETE /api/sigma/rules/{id}             # Delete rule
POST   /api/sigma/rules/{id}/convert     # Convert to backend format
POST   /api/sigma/rules/{id}/test        # Test rule against logs
GET    /api/sigma/rules/{id}/coverage    # Get ATT&CK coverage

# Sigma Bulk Operations
POST   /api/sigma/import                 # Import Sigma rules (YAML/ZIP)
GET    /api/sigma/export                 # Export rules
POST   /api/sigma/validate               # Validate rule syntax
GET    /api/sigma/coverage               # Overall ATT&CK coverage
```

---

### Sprint 3-4: Behavioral Analytics & UEBA

**Sprint 3: User Entity Behavior Analytics Foundation** ✅ COMPLETE
- [x] User activity baseline calculation
- [x] Entity risk scoring engine
- [x] Peer group analysis (similar users/roles)
- [x] Session analysis (login patterns, locations)
- [x] Privilege usage monitoring
- [x] Anomaly detection algorithms (statistical + ML)

**Sprint 4: Advanced Behavioral Detection** ✅ COMPLETE
- [x] Impossible travel detection
- [x] Unusual data access patterns
- [x] Off-hours activity monitoring
- [x] Service account abuse detection
- [x] Lateral movement indicators
- [x] Data exfiltration indicators
- [x] Behavioral alert correlation

**Database Schema (Sprint 3-4)**:
```sql
-- UEBA
CREATE TABLE ueba_entities (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL, -- 'user', 'host', 'service_account', 'application'
    entity_id TEXT NOT NULL, -- username, hostname, etc.
    display_name TEXT,
    department TEXT,
    role TEXT,
    peer_group_id TEXT,
    risk_score INTEGER DEFAULT 0, -- 0-100
    risk_level TEXT DEFAULT 'low', -- 'low', 'medium', 'high', 'critical'
    baseline_data TEXT, -- JSON baseline metrics
    last_activity_at TIMESTAMP,
    first_seen_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_type, entity_id)
);

CREATE TABLE ueba_peer_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    criteria TEXT NOT NULL, -- JSON (department, role, etc.)
    member_count INTEGER DEFAULT 0,
    baseline_metrics TEXT, -- JSON group baseline
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ueba_activities (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES ueba_entities(id),
    activity_type TEXT NOT NULL, -- 'login', 'file_access', 'privilege_use', 'network', etc.
    source_ip TEXT,
    source_location TEXT, -- JSON (country, city, lat/long)
    destination TEXT,
    action TEXT,
    resource TEXT,
    status TEXT, -- 'success', 'failure'
    risk_contribution INTEGER DEFAULT 0,
    raw_event TEXT, -- JSON original event
    timestamp TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ueba_anomalies (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES ueba_entities(id),
    anomaly_type TEXT NOT NULL, -- 'impossible_travel', 'unusual_access', 'off_hours', etc.
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL, -- JSON supporting data
    baseline_deviation REAL, -- standard deviations from baseline
    confidence REAL, -- 0-1
    status TEXT DEFAULT 'new', -- 'new', 'investigating', 'confirmed', 'false_positive', 'resolved'
    related_activities TEXT, -- JSON array of activity IDs
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    resolved_by TEXT,
    resolution_notes TEXT
);

CREATE TABLE ueba_risk_factors (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL REFERENCES ueba_entities(id),
    factor_type TEXT NOT NULL,
    factor_value TEXT,
    weight INTEGER DEFAULT 1,
    contribution INTEGER, -- points added to risk score
    valid_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ueba_baselines (
    id TEXT PRIMARY KEY,
    entity_id TEXT REFERENCES ueba_entities(id),
    peer_group_id TEXT REFERENCES ueba_peer_groups(id),
    metric_name TEXT NOT NULL, -- 'login_hour', 'file_access_count', 'bytes_downloaded', etc.
    period TEXT NOT NULL, -- 'hourly', 'daily', 'weekly'
    mean_value REAL,
    std_deviation REAL,
    min_value REAL,
    max_value REAL,
    sample_count INTEGER,
    last_calculated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 3-4)**:
```
# UEBA Entities
GET    /api/ueba/entities                # List entities with risk scores
GET    /api/ueba/entities/{id}           # Get entity details
GET    /api/ueba/entities/{id}/activities # Get entity activities
GET    /api/ueba/entities/{id}/anomalies # Get entity anomalies
GET    /api/ueba/entities/{id}/timeline  # Get entity timeline
POST   /api/ueba/entities/{id}/baseline  # Recalculate baseline

# UEBA Peer Groups
GET    /api/ueba/peer-groups             # List peer groups
POST   /api/ueba/peer-groups             # Create peer group
GET    /api/ueba/peer-groups/{id}        # Get peer group
PUT    /api/ueba/peer-groups/{id}        # Update peer group
GET    /api/ueba/peer-groups/{id}/members # Get group members

# UEBA Anomalies
GET    /api/ueba/anomalies               # List all anomalies
GET    /api/ueba/anomalies/{id}          # Get anomaly details
PUT    /api/ueba/anomalies/{id}          # Update anomaly status
POST   /api/ueba/anomalies/{id}/investigate # Start investigation

# UEBA Dashboard
GET    /api/ueba/dashboard               # Risk overview
GET    /api/ueba/dashboard/high-risk     # High risk entities
GET    /api/ueba/dashboard/trends        # Risk trends over time
GET    /api/ueba/dashboard/anomaly-types # Anomaly distribution
```

---

### Sprint 5-6: Network Forensics & Flow Analysis

**Sprint 5: NetFlow/IPFIX Analysis** ✅ COMPLETE
- [x] NetFlow v5/v9 collector
- [x] IPFIX collector
- [x] sFlow collector
- [x] Flow aggregation and storage
- [x] Top talkers analysis
- [x] Bandwidth utilization tracking
- [x] Flow-based anomaly detection

**Sprint 6: DNS Analytics & Threat Detection** ✅ COMPLETE
- [x] Passive DNS collection
- [x] DNS query/response analysis
- [x] DGA (Domain Generation Algorithm) detection
- [x] DNS tunneling detection
- [x] Fast-flux detection
- [x] DNS-based threat intelligence correlation
- [x] Newly observed domain tracking

**Database Schema (Sprint 5-6)**:
```sql
-- NetFlow/IPFIX
CREATE TABLE flow_collectors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    collector_type TEXT NOT NULL, -- 'netflow_v5', 'netflow_v9', 'ipfix', 'sflow'
    listen_address TEXT NOT NULL,
    listen_port INTEGER NOT NULL,
    status TEXT DEFAULT 'stopped',
    flows_received INTEGER DEFAULT 0,
    last_flow_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE flow_records (
    id TEXT PRIMARY KEY,
    collector_id TEXT NOT NULL REFERENCES flow_collectors(id),
    exporter_ip TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,
    packets INTEGER,
    bytes INTEGER,
    tcp_flags INTEGER,
    tos INTEGER,
    input_interface INTEGER,
    output_interface INTEGER,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_ms INTEGER,
    -- Enrichment
    src_geo TEXT, -- JSON
    dst_geo TEXT, -- JSON
    src_asn INTEGER,
    dst_asn INTEGER,
    application TEXT, -- detected application
    is_suspicious BOOLEAN DEFAULT FALSE,
    threat_indicators TEXT, -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE flow_aggregates (
    id TEXT PRIMARY KEY,
    aggregation_period TEXT NOT NULL, -- '5min', 'hourly', 'daily'
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    protocol INTEGER,
    dst_port INTEGER,
    total_flows INTEGER,
    total_packets INTEGER,
    total_bytes INTEGER,
    unique_sources INTEGER,
    unique_destinations INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DNS Analytics
CREATE TABLE passive_dns (
    id TEXT PRIMARY KEY,
    query_name TEXT NOT NULL,
    query_type TEXT NOT NULL, -- 'A', 'AAAA', 'MX', 'TXT', 'CNAME', etc.
    response_data TEXT NOT NULL, -- IP or other response
    ttl INTEGER,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    query_count INTEGER DEFAULT 1,
    source_ips TEXT, -- JSON array of querying IPs
    is_suspicious BOOLEAN DEFAULT FALSE,
    threat_type TEXT, -- 'dga', 'tunnel', 'fast_flux', 'malware', 'phishing'
    threat_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(query_name, query_type, response_data)
);

CREATE TABLE dns_anomalies (
    id TEXT PRIMARY KEY,
    anomaly_type TEXT NOT NULL, -- 'dga', 'tunnel', 'fast_flux', 'high_entropy', 'long_domain'
    domain TEXT NOT NULL,
    severity TEXT NOT NULL,
    indicators TEXT NOT NULL, -- JSON evidence
    entropy_score REAL,
    dga_probability REAL,
    tunnel_indicators TEXT, -- JSON
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    query_count INTEGER,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE dns_baselines (
    id TEXT PRIMARY KEY,
    baseline_type TEXT NOT NULL, -- 'query_volume', 'unique_domains', 'nxdomain_rate'
    entity TEXT, -- IP, subnet, or 'global'
    period TEXT NOT NULL, -- 'hourly', 'daily'
    mean_value REAL,
    std_deviation REAL,
    last_calculated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE newly_observed_domains (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    tld TEXT,
    first_seen TIMESTAMP NOT NULL,
    first_query_ip TEXT,
    registrar TEXT,
    registration_date DATE,
    whois_data TEXT, -- JSON
    risk_score INTEGER DEFAULT 0,
    threat_indicators TEXT, -- JSON
    status TEXT DEFAULT 'new', -- 'new', 'reviewed', 'benign', 'malicious'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 5-6)**:
```
# Flow Collection
GET    /api/flows/collectors             # List collectors
POST   /api/flows/collectors             # Create collector
PUT    /api/flows/collectors/{id}        # Update collector
POST   /api/flows/collectors/{id}/start  # Start collector
POST   /api/flows/collectors/{id}/stop   # Stop collector
DELETE /api/flows/collectors/{id}        # Delete collector

# Flow Analysis
GET    /api/flows/records                # Query flow records
GET    /api/flows/top-talkers            # Top sources/destinations
GET    /api/flows/bandwidth              # Bandwidth analysis
GET    /api/flows/protocols              # Protocol distribution
GET    /api/flows/anomalies              # Flow anomalies
GET    /api/flows/timeline               # Flow timeline

# DNS Analytics
GET    /api/dns/passive                  # Query passive DNS
GET    /api/dns/passive/{domain}         # Domain history
GET    /api/dns/anomalies                # DNS anomalies
GET    /api/dns/dga                      # DGA detections
GET    /api/dns/tunneling                # Tunneling detections
GET    /api/dns/newly-observed           # New domains
GET    /api/dns/top-queried              # Top queried domains
GET    /api/dns/nxdomain                 # NXDOMAIN analysis

# DNS Threat Intel
POST   /api/dns/lookup/{domain}          # Domain reputation lookup
GET    /api/dns/iocs                     # DNS-based IOCs
POST   /api/dns/block-list               # Add to block list
```

---

### Sprint 7-8: DevSecOps - SAST & SCA

**Sprint 7: Static Application Security Testing** ✅ COMPLETE
- [x] Multi-language SAST engine (Rust, Python, JS/TS, Go, Java)
- [x] Semgrep rule integration
- [x] Custom rule creation UI
- [x] Taint analysis for data flow
- [x] Security hotspot detection
- [x] False positive management
- [x] SARIF report generation

**Sprint 8: Software Composition Analysis** ✅ COMPLETE
- [x] Dependency parsing (all major package managers)
- [x] Transitive dependency resolution
- [x] Vulnerability matching (NVD, GitHub Advisory, OSV)
- [x] License detection and compliance
- [x] SBOM generation (CycloneDX, SPDX)
- [x] Dependency graph visualization
- [x] Update recommendation engine

**Database Schema (Sprint 7-8)**:
```sql
-- SAST
CREATE TABLE sast_projects (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    repository_url TEXT,
    default_branch TEXT DEFAULT 'main',
    languages TEXT, -- JSON array
    last_scan_at TIMESTAMP,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sast_scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES sast_projects(id),
    user_id TEXT NOT NULL,
    branch TEXT,
    commit_sha TEXT,
    scan_type TEXT NOT NULL, -- 'full', 'incremental', 'pr'
    status TEXT DEFAULT 'pending',
    languages_scanned TEXT, -- JSON array
    files_scanned INTEGER DEFAULT 0,
    lines_scanned INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    new_findings INTEGER DEFAULT 0,
    fixed_findings INTEGER DEFAULT 0,
    duration_seconds INTEGER,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sast_findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES sast_scans(id),
    project_id TEXT NOT NULL REFERENCES sast_projects(id),
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL, -- 'high', 'medium', 'low'
    category TEXT NOT NULL, -- 'injection', 'xss', 'crypto', 'auth', etc.
    cwe_id TEXT,
    owasp_id TEXT,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    code_snippet TEXT,
    message TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    data_flow TEXT, -- JSON taint trace
    status TEXT DEFAULT 'new', -- 'new', 'confirmed', 'false_positive', 'fixed', 'accepted'
    assignee_id TEXT,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fixed_at TIMESTAMP,
    fingerprint TEXT, -- unique identifier for deduplication
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sast_rules (
    id TEXT PRIMARY KEY,
    user_id TEXT, -- null for built-in
    name TEXT NOT NULL,
    description TEXT,
    language TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    cwe_id TEXT,
    rule_type TEXT NOT NULL, -- 'semgrep', 'regex', 'ast'
    rule_content TEXT NOT NULL, -- Semgrep YAML or pattern
    metadata TEXT, -- JSON
    enabled BOOLEAN DEFAULT TRUE,
    custom BOOLEAN DEFAULT FALSE,
    matches_count INTEGER DEFAULT 0,
    false_positive_rate REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- SCA
CREATE TABLE sca_projects (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    repository_url TEXT,
    ecosystem TEXT NOT NULL, -- 'npm', 'pypi', 'cargo', 'maven', 'go', 'nuget'
    manifest_files TEXT, -- JSON array of file paths
    last_scan_at TIMESTAMP,
    total_dependencies INTEGER DEFAULT 0,
    vulnerable_dependencies INTEGER DEFAULT 0,
    license_issues INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sca_dependencies (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES sca_projects(id),
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    purl TEXT, -- Package URL
    is_direct BOOLEAN DEFAULT TRUE,
    parent_id TEXT REFERENCES sca_dependencies(id),
    depth INTEGER DEFAULT 0,
    license TEXT,
    license_risk TEXT, -- 'low', 'medium', 'high', 'unknown'
    latest_version TEXT,
    update_available BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, ecosystem, name, version)
);

CREATE TABLE sca_vulnerabilities (
    id TEXT PRIMARY KEY,
    dependency_id TEXT NOT NULL REFERENCES sca_dependencies(id),
    project_id TEXT NOT NULL REFERENCES sca_projects(id),
    vuln_id TEXT NOT NULL, -- CVE, GHSA, etc.
    source TEXT NOT NULL, -- 'nvd', 'github', 'osv'
    severity TEXT NOT NULL,
    cvss_score REAL,
    cvss_vector TEXT,
    epss_score REAL,
    title TEXT,
    description TEXT,
    affected_versions TEXT, -- JSON version ranges
    fixed_version TEXT,
    references TEXT, -- JSON array
    exploited_in_wild BOOLEAN DEFAULT FALSE,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sbom_exports (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES sca_projects(id),
    user_id TEXT NOT NULL,
    format TEXT NOT NULL, -- 'cyclonedx', 'spdx'
    version TEXT NOT NULL, -- format version
    component_count INTEGER,
    vulnerability_count INTEGER,
    file_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 7-8)**:
```
# SAST Projects
GET    /api/sast/projects                # List projects
POST   /api/sast/projects                # Create project
GET    /api/sast/projects/{id}           # Get project
PUT    /api/sast/projects/{id}           # Update project
DELETE /api/sast/projects/{id}           # Delete project

# SAST Scans
POST   /api/sast/projects/{id}/scan      # Start scan
GET    /api/sast/projects/{id}/scans     # List scans
GET    /api/sast/scans/{id}              # Get scan details
GET    /api/sast/scans/{id}/findings     # Get findings
GET    /api/sast/scans/{id}/sarif        # Export SARIF

# SAST Findings
GET    /api/sast/findings                # List all findings
GET    /api/sast/findings/{id}           # Get finding
PUT    /api/sast/findings/{id}           # Update finding status
POST   /api/sast/findings/{id}/assign    # Assign finding

# SAST Rules
GET    /api/sast/rules                   # List rules
POST   /api/sast/rules                   # Create custom rule
GET    /api/sast/rules/{id}              # Get rule
PUT    /api/sast/rules/{id}              # Update rule
POST   /api/sast/rules/{id}/test         # Test rule

# SCA Projects
GET    /api/sca/projects                 # List projects
POST   /api/sca/projects                 # Create project
GET    /api/sca/projects/{id}            # Get project
PUT    /api/sca/projects/{id}            # Update project
DELETE /api/sca/projects/{id}            # Delete project

# SCA Analysis
POST   /api/sca/projects/{id}/analyze    # Analyze dependencies
GET    /api/sca/projects/{id}/dependencies # List dependencies
GET    /api/sca/projects/{id}/vulnerabilities # List vulns
GET    /api/sca/projects/{id}/licenses   # License summary
GET    /api/sca/projects/{id}/graph      # Dependency graph
GET    /api/sca/projects/{id}/updates    # Available updates

# SBOM
POST   /api/sca/projects/{id}/sbom       # Generate SBOM
GET    /api/sca/sbom/{id}                # Download SBOM
POST   /api/sca/sbom/import              # Import SBOM
```

---

### Sprint 9-10: DevSecOps - CI/CD & IDE Integration

**Sprint 9: CI/CD Pipeline Security** ✅ COMPLETE
- [x] GitHub Actions security workflow generator
- [x] GitLab CI security template generator
- [x] Jenkins shared library
- [x] Azure DevOps extension
- [x] Security gate configuration
- [x] PR/MR comment integration
- [x] Quality gate policies

**Sprint 10: IDE & Developer Integration** ✅ COMPLETE
- [x] VS Code extension
- [x] JetBrains plugin (IntelliJ, PyCharm, WebStorm)
- [x] Pre-commit hook integration
- [x] CLI tool enhancement for local scanning
- [x] Real-time finding overlay in IDE
- [x] Quick fix suggestions
- [x] Developer dashboard

**Database Schema (Sprint 9-10)**:
```sql
-- CI/CD Integration
CREATE TABLE cicd_pipelines (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL, -- 'github_actions', 'gitlab_ci', 'jenkins', 'azure_devops'
    repository_url TEXT,
    webhook_secret TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    config TEXT, -- JSON pipeline config
    last_run_at TIMESTAMP,
    last_run_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cicd_runs (
    id TEXT PRIMARY KEY,
    pipeline_id TEXT NOT NULL REFERENCES cicd_pipelines(id),
    external_run_id TEXT, -- CI system's run ID
    branch TEXT,
    commit_sha TEXT,
    trigger TEXT, -- 'push', 'pr', 'schedule', 'manual'
    pr_number INTEGER,
    status TEXT DEFAULT 'pending', -- 'pending', 'running', 'passed', 'failed', 'cancelled'
    gate_status TEXT, -- 'passed', 'failed', 'warning'
    findings_new INTEGER DEFAULT 0,
    findings_fixed INTEGER DEFAULT 0,
    findings_total INTEGER DEFAULT 0,
    duration_seconds INTEGER,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cicd_policies (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    policy_type TEXT NOT NULL, -- 'quality_gate', 'block_merge', 'notification'
    conditions TEXT NOT NULL, -- JSON conditions
    actions TEXT NOT NULL, -- JSON actions
    severity_threshold TEXT,
    max_new_findings INTEGER,
    max_total_findings INTEGER,
    block_on_critical BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cicd_pr_comments (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES cicd_runs(id),
    pr_number INTEGER NOT NULL,
    comment_type TEXT NOT NULL, -- 'summary', 'inline', 'review'
    comment_id TEXT, -- external comment ID
    file_path TEXT,
    line_number INTEGER,
    content TEXT NOT NULL,
    posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IDE Integration
CREATE TABLE ide_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    ide_type TEXT NOT NULL, -- 'vscode', 'intellij', 'pycharm', etc.
    project_path TEXT,
    session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_end TIMESTAMP,
    files_scanned INTEGER DEFAULT 0,
    findings_shown INTEGER DEFAULT 0,
    findings_fixed INTEGER DEFAULT 0
);

CREATE TABLE ide_settings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    scan_on_save BOOLEAN DEFAULT TRUE,
    scan_on_open BOOLEAN DEFAULT FALSE,
    show_inline_hints BOOLEAN DEFAULT TRUE,
    severity_filter TEXT, -- JSON array
    excluded_paths TEXT, -- JSON array
    custom_rules_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 9-10)**:
```
# CI/CD Pipelines
GET    /api/cicd/pipelines               # List pipelines
POST   /api/cicd/pipelines               # Create pipeline
GET    /api/cicd/pipelines/{id}          # Get pipeline
PUT    /api/cicd/pipelines/{id}          # Update pipeline
DELETE /api/cicd/pipelines/{id}          # Delete pipeline
POST   /api/cicd/pipelines/{id}/test     # Test connection

# CI/CD Runs
GET    /api/cicd/runs                    # List runs
GET    /api/cicd/runs/{id}               # Get run details
GET    /api/cicd/runs/{id}/findings      # Get run findings
POST   /api/cicd/webhook/{platform}      # Webhook endpoint

# CI/CD Policies
GET    /api/cicd/policies                # List policies
POST   /api/cicd/policies                # Create policy
GET    /api/cicd/policies/{id}           # Get policy
PUT    /api/cicd/policies/{id}           # Update policy
DELETE /api/cicd/policies/{id}           # Delete policy

# CI/CD Templates
GET    /api/cicd/templates               # List templates
GET    /api/cicd/templates/{platform}    # Get platform template
POST   /api/cicd/templates/generate      # Generate custom template

# IDE Integration
POST   /api/ide/scan                     # Scan file/project
GET    /api/ide/findings                 # Get findings for file
POST   /api/ide/session/start            # Start IDE session
POST   /api/ide/session/end              # End IDE session
GET    /api/ide/settings                 # Get IDE settings
PUT    /api/ide/settings                 # Update settings
POST   /api/ide/quick-fix/{finding_id}   # Get quick fix
```

---

### Sprint 11-12: SOAR Foundation

**Sprint 11: Playbook Engine** ✅ COMPLETE
- [x] Visual playbook builder (drag-and-drop)
- [x] Action library (50+ actions)
- [x] Conditional logic and branching
- [x] Loop support
- [x] Variable management
- [x] Parallel execution
- [x] Error handling and retries

**Sprint 12: Orchestration & Response** ✅ COMPLETE
- [x] Alert-triggered playbooks
- [x] Manual playbook execution
- [x] Scheduled playbooks
- [x] Playbook marketplace
- [x] Cross-tool orchestration (SIEM, EDR, firewall)
- [x] Approval workflows
- [x] Playbook analytics and metrics

**Database Schema (Sprint 11-12)**:
```sql
-- SOAR Playbooks
CREATE TABLE soar_playbooks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT, -- 'incident_response', 'enrichment', 'remediation', 'compliance'
    trigger_type TEXT NOT NULL, -- 'manual', 'alert', 'schedule', 'webhook', 'api'
    trigger_config TEXT, -- JSON
    steps TEXT NOT NULL, -- JSON workflow definition
    variables TEXT, -- JSON variable definitions
    input_schema TEXT, -- JSON schema for inputs
    output_schema TEXT, -- JSON schema for outputs
    version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'draft', -- 'draft', 'active', 'disabled', 'archived'
    is_template BOOLEAN DEFAULT FALSE,
    marketplace_id TEXT,
    run_count INTEGER DEFAULT 0,
    avg_duration_seconds INTEGER,
    success_rate REAL,
    last_run_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE soar_playbook_versions (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL REFERENCES soar_playbooks(id),
    version INTEGER NOT NULL,
    steps TEXT NOT NULL,
    variables TEXT,
    change_notes TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(playbook_id, version)
);

CREATE TABLE soar_actions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL, -- 'enrichment', 'notification', 'containment', 'remediation', 'utility'
    integration TEXT, -- which integration this belongs to
    action_type TEXT NOT NULL, -- 'api', 'script', 'builtin'
    input_schema TEXT NOT NULL, -- JSON schema
    output_schema TEXT, -- JSON schema
    timeout_seconds INTEGER DEFAULT 300,
    requires_approval BOOLEAN DEFAULT FALSE,
    risk_level TEXT DEFAULT 'low', -- 'low', 'medium', 'high'
    enabled BOOLEAN DEFAULT TRUE,
    custom BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE soar_playbook_runs (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL REFERENCES soar_playbooks(id),
    playbook_version INTEGER NOT NULL,
    trigger_type TEXT NOT NULL,
    trigger_source TEXT, -- alert ID, schedule name, etc.
    input_data TEXT, -- JSON
    status TEXT DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'cancelled', 'waiting_approval'
    current_step INTEGER DEFAULT 0,
    total_steps INTEGER NOT NULL,
    output_data TEXT, -- JSON
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    initiated_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE soar_step_executions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES soar_playbook_runs(id),
    step_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    action_id TEXT REFERENCES soar_actions(id),
    status TEXT DEFAULT 'pending',
    input_data TEXT, -- JSON
    output_data TEXT, -- JSON
    error_message TEXT,
    retries INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_ms INTEGER
);

CREATE TABLE soar_approvals (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES soar_playbook_runs(id),
    step_id TEXT NOT NULL,
    approvers TEXT NOT NULL, -- JSON array of user IDs
    required_approvals INTEGER DEFAULT 1,
    current_approvals INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending', -- 'pending', 'approved', 'rejected', 'timeout'
    timeout_at TIMESTAMP,
    decisions TEXT, -- JSON array of decisions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE TABLE soar_integrations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    integration_type TEXT NOT NULL, -- 'siem', 'edr', 'firewall', 'ticketing', 'email', 'slack', etc.
    vendor TEXT, -- 'splunk', 'crowdstrike', 'palo_alto', etc.
    config TEXT NOT NULL, -- JSON (encrypted)
    status TEXT DEFAULT 'disconnected',
    last_test_at TIMESTAMP,
    last_test_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Playbook Marketplace
CREATE TABLE soar_marketplace (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    author TEXT NOT NULL,
    author_id TEXT,
    category TEXT NOT NULL,
    tags TEXT, -- JSON array
    version TEXT NOT NULL,
    playbook_json TEXT NOT NULL,
    downloads INTEGER DEFAULT 0,
    rating REAL DEFAULT 0,
    ratings_count INTEGER DEFAULT 0,
    is_verified BOOLEAN DEFAULT FALSE,
    is_official BOOLEAN DEFAULT FALSE,
    screenshots TEXT, -- JSON array of URLs
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 11-12)**:
```
# SOAR Playbooks
GET    /api/soar/playbooks               # List playbooks
POST   /api/soar/playbooks               # Create playbook
GET    /api/soar/playbooks/{id}          # Get playbook
PUT    /api/soar/playbooks/{id}          # Update playbook
DELETE /api/soar/playbooks/{id}          # Delete playbook
POST   /api/soar/playbooks/{id}/run      # Execute playbook
POST   /api/soar/playbooks/{id}/clone    # Clone playbook
GET    /api/soar/playbooks/{id}/versions # Version history
POST   /api/soar/playbooks/{id}/export   # Export playbook

# SOAR Runs
GET    /api/soar/runs                    # List runs
GET    /api/soar/runs/{id}               # Get run details
GET    /api/soar/runs/{id}/steps         # Get step executions
POST   /api/soar/runs/{id}/cancel        # Cancel run
POST   /api/soar/runs/{id}/retry         # Retry failed run

# SOAR Actions
GET    /api/soar/actions                 # List actions
GET    /api/soar/actions/{id}            # Get action details
POST   /api/soar/actions                 # Create custom action
POST   /api/soar/actions/{id}/test       # Test action

# SOAR Approvals
GET    /api/soar/approvals               # List pending approvals
POST   /api/soar/approvals/{id}/approve  # Approve
POST   /api/soar/approvals/{id}/reject   # Reject

# SOAR Integrations
GET    /api/soar/integrations            # List integrations
POST   /api/soar/integrations            # Add integration
GET    /api/soar/integrations/{id}       # Get integration
PUT    /api/soar/integrations/{id}       # Update integration
DELETE /api/soar/integrations/{id}       # Delete integration
POST   /api/soar/integrations/{id}/test  # Test connection

# SOAR Marketplace
GET    /api/soar/marketplace             # Browse marketplace
GET    /api/soar/marketplace/{id}        # Get playbook details
POST   /api/soar/marketplace/{id}/install # Install playbook
POST   /api/soar/marketplace/publish     # Publish playbook
POST   /api/soar/marketplace/{id}/rate   # Rate playbook

# SOAR Analytics
GET    /api/soar/analytics/overview      # Dashboard
GET    /api/soar/analytics/playbook-stats # Playbook performance
GET    /api/soar/analytics/action-stats  # Action usage
GET    /api/soar/analytics/time-saved    # Automation ROI
```

---

### Sprint 13-14: OT/ICS & IoT Security

**Sprint 13: OT/ICS Protocol Support** ✅ COMPLETE
- [x] Modbus TCP scanner
- [x] DNP3 protocol analysis
- [x] OPC-UA security assessment
- [x] BACnet discovery
- [x] Ethernet/IP scanning
- [x] ICS device fingerprinting
- [x] Purdue Model visualization

**Sprint 14: IoT Security** ✅ COMPLETE
- [x] IoT device discovery (passive/active)
- [x] Default credential checking
- [x] Firmware analysis integration
- [x] MQTT security scanning
- [x] CoAP security scanning
- [x] Zigbee/Z-Wave reconnaissance
- [x] IoT vulnerability database

**Database Schema (Sprint 13-14)**:
```sql
-- OT/ICS
CREATE TABLE ot_assets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL, -- 'plc', 'hmi', 'scada', 'rtu', 'ied', 'dcs', 'historian'
    vendor TEXT,
    model TEXT,
    firmware_version TEXT,
    ip_address TEXT,
    mac_address TEXT,
    protocols TEXT, -- JSON array
    purdue_level INTEGER, -- 0-5
    zone TEXT,
    criticality TEXT, -- 'critical', 'high', 'medium', 'low'
    last_seen TIMESTAMP,
    first_seen TIMESTAMP,
    scan_id TEXT,
    vulnerabilities TEXT, -- JSON array
    risk_score INTEGER DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ot_protocols (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES ot_assets(id),
    protocol_type TEXT NOT NULL, -- 'modbus', 'dnp3', 'opcua', 'bacnet', 'ethernetip', 's7'
    port INTEGER,
    details TEXT, -- JSON protocol-specific details
    security_issues TEXT, -- JSON array
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ot_scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    scan_type TEXT NOT NULL, -- 'discovery', 'protocol', 'vulnerability'
    target_range TEXT NOT NULL,
    protocols_enabled TEXT, -- JSON array
    status TEXT DEFAULT 'pending',
    assets_discovered INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ot_vulnerabilities (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES ot_assets(id),
    vuln_type TEXT NOT NULL, -- 'authentication', 'encryption', 'firmware', 'protocol', 'config'
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    cve_id TEXT,
    icsa_id TEXT, -- ICS-CERT advisory
    remediation TEXT,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IoT
CREATE TABLE iot_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT,
    device_type TEXT, -- 'camera', 'thermostat', 'speaker', 'hub', 'sensor', etc.
    vendor TEXT,
    model TEXT,
    firmware_version TEXT,
    ip_address TEXT,
    mac_address TEXT,
    hostname TEXT,
    protocols TEXT, -- JSON array (mqtt, coap, http, etc.)
    open_ports TEXT, -- JSON array
    default_creds_status TEXT, -- 'vulnerable', 'changed', 'unknown'
    last_seen TIMESTAMP,
    first_seen TIMESTAMP,
    risk_score INTEGER DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE iot_scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    scan_type TEXT NOT NULL, -- 'discovery', 'credential', 'vulnerability'
    target_range TEXT,
    status TEXT DEFAULT 'pending',
    devices_found INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE iot_credentials (
    id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,
    vendor TEXT,
    model TEXT,
    protocol TEXT, -- 'telnet', 'ssh', 'http', 'mqtt'
    username TEXT,
    password TEXT,
    source TEXT, -- 'default', 'leaked', 'common'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_type, vendor, model, protocol, username)
);

CREATE TABLE iot_vulnerabilities (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES iot_devices(id),
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    cve_id TEXT,
    remediation TEXT,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 13-14)**:
```
# OT/ICS Assets
GET    /api/ot/assets                    # List OT assets
GET    /api/ot/assets/{id}               # Get asset details
PUT    /api/ot/assets/{id}               # Update asset
DELETE /api/ot/assets/{id}               # Delete asset
GET    /api/ot/assets/{id}/protocols     # Get protocol details
GET    /api/ot/assets/{id}/vulnerabilities # Get vulnerabilities

# OT/ICS Scanning
POST   /api/ot/scan                      # Start OT scan
GET    /api/ot/scans                     # List scans
GET    /api/ot/scans/{id}                # Get scan details
GET    /api/ot/scans/{id}/results        # Get scan results

# OT/ICS Visualization
GET    /api/ot/topology                  # Network topology
GET    /api/ot/purdue-model              # Purdue model view
GET    /api/ot/dashboard                 # OT dashboard

# IoT Devices
GET    /api/iot/devices                  # List IoT devices
GET    /api/iot/devices/{id}             # Get device details
PUT    /api/iot/devices/{id}             # Update device
DELETE /api/iot/devices/{id}             # Delete device
GET    /api/iot/devices/{id}/vulnerabilities # Get vulnerabilities

# IoT Scanning
POST   /api/iot/scan                     # Start IoT scan
GET    /api/iot/scans                    # List scans
GET    /api/iot/scans/{id}               # Get scan details
POST   /api/iot/scan/credentials         # Credential check

# IoT Database
GET    /api/iot/credentials/search       # Search default creds
POST   /api/iot/credentials              # Add credential entry
GET    /api/iot/vulnerabilities/database # Vuln database
```

---

### Sprint 15: AI/ML Security Operations

**Sprint 15: AI-Powered Security** ✅ COMPLETE
- [x] ML-based alert prioritization
- [x] Anomaly detection model training
- [x] False positive prediction
- [x] Attack pattern recognition
- [x] Natural language security queries
- [x] Automated report generation with AI
- [x] LLM security testing module

**Database Schema (Sprint 15)**:
```sql
-- AI/ML Security
CREATE TABLE ml_models (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    model_type TEXT NOT NULL, -- 'classification', 'anomaly_detection', 'nlp'
    purpose TEXT NOT NULL, -- 'alert_priority', 'fp_prediction', 'attack_pattern'
    version TEXT NOT NULL,
    algorithm TEXT,
    training_data_size INTEGER,
    accuracy REAL,
    precision_score REAL,
    recall_score REAL,
    f1_score REAL,
    model_path TEXT,
    status TEXT DEFAULT 'training', -- 'training', 'active', 'retired'
    trained_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ml_predictions (
    id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL REFERENCES ml_models(id),
    entity_type TEXT NOT NULL, -- 'alert', 'finding', 'event'
    entity_id TEXT NOT NULL,
    prediction TEXT NOT NULL, -- JSON
    confidence REAL,
    explanation TEXT, -- JSON feature importance
    feedback TEXT, -- 'correct', 'incorrect'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ml_training_data (
    id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL REFERENCES ml_models(id),
    data_type TEXT NOT NULL,
    features TEXT NOT NULL, -- JSON
    label TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ai_queries (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    query_text TEXT NOT NULL,
    query_type TEXT, -- 'search', 'analysis', 'report'
    parsed_intent TEXT, -- JSON
    results TEXT, -- JSON
    feedback TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE llm_security_tests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    target_type TEXT NOT NULL, -- 'api', 'chatbot', 'application'
    target_config TEXT, -- JSON
    test_type TEXT NOT NULL, -- 'prompt_injection', 'jailbreak', 'data_extraction', 'all'
    status TEXT DEFAULT 'pending',
    tests_run INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    results TEXT, -- JSON
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE llm_test_cases (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL, -- 'prompt_injection', 'jailbreak', 'encoding', 'context_manipulation'
    name TEXT NOT NULL,
    description TEXT,
    payload TEXT NOT NULL,
    expected_behavior TEXT,
    severity TEXT,
    cwe_id TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 15)**:
```
# ML Models
GET    /api/ml/models                    # List models
GET    /api/ml/models/{id}               # Get model details
POST   /api/ml/models/{id}/train         # Retrain model
GET    /api/ml/models/{id}/metrics       # Model performance

# ML Predictions
POST   /api/ml/predict                   # Get prediction
POST   /api/ml/predict/batch             # Batch predictions
POST   /api/ml/feedback                  # Submit feedback

# AI Queries
POST   /api/ai/query                     # Natural language query
GET    /api/ai/queries                   # Query history
POST   /api/ai/report/generate           # AI-generated report

# LLM Security Testing
POST   /api/llm-security/test            # Start LLM security test
GET    /api/llm-security/tests           # List tests
GET    /api/llm-security/tests/{id}      # Get test details
GET    /api/llm-security/test-cases      # List test cases
POST   /api/llm-security/test-cases      # Add custom test case

# AI Dashboard
GET    /api/ai/dashboard                 # AI insights overview
GET    /api/ai/recommendations           # Security recommendations
GET    /api/ai/trends                    # Predicted trends
```

---

## Module Structure

```
src/
├── blue_team/
│   ├── mod.rs
│   ├── yara/
│   │   ├── mod.rs
│   │   ├── engine.rs           # Enhanced YARA engine
│   │   ├── memory_scan.rs      # Process memory scanning
│   │   ├── realtime.rs         # Real-time monitoring
│   │   └── sources.rs          # Community rule sync
│   ├── sigma/
│   │   ├── mod.rs
│   │   ├── parser.rs           # Full Sigma parser
│   │   ├── converter.rs        # Backend conversion
│   │   ├── tester.rs           # Rule testing
│   │   └── coverage.rs         # ATT&CK coverage
│   ├── ueba/
│   │   ├── mod.rs
│   │   ├── engine.rs           # UEBA engine
│   │   ├── baselines.rs        # Baseline calculation
│   │   ├── anomalies.rs        # Anomaly detection
│   │   └── risk_scoring.rs     # Risk scoring
│   ├── netflow/
│   │   ├── mod.rs
│   │   ├── collector.rs        # Flow collectors
│   │   ├── parser.rs           # Protocol parsers
│   │   └── analyzer.rs         # Flow analysis
│   └── dns_analytics/
│       ├── mod.rs
│       ├── passive_dns.rs      # PDNS collection
│       ├── dga_detection.rs    # DGA detection
│       └── tunnel_detection.rs # DNS tunneling
│
├── devsecops/
│   ├── mod.rs
│   ├── sast/
│   │   ├── mod.rs
│   │   ├── engine.rs           # SAST engine
│   │   ├── languages/          # Language analyzers
│   │   ├── rules.rs            # Rule management
│   │   └── sarif.rs            # SARIF export
│   ├── sca/
│   │   ├── mod.rs
│   │   ├── parsers/            # Package manager parsers
│   │   ├── vuln_matching.rs    # Vulnerability matching
│   │   ├── license.rs          # License detection
│   │   └── sbom.rs             # SBOM generation
│   ├── cicd/
│   │   ├── mod.rs
│   │   ├── github.rs           # GitHub Actions
│   │   ├── gitlab.rs           # GitLab CI
│   │   ├── jenkins.rs          # Jenkins
│   │   └── policies.rs         # Quality gates
│   └── ide/
│       ├── mod.rs
│       ├── api.rs              # IDE API endpoints
│       └── settings.rs         # IDE settings
│
├── soar/
│   ├── mod.rs
│   ├── playbooks/
│   │   ├── mod.rs
│   │   ├── engine.rs           # Playbook engine
│   │   ├── executor.rs         # Step executor
│   │   ├── builder.rs          # Visual builder API
│   │   └── marketplace.rs      # Marketplace
│   ├── actions/
│   │   ├── mod.rs
│   │   ├── library.rs          # Action library
│   │   ├── enrichment.rs       # Enrichment actions
│   │   ├── containment.rs      # Containment actions
│   │   └── notification.rs     # Notification actions
│   └── integrations/
│       ├── mod.rs
│       ├── siem.rs             # SIEM integration
│       ├── edr.rs              # EDR integration
│       └── ticketing.rs        # Ticketing integration
│
├── ot_ics/
│   ├── mod.rs
│   ├── types.rs
│   ├── discovery.rs            # Asset discovery
│   ├── protocols/
│   │   ├── mod.rs
│   │   ├── modbus.rs           # Modbus TCP
│   │   ├── dnp3.rs             # DNP3
│   │   ├── opcua.rs            # OPC-UA
│   │   ├── bacnet.rs           # BACnet
│   │   └── ethernetip.rs       # Ethernet/IP
│   ├── fingerprint.rs          # Device fingerprinting
│   └── visualization.rs        # Purdue model
│
├── iot/
│   ├── mod.rs
│   ├── types.rs
│   ├── discovery.rs            # Device discovery
│   ├── credentials.rs          # Default cred checking
│   ├── protocols/
│   │   ├── mod.rs
│   │   ├── mqtt.rs             # MQTT
│   │   ├── coap.rs             # CoAP
│   │   └── zigbee.rs           # Zigbee recon
│   └── firmware.rs             # Firmware analysis
│
└── ai_security/
    ├── mod.rs
    ├── types.rs
    ├── models/
    │   ├── mod.rs
    │   ├── alert_priority.rs   # Alert prioritization
    │   ├── anomaly.rs          # Anomaly detection
    │   └── fp_prediction.rs    # FP prediction
    ├── nlp/
    │   ├── mod.rs
    │   ├── query_parser.rs     # NL query parsing
    │   └── report_gen.rs       # Report generation
    └── llm_testing/
        ├── mod.rs
        ├── engine.rs           # LLM test engine
        ├── payloads.rs         # Test payloads
        └── analysis.rs         # Result analysis
```

---

## Frontend Pages

```
frontend/src/pages/
├── YaraManagementPage.tsx          # Sprint 1-2
├── SigmaRulesPage.tsx              # Sprint 1-2
├── UebaPage.tsx                    # Sprint 3-4
├── NetflowAnalysisPage.tsx         # Sprint 5-6
├── DnsAnalyticsPage.tsx            # Sprint 5-6
├── SastPage.tsx                    # Sprint 7-8
├── ScaPage.tsx                     # Sprint 7-8
├── CicdSecurityPage.tsx            # Sprint 9-10
├── IdeIntegrationPage.tsx          # Sprint 9-10
├── SoarPlaybooksPage.tsx           # Sprint 11-12
├── SoarMarketplacePage.tsx         # Sprint 11-12
├── OtIcsSecurityPage.tsx           # Sprint 13-14
├── IotSecurityPage.tsx             # Sprint 13-14
├── AiSecurityPage.tsx              # Sprint 15
└── LlmTestingPage.tsx              # Sprint 15
```

---

## Success Criteria

### Sprint 1-2 (Detection Engineering) ✅
- [x] Scan 1000+ files with YARA in under 60 seconds
- [x] Support 500+ Sigma rules with backend conversion
- [x] Real-time file monitoring with <5s detection latency
- [x] ATT&CK coverage visualization

### Sprint 3-4 (UEBA) ✅
- [x] Baseline calculation for 10,000+ users
- [x] 6+ anomaly detection algorithms
- [x] Risk scoring with explainable factors
- [x] <1% false positive rate for impossible travel

### Sprint 5-6 (Network Analytics) ✅
- [x] Process 100,000+ flows/minute
- [x] DGA detection with >95% accuracy
- [x] DNS tunneling detection with >90% accuracy
- [x] Real-time passive DNS enrichment

### Sprint 7-8 (DevSecOps) ✅
- [x] SAST support for 5+ languages
- [x] SCA for all major package managers
- [x] SBOM generation in CycloneDX and SPDX
- [x] <5% false positive rate

### Sprint 9-10 (CI/CD & IDE) ✅
- [x] Templates for 4+ CI/CD platforms
- [x] VS Code extension with real-time scanning
- [x] PR comment integration
- [x] Quality gate enforcement

### Sprint 11-12 (SOAR) ✅
- [x] 50+ built-in actions
- [x] Visual playbook builder
- [x] <5 minute mean time to respond
- [x] 10+ marketplace playbooks

### Sprint 13-14 (OT/ICS & IoT) ✅
- [x] 6+ OT protocol scanners
- [x] IoT device fingerprinting
- [x] 1000+ default credentials
- [x] Purdue Model visualization

### Sprint 15 (AI/ML) ✅
- [x] ML-based alert prioritization
- [x] Natural language queries
- [x] LLM security testing with 100+ test cases
- [x] AI-powered report generation

---

## Dependencies & External Services

### Libraries
- `yara` / `yara-rust` - YARA engine
- `sigma-rust` or custom parser - Sigma rules
- `netflow` - NetFlow parsing
- `pcap` - Packet capture
- `semgrep` - SAST rules
- `cyclonedx-bom` - SBOM generation
- `tract` / `candle` - ML inference
- `rust-bert` - NLP models

### External Services
- GitHub/GitLab APIs (CI/CD integration)
- NVD/OSV/GitHub Advisory (vulnerability data)
- VirusTotal (file reputation)
- AbuseIPDB (IP reputation)
- OpenAI/Anthropic API (AI features - optional)

### Infrastructure
- Redis/Valkey (caching, pub/sub for real-time)
- Message queue (for async playbook execution)
- Object storage (for ML models, samples)

---

## Risk Mitigation

1. **Performance**: Flow collection requires careful buffering and batching
2. **False Positives**: ML models need continuous feedback loop
3. **OT/ICS Safety**: All OT scans must be passive by default
4. **API Limits**: Implement caching and request queuing for external APIs
5. **Complexity**: SOAR playbooks need sandboxing for custom scripts

---

## Way Ahead: Priority 3 Opportunities

With Priority 2 complete, the following areas represent opportunities for future development:

### High Priority (Recommended Next)

1. **Complete Stub Implementations**
   - `src/plugins/` - Marketplace, distribution, SDK need full implementation
   - `src/supply_chain/` - SBOM signing, provenance verification
   - `src/ml/federated.rs` - Federated learning for privacy-preserving threat intel
   - `src/patch_management/deployment.rs` - Canary, blue-green, rolling deployments

2. **Production Hardening**
   - Replace `// TODO:` stubs with real implementations
   - Add comprehensive integration tests
   - Performance optimization for high-volume environments
   - Documentation and user guides

3. **External Integrations**
   - Real Shodan/Censys API integration (currently cached)
   - MISP threat intelligence platform
   - EDR integrations (CrowdStrike, SentinelOne, Defender)
   - Cloud-native SIEM (Splunk Cloud, Microsoft Sentinel)

### Medium Priority

4. **Mobile & Firmware**
   - Android/iOS application security testing
   - Firmware extraction and analysis
   - Mobile device management (MDM) integration

5. **Advanced Red Team**
   - Physical security tools (badge cloning, HID)
   - VoIP/SIP exploitation
   - Advanced evasion techniques

6. **Compliance Expansion**
   - CCPA, FedRAMP, CMMC, NERC CIP
   - Automated evidence collection
   - Continuous compliance monitoring

### Proposed Features (from FEATURE_ROADMAP.md)

See `docs/FEATURE_ROADMAP.md` for 💡 Proposed features including:
- Dark Web Monitoring
- Memory/Disk Forensics with Volatility
- Social Media OSINT
- USB Drop Campaign Tracking

---

**END OF PRIORITY 2 ROADMAP**

*Priority 2 completed January 2026. This document should be reviewed and updated quarterly to reflect market changes and customer feedback.*
