# HeroForge Priority 1 Feature Implementation Plan
## Cybersecurity Research Platform Enhancement

---

## Overview

This plan implements 4 major feature categories with 32 features across 12 sprints.

**Timeline**: 12 sprints (2-week sprints = 24 weeks / 6 months)
**Goal**: Transform HeroForge into a comprehensive cybersecurity research platform

---

## Feature Categories

### Category A: Vulnerability Research & Exploit Development (8 features)
### Category B: Malware Analysis Lab (8 features)
### Category C: Network Traffic Analysis (8 features)
### Category D: Threat Intelligence Platform (8 features)

---

## Sprint Breakdown

### Sprint 1-2: Exploit Database & Research Foundation

**Sprint 1: Exploit Database Integration**
- [ ] Exploit-DB API integration (search, download, metadata)
- [ ] Metasploit module database integration
- [ ] PacketStorm feed integration
- [ ] CVE-to-exploit mapping engine
- [ ] Exploit search UI with filters (CVE, platform, type)
- [ ] Local exploit cache with versioning

**Sprint 2: PoC Repository & Research Workspace**
- [ ] PoC code repository with git-like versioning
- [ ] Research notes system (Markdown with linking)
- [ ] CVE research workspace UI
- [ ] Exploit development timeline tracking
- [ ] PoC testing sandbox integration
- [ ] Exploit effectiveness scoring

**Database Schema (Sprint 1-2)**:
```sql
-- Exploit Database
CREATE TABLE exploits (
    id TEXT PRIMARY KEY,
    exploit_db_id TEXT,
    metasploit_module TEXT,
    cve_ids TEXT, -- JSON array
    title TEXT NOT NULL,
    description TEXT,
    platform TEXT, -- windows, linux, multi, etc.
    architecture TEXT, -- x86, x64, arm, etc.
    exploit_type TEXT, -- remote, local, webapps, dos
    author TEXT,
    source_url TEXT,
    source TEXT, -- exploit_db, metasploit, packetstorm, custom
    code TEXT, -- actual exploit code
    language TEXT, -- python, ruby, c, etc.
    verified BOOLEAN DEFAULT FALSE,
    reliability TEXT, -- excellent, good, average, low
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE exploit_targets (
    id TEXT PRIMARY KEY,
    exploit_id TEXT NOT NULL REFERENCES exploits(id),
    product TEXT NOT NULL,
    version TEXT,
    os TEXT,
    notes TEXT
);

CREATE TABLE poc_repository (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    cve_id TEXT,
    exploit_id TEXT REFERENCES exploits(id),
    language TEXT,
    status TEXT DEFAULT 'development', -- development, testing, verified, failed
    code TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    parent_version_id TEXT,
    test_results TEXT, -- JSON
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE research_notes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL, -- Markdown
    tags TEXT, -- JSON array
    linked_cves TEXT, -- JSON array
    linked_exploits TEXT, -- JSON array
    linked_findings TEXT, -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**API Endpoints (Sprint 1-2)**:
```
# Exploit Database
GET    /api/exploits                    # Search exploits
GET    /api/exploits/{id}               # Get exploit details
GET    /api/exploits/by-cve/{cve}       # Get exploits for CVE
POST   /api/exploits/sync               # Sync from sources
GET    /api/exploits/sources            # List available sources

# PoC Repository
GET    /api/poc                         # List user's PoCs
POST   /api/poc                         # Create PoC
GET    /api/poc/{id}                    # Get PoC details
PUT    /api/poc/{id}                    # Update PoC
DELETE /api/poc/{id}                    # Delete PoC
GET    /api/poc/{id}/versions           # Version history
POST   /api/poc/{id}/test               # Test PoC in sandbox

# Research Notes
GET    /api/research/notes              # List notes
POST   /api/research/notes              # Create note
GET    /api/research/notes/{id}         # Get note
PUT    /api/research/notes/{id}         # Update note
DELETE /api/research/notes/{id}         # Delete note
GET    /api/research/workspace/{cve}    # Get CVE workspace
```

---

### Sprint 3-4: Binary Analysis & Fuzzing

**Sprint 3: Binary Analysis Engine**
- [ ] PE file parser (headers, sections, imports, exports)
- [ ] ELF file parser (headers, sections, symbols)
- [ ] String extraction with encoding detection
- [ ] Entropy analysis for packer detection
- [ ] Hash computation (MD5, SHA1, SHA256, imphash, ssdeep)
- [ ] Basic disassembly (Capstone integration)
- [ ] Binary analysis UI with hex viewer

**Sprint 4: Fuzzing Framework**
- [ ] Protocol fuzzer engine (template-based)
- [ ] HTTP fuzzer with payload generation
- [ ] File format fuzzer (mutation-based)
- [ ] Grammar-based fuzzing support
- [ ] Crash detection and triage
- [ ] Coverage tracking integration
- [ ] Fuzzing campaign management UI

**Database Schema (Sprint 3-4)**:
```sql
-- Binary Analysis
CREATE TABLE binary_samples (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER,
    file_type TEXT, -- pe, elf, macho, etc.
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    ssdeep TEXT,
    imphash TEXT,
    entropy REAL,
    packed BOOLEAN DEFAULT FALSE,
    packer_name TEXT,
    architecture TEXT,
    analysis_status TEXT DEFAULT 'pending',
    analysis_results TEXT, -- JSON
    strings_extracted INTEGER,
    imports_count INTEGER,
    exports_count INTEGER,
    sections_json TEXT,
    upload_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE binary_strings (
    id TEXT PRIMARY KEY,
    sample_id TEXT NOT NULL REFERENCES binary_samples(id),
    string_value TEXT NOT NULL,
    encoding TEXT, -- ascii, utf-8, utf-16
    offset INTEGER,
    section TEXT,
    string_type TEXT -- url, ip, path, registry, etc.
);

-- Fuzzing
CREATE TABLE fuzzing_campaigns (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL, -- protocol, file, api
    target_config TEXT NOT NULL, -- JSON
    fuzzer_type TEXT NOT NULL, -- mutation, generation, grammar
    template TEXT, -- fuzzing template
    status TEXT DEFAULT 'created',
    total_iterations INTEGER DEFAULT 0,
    crashes_found INTEGER DEFAULT 0,
    unique_crashes INTEGER DEFAULT 0,
    coverage_percent REAL,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE fuzzing_crashes (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES fuzzing_campaigns(id),
    crash_type TEXT, -- segfault, heap_overflow, stack_overflow, etc.
    input_data BLOB,
    crash_hash TEXT, -- unique crash identifier
    stack_trace TEXT,
    registers TEXT, -- JSON
    exploitability TEXT, -- exploitable, probably_exploitable, unknown, not_exploitable
    reproduced BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### Sprint 5-6: Malware Analysis Foundation

**Sprint 5: Static Analysis Engine**
- [ ] Malware sample upload and storage (encrypted)
- [ ] Automated static analysis pipeline
- [ ] YARA rule matching engine (enhanced)
- [ ] Packer/crypter detection
- [ ] Suspicious API pattern detection
- [ ] Embedded resource extraction
- [ ] Certificate/signature verification
- [ ] Malware classification scoring

**Sprint 6: Sandbox Integration**
- [ ] Cuckoo Sandbox API integration
- [ ] Any.Run API integration
- [ ] Hybrid Analysis API integration
- [ ] Sandbox result normalization
- [ ] Behavioral report parsing
- [ ] Network IOC extraction from sandbox
- [ ] File IOC extraction from sandbox
- [ ] Sandbox comparison view

**Database Schema (Sprint 5-6)**:
```sql
-- Malware Analysis
CREATE TABLE malware_samples (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER,
    file_type TEXT,
    mime_type TEXT,
    md5 TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    ssdeep TEXT,
    imphash TEXT,
    tlsh TEXT, -- trend micro locality sensitive hash
    entropy REAL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source TEXT, -- upload, sandbox, feed
    classification TEXT, -- trojan, ransomware, rat, etc.
    family TEXT, -- malware family name
    threat_score INTEGER, -- 0-100
    tags TEXT, -- JSON array
    encrypted_path TEXT, -- encrypted storage path
    analysis_status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE malware_static_analysis (
    id TEXT PRIMARY KEY,
    sample_id TEXT NOT NULL REFERENCES malware_samples(id),
    pe_info TEXT, -- JSON (headers, sections, etc.)
    elf_info TEXT, -- JSON
    imports TEXT, -- JSON array
    exports TEXT, -- JSON array
    strings_interesting TEXT, -- JSON array of notable strings
    yara_matches TEXT, -- JSON array of rule matches
    packer_detected TEXT,
    compiler_detected TEXT,
    certificates TEXT, -- JSON
    resources TEXT, -- JSON array of embedded resources
    suspicious_patterns TEXT, -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE malware_sandbox_results (
    id TEXT PRIMARY KEY,
    sample_id TEXT NOT NULL REFERENCES malware_samples(id),
    sandbox_type TEXT NOT NULL, -- cuckoo, anyrun, hybrid_analysis
    sandbox_id TEXT, -- external ID
    status TEXT,
    score INTEGER,
    verdict TEXT, -- malicious, suspicious, clean
    processes TEXT, -- JSON array
    network_activity TEXT, -- JSON
    file_activity TEXT, -- JSON
    registry_activity TEXT, -- JSON
    dropped_files TEXT, -- JSON array
    signatures_matched TEXT, -- JSON array
    screenshots TEXT, -- JSON array of URLs
    raw_report TEXT, -- full JSON report
    submitted_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE malware_iocs (
    id TEXT PRIMARY KEY,
    sample_id TEXT NOT NULL REFERENCES malware_samples(id),
    ioc_type TEXT NOT NULL, -- ip, domain, url, hash, mutex, registry, file
    ioc_value TEXT NOT NULL,
    context TEXT, -- where it was found
    confidence INTEGER, -- 0-100
    source TEXT, -- static, dynamic, sandbox
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(sample_id, ioc_type, ioc_value)
);
```

---

### Sprint 7-8: Dynamic Analysis & YARA

**Sprint 7: Dynamic Analysis Hooks**
- [ ] Process monitoring framework
- [ ] API call hooking (Windows/Linux)
- [ ] Network capture during execution
- [ ] File system monitoring
- [ ] Registry monitoring (Windows)
- [ ] Behavior timeline generation
- [ ] Anti-analysis detection
- [ ] Execution environment isolation

**Sprint 8: YARA Rule Management**
- [ ] Visual YARA rule builder UI
- [ ] Rule syntax validation
- [ ] Rule testing against samples
- [ ] Rule performance metrics
- [ ] Community rule import (YARA-Rules repo)
- [ ] Rule versioning and history
- [ ] Rule effectiveness scoring
- [ ] Bulk scanning with rules

**Database Schema (Sprint 7-8)**:
```sql
-- YARA Rules
CREATE TABLE yara_rules (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    description TEXT,
    rule_content TEXT NOT NULL,
    tags TEXT, -- JSON array
    category TEXT, -- malware, packer, webshell, etc.
    threat_type TEXT, -- trojan, ransomware, etc.
    source TEXT, -- custom, community, vendor
    author TEXT,
    reference_urls TEXT, -- JSON array
    enabled BOOLEAN DEFAULT TRUE,
    matches_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    last_matched_at TIMESTAMP,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE yara_rule_matches (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES yara_rules(id),
    sample_id TEXT REFERENCES malware_samples(id),
    binary_id TEXT REFERENCES binary_samples(id),
    file_path TEXT,
    matched_strings TEXT, -- JSON array
    match_offset INTEGER,
    scan_type TEXT, -- file, memory, network
    false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### Sprint 9-10: Network Traffic Analysis

**Sprint 9: Deep Packet Inspection**
- [ ] PCAP upload and storage
- [ ] Protocol dissection engine (50+ protocols)
- [ ] Session reconstruction
- [ ] File carving from streams
- [ ] SSL/TLS decryption (with keys)
- [ ] DNS query/response analysis
- [ ] HTTP transaction extraction
- [ ] Statistical analysis (bytes, packets, duration)

**Sprint 10: IDS Integration & Traffic Replay**
- [ ] Suricata rule testing
- [ ] Zeek log parsing
- [ ] Snort rule validation
- [ ] Traffic replay with modification
- [ ] JA3/JA3S fingerprinting
- [ ] Beacon detection algorithms
- [ ] Protocol anomaly detection
- [ ] Network forensics timeline

**Database Schema (Sprint 9-10)**:
```sql
-- Network Traffic Analysis
CREATE TABLE pcap_captures (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER,
    file_hash TEXT,
    capture_start TIMESTAMP,
    capture_end TIMESTAMP,
    duration_seconds REAL,
    packet_count INTEGER,
    byte_count INTEGER,
    protocols_detected TEXT, -- JSON array
    storage_path TEXT,
    analysis_status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pcap_sessions (
    id TEXT PRIMARY KEY,
    pcap_id TEXT NOT NULL REFERENCES pcap_captures(id),
    session_type TEXT, -- tcp, udp, icmp
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT, -- http, dns, smtp, etc.
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    packets INTEGER,
    bytes_to_server INTEGER,
    bytes_to_client INTEGER,
    state TEXT, -- established, closed, reset
    extracted_files TEXT, -- JSON array of carved files
    notes TEXT
);

CREATE TABLE pcap_dns_queries (
    id TEXT PRIMARY KEY,
    pcap_id TEXT NOT NULL REFERENCES pcap_captures(id),
    session_id TEXT REFERENCES pcap_sessions(id),
    query_time TIMESTAMP,
    query_type TEXT, -- A, AAAA, MX, TXT, etc.
    query_name TEXT,
    response_code TEXT,
    answers TEXT, -- JSON array
    ttl INTEGER,
    is_suspicious BOOLEAN DEFAULT FALSE,
    dga_score REAL -- domain generation algorithm score
);

CREATE TABLE pcap_http_transactions (
    id TEXT PRIMARY KEY,
    pcap_id TEXT NOT NULL REFERENCES pcap_captures(id),
    session_id TEXT REFERENCES pcap_sessions(id),
    request_time TIMESTAMP,
    method TEXT,
    host TEXT,
    uri TEXT,
    user_agent TEXT,
    request_headers TEXT, -- JSON
    request_body_size INTEGER,
    response_code INTEGER,
    response_headers TEXT, -- JSON
    response_body_size INTEGER,
    content_type TEXT,
    is_suspicious BOOLEAN DEFAULT FALSE
);

CREATE TABLE ja3_fingerprints (
    id TEXT PRIMARY KEY,
    ja3_hash TEXT NOT NULL UNIQUE,
    ja3_string TEXT,
    ja3s_hash TEXT,
    ja3s_string TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    seen_count INTEGER DEFAULT 1,
    known_client TEXT, -- known application/malware
    threat_score INTEGER, -- 0-100
    notes TEXT
);

CREATE TABLE ids_rules (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    rule_type TEXT NOT NULL, -- suricata, snort, zeek
    sid INTEGER,
    rule_content TEXT NOT NULL,
    description TEXT,
    category TEXT,
    severity TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    source TEXT, -- custom, emerging_threats, etc.
    hits_count INTEGER DEFAULT 0,
    last_hit_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### Sprint 11-12: Threat Intelligence Platform

**Sprint 11: MISP & STIX Integration**
- [ ] MISP API full integration (events, attributes, objects)
- [ ] STIX 2.1 bundle import/export
- [ ] TAXII client for feed consumption
- [ ] IOC enrichment from MISP
- [ ] Threat actor correlation
- [ ] Event sharing and collaboration
- [ ] TLP (Traffic Light Protocol) support
- [ ] Galaxy/cluster integration

**Sprint 12: Threat Actor & Campaign Tracking**
- [ ] Threat actor profile database
- [ ] APT group tracking (TTPs, IOCs, targets)
- [ ] Campaign management and linking
- [ ] Diamond Model implementation
- [ ] Kill chain visualization
- [ ] Attribution confidence scoring
- [ ] Intelligence requirements tracking
- [ ] Threat briefing generation

**Database Schema (Sprint 11-12)**:
```sql
-- Threat Intelligence
CREATE TABLE threat_actors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    aliases TEXT, -- JSON array
    description TEXT,
    motivation TEXT, -- espionage, financial, hacktivism, etc.
    sophistication TEXT, -- novice, intermediate, advanced, expert
    resource_level TEXT, -- individual, small_team, organization, government
    primary_targets TEXT, -- JSON array of sectors
    target_regions TEXT, -- JSON array
    first_seen DATE,
    last_seen DATE,
    active BOOLEAN DEFAULT TRUE,
    mitre_groups TEXT, -- JSON array of MITRE group IDs
    external_references TEXT, -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE threat_actor_ttps (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES threat_actors(id),
    mitre_technique_id TEXT NOT NULL,
    mitre_tactic TEXT,
    description TEXT,
    tools_used TEXT, -- JSON array
    confidence INTEGER, -- 0-100
    first_observed DATE,
    last_observed DATE,
    references TEXT -- JSON array
);

CREATE TABLE threat_campaigns (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    actor_id TEXT REFERENCES threat_actors(id),
    status TEXT DEFAULT 'active', -- active, concluded, monitoring
    first_seen DATE,
    last_seen DATE,
    target_sectors TEXT, -- JSON array
    target_regions TEXT, -- JSON array
    target_organizations TEXT, -- JSON array
    objectives TEXT,
    kill_chain_phases TEXT, -- JSON array
    confidence INTEGER, -- 0-100
    tlp TEXT DEFAULT 'amber',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE campaign_iocs (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES threat_campaigns(id),
    ioc_id TEXT NOT NULL REFERENCES iocs(id),
    context TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    confidence INTEGER,
    UNIQUE(campaign_id, ioc_id)
);

CREATE TABLE campaign_incidents (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES threat_campaigns(id),
    incident_id TEXT, -- link to IR incidents
    victim_org TEXT,
    victim_sector TEXT,
    victim_region TEXT,
    attack_date DATE,
    discovery_date DATE,
    impact TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE misp_instances (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    api_key TEXT NOT NULL, -- encrypted
    verify_ssl BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,
    last_sync_at TIMESTAMP,
    sync_status TEXT,
    org_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE misp_events (
    id TEXT PRIMARY KEY,
    misp_instance_id TEXT NOT NULL REFERENCES misp_instances(id),
    misp_event_id TEXT NOT NULL,
    uuid TEXT,
    info TEXT,
    threat_level TEXT,
    analysis_status TEXT,
    distribution TEXT,
    org_name TEXT,
    date DATE,
    attribute_count INTEGER,
    published BOOLEAN,
    raw_event TEXT, -- JSON
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(misp_instance_id, misp_event_id)
);

CREATE TABLE stix_bundles (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    stix_version TEXT DEFAULT '2.1',
    object_count INTEGER,
    bundle_content TEXT, -- JSON
    source TEXT, -- import, export, taxii
    taxii_collection TEXT,
    imported_at TIMESTAMP,
    exported_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE intelligence_requirements (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    priority TEXT, -- critical, high, medium, low
    category TEXT, -- strategic, operational, tactical
    requester TEXT,
    status TEXT DEFAULT 'open', -- open, in_progress, answered, closed
    due_date DATE,
    answer TEXT,
    answered_at TIMESTAMP,
    linked_actors TEXT, -- JSON array
    linked_campaigns TEXT, -- JSON array
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Module Structure

```
src/
├── exploit_research/
│   ├── mod.rs
│   ├── types.rs
│   ├── exploit_db.rs         # Exploit-DB API
│   ├── metasploit.rs         # Metasploit module DB
│   ├── packetstorm.rs        # PacketStorm feed
│   ├── poc_repository.rs     # PoC management
│   └── research_notes.rs     # Research notes
│
├── binary_analysis/
│   ├── mod.rs
│   ├── types.rs
│   ├── pe_parser.rs          # PE file analysis
│   ├── elf_parser.rs         # ELF file analysis
│   ├── strings.rs            # String extraction
│   ├── entropy.rs            # Entropy analysis
│   ├── disassembly.rs        # Capstone integration
│   └── hashing.rs            # Hash computation
│
├── fuzzing/
│   ├── mod.rs
│   ├── types.rs
│   ├── engine.rs             # Fuzzing engine
│   ├── mutators.rs           # Mutation strategies
│   ├── generators.rs         # Input generation
│   ├── crash_triage.rs       # Crash analysis
│   └── coverage.rs           # Coverage tracking
│
├── malware_analysis/
│   ├── mod.rs
│   ├── types.rs
│   ├── sample_store.rs       # Encrypted sample storage
│   ├── static_analysis.rs    # Static analysis engine
│   ├── sandbox/
│   │   ├── mod.rs
│   │   ├── cuckoo.rs         # Cuckoo API
│   │   ├── anyrun.rs         # Any.Run API
│   │   └── hybrid.rs         # Hybrid Analysis API
│   ├── yara/
│   │   ├── mod.rs
│   │   ├── engine.rs         # YARA scanning
│   │   ├── rules.rs          # Rule management
│   │   └── builder.rs        # Visual rule builder
│   ├── ioc_extraction.rs     # IOC extraction
│   └── classification.rs     # Malware classification
│
├── traffic_analysis/
│   ├── mod.rs
│   ├── types.rs
│   ├── pcap/
│   │   ├── mod.rs
│   │   ├── parser.rs         # PCAP parsing
│   │   ├── sessions.rs       # Session reconstruction
│   │   └── carving.rs        # File carving
│   ├── protocols/
│   │   ├── mod.rs
│   │   ├── dns.rs            # DNS analysis
│   │   ├── http.rs           # HTTP analysis
│   │   ├── tls.rs            # TLS analysis
│   │   └── ...               # Other protocols
│   ├── ids/
│   │   ├── mod.rs
│   │   ├── suricata.rs       # Suricata integration
│   │   ├── zeek.rs           # Zeek integration
│   │   └── snort.rs          # Snort rules
│   ├── fingerprinting.rs     # JA3/JA3S
│   └── beacon_detection.rs   # C2 beacon detection
│
├── threat_intel/              # Enhanced existing module
│   ├── mod.rs
│   ├── types.rs
│   ├── misp/
│   │   ├── mod.rs
│   │   ├── client.rs         # MISP API client
│   │   ├── events.rs         # Event management
│   │   └── sync.rs           # Synchronization
│   ├── stix/
│   │   ├── mod.rs
│   │   ├── parser.rs         # STIX 2.1 parser
│   │   ├── builder.rs        # STIX builder
│   │   └── taxii.rs          # TAXII client
│   ├── actors.rs             # Threat actor profiles
│   ├── campaigns.rs          # Campaign tracking
│   ├── diamond.rs            # Diamond model
│   └── kill_chain.rs         # Kill chain mapping
```

---

## Frontend Pages

```
frontend/src/pages/
├── ExploitDatabasePage.tsx       # Sprint 1
├── PocRepositoryPage.tsx         # Sprint 2
├── ResearchWorkspacePage.tsx     # Sprint 2
├── BinaryAnalysisPage.tsx        # Sprint 3
├── FuzzingPage.tsx               # Sprint 4
├── MalwareAnalysisPage.tsx       # Sprint 5-6
├── YaraRulesPage.tsx             # Sprint 8
├── TrafficAnalysisPage.tsx       # Sprint 9-10
├── ThreatIntelPage.tsx           # Sprint 11-12 (enhanced)
├── ThreatActorsPage.tsx          # Sprint 12
└── CampaignTrackingPage.tsx      # Sprint 12
```

---

## Success Criteria

### Sprint 1-2 (Exploit Research)
- [ ] Search 50,000+ exploits from Exploit-DB
- [ ] Link exploits to discovered CVEs automatically
- [ ] Create and version PoC code
- [ ] Research notes with cross-references

### Sprint 3-4 (Binary Analysis & Fuzzing)
- [ ] Analyze PE and ELF files with full header parsing
- [ ] Detect 20+ common packers
- [ ] Run fuzzing campaigns with crash detection
- [ ] Generate crash exploitability reports

### Sprint 5-8 (Malware Analysis)
- [ ] Automated static analysis pipeline
- [ ] Integration with 3+ sandbox providers
- [ ] 500+ YARA rules loaded
- [ ] Visual YARA rule builder

### Sprint 9-10 (Traffic Analysis)
- [ ] Parse 50+ protocols from PCAP
- [ ] Extract files from network streams
- [ ] JA3 fingerprint database with threat scoring
- [ ] IDS rule testing framework

### Sprint 11-12 (Threat Intelligence)
- [ ] Full MISP synchronization
- [ ] STIX 2.1 import/export
- [ ] 100+ threat actor profiles
- [ ] Campaign tracking with Diamond Model

---

## Dependencies & External Services

### APIs Required
- Exploit-DB (free, rate limited)
- Any.Run (API key required)
- Hybrid Analysis (API key required)
- VirusTotal (API key required)
- MISP (self-hosted or community instance)

### Libraries
- `capstone` - Disassembly
- `yara` - YARA rule engine
- `pcap-parser` - PCAP parsing
- `goblin` - Binary parsing (PE/ELF)
- `stix2` - STIX 2.1 support

### Optional Infrastructure
- Cuckoo Sandbox (self-hosted)
- MISP instance (self-hosted recommended)
- TAXII server (for feed consumption)

---

## Risk Mitigation

1. **Malware Handling**: All samples encrypted at rest, isolated analysis
2. **Exploit Code**: No automatic execution, sandbox testing only
3. **Rate Limits**: Implement caching and request queuing
4. **Legal Compliance**: Terms of service acknowledgment for dangerous features
5. **Data Privacy**: TLP enforcement, access controls

---

## Getting Started

Begin with Sprint 1: Exploit Database Integration
- Low external dependencies
- High immediate value
- Foundation for PoC repository
