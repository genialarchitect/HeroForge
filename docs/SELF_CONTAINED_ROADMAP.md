# HeroForge Self-Contained Platform Roadmap

This document outlines the plan to make HeroForge a fully self-contained security platform that requires no external tools. The goal is to eliminate all dependencies on third-party executables while maintaining or improving functionality.

## Current External Dependencies

| Tool | Current Usage | Native Replacement Strategy |
|------|--------------|----------------------------|
| SharpHound/BloodHound | AD data collection | Native LDAP collection engine |
| Nuclei | Template-based scanning | Native template engine |
| Hashcat | Password cracking | Native GPU-accelerated cracker |
| Aircrack-ng | WiFi security | Native wireless analysis |
| smbclient | SMB enumeration | Native SMB protocol implementation |
| enum4linux | Windows enumeration | Native Windows enum via SMB/RPC |
| Volatility | Memory forensics | Native memory analysis (partial) |

---

## Phase 1: Core Protocol Implementations (Sprints 1-3)

### Sprint 1: Native LDAP/AD Collection Engine ✅ COMPLETE

Replace SharpHound dependency with native Active Directory data collection.

**Features:**
1. **Native LDAP Client**
   - LDAP bind (simple, NTLM, Kerberos)
   - Paged LDAP search for large domains
   - Connection pooling and failover
   - TLS/STARTTLS support

2. **AD Object Enumeration**
   - Users (attributes, group memberships, SPNs)
   - Computers (OS, delegation, services)
   - Groups (nested memberships, permissions)
   - GPOs (linked objects, settings)
   - OUs (structure, inheritance)
   - Trusts (type, direction, transitivity)
   - ACLs (DACLs, ownership, inheritance)

3. **Privilege Path Analysis**
   - Kerberoastable accounts detection
   - AS-REP roastable accounts
   - Delegation attack paths (unconstrained, constrained, RBCD)
   - ACL-based attack paths (GenericAll, WriteDacl, etc.)
   - Local admin path calculation
   - DCSync rights detection

4. **Session/Logon Collection**
   - NetSessionEnum
   - NetWkstaUserEnum
   - Remote registry logon sessions
   - RPC-based session collection

**Files to Create:**
```
src/scanner/ad_collector/
  mod.rs
  ldap_client.rs      # Native LDAP implementation
  kerberos.rs         # Kerberos authentication
  ntlm.rs             # NTLM authentication
  objects.rs          # AD object parsing
  acl_parser.rs       # Security descriptor parsing
  path_calculator.rs  # Attack path algorithms
  session_enum.rs     # Session collection
  types.rs
```

**Dependencies:**
- `ldap3` crate for LDAP protocol
- `gssapi` or custom Kerberos implementation
- `ntlm` crate for NTLM auth

---

### Sprint 2: Native SMB Protocol Stack ✅ COMPLETE

Replace smbclient and enum4linux with native SMB implementation.

**Features:**
1. **SMB Protocol Support**
   - SMB1, SMB2, SMB3 negotiation
   - Signing and encryption
   - Named pipe operations
   - File/share enumeration

2. **RPC Over Named Pipes**
   - SAMR (user/group enumeration)
   - LSARPC (LSA policy, SID resolution)
   - SRVSVC (share enumeration)
   - WKSSVC (workstation info)
   - DRSUAPI (DCSync simulation)

3. **Enumeration Features**
   - Share listing with permissions
   - File/directory enumeration
   - User/group enumeration
   - Password policy extraction
   - Trust relationship discovery

**Files to Create:**
```
src/scanner/smb_native/
  mod.rs
  protocol.rs         # SMB protocol implementation
  smb2.rs             # SMB2/3 specifics
  ntlm_auth.rs        # NTLM authentication
  rpc/
    mod.rs
    samr.rs           # SAMR operations
    lsarpc.rs         # LSA operations
    srvsvc.rs         # Server service
    wkssvc.rs         # Workstation service
  enumeration.rs      # High-level enum functions
  types.rs
```

**Dependencies:**
- `smb` or custom SMB implementation
- Binary parsing with `nom` or `binread`

---

### Sprint 3: Native Vulnerability Template Engine ✅ COMPLETE

Replace Nuclei with a native template-based vulnerability scanner.

**Features:**
1. **Template Format**
   - YAML-based templates (Nuclei-compatible)
   - Custom HeroForge template format
   - Template inheritance and composition
   - Automatic template updates

2. **Protocol Support**
   - HTTP/HTTPS with full request control
   - TCP raw sockets
   - UDP probes
   - DNS queries
   - WebSocket testing
   - Headless browser (via embedded Chromium)

3. **Matching Engine**
   - Regex matching
   - Binary pattern matching
   - DSL expressions
   - Multi-step workflows
   - OOB detection (DNS, HTTP callbacks)

4. **Execution Features**
   - Parallel template execution
   - Rate limiting per host
   - Smart deduplication
   - Result correlation

**Files to Create:**
```
src/scanner/template_engine/
  mod.rs
  parser.rs           # Template YAML parsing
  compiler.rs         # Template compilation
  executor.rs         # Template execution
  matcher.rs          # Response matching
  protocols/
    mod.rs
    http.rs
    tcp.rs
    udp.rs
    dns.rs
    websocket.rs
    headless.rs       # Headless browser
  oob/
    mod.rs
    dns_server.rs     # OOB DNS callback server
    http_server.rs    # OOB HTTP callback server
  types.rs
```

---

## Phase 2: Advanced Capabilities (Sprints 4-6)

### Sprint 4: Native Password Cracking Engine ✅ COMPLETE

Replace Hashcat/John with native GPU-accelerated password cracking.

**Features:**
1. **Hash Support**
   - NTLM
   - NetNTLMv2
   - Kerberos (AS-REP, TGS)
   - bcrypt, scrypt, Argon2
   - MD5, SHA1, SHA256, SHA512
   - PBKDF2

2. **Attack Modes**
   - Dictionary attack
   - Brute force
   - Rule-based mutations
   - Combinator attacks
   - Mask attacks
   - Markov chain attacks

3. **Acceleration**
   - SIMD vectorization (CPU)
   - OpenCL GPU support (future)
   - Distributed cracking via agents

4. **Wordlist Management**
   - Built-in common wordlists
   - Custom wordlist upload
   - Wordlist combination
   - Password policy-aware generation

**Files to Create:**
```
src/cracking/native/
  mod.rs
  engine.rs           # Main cracking engine
  hashes/
    mod.rs
    ntlm.rs
    netntlmv2.rs
    kerberos.rs
    bcrypt.rs
    md5_sha.rs
  attacks/
    mod.rs
    dictionary.rs
    bruteforce.rs
    rules.rs
    mask.rs
  wordlists/
    mod.rs
    embedded.rs       # Built-in wordlists
    manager.rs        # Wordlist management
  types.rs
```

---

### Sprint 5: Native Memory Forensics Engine

Enhance memory analysis capabilities beyond Volatility dependency.

**Features:**
1. **Memory Dump Parsing**
   - Raw memory dumps
   - Crash dumps (Windows)
   - Hibernation files
   - VMware snapshots (.vmem)
   - VirtualBox memory
   - Hyper-V snapshots

2. **OS-Specific Analysis**
   - **Windows:**
     - Process list reconstruction
     - DLL injection detection
     - Hollow process detection
     - Credential extraction (LSASS)
     - Registry hive extraction
     - Network connections
     - Kernel module analysis
   - **Linux:**
     - Task list reconstruction
     - Shared library analysis
     - Network connections
     - Kernel module analysis
     - Memory-mapped files

3. **Malware Detection**
   - Code injection patterns
   - Rootkit detection
   - Hidden process detection
   - Memory-only malware identification
   - YARA scanning of memory

4. **Artifact Extraction**
   - Command history
   - Browser artifacts
   - Clipboard contents
   - Screenshot detection
   - Decrypted credentials

**Files to Create:**
```
src/forensics/memory_native/
  mod.rs
  dump_parser.rs      # Memory dump format parsing
  windows/
    mod.rs
    processes.rs
    dlls.rs
    credentials.rs
    registry.rs
    networking.rs
    kernel.rs
  linux/
    mod.rs
    tasks.rs
    libraries.rs
    networking.rs
    kernel.rs
  detection/
    mod.rs
    injection.rs
    rootkit.rs
    hidden.rs
  extraction/
    mod.rs
    credentials.rs
    browser.rs
    history.rs
  types.rs
```

---

### Sprint 6: Native Wireless Security Engine

Replace Aircrack-ng with native wireless analysis.

**Features:**
1. **Wireless Scanning**
   - Access point enumeration
   - Client detection
   - Channel hopping
   - Hidden SSID discovery

2. **Security Analysis**
   - WPA/WPA2 handshake capture
   - PMKID attack support
   - WEP (legacy) analysis
   - WPA3 capability detection
   - Rogue AP detection
   - Evil twin detection

3. **Attack Capabilities**
   - Deauthentication (authorized testing)
   - Handshake capture
   - Beacon flood detection
   - Channel interference analysis

4. **Cracking Integration**
   - Native WPA/WPA2 PSK cracking
   - Dictionary attacks
   - Rule-based mutations
   - Cloud-based cracking integration

**Files to Create:**
```
src/scanner/wireless_native/
  mod.rs
  monitor.rs          # Monitor mode handling
  scanner.rs          # Network discovery
  handshake/
    mod.rs
    capture.rs        # 4-way handshake capture
    pmkid.rs          # PMKID extraction
  analysis/
    mod.rs
    security.rs       # Security assessment
    rogue_ap.rs       # Rogue AP detection
  cracking/
    mod.rs
    wpa.rs            # WPA/WPA2 cracking
  types.rs
```

**Note:** Wireless operations require `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.

---

## Phase 3: Integration & Polish (Sprints 7-9)

### Sprint 7: Unified Credential Management

Centralized credential handling across all native engines.

**Features:**
1. **Credential Store**
   - Encrypted credential storage
   - Automatic credential reuse
   - Credential health monitoring
   - Password expiration tracking

2. **Credential Discovery**
   - Automatic credential extraction from scans
   - Memory dump credential extraction
   - Config file credential discovery
   - Browser credential extraction

3. **Credential Attacks**
   - Password spraying (all protocols)
   - Credential stuffing
   - Kerberoasting (native)
   - AS-REP roasting (native)
   - Golden/Silver ticket generation

4. **Hash Management**
   - Hash identification
   - Hash storage
   - Cracking job management
   - Result correlation

**Files to Create:**
```
src/credentials/
  mod.rs
  store.rs            # Encrypted credential store
  discovery.rs        # Credential discovery
  attacks/
    mod.rs
    spray.rs          # Password spraying
    kerberoast.rs     # Kerberoasting
    asrep.rs          # AS-REP roasting
    tickets.rs        # Ticket attacks
  hashes/
    mod.rs
    identifier.rs     # Hash type identification
    manager.rs        # Hash job management
  types.rs
```

---

### Sprint 8: Native Network Protocol Analyzers

Deep packet analysis without external tools.

**Features:**
1. **Protocol Decoders**
   - HTTP/HTTPS (with TLS interception)
   - DNS (queries and responses)
   - SMB/CIFS
   - Kerberos
   - LDAP
   - RDP
   - SSH
   - SMTP/IMAP/POP3

2. **Traffic Analysis**
   - Protocol statistics
   - Anomaly detection
   - Exfiltration detection
   - C2 traffic identification
   - Encrypted traffic analysis

3. **Credential Extraction**
   - HTTP Basic/Digest auth
   - NTLM challenges/responses
   - Kerberos tickets
   - FTP credentials
   - SMTP credentials

4. **File Carving**
   - HTTP file extraction
   - SMB file transfers
   - Email attachments
   - Protocol-specific extraction

**Files to Create:**
```
src/traffic_analysis/native/
  mod.rs
  capture.rs          # Packet capture
  decoders/
    mod.rs
    http.rs
    dns.rs
    smb.rs
    kerberos.rs
    ldap.rs
    rdp.rs
    ssh.rs
    email.rs
  analysis/
    mod.rs
    anomaly.rs
    exfiltration.rs
    c2_detection.rs
  extraction/
    mod.rs
    credentials.rs
    files.rs
  types.rs
```

---

### Sprint 9: Performance & Production Hardening

Optimize all native implementations for production use.

**Features:**
1. **Performance Optimization**
   - Connection pooling across all protocols
   - Async I/O everywhere
   - Memory usage optimization
   - CPU/GPU load balancing

2. **Reliability**
   - Graceful degradation
   - Automatic retry with backoff
   - Circuit breakers for external services
   - Comprehensive error handling

3. **Observability**
   - Performance metrics per operation
   - Resource usage tracking
   - Scan progress estimation
   - Detailed timing breakdowns

4. **Security**
   - Credential encryption at rest
   - Secure memory handling
   - Audit logging
   - Rate limiting

---

## Migration Path

### For Existing Installations

1. **Parallel Operation Mode**
   - Native engines run alongside external tools
   - Results are merged and deduplicated
   - Gradual transition to native-only

2. **Compatibility Layer**
   - Accept existing Nuclei templates
   - Import SharpHound ZIP files
   - Convert Hashcat sessions

3. **Feature Parity Validation**
   - Automated comparison of results
   - Coverage analysis
   - Performance benchmarking

---

## Success Metrics

| Metric | Target |
|--------|--------|
| External tool dependencies | 0 |
| AD collection coverage | 100% of SharpHound features |
| Vulnerability template support | 90% Nuclei compatibility |
| Password cracking speed | Within 50% of Hashcat |
| Memory analysis coverage | 80% of Volatility features |

---

## Dependencies (Rust Crates)

```toml
# AD/LDAP
ldap3 = "0.11"
gssapi = "0.5"  # or custom Kerberos
ntlm = "0.1"

# SMB
smb = "0.3"  # or custom implementation

# Template Engine
tera = "1.19"  # Template rendering
regex = "1.10"
scraper = "0.19"  # HTML parsing
headless_chrome = "1.0"  # Headless browser

# Password Cracking
rayon = "1.10"  # Parallel processing
simd-json = "0.13"  # SIMD optimization

# Memory Analysis
memmap2 = "0.9"
goblin = "0.9"
yara-x = "0.5"

# Wireless
pcap = "2.0"
ieee80211 = "0.3"

# Network Analysis
pnet = "0.35"
etherparse = "0.15"
```

---

## Timeline Summary

| Phase | Sprints | Focus |
|-------|---------|-------|
| Phase 1 | 1-3 | Core protocols (LDAP, SMB, Templates) |
| Phase 2 | 4-6 | Advanced (Cracking, Memory, Wireless) |
| Phase 3 | 7-9 | Integration & Polish |

**Total: 9 sprints (4.5 months at 2 weeks/sprint)**

---

## Notes

- All native implementations will be async-first using Tokio
- Memory safety guaranteed by Rust's ownership model
- Cross-platform support (Linux primary, Windows secondary)
- Docker container includes all dependencies
- No external binaries required post-installation
