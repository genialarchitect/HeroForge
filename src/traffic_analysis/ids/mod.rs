//! IDS Rule Engine Module
//!
//! Suricata/Snort compatible rule parsing and matching:
//! - Rule file parsing (Suricata/Snort format)
//! - Content matching with modifiers
//! - PCRE pattern matching
//! - Flow tracking
//! - Alert generation

use crate::traffic_analysis::types::*;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;

/// IDS rule engine for Suricata/Snort rule matching
pub struct IdsEngine {
    /// Loaded rules
    rules: Vec<IdsRule>,
    /// Compiled rule patterns
    compiled_rules: Vec<CompiledIdsRule>,
    /// Generated alerts
    alerts: Vec<IdsAlert>,
    /// Rule hit counts
    hit_counts: HashMap<String, u64>,
}

/// Compiled IDS rule for efficient matching
#[derive(Debug)]
struct CompiledIdsRule {
    rule_id: String,
    /// Protocol filter
    protocol: IdsProtocol,
    /// Source address filter
    src_addr: AddressSpec,
    /// Source port filter
    src_port: PortSpec,
    /// Destination address filter
    dst_addr: AddressSpec,
    /// Destination port filter
    dst_port: PortSpec,
    /// Direction
    bidirectional: bool,
    /// Content patterns
    content_patterns: Vec<ContentPattern>,
    /// PCRE patterns
    pcre_patterns: Vec<Regex>,
    /// Flow options
    flow: FlowOptions,
    /// Threshold options
    threshold: Option<ThresholdOptions>,
}

/// Protocol specification
#[derive(Debug, Clone, PartialEq)]
enum IdsProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    Ip,
}

/// Address specification
#[derive(Debug, Clone)]
enum AddressSpec {
    Any,
    Single(IpAddr),
    Cidr(IpAddr, u8),
    Group(Vec<AddressSpec>),
    Negated(Box<AddressSpec>),
    Variable(String),
}

/// Port specification
#[derive(Debug, Clone)]
enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    Group(Vec<PortSpec>),
    Negated(Box<PortSpec>),
    Variable(String),
}

/// Content pattern with modifiers
#[derive(Debug)]
struct ContentPattern {
    /// Pattern bytes
    pattern: Vec<u8>,
    /// Case insensitive
    nocase: bool,
    /// Negated match
    negated: bool,
    /// Offset from start
    offset: Option<usize>,
    /// Depth to search
    depth: Option<usize>,
    /// Relative to previous match
    distance: Option<isize>,
    /// Within N bytes of previous
    within: Option<usize>,
    /// Fast pattern (primary match)
    fast_pattern: bool,
}

/// Flow options
#[derive(Debug, Default)]
struct FlowOptions {
    to_server: bool,
    to_client: bool,
    established: bool,
    not_established: bool,
    stateless: bool,
}

/// Threshold options
#[derive(Debug)]
struct ThresholdOptions {
    threshold_type: ThresholdType,
    track: TrackBy,
    count: u32,
    seconds: u32,
}

#[derive(Debug)]
enum ThresholdType {
    Threshold,
    Limit,
    Both,
}

#[derive(Debug)]
enum TrackBy {
    BySrc,
    ByDst,
    ByRule,
}

impl IdsEngine {
    /// Create a new IDS engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_rules: Vec::new(),
            alerts: Vec::new(),
            hit_counts: HashMap::new(),
        }
    }

    /// Load rules from file content
    pub fn load_rules_from_content(&mut self, content: &str, source: IdsRuleSource) -> Result<usize, String> {
        let mut loaded = 0;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse rule
            if let Some(rule) = self.parse_rule(line, &source) {
                if let Some(compiled) = self.compile_rule(&rule) {
                    self.compiled_rules.push(compiled);
                    self.rules.push(rule);
                    loaded += 1;
                }
            }
        }

        Ok(loaded)
    }

    /// Parse a single Suricata/Snort rule
    fn parse_rule(&self, line: &str, source: &IdsRuleSource) -> Option<IdsRule> {
        // Format: action protocol src_addr src_port -> dst_addr dst_port (options)

        // Find the options section
        let options_start = line.find('(')?;
        let options_end = line.rfind(')')?;

        let header = &line[..options_start].trim();
        let options = &line[options_start + 1..options_end];

        // Parse header
        let header_parts: Vec<&str> = header.split_whitespace().collect();
        if header_parts.len() < 6 {
            return None;
        }

        let _action = header_parts[0]; // alert, log, pass, drop, reject
        let _protocol = header_parts[1]; // tcp, udp, icmp, ip, any

        // Parse options
        let mut sid = None;
        let mut gid = None;
        let mut rev = 1u32;
        let mut msg = String::new();
        let mut classtype = String::new();
        let mut priority = IdsSeverity::Medium;
        let mut references = Vec::new();

        for opt in options.split(';') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            if let Some((key, value)) = opt.split_once(':') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');

                match key {
                    "sid" => sid = value.parse().ok(),
                    "gid" => gid = value.parse().ok(),
                    "rev" => rev = value.parse().unwrap_or(1),
                    "msg" => msg = value.to_string(),
                    "classtype" => classtype = value.to_string(),
                    "priority" => {
                        priority = match value {
                            "1" => IdsSeverity::Critical,
                            "2" => IdsSeverity::High,
                            "3" => IdsSeverity::Medium,
                            "4" => IdsSeverity::Low,
                            _ => IdsSeverity::Info,
                        };
                    }
                    "reference" => references.push(value.to_string()),
                    _ => {}
                }
            }
        }

        let sid = sid?;

        Some(IdsRule {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: None,
            rule_type: IdsRuleType::Suricata,
            sid: Some(sid),
            gid,
            revision: rev,
            rule_content: line.to_string(),
            message: msg,
            category: classtype,
            severity: priority,
            enabled: true,
            source: source.clone(),
            references,
            hits_count: 0,
            last_hit_at: None,
            created_at: Utc::now(),
        })
    }

    /// Compile a rule for efficient matching
    fn compile_rule(&self, rule: &IdsRule) -> Option<CompiledIdsRule> {
        let content = &rule.rule_content;

        // Find options section
        let options_start = content.find('(')?;
        let options_end = content.rfind(')')?;

        let header = &content[..options_start].trim();
        let options = &content[options_start + 1..options_end];

        // Parse header
        let header_parts: Vec<&str> = header.split_whitespace().collect();
        if header_parts.len() < 6 {
            return None;
        }

        let protocol = match header_parts[1] {
            "tcp" => IdsProtocol::Tcp,
            "udp" => IdsProtocol::Udp,
            "icmp" => IdsProtocol::Icmp,
            "ip" => IdsProtocol::Ip,
            _ => IdsProtocol::Any,
        };

        let src_addr = self.parse_address_spec(header_parts[2]);
        let src_port = self.parse_port_spec(header_parts[3]);

        let bidirectional = header_parts[4] == "<>";

        let dst_addr = self.parse_address_spec(header_parts[5]);
        let dst_port = if header_parts.len() > 6 {
            self.parse_port_spec(header_parts[6])
        } else {
            PortSpec::Any
        };

        // Parse options
        let mut content_patterns = Vec::new();
        let mut pcre_patterns = Vec::new();
        let mut flow = FlowOptions::default();
        let mut threshold = None;

        let mut current_content: Option<ContentPattern> = None;

        for opt in options.split(';') {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }

            if let Some((key, value)) = opt.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "content" => {
                        // Save previous content pattern
                        if let Some(cp) = current_content.take() {
                            content_patterns.push(cp);
                        }

                        let negated = value.starts_with('!');
                        let value = value.trim_start_matches('!').trim_matches('"');

                        // Parse content (handles hex with |XX XX|)
                        let pattern = self.parse_content_pattern(value);

                        current_content = Some(ContentPattern {
                            pattern,
                            nocase: false,
                            negated,
                            offset: None,
                            depth: None,
                            distance: None,
                            within: None,
                            fast_pattern: false,
                        });
                    }
                    "nocase" => {
                        if let Some(ref mut cp) = current_content {
                            cp.nocase = true;
                        }
                    }
                    "offset" => {
                        if let Some(ref mut cp) = current_content {
                            cp.offset = value.parse().ok();
                        }
                    }
                    "depth" => {
                        if let Some(ref mut cp) = current_content {
                            cp.depth = value.parse().ok();
                        }
                    }
                    "distance" => {
                        if let Some(ref mut cp) = current_content {
                            cp.distance = value.parse().ok();
                        }
                    }
                    "within" => {
                        if let Some(ref mut cp) = current_content {
                            cp.within = value.parse().ok();
                        }
                    }
                    "fast_pattern" => {
                        if let Some(ref mut cp) = current_content {
                            cp.fast_pattern = true;
                        }
                    }
                    "pcre" => {
                        let pattern = value.trim_matches('"').trim_matches('/');
                        if let Ok(re) = Regex::new(pattern) {
                            pcre_patterns.push(re);
                        }
                    }
                    "flow" => {
                        for flow_opt in value.split(',') {
                            match flow_opt.trim() {
                                "to_server" | "from_client" => flow.to_server = true,
                                "to_client" | "from_server" => flow.to_client = true,
                                "established" => flow.established = true,
                                "not_established" => flow.not_established = true,
                                "stateless" => flow.stateless = true,
                                _ => {}
                            }
                        }
                    }
                    "threshold" => {
                        // Parse threshold: type limit, track by_src, count 5, seconds 60
                        let mut th_type = ThresholdType::Threshold;
                        let mut track = TrackBy::BySrc;
                        let mut count = 1u32;
                        let mut seconds = 60u32;

                        for part in value.split(',') {
                            let part = part.trim();
                            if let Some((k, v)) = part.split_once(' ') {
                                match k.trim() {
                                    "type" => {
                                        th_type = match v.trim() {
                                            "limit" => ThresholdType::Limit,
                                            "both" => ThresholdType::Both,
                                            _ => ThresholdType::Threshold,
                                        };
                                    }
                                    "track" => {
                                        track = match v.trim() {
                                            "by_dst" => TrackBy::ByDst,
                                            "by_rule" => TrackBy::ByRule,
                                            _ => TrackBy::BySrc,
                                        };
                                    }
                                    "count" => count = v.trim().parse().unwrap_or(1),
                                    "seconds" => seconds = v.trim().parse().unwrap_or(60),
                                    _ => {}
                                }
                            }
                        }

                        threshold = Some(ThresholdOptions {
                            threshold_type: th_type,
                            track,
                            count,
                            seconds,
                        });
                    }
                    _ => {}
                }
            } else {
                // Handle keywords without values
                match opt {
                    "nocase" => {
                        if let Some(ref mut cp) = current_content {
                            cp.nocase = true;
                        }
                    }
                    "fast_pattern" => {
                        if let Some(ref mut cp) = current_content {
                            cp.fast_pattern = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Save last content pattern
        if let Some(cp) = current_content {
            content_patterns.push(cp);
        }

        Some(CompiledIdsRule {
            rule_id: rule.id.clone(),
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            bidirectional,
            content_patterns,
            pcre_patterns,
            flow,
            threshold,
        })
    }

    /// Parse address specification
    fn parse_address_spec(&self, spec: &str) -> AddressSpec {
        let spec = spec.trim();

        if spec == "any" || spec == "$HOME_NET" || spec == "$EXTERNAL_NET" {
            return AddressSpec::Any;
        }

        if spec.starts_with('!') {
            return AddressSpec::Negated(Box::new(self.parse_address_spec(&spec[1..])));
        }

        if spec.starts_with('[') && spec.ends_with(']') {
            let inner = &spec[1..spec.len() - 1];
            let addrs: Vec<AddressSpec> = inner.split(',')
                .map(|s| self.parse_address_spec(s.trim()))
                .collect();
            return AddressSpec::Group(addrs);
        }

        if spec.starts_with('$') {
            return AddressSpec::Variable(spec.to_string());
        }

        if spec.contains('/') {
            let parts: Vec<&str> = spec.split('/').collect();
            if parts.len() == 2 {
                if let (Ok(ip), Ok(mask)) = (parts[0].parse(), parts[1].parse()) {
                    return AddressSpec::Cidr(ip, mask);
                }
            }
        }

        if let Ok(ip) = spec.parse() {
            return AddressSpec::Single(ip);
        }

        AddressSpec::Any
    }

    /// Parse port specification
    fn parse_port_spec(&self, spec: &str) -> PortSpec {
        let spec = spec.trim();

        if spec == "any" || spec.starts_with('$') {
            return PortSpec::Any;
        }

        if spec.starts_with('!') {
            return PortSpec::Negated(Box::new(self.parse_port_spec(&spec[1..])));
        }

        if spec.starts_with('[') && spec.ends_with(']') {
            let inner = &spec[1..spec.len() - 1];
            let ports: Vec<PortSpec> = inner.split(',')
                .map(|s| self.parse_port_spec(s.trim()))
                .collect();
            return PortSpec::Group(ports);
        }

        if spec.contains(':') {
            let parts: Vec<&str> = spec.split(':').collect();
            if parts.len() == 2 {
                let start = if parts[0].is_empty() { 0 } else { parts[0].parse().unwrap_or(0) };
                let end = if parts[1].is_empty() { 65535 } else { parts[1].parse().unwrap_or(65535) };
                return PortSpec::Range(start, end);
            }
        }

        if let Ok(port) = spec.parse() {
            return PortSpec::Single(port);
        }

        PortSpec::Any
    }

    /// Parse content pattern (handles hex encoding)
    fn parse_content_pattern(&self, content: &str) -> Vec<u8> {
        let mut result = Vec::new();
        let mut in_hex = false;
        let mut hex_chars = String::new();

        for c in content.chars() {
            if c == '|' {
                if in_hex {
                    // End of hex section
                    for hex_byte in hex_chars.split_whitespace() {
                        if let Ok(byte) = u8::from_str_radix(hex_byte, 16) {
                            result.push(byte);
                        }
                    }
                    hex_chars.clear();
                }
                in_hex = !in_hex;
            } else if in_hex {
                hex_chars.push(c);
            } else {
                result.push(c as u8);
            }
        }

        result
    }

    /// Match a packet against all rules
    pub fn match_packet(
        &mut self,
        pcap_id: &str,
        session_id: Option<&str>,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: u8,
        payload: &[u8],
        is_to_server: bool,
    ) -> Vec<IdsAlert> {
        let mut alerts = Vec::new();

        let ids_protocol = match protocol {
            6 => IdsProtocol::Tcp,
            17 => IdsProtocol::Udp,
            1 => IdsProtocol::Icmp,
            _ => IdsProtocol::Ip,
        };

        for (idx, compiled) in self.compiled_rules.iter().enumerate() {
            // Check protocol
            if compiled.protocol != IdsProtocol::Any && compiled.protocol != ids_protocol {
                continue;
            }

            // Check addresses and ports
            let forward_match = self.match_address(&compiled.src_addr, src_ip) &&
                               self.match_port(&compiled.src_port, src_port) &&
                               self.match_address(&compiled.dst_addr, dst_ip) &&
                               self.match_port(&compiled.dst_port, dst_port);

            let reverse_match = compiled.bidirectional &&
                               self.match_address(&compiled.src_addr, dst_ip) &&
                               self.match_port(&compiled.src_port, dst_port) &&
                               self.match_address(&compiled.dst_addr, src_ip) &&
                               self.match_port(&compiled.dst_port, src_port);

            if !forward_match && !reverse_match {
                continue;
            }

            // Check flow
            if compiled.flow.to_server && !is_to_server {
                continue;
            }
            if compiled.flow.to_client && is_to_server {
                continue;
            }

            // Check content patterns
            if !self.match_content_patterns(&compiled.content_patterns, payload) {
                continue;
            }

            // Check PCRE patterns
            let payload_str = String::from_utf8_lossy(payload);
            let pcre_match = compiled.pcre_patterns.is_empty() ||
                compiled.pcre_patterns.iter().all(|re| re.is_match(&payload_str));

            if !pcre_match {
                continue;
            }

            // Rule matched - generate alert
            let rule = &self.rules[idx];

            // Update hit count
            *self.hit_counts.entry(rule.id.clone()).or_insert(0) += 1;

            let alert = IdsAlert {
                id: uuid::Uuid::new_v4().to_string(),
                pcap_id: pcap_id.to_string(),
                rule_id: rule.id.clone(),
                session_id: session_id.map(|s| s.to_string()),
                timestamp: Utc::now(),
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol: format!("{:?}", ids_protocol),
                message: rule.message.clone(),
                severity: rule.severity.clone(),
                payload_excerpt: if payload.len() > 256 {
                    Some(format!("{:?}...", &payload[..256]))
                } else {
                    Some(format!("{:?}", payload))
                },
                is_false_positive: false,
                notes: None,
            };

            alerts.push(alert.clone());
            self.alerts.push(alert);
        }

        alerts
    }

    /// Match address specification
    fn match_address(&self, spec: &AddressSpec, addr: IpAddr) -> bool {
        match spec {
            AddressSpec::Any => true,
            AddressSpec::Single(ip) => *ip == addr,
            AddressSpec::Cidr(ip, mask) => {
                // Simple CIDR match
                match (ip, addr) {
                    (IpAddr::V4(net), IpAddr::V4(host)) => {
                        let net_bits = u32::from(*net);
                        let host_bits = u32::from(host);
                        let mask_bits = !0u32 << (32 - mask);
                        (net_bits & mask_bits) == (host_bits & mask_bits)
                    }
                    (IpAddr::V6(net), IpAddr::V6(host)) => {
                        let net_bits = u128::from(*net);
                        let host_bits = u128::from(host);
                        let mask_bits = !0u128 << (128 - mask);
                        (net_bits & mask_bits) == (host_bits & mask_bits)
                    }
                    _ => false,
                }
            }
            AddressSpec::Group(addrs) => addrs.iter().any(|a| self.match_address(a, addr)),
            AddressSpec::Negated(inner) => !self.match_address(inner, addr),
            AddressSpec::Variable(_) => true, // Variables match any
        }
    }

    /// Match port specification
    fn match_port(&self, spec: &PortSpec, port: u16) -> bool {
        match spec {
            PortSpec::Any => true,
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(start, end) => port >= *start && port <= *end,
            PortSpec::Group(ports) => ports.iter().any(|p| self.match_port(p, port)),
            PortSpec::Negated(inner) => !self.match_port(inner, port),
            PortSpec::Variable(_) => true,
        }
    }

    /// Match content patterns
    fn match_content_patterns(&self, patterns: &[ContentPattern], payload: &[u8]) -> bool {
        if patterns.is_empty() {
            return true;
        }

        let mut last_match_end = 0usize;

        for pattern in patterns {
            let search_start = if let Some(dist) = pattern.distance {
                (last_match_end as isize + dist).max(0) as usize
            } else if let Some(offset) = pattern.offset {
                offset
            } else {
                0
            };

            let search_end = if let Some(within) = pattern.within {
                (last_match_end + within).min(payload.len())
            } else if let Some(depth) = pattern.depth {
                (search_start + depth).min(payload.len())
            } else {
                payload.len()
            };

            if search_start >= search_end || search_start >= payload.len() {
                if pattern.negated {
                    continue;
                }
                return false;
            }

            let search_space = &payload[search_start..search_end];
            let found = self.find_pattern(search_space, &pattern.pattern, pattern.nocase);

            if pattern.negated {
                if found.is_some() {
                    return false;
                }
            } else {
                match found {
                    Some(pos) => last_match_end = search_start + pos + pattern.pattern.len(),
                    None => return false,
                }
            }
        }

        true
    }

    /// Find pattern in payload
    fn find_pattern(&self, haystack: &[u8], needle: &[u8], nocase: bool) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }

        if nocase {
            let haystack_lower: Vec<u8> = haystack.iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            let needle_lower: Vec<u8> = needle.iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();

            for i in 0..=haystack_lower.len() - needle_lower.len() {
                if haystack_lower[i..i + needle_lower.len()] == needle_lower[..] {
                    return Some(i);
                }
            }
        } else {
            for i in 0..=haystack.len() - needle.len() {
                if haystack[i..i + needle.len()] == needle[..] {
                    return Some(i);
                }
            }
        }

        None
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> &[IdsAlert] {
        &self.alerts
    }

    /// Get loaded rules
    pub fn get_rules(&self) -> &[IdsRule] {
        &self.rules
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Clear alerts
    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }
}

impl Default for IdsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Load Emerging Threats rules from content
pub fn load_emerging_threats_rules(content: &str) -> Vec<IdsRule> {
    let mut engine = IdsEngine::new();
    let _ = engine.load_rules_from_content(content, IdsRuleSource::EmergingThreats);
    engine.rules
}

/// Get built-in security rules
pub fn get_builtin_rules() -> Vec<IdsRule> {
    let rules = r#"
# SQL Injection
alert http any any -> any any (msg:"SQL Injection Attempt - UNION SELECT"; flow:to_server; content:"union"; nocase; content:"select"; nocase; distance:0; within:15; sid:1000001; rev:1; classtype:web-application-attack; priority:2;)
alert http any any -> any any (msg:"SQL Injection Attempt - OR 1=1"; flow:to_server; content:"or"; nocase; content:"1=1"; distance:0; within:10; sid:1000002; rev:1; classtype:web-application-attack; priority:2;)

# XSS
alert http any any -> any any (msg:"XSS Attempt - Script Tag"; flow:to_server; content:"<script"; nocase; sid:1000003; rev:1; classtype:web-application-attack; priority:2;)
alert http any any -> any any (msg:"XSS Attempt - Event Handler"; flow:to_server; content:"onerror="; nocase; sid:1000004; rev:1; classtype:web-application-attack; priority:2;)

# Command Injection
alert http any any -> any any (msg:"Command Injection - Pipe"; flow:to_server; content:"|"; content:"cat"; distance:0; within:20; sid:1000005; rev:1; classtype:web-application-attack; priority:1;)
alert http any any -> any any (msg:"Command Injection - Backtick"; flow:to_server; content:"`"; sid:1000006; rev:1; classtype:web-application-attack; priority:2;)

# Directory Traversal
alert http any any -> any any (msg:"Directory Traversal Attempt"; flow:to_server; content:"../"; sid:1000007; rev:1; classtype:web-application-attack; priority:2;)

# Suspicious User Agents
alert http any any -> any any (msg:"Suspicious User Agent - SQLMap"; flow:to_server; content:"sqlmap"; nocase; sid:1000008; rev:1; classtype:web-application-attack; priority:2;)
alert http any any -> any any (msg:"Suspicious User Agent - Nikto"; flow:to_server; content:"Nikto"; nocase; sid:1000009; rev:1; classtype:web-application-attack; priority:2;)
alert http any any -> any any (msg:"Suspicious User Agent - Nmap"; flow:to_server; content:"Nmap"; sid:1000010; rev:1; classtype:policy-violation; priority:3;)

# Malware C2
alert tcp any any -> any any (msg:"Possible Beacon - Regular Interval"; flow:established; dsize:>0; dsize:<100; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000011; rev:1; classtype:trojan-activity; priority:1;)

# DNS Tunneling
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Long Query"; content:"|00 01|"; content:!"|00 00 00 00 00|"; dsize:>100; sid:1000012; rev:1; classtype:policy-violation; priority:2;)

# SSH Brute Force
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"SSH-"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000013; rev:1; classtype:attempted-admin; priority:2;)

# Cryptocurrency Mining
alert tcp any any -> any any (msg:"Cryptocurrency Stratum Protocol"; flow:established; content:"mining.subscribe"; nocase; sid:1000014; rev:1; classtype:policy-violation; priority:2;)

# Exfiltration
alert tcp any any -> any any (msg:"Large Outbound Data Transfer"; flow:to_server,established; dsize:>10000; threshold:type threshold, track by_src, count 5, seconds 300; sid:1000015; rev:1; classtype:policy-violation; priority:3;)
"#;

    load_emerging_threats_rules(rules)
}
