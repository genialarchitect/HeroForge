#![allow(dead_code)]
//! Built-in IDS Rules Database
//!
//! This module provides a collection of pre-defined IDS rules for common
//! threat detection scenarios, including:
//! - Malware C2 communication patterns
//! - Exploit attempt signatures
//! - Suspicious traffic patterns
//! - Data exfiltration indicators
//! - Policy violations
//!
//! Rules are organized by category and follow Emerging Threats style formatting.

use std::collections::HashMap;
use std::sync::LazyLock;

use super::{
    ContentMatch, IdsAddress, IdsDirection, IdsPort, IdsProtocol, IdsRule, IdsRuleAction,
    PcreMatch, RuleClasstype, RuleReference,
};

// =============================================================================
// Rule Categories
// =============================================================================

/// IDS rule category
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleCategory {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
}

/// All available rule categories
pub static RULE_CATEGORIES: LazyLock<Vec<RuleCategory>> = LazyLock::new(|| {
    vec![
        RuleCategory {
            id: "malware-c2",
            name: "Malware Command & Control",
            description: "Detection of malware C2 communication patterns and beacons",
        },
        RuleCategory {
            id: "exploit-attempts",
            name: "Exploit Attempts",
            description: "Detection of exploitation attempts against known vulnerabilities",
        },
        RuleCategory {
            id: "suspicious-traffic",
            name: "Suspicious Traffic",
            description: "Detection of unusual or suspicious network traffic patterns",
        },
        RuleCategory {
            id: "data-exfiltration",
            name: "Data Exfiltration",
            description: "Detection of potential data exfiltration attempts",
        },
        RuleCategory {
            id: "policy-violation",
            name: "Policy Violations",
            description: "Detection of security policy violations",
        },
        RuleCategory {
            id: "reconnaissance",
            name: "Reconnaissance",
            description: "Detection of network scanning and reconnaissance activities",
        },
        RuleCategory {
            id: "credential-theft",
            name: "Credential Theft",
            description: "Detection of credential harvesting and theft attempts",
        },
        RuleCategory {
            id: "web-attacks",
            name: "Web Application Attacks",
            description: "Detection of web application attacks (SQLi, XSS, etc.)",
        },
        RuleCategory {
            id: "lateral-movement",
            name: "Lateral Movement",
            description: "Detection of lateral movement techniques",
        },
        RuleCategory {
            id: "persistence",
            name: "Persistence",
            description: "Detection of persistence mechanism establishment",
        },
    ]
});

// =============================================================================
// Built-in Rules Database
// =============================================================================

/// Rules database with built-in and custom rules
#[derive(Debug, Clone)]
pub struct RulesDatabase {
    /// All rules indexed by SID
    rules: HashMap<u64, IdsRule>,
    /// Rules indexed by category
    by_category: HashMap<String, Vec<u64>>,
}

impl Default for RulesDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesDatabase {
    /// Create a new rules database with built-in rules
    pub fn new() -> Self {
        let mut db = Self {
            rules: HashMap::new(),
            by_category: HashMap::new(),
        };

        // Load all built-in rules
        db.load_builtin_rules();

        db
    }

    /// Create an empty rules database
    pub fn empty() -> Self {
        Self {
            rules: HashMap::new(),
            by_category: HashMap::new(),
        }
    }

    /// Load all built-in rules
    fn load_builtin_rules(&mut self) {
        // Load rules from each category
        for rule in get_malware_c2_rules() {
            self.add_rule(rule, "malware-c2");
        }
        for rule in get_exploit_rules() {
            self.add_rule(rule, "exploit-attempts");
        }
        for rule in get_suspicious_traffic_rules() {
            self.add_rule(rule, "suspicious-traffic");
        }
        for rule in get_data_exfiltration_rules() {
            self.add_rule(rule, "data-exfiltration");
        }
        for rule in get_policy_violation_rules() {
            self.add_rule(rule, "policy-violation");
        }
        for rule in get_reconnaissance_rules() {
            self.add_rule(rule, "reconnaissance");
        }
        for rule in get_credential_theft_rules() {
            self.add_rule(rule, "credential-theft");
        }
        for rule in get_web_attack_rules() {
            self.add_rule(rule, "web-attacks");
        }
        for rule in get_lateral_movement_rules() {
            self.add_rule(rule, "lateral-movement");
        }
        for rule in get_persistence_rules() {
            self.add_rule(rule, "persistence");
        }
    }

    /// Add a rule to the database
    pub fn add_rule(&mut self, mut rule: IdsRule, category: &str) {
        rule.category = Some(category.to_string());
        let sid = rule.sid;

        self.rules.insert(sid, rule);
        self.by_category
            .entry(category.to_string())
            .or_default()
            .push(sid);
    }

    /// Get a rule by SID
    pub fn get_rule(&self, sid: u64) -> Option<&IdsRule> {
        self.rules.get(&sid)
    }

    /// Get all rules
    pub fn all_rules(&self) -> Vec<&IdsRule> {
        self.rules.values().collect()
    }

    /// Get rules by category
    pub fn get_by_category(&self, category: &str) -> Vec<&IdsRule> {
        self.by_category
            .get(category)
            .map(|sids| {
                sids.iter()
                    .filter_map(|sid| self.rules.get(sid))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all enabled rules
    pub fn get_enabled_rules(&self) -> Vec<&IdsRule> {
        self.rules.values().filter(|r| r.enabled).collect()
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get category rule counts
    pub fn category_counts(&self) -> HashMap<String, usize> {
        self.by_category
            .iter()
            .map(|(cat, sids)| (cat.clone(), sids.len()))
            .collect()
    }

    /// Remove a rule by SID
    pub fn remove_rule(&mut self, sid: u64) -> Option<IdsRule> {
        if let Some(rule) = self.rules.remove(&sid) {
            if let Some(category) = &rule.category {
                if let Some(sids) = self.by_category.get_mut(category) {
                    sids.retain(|s| *s != sid);
                }
            }
            Some(rule)
        } else {
            None
        }
    }

    /// Enable/disable a rule by SID
    pub fn set_rule_enabled(&mut self, sid: u64, enabled: bool) -> bool {
        if let Some(rule) = self.rules.get_mut(&sid) {
            rule.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Search rules by message text
    pub fn search_by_message(&self, query: &str) -> Vec<&IdsRule> {
        let query_lower = query.to_lowercase();
        self.rules
            .values()
            .filter(|r| r.msg.to_lowercase().contains(&query_lower))
            .collect()
    }
}

// =============================================================================
// Built-in Rule Definitions
// =============================================================================

/// Get all default built-in rules
pub fn get_default_rules() -> Vec<IdsRule> {
    let mut rules = Vec::new();

    rules.extend(get_malware_c2_rules());
    rules.extend(get_exploit_rules());
    rules.extend(get_suspicious_traffic_rules());
    rules.extend(get_data_exfiltration_rules());
    rules.extend(get_policy_violation_rules());
    rules.extend(get_reconnaissance_rules());
    rules.extend(get_credential_theft_rules());
    rules.extend(get_web_attack_rules());
    rules.extend(get_lateral_movement_rules());
    rules.extend(get_persistence_rules());

    rules
}

/// Get rules by category name
pub fn get_rules_by_category(category: &str) -> Vec<IdsRule> {
    match category {
        "malware-c2" => get_malware_c2_rules(),
        "exploit-attempts" => get_exploit_rules(),
        "suspicious-traffic" => get_suspicious_traffic_rules(),
        "data-exfiltration" => get_data_exfiltration_rules(),
        "policy-violation" => get_policy_violation_rules(),
        "reconnaissance" => get_reconnaissance_rules(),
        "credential-theft" => get_credential_theft_rules(),
        "web-attacks" => get_web_attack_rules(),
        "lateral-movement" => get_lateral_movement_rules(),
        "persistence" => get_persistence_rules(),
        _ => Vec::new(),
    }
}

// =============================================================================
// Malware C2 Rules
// =============================================================================

fn get_malware_c2_rules() -> Vec<IdsRule> {
    vec![
        // Generic C2 beacon detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3000001,
            rev: 1,
            msg: "MALWARE Generic C2 Beacon - Base64 Encoded POST Data".to_string(),
            classtype: Some(RuleClasstype {
                name: "trojan-activity".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            flow: Some("established,to_server".to_string()),
            content_matches: vec![
                ContentMatch {
                    pattern: b"POST".to_vec(),
                    ..Default::default()
                },
            ],
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"^[A-Za-z0-9+/]{50,}={0,2}$".to_string(),
                    flags: "m".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1071".to_string(), "T1132".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "url".to_string(),
                    value: "attack.mitre.org/techniques/T1071".to_string(),
                },
            ],
            enabled: true,
            category: Some("malware-c2".to_string()),
            ..Default::default()
        },

        // Cobalt Strike beacon detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3000002,
            rev: 1,
            msg: "MALWARE Cobalt Strike Beacon Checkin".to_string(),
            classtype: Some(RuleClasstype {
                name: "trojan-activity".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            flow: Some("established,to_server".to_string()),
            content_matches: vec![
                ContentMatch {
                    pattern: b"/submit.php?id=".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1071.001".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "url".to_string(),
                    value: "www.cobaltstrike.com".to_string(),
                },
            ],
            enabled: true,
            category: Some("malware-c2".to_string()),
            ..Default::default()
        },

        // Metasploit Meterpreter detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3000003,
            rev: 1,
            msg: "MALWARE Metasploit Meterpreter Reverse Shell".to_string(),
            classtype: Some(RuleClasstype {
                name: "trojan-activity".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: vec![0x4d, 0x5a, 0x90, 0x00], // MZ header
                    depth: Some(4),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1059.001".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            enabled: true,
            category: Some("malware-c2".to_string()),
            ..Default::default()
        },

        // Empire C2 detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3000004,
            rev: 1,
            msg: "MALWARE Empire PowerShell C2 Communication".to_string(),
            classtype: Some(RuleClasstype {
                name: "trojan-activity".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            flow: Some("established,to_server".to_string()),
            content_matches: vec![
                ContentMatch {
                    pattern: b"session=".to_vec(),
                    ..Default::default()
                },
                ContentMatch {
                    pattern: b"PHPSESSID=".to_vec(),
                    ..Default::default()
                },
            ],
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"Cookie:.*[A-Za-z0-9+/]{64,}".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1059.001".to_string(), "T1071.001".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            enabled: true,
            category: Some("malware-c2".to_string()),
            ..Default::default()
        },

        // DNS tunneling C2
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Dns,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Single(53),
            direction: IdsDirection::Unidirectional,
            sid: 3000005,
            rev: 1,
            msg: "MALWARE Possible DNS Tunneling C2 - Long Subdomain".to_string(),
            classtype: Some(RuleClasstype {
                name: "trojan-activity".to_string(),
                priority: 1,
            }),
            priority: Some(2),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"[a-z0-9]{50,}\.".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1071.004".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            enabled: true,
            category: Some("malware-c2".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Exploit Rules
// =============================================================================

fn get_exploit_rules() -> Vec<IdsRule> {
    vec![
        // Log4Shell (CVE-2021-44228)
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3001001,
            rev: 3,
            msg: "EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-admin".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"${jndi:".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1190".to_string()],
            mitre_tactics: vec!["TA0001".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "cve".to_string(),
                    value: "2021-44228".to_string(),
                },
            ],
            enabled: true,
            category: Some("exploit-attempts".to_string()),
            ..Default::default()
        },

        // Spring4Shell (CVE-2022-22965)
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3001002,
            rev: 1,
            msg: "EXPLOIT Spring4Shell RCE Attempt (CVE-2022-22965)".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-admin".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"class.module.classLoader".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1190".to_string()],
            mitre_tactics: vec!["TA0001".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "cve".to_string(),
                    value: "2022-22965".to_string(),
                },
            ],
            enabled: true,
            category: Some("exploit-attempts".to_string()),
            ..Default::default()
        },

        // ProxyShell/ProxyLogon
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3001003,
            rev: 1,
            msg: "EXPLOIT Microsoft Exchange ProxyShell/ProxyLogon Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-admin".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"/autodiscover/autodiscover.json".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
                ContentMatch {
                    pattern: b"/mapi/nspi/".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1190".to_string()],
            mitre_tactics: vec!["TA0001".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "cve".to_string(),
                    value: "2021-34473".to_string(),
                },
            ],
            enabled: true,
            category: Some("exploit-attempts".to_string()),
            ..Default::default()
        },

        // Shellshock (CVE-2014-6271)
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3001004,
            rev: 1,
            msg: "EXPLOIT GNU Bash Shellshock RCE Attempt (CVE-2014-6271)".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-admin".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"() {".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1190".to_string()],
            mitre_tactics: vec!["TA0001".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "cve".to_string(),
                    value: "2014-6271".to_string(),
                },
            ],
            enabled: true,
            category: Some("exploit-attempts".to_string()),
            ..Default::default()
        },

        // EternalBlue SMB
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Unidirectional,
            sid: 3001005,
            rev: 1,
            msg: "EXPLOIT EternalBlue SMB Remote Code Execution (MS17-010)".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-admin".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: vec![0xff, 0x53, 0x4d, 0x42], // SMB header
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1210".to_string()],
            mitre_tactics: vec!["TA0008".to_string()],
            references: vec![
                RuleReference {
                    ref_type: "cve".to_string(),
                    value: "2017-0144".to_string(),
                },
            ],
            enabled: true,
            category: Some("exploit-attempts".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Suspicious Traffic Rules
// =============================================================================

fn get_suspicious_traffic_rules() -> Vec<IdsRule> {
    vec![
        // Reverse shell detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3002001,
            rev: 1,
            msg: "SUSPICIOUS Possible Bash Reverse Shell".to_string(),
            classtype: Some(RuleClasstype {
                name: "suspicious-activity".to_string(),
                priority: 2,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"/bin/bash".to_vec(),
                    ..Default::default()
                },
                ContentMatch {
                    pattern: b"/dev/tcp/".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1059.004".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            enabled: true,
            category: Some("suspicious-traffic".to_string()),
            ..Default::default()
        },

        // PowerShell download cradle
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3002002,
            rev: 1,
            msg: "SUSPICIOUS PowerShell Download Cradle Detected".to_string(),
            classtype: Some(RuleClasstype {
                name: "suspicious-activity".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"(IEX|Invoke-Expression).*(New-Object|WebClient|DownloadString)".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1059.001".to_string(), "T1105".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            enabled: true,
            category: Some("suspicious-traffic".to_string()),
            ..Default::default()
        },

        // Tor hidden service access
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Group(vec![
                IdsPort::Single(9001),
                IdsPort::Single(9030),
                IdsPort::Single(9050),
                IdsPort::Single(9051),
            ]),
            direction: IdsDirection::Unidirectional,
            sid: 3002003,
            rev: 1,
            msg: "SUSPICIOUS Possible Tor Network Traffic".to_string(),
            classtype: Some(RuleClasstype {
                name: "suspicious-activity".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            mitre_techniques: vec!["T1090.003".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            enabled: true,
            category: Some("suspicious-traffic".to_string()),
            ..Default::default()
        },

        // ICMP tunnel detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Icmp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3002004,
            rev: 1,
            msg: "SUSPICIOUS Possible ICMP Tunnel - Large ICMP Payload".to_string(),
            classtype: Some(RuleClasstype {
                name: "suspicious-activity".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            mitre_techniques: vec!["T1095".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            enabled: true,
            category: Some("suspicious-traffic".to_string()),
            ..Default::default()
        },

        // Unusual outbound ports
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Group(vec![
                IdsPort::Single(4444),
                IdsPort::Single(5555),
                IdsPort::Single(6666),
                IdsPort::Single(31337),
            ]),
            direction: IdsDirection::Unidirectional,
            sid: 3002005,
            rev: 1,
            msg: "SUSPICIOUS Outbound Connection to Common Malware Port".to_string(),
            classtype: Some(RuleClasstype {
                name: "suspicious-activity".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            mitre_techniques: vec!["T1571".to_string()],
            mitre_tactics: vec!["TA0011".to_string()],
            enabled: true,
            category: Some("suspicious-traffic".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Data Exfiltration Rules
// =============================================================================

fn get_data_exfiltration_rules() -> Vec<IdsRule> {
    vec![
        // Large DNS query (possible exfil)
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Dns,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Single(53),
            direction: IdsDirection::Unidirectional,
            sid: 3003001,
            rev: 1,
            msg: "EXFILTRATION Possible DNS Data Exfiltration - Large Query".to_string(),
            classtype: Some(RuleClasstype {
                name: "bad-unknown".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            mitre_techniques: vec!["T1048.003".to_string()],
            mitre_tactics: vec!["TA0010".to_string()],
            enabled: true,
            category: Some("data-exfiltration".to_string()),
            ..Default::default()
        },

        // HTTP POST with large body
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3003002,
            rev: 1,
            msg: "EXFILTRATION Large HTTP POST to External Host".to_string(),
            classtype: Some(RuleClasstype {
                name: "bad-unknown".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            flow: Some("established,to_server".to_string()),
            content_matches: vec![
                ContentMatch {
                    pattern: b"POST".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1048.001".to_string()],
            mitre_tactics: vec!["TA0010".to_string()],
            enabled: true,
            category: Some("data-exfiltration".to_string()),
            ..Default::default()
        },

        // Cloud storage upload
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3003003,
            rev: 1,
            msg: "EXFILTRATION Upload to Cloud Storage Service".to_string(),
            classtype: Some(RuleClasstype {
                name: "policy-violation".to_string(),
                priority: 2,
            }),
            priority: Some(3),
            flow: Some("established,to_server".to_string()),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"(dropbox|onedrive|drive\.google|box\.com|mega\.nz)".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1567.002".to_string()],
            mitre_tactics: vec!["TA0010".to_string()],
            enabled: true,
            category: Some("data-exfiltration".to_string()),
            ..Default::default()
        },

        // FTP upload of sensitive files
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Ftp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Group(vec![IdsPort::Single(20), IdsPort::Single(21)]),
            direction: IdsDirection::Unidirectional,
            sid: 3003004,
            rev: 1,
            msg: "EXFILTRATION FTP Upload to External Server".to_string(),
            classtype: Some(RuleClasstype {
                name: "bad-unknown".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: b"STOR".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1048".to_string()],
            mitre_tactics: vec!["TA0010".to_string()],
            enabled: true,
            category: Some("data-exfiltration".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Policy Violation Rules
// =============================================================================

fn get_policy_violation_rules() -> Vec<IdsRule> {
    vec![
        // Cleartext credentials
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Single(80),
            direction: IdsDirection::Bidirectional,
            sid: 3004001,
            rev: 1,
            msg: "POLICY Cleartext Password in HTTP Traffic".to_string(),
            classtype: Some(RuleClasstype {
                name: "policy-violation".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"(password|passwd|pwd)\s*[=:]\s*[^\s&]+".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1552.001".to_string()],
            mitre_tactics: vec!["TA0006".to_string()],
            enabled: true,
            category: Some("policy-violation".to_string()),
            ..Default::default()
        },

        // Telnet usage
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(23),
            direction: IdsDirection::Unidirectional,
            sid: 3004002,
            rev: 1,
            msg: "POLICY Telnet Connection Detected - Use SSH Instead".to_string(),
            classtype: Some(RuleClasstype {
                name: "policy-violation".to_string(),
                priority: 2,
            }),
            priority: Some(3),
            mitre_techniques: vec!["T1021.001".to_string()],
            mitre_tactics: vec!["TA0008".to_string()],
            enabled: true,
            category: Some("policy-violation".to_string()),
            ..Default::default()
        },

        // Weak SSL/TLS
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tls,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Any,
            dst_port: IdsPort::Any,
            direction: IdsDirection::Bidirectional,
            sid: 3004003,
            rev: 1,
            msg: "POLICY Weak SSL/TLS Version Detected (SSLv3 or TLS 1.0)".to_string(),
            classtype: Some(RuleClasstype {
                name: "policy-violation".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            mitre_techniques: vec!["T1557".to_string()],
            mitre_tactics: vec!["TA0006".to_string()],
            enabled: true,
            category: Some("policy-violation".to_string()),
            ..Default::default()
        },

        // P2P file sharing
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$EXTERNAL_NET".to_string()),
            dst_port: IdsPort::Group(vec![
                IdsPort::Single(6881),
                IdsPort::Range(6881, 6889),
            ]),
            direction: IdsDirection::Bidirectional,
            sid: 3004004,
            rev: 1,
            msg: "POLICY BitTorrent P2P Traffic Detected".to_string(),
            classtype: Some(RuleClasstype {
                name: "policy-violation".to_string(),
                priority: 2,
            }),
            priority: Some(3),
            enabled: true,
            category: Some("policy-violation".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Reconnaissance Rules
// =============================================================================

fn get_reconnaissance_rules() -> Vec<IdsRule> {
    vec![
        // Nmap SYN scan
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3005001,
            rev: 1,
            msg: "RECON Possible Nmap SYN Scan Detected".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-recon".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            mitre_techniques: vec!["T1046".to_string()],
            mitre_tactics: vec!["TA0007".to_string()],
            enabled: true,
            category: Some("reconnaissance".to_string()),
            ..Default::default()
        },

        // Version scan
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3005002,
            rev: 1,
            msg: "RECON Service Version Detection Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-recon".to_string(),
                priority: 2,
            }),
            priority: Some(3),
            mitre_techniques: vec!["T1046".to_string()],
            mitre_tactics: vec!["TA0007".to_string()],
            enabled: true,
            category: Some("reconnaissance".to_string()),
            ..Default::default()
        },

        // DNS zone transfer attempt
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Dns,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(53),
            direction: IdsDirection::Unidirectional,
            sid: 3005003,
            rev: 1,
            msg: "RECON DNS Zone Transfer Attempt (AXFR)".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-recon".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: vec![0x00, 0xfc], // AXFR query type
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1590.002".to_string()],
            mitre_tactics: vec!["TA0043".to_string()],
            enabled: true,
            category: Some("reconnaissance".to_string()),
            ..Default::default()
        },

        // SNMP community string scan
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Snmp,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(161),
            direction: IdsDirection::Unidirectional,
            sid: 3005004,
            rev: 1,
            msg: "RECON SNMP Community String Scan".to_string(),
            classtype: Some(RuleClasstype {
                name: "attempted-recon".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: b"public".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1046".to_string()],
            mitre_tactics: vec!["TA0007".to_string()],
            enabled: true,
            category: Some("reconnaissance".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Credential Theft Rules
// =============================================================================

fn get_credential_theft_rules() -> Vec<IdsRule> {
    vec![
        // Mimikatz detection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Bidirectional,
            sid: 3006001,
            rev: 1,
            msg: "CREDENTIAL Possible Mimikatz DCSync Activity".to_string(),
            classtype: Some(RuleClasstype {
                name: "credential-theft".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"mimikatz".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1003.006".to_string()],
            mitre_tactics: vec!["TA0006".to_string()],
            enabled: true,
            category: Some("credential-theft".to_string()),
            ..Default::default()
        },

        // Kerberoasting
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(88),
            direction: IdsDirection::Unidirectional,
            sid: 3006002,
            rev: 1,
            msg: "CREDENTIAL Possible Kerberoasting Attack".to_string(),
            classtype: Some(RuleClasstype {
                name: "credential-theft".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            mitre_techniques: vec!["T1558.003".to_string()],
            mitre_tactics: vec!["TA0006".to_string()],
            enabled: true,
            category: Some("credential-theft".to_string()),
            ..Default::default()
        },

        // NTLM relay
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Bidirectional,
            sid: 3006003,
            rev: 1,
            msg: "CREDENTIAL Possible NTLM Relay Attack".to_string(),
            classtype: Some(RuleClasstype {
                name: "credential-theft".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"NTLMSSP".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1557.001".to_string()],
            mitre_tactics: vec!["TA0006".to_string()],
            enabled: true,
            category: Some("credential-theft".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Web Attack Rules
// =============================================================================

fn get_web_attack_rules() -> Vec<IdsRule> {
    vec![
        // SQL Injection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3007001,
            rev: 1,
            msg: "WEB-ATTACK SQL Injection Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "web-application-attack".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"(\b(union|select|insert|update|delete|drop|exec|execute)\b.*\b(from|into|where|table)\b)".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1190".to_string()],
            mitre_tactics: vec!["TA0001".to_string()],
            enabled: true,
            category: Some("web-attacks".to_string()),
            ..Default::default()
        },

        // XSS
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3007002,
            rev: 1,
            msg: "WEB-ATTACK Cross-Site Scripting (XSS) Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "web-application-attack".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"(<script[^>]*>|javascript:|on(load|error|click|mouse)\s*=)".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1059.007".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            enabled: true,
            category: Some("web-attacks".to_string()),
            ..Default::default()
        },

        // Path traversal
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3007003,
            rev: 1,
            msg: "WEB-ATTACK Directory Traversal Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "web-application-attack".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            content_matches: vec![
                ContentMatch {
                    pattern: b"../".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1083".to_string()],
            mitre_tactics: vec!["TA0007".to_string()],
            enabled: true,
            category: Some("web-attacks".to_string()),
            ..Default::default()
        },

        // Command injection
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Http,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Any,
            direction: IdsDirection::Unidirectional,
            sid: 3007004,
            rev: 1,
            msg: "WEB-ATTACK Command Injection Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "web-application-attack".to_string(),
                priority: 1,
            }),
            priority: Some(1),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"([;|`]|\$\(|&&|\|\|)".to_string(),
                    flags: "".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1059".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            enabled: true,
            category: Some("web-attacks".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Lateral Movement Rules
// =============================================================================

fn get_lateral_movement_rules() -> Vec<IdsRule> {
    vec![
        // PsExec
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Unidirectional,
            sid: 3008001,
            rev: 1,
            msg: "LATERAL-MOVEMENT PsExec Remote Execution".to_string(),
            classtype: Some(RuleClasstype {
                name: "misc-attack".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: b"PSEXESVC".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1570".to_string()],
            mitre_tactics: vec!["TA0008".to_string()],
            enabled: true,
            category: Some("lateral-movement".to_string()),
            ..Default::default()
        },

        // WMI remote execution
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Tcp,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(135),
            direction: IdsDirection::Unidirectional,
            sid: 3008002,
            rev: 1,
            msg: "LATERAL-MOVEMENT WMI Remote Execution".to_string(),
            classtype: Some(RuleClasstype {
                name: "misc-attack".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: b"IWbemServices".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1047".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            enabled: true,
            category: Some("lateral-movement".to_string()),
            ..Default::default()
        },

        // RDP brute force
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Rdp,
            src_addr: IdsAddress::Any,
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(3389),
            direction: IdsDirection::Unidirectional,
            sid: 3008003,
            rev: 1,
            msg: "LATERAL-MOVEMENT RDP Connection Attempt".to_string(),
            classtype: Some(RuleClasstype {
                name: "misc-attack".to_string(),
                priority: 2,
            }),
            priority: Some(3),
            mitre_techniques: vec!["T1021.001".to_string()],
            mitre_tactics: vec!["TA0008".to_string()],
            enabled: true,
            category: Some("lateral-movement".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Persistence Rules
// =============================================================================

fn get_persistence_rules() -> Vec<IdsRule> {
    vec![
        // Scheduled task creation
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Unidirectional,
            sid: 3009001,
            rev: 1,
            msg: "PERSISTENCE Remote Scheduled Task Creation".to_string(),
            classtype: Some(RuleClasstype {
                name: "misc-attack".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: b"\\Tasks\\".to_vec(),
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1053.005".to_string()],
            mitre_tactics: vec!["TA0003".to_string()],
            enabled: true,
            category: Some("persistence".to_string()),
            ..Default::default()
        },

        // Service installation
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Unidirectional,
            sid: 3009002,
            rev: 1,
            msg: "PERSISTENCE Remote Service Installation".to_string(),
            classtype: Some(RuleClasstype {
                name: "misc-attack".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            content_matches: vec![
                ContentMatch {
                    pattern: b"svcctl".to_vec(),
                    nocase: true,
                    ..Default::default()
                },
            ],
            mitre_techniques: vec!["T1543.003".to_string()],
            mitre_tactics: vec!["TA0003".to_string()],
            enabled: true,
            category: Some("persistence".to_string()),
            ..Default::default()
        },

        // Registry run key
        IdsRule {
            action: IdsRuleAction::Alert,
            protocol: IdsProtocol::Smb,
            src_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            src_port: IdsPort::Any,
            dst_addr: IdsAddress::Variable("$HOME_NET".to_string()),
            dst_port: IdsPort::Single(445),
            direction: IdsDirection::Unidirectional,
            sid: 3009003,
            rev: 1,
            msg: "PERSISTENCE Registry Run Key Modification".to_string(),
            classtype: Some(RuleClasstype {
                name: "misc-attack".to_string(),
                priority: 2,
            }),
            priority: Some(2),
            pcre_matches: vec![
                PcreMatch {
                    pattern: r"(CurrentVersion\\Run|Winlogon)".to_string(),
                    flags: "i".to_string(),
                    negated: false,
                    relative: false,
                },
            ],
            mitre_techniques: vec!["T1547.001".to_string()],
            mitre_tactics: vec!["TA0003".to_string()],
            enabled: true,
            category: Some("persistence".to_string()),
            ..Default::default()
        },
    ]
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_database_new() {
        let db = RulesDatabase::new();
        assert!(db.rule_count() > 0);
    }

    #[test]
    fn test_get_rule_by_sid() {
        let db = RulesDatabase::new();
        let rule = db.get_rule(3000001);
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().sid, 3000001);
    }

    #[test]
    fn test_get_by_category() {
        let db = RulesDatabase::new();
        let malware_rules = db.get_by_category("malware-c2");
        assert!(!malware_rules.is_empty());
        for rule in malware_rules {
            assert_eq!(rule.category, Some("malware-c2".to_string()));
        }
    }

    #[test]
    fn test_category_counts() {
        let db = RulesDatabase::new();
        let counts = db.category_counts();
        assert!(counts.contains_key("malware-c2"));
        assert!(counts.contains_key("exploit-attempts"));
    }

    #[test]
    fn test_search_by_message() {
        let db = RulesDatabase::new();
        let results = db.search_by_message("Log4j");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_enable_disable_rule() {
        let mut db = RulesDatabase::new();
        let sid = 3000001;

        assert!(db.get_rule(sid).unwrap().enabled);

        db.set_rule_enabled(sid, false);
        assert!(!db.get_rule(sid).unwrap().enabled);

        db.set_rule_enabled(sid, true);
        assert!(db.get_rule(sid).unwrap().enabled);
    }

    #[test]
    fn test_get_default_rules() {
        let rules = get_default_rules();
        assert!(!rules.is_empty());

        // Check that all rules have valid SIDs
        for rule in &rules {
            assert!(rule.sid > 0);
        }
    }

    #[test]
    fn test_rule_categories_exist() {
        assert!(!RULE_CATEGORIES.is_empty());

        for category in RULE_CATEGORIES.iter() {
            let rules = get_rules_by_category(category.id);
            // Some categories should have rules
            if !rules.is_empty() {
                assert!(rules.iter().all(|r| r.sid > 0));
            }
        }
    }
}
