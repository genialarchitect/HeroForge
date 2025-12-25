//! Built-in YARA Rules for Threat Detection
//!
//! This module contains pre-defined YARA rules for detecting common threats:
//! - Malware family signatures (Emotet, TrickBot, Cobalt Strike, etc.)
//! - Suspicious PE characteristics
//! - Packed/encrypted binary detection
//! - Webshell detection
//! - Cryptocurrency miner signatures
//! - RAT/backdoor indicators

#![allow(dead_code)]

use super::{StringModifier, StringValue, YaraRule, YaraRuleMetadata, YaraString};

/// Get all built-in YARA rules
pub fn get_builtin_rules() -> Vec<YaraRule> {
    let mut rules = Vec::new();

    // Malware families
    rules.extend(get_emotet_rules());
    rules.extend(get_trickbot_rules());
    rules.extend(get_cobalt_strike_rules());
    rules.extend(get_metasploit_rules());

    // PE characteristics
    rules.extend(get_suspicious_pe_rules());
    rules.extend(get_packed_binary_rules());

    // Web threats
    rules.extend(get_webshell_rules());

    // Crypto miners
    rules.extend(get_cryptominer_rules());

    // RATs and backdoors
    rules.extend(get_rat_rules());

    // Ransomware indicators
    rules.extend(get_ransomware_rules());

    // Rootkit indicators
    rules.extend(get_rootkit_rules());

    rules
}

// ============================================================================
// Emotet Malware Rules
// ============================================================================

fn get_emotet_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "Emotet_Dropper".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Emotet dropper/loader patterns".to_string()),
                reference: Some("https://attack.mitre.org/software/S0367/".to_string()),
                malware_family: Some("Emotet".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["malware".to_string(), "emotet".to_string(), "banking".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$emotet_str1".to_string(),
                    value: StringValue::Text("Emotet".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$emotet_mutex".to_string(),
                    value: StringValue::Text("PEM%x".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$emotet_reg".to_string(),
                    value: StringValue::Text("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$emotet_api1".to_string(),
                    value: StringValue::Text("VirtualAllocExNuma".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$emotet_api2".to_string(),
                    value: StringValue::Text("NtQueryInformationProcess".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "Emotet_Document".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Emotet malicious document patterns".to_string()),
                malware_family: Some("Emotet".to_string()),
                severity: Some("high".to_string()),
                ..Default::default()
            },
            tags: vec!["malware".to_string(), "emotet".to_string(), "maldoc".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$macro1".to_string(),
                    value: StringValue::Text("AutoOpen".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$macro2".to_string(),
                    value: StringValue::Text("Auto_Open".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$shell".to_string(),
                    value: StringValue::Text("WScript.Shell".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$powershell".to_string(),
                    value: StringValue::Text("powershell".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$hidden".to_string(),
                    value: StringValue::Text("-WindowStyle Hidden".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "($macro1 or $macro2) and ($shell or $powershell)".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// TrickBot Malware Rules
// ============================================================================

fn get_trickbot_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "TrickBot_Loader".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects TrickBot loader patterns".to_string()),
                reference: Some("https://attack.mitre.org/software/S0266/".to_string()),
                malware_family: Some("TrickBot".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["malware".to_string(), "trickbot".to_string(), "banking".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$trick_str1".to_string(),
                    value: StringValue::Text("moduleconfig".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$trick_str2".to_string(),
                    value: StringValue::Text("injectDll32".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$trick_str3".to_string(),
                    value: StringValue::Text("injectDll64".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$trick_cfg".to_string(),
                    value: StringValue::Text("<mcconf>".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$trick_bot".to_string(),
                    value: StringValue::Text("bot_id".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "3 of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Cobalt Strike Rules
// ============================================================================

fn get_cobalt_strike_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "CobaltStrike_Beacon".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Cobalt Strike Beacon payload patterns".to_string()),
                reference: Some("https://attack.mitre.org/software/S0154/".to_string()),
                malware_family: Some("Cobalt Strike".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["apt".to_string(), "cobaltstrike".to_string(), "beacon".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$beacon1".to_string(),
                    value: StringValue::Text("%s (admin)".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$beacon2".to_string(),
                    value: StringValue::Text("beacon.dll".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$beacon3".to_string(),
                    value: StringValue::Text("beacon.x64.dll".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$beacon4".to_string(),
                    value: StringValue::Hex(vec![0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48]), // MZ + specific bytes
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$config1".to_string(),
                    value: StringValue::Text(".http-get.server.output".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$config2".to_string(),
                    value: StringValue::Text(".http-post.client".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$pipe".to_string(),
                    value: StringValue::Text("\\\\.\\pipe\\".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "CobaltStrike_Stager".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Cobalt Strike stager shellcode".to_string()),
                malware_family: Some("Cobalt Strike".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["apt".to_string(), "cobaltstrike".to_string(), "shellcode".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$stager_x86".to_string(),
                    value: StringValue::Hex(vec![0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00]),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$stager_x64".to_string(),
                    value: StringValue::Hex(vec![0xFC, 0x48, 0x83, 0xE4, 0xF0]),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$reflective".to_string(),
                    value: StringValue::Text("ReflectiveLoader".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Metasploit Rules
// ============================================================================

fn get_metasploit_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "Metasploit_Meterpreter".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Metasploit Meterpreter payload".to_string()),
                malware_family: Some("Metasploit".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["pentest".to_string(), "metasploit".to_string(), "meterpreter".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$meterpreter1".to_string(),
                    value: StringValue::Text("metsrv.dll".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$meterpreter2".to_string(),
                    value: StringValue::Text("ext_server_stdapi".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$meterpreter3".to_string(),
                    value: StringValue::Text("ext_server_priv".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$reverse_tcp".to_string(),
                    value: StringValue::Hex(vec![0x6A, 0x10, 0x56, 0x57, 0x68, 0x99, 0xA5, 0x74, 0x61]),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "Metasploit_Shellcode".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects common Metasploit shellcode patterns".to_string()),
                malware_family: Some("Metasploit".to_string()),
                severity: Some("high".to_string()),
                ..Default::default()
            },
            tags: vec!["shellcode".to_string(), "metasploit".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$shikata".to_string(),
                    value: StringValue::Hex(vec![0xD9, 0x74, 0x24, 0xF4]),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$call_4".to_string(),
                    value: StringValue::Hex(vec![0xE8, 0xFF, 0xFF, 0xFF, 0xFF]),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Suspicious PE Characteristics Rules
// ============================================================================

fn get_suspicious_pe_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "Suspicious_PE_Headers".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects PE files with suspicious header characteristics".to_string()),
                severity: Some("medium".to_string()),
                ..Default::default()
            },
            tags: vec!["pe".to_string(), "suspicious".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$mz".to_string(),
                    value: StringValue::Hex(vec![0x4D, 0x5A]),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$pe".to_string(),
                    value: StringValue::Hex(vec![0x50, 0x45, 0x00, 0x00]),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$section_rwx".to_string(),
                    value: StringValue::Hex(vec![0xE0, 0x00, 0x00, 0x60]), // Read/Write/Execute section
                    modifiers: vec![],
                },
            ],
            condition: "$mz and $pe and $section_rwx".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "PE_Anomalies".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects PE files with anomalous section names".to_string()),
                severity: Some("medium".to_string()),
                ..Default::default()
            },
            tags: vec!["pe".to_string(), "anomaly".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$upx0".to_string(),
                    value: StringValue::Text("UPX0".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$upx1".to_string(),
                    value: StringValue::Text("UPX1".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$nsp0".to_string(),
                    value: StringValue::Text(".nsp0".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$aspack".to_string(),
                    value: StringValue::Text(".aspack".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$vmprotect".to_string(),
                    value: StringValue::Text(".vmp".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Packed/Encrypted Binary Rules
// ============================================================================

fn get_packed_binary_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "UPX_Packed".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects UPX packed executables".to_string()),
                severity: Some("low".to_string()),
                ..Default::default()
            },
            tags: vec!["packer".to_string(), "upx".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$upx_magic".to_string(),
                    value: StringValue::Text("UPX!".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$upx_sig".to_string(),
                    value: StringValue::Hex(vec![0x55, 0x50, 0x58, 0x21]),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "Themida_Packed".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Themida/WinLicense packed executables".to_string()),
                severity: Some("medium".to_string()),
                ..Default::default()
            },
            tags: vec!["packer".to_string(), "themida".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$themida1".to_string(),
                    value: StringValue::Text(".themida".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$winlicense".to_string(),
                    value: StringValue::Text("WinLicense".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$oreans".to_string(),
                    value: StringValue::Text("Oreans Technologies".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "VMProtect_Packed".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects VMProtect packed executables".to_string()),
                severity: Some("medium".to_string()),
                ..Default::default()
            },
            tags: vec!["packer".to_string(), "vmprotect".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$vmp1".to_string(),
                    value: StringValue::Text(".vmp0".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$vmp2".to_string(),
                    value: StringValue::Text(".vmp1".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$vmprotect".to_string(),
                    value: StringValue::Text("VMProtect".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Webshell Detection Rules
// ============================================================================

fn get_webshell_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "PHP_Webshell".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects PHP webshell patterns".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["webshell".to_string(), "php".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$eval".to_string(),
                    value: StringValue::Text("eval(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$base64".to_string(),
                    value: StringValue::Text("base64_decode(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$exec".to_string(),
                    value: StringValue::Text("exec(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$system".to_string(),
                    value: StringValue::Text("system(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$passthru".to_string(),
                    value: StringValue::Text("passthru(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$shell_exec".to_string(),
                    value: StringValue::Text("shell_exec(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$assert".to_string(),
                    value: StringValue::Text("assert(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$preg_replace".to_string(),
                    value: StringValue::Text("preg_replace(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$create_function".to_string(),
                    value: StringValue::Text("create_function(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$cmd".to_string(),
                    value: StringValue::Text("$_REQUEST['cmd']".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$cmd2".to_string(),
                    value: StringValue::Text("$_GET['cmd']".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$cmd3".to_string(),
                    value: StringValue::Text("$_POST['cmd']".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "3 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "ASP_Webshell".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects ASP/ASPX webshell patterns".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["webshell".to_string(), "asp".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$wscript".to_string(),
                    value: StringValue::Text("WScript.Shell".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$scripting".to_string(),
                    value: StringValue::Text("Scripting.FileSystemObject".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$execute".to_string(),
                    value: StringValue::Text("Execute(".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$cmd".to_string(),
                    value: StringValue::Text("cmd /c".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$process_start".to_string(),
                    value: StringValue::Text("Process.Start".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "JSP_Webshell".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects JSP webshell patterns".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["webshell".to_string(), "jsp".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$runtime".to_string(),
                    value: StringValue::Text("Runtime.getRuntime()".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$exec".to_string(),
                    value: StringValue::Text(".exec(".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$process_builder".to_string(),
                    value: StringValue::Text("ProcessBuilder".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$cmd".to_string(),
                    value: StringValue::Text("request.getParameter(\"cmd\")".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Cryptocurrency Miner Rules
// ============================================================================

fn get_cryptominer_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "CryptoMiner_Generic".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects cryptocurrency miner indicators".to_string()),
                severity: Some("high".to_string()),
                ..Default::default()
            },
            tags: vec!["cryptominer".to_string(), "pua".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$stratum".to_string(),
                    value: StringValue::Text("stratum+tcp://".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$stratum_ssl".to_string(),
                    value: StringValue::Text("stratum+ssl://".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$pool1".to_string(),
                    value: StringValue::Text("pool.minexmr.com".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$pool2".to_string(),
                    value: StringValue::Text("xmrpool.eu".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$pool3".to_string(),
                    value: StringValue::Text("supportxmr.com".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$cryptonight".to_string(),
                    value: StringValue::Text("cryptonight".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$randomx".to_string(),
                    value: StringValue::Text("randomx".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "XMRig_Miner".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects XMRig cryptocurrency miner".to_string()),
                severity: Some("high".to_string()),
                ..Default::default()
            },
            tags: vec!["cryptominer".to_string(), "xmrig".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$xmrig1".to_string(),
                    value: StringValue::Text("xmrig".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$xmrig2".to_string(),
                    value: StringValue::Text("--donate-level".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$xmrig3".to_string(),
                    value: StringValue::Text("\"coin\": \"monero\"".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$xmrig4".to_string(),
                    value: StringValue::Text("\"algo\": \"rx".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// RAT/Backdoor Rules
// ============================================================================

fn get_rat_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "NjRAT".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects njRAT remote access trojan".to_string()),
                reference: Some("https://attack.mitre.org/software/S0385/".to_string()),
                malware_family: Some("njRAT".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["rat".to_string(), "njrat".to_string(), "backdoor".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$njrat1".to_string(),
                    value: StringValue::Text("njRAT".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$njrat2".to_string(),
                    value: StringValue::Text("Bladabindi".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$njrat3".to_string(),
                    value: StringValue::Text("netsh firewall add".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$keylog".to_string(),
                    value: StringValue::Text("[kl]".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "QuasarRAT".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Quasar remote access trojan".to_string()),
                malware_family: Some("Quasar".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["rat".to_string(), "quasar".to_string(), "backdoor".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$quasar1".to_string(),
                    value: StringValue::Text("Quasar".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$quasar2".to_string(),
                    value: StringValue::Text("QuasarClient".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$quasar3".to_string(),
                    value: StringValue::Text("HandleGetProcesses".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$quasar4".to_string(),
                    value: StringValue::Text("DoShellExecute".to_string()),
                    modifiers: vec![],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "RemcosRAT".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects Remcos remote access trojan".to_string()),
                malware_family: Some("Remcos".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["rat".to_string(), "remcos".to_string(), "backdoor".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$remcos1".to_string(),
                    value: StringValue::Text("Remcos".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$remcos2".to_string(),
                    value: StringValue::Text("Breaking-Security.Net".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$remcos3".to_string(),
                    value: StringValue::Text("remcos.exe".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "Generic_Backdoor".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects generic backdoor indicators".to_string()),
                severity: Some("high".to_string()),
                ..Default::default()
            },
            tags: vec!["backdoor".to_string(), "generic".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$bind_shell".to_string(),
                    value: StringValue::Text("bind_shell".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$reverse_shell".to_string(),
                    value: StringValue::Text("reverse_shell".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$c2_beacon".to_string(),
                    value: StringValue::Text("beacon".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$keylogger".to_string(),
                    value: StringValue::Text("keylogger".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Ransomware Indicators
// ============================================================================

fn get_ransomware_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "Ransomware_Generic".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects generic ransomware indicators".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["ransomware".to_string(), "crypto".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$ransom1".to_string(),
                    value: StringValue::Text("Your files have been encrypted".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$ransom2".to_string(),
                    value: StringValue::Text("Pay bitcoin".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$ransom3".to_string(),
                    value: StringValue::Text("README_TO_DECRYPT".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$ransom4".to_string(),
                    value: StringValue::Text("HOW_TO_RECOVER".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$vssadmin".to_string(),
                    value: StringValue::Text("vssadmin delete shadows".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$bcdedit".to_string(),
                    value: StringValue::Text("bcdedit /set {default} recoveryenabled No".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$wbadmin".to_string(),
                    value: StringValue::Text("wbadmin delete catalog".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "2 of them".to_string(),
            is_builtin: true,
        },
        YaraRule {
            name: "Ransomware_LockBit".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects LockBit ransomware indicators".to_string()),
                malware_family: Some("LockBit".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["ransomware".to_string(), "lockbit".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$lockbit1".to_string(),
                    value: StringValue::Text("LockBit".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$lockbit2".to_string(),
                    value: StringValue::Text(".lockbit".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
                YaraString {
                    identifier: "$lockbit3".to_string(),
                    value: StringValue::Text("Restore-My-Files.txt".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "any of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Rootkit Indicators
// ============================================================================

fn get_rootkit_rules() -> Vec<YaraRule> {
    vec![
        YaraRule {
            name: "Rootkit_Generic".to_string(),
            metadata: YaraRuleMetadata {
                author: Some("HeroForge".to_string()),
                description: Some("Detects generic rootkit indicators".to_string()),
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            tags: vec!["rootkit".to_string(), "stealth".to_string()],
            strings: vec![
                YaraString {
                    identifier: "$hook1".to_string(),
                    value: StringValue::Text("NtQueryDirectoryFile".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$hook2".to_string(),
                    value: StringValue::Text("NtEnumerateValueKey".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$hook3".to_string(),
                    value: StringValue::Text("NtQuerySystemInformation".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$driver".to_string(),
                    value: StringValue::Text("\\Device\\PhysicalMemory".to_string()),
                    modifiers: vec![],
                },
                YaraString {
                    identifier: "$kernel".to_string(),
                    value: StringValue::Text("\\SystemRoot\\System32\\drivers".to_string()),
                    modifiers: vec![StringModifier::Nocase],
                },
            ],
            condition: "3 of them".to_string(),
            is_builtin: true,
        },
    ]
}

// ============================================================================
// Rule Categories
// ============================================================================

/// Category of YARA rule
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleCategory {
    Malware,
    Packer,
    Webshell,
    Cryptominer,
    RAT,
    Ransomware,
    Rootkit,
    PESuspicious,
    Custom,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleCategory::Malware => write!(f, "Malware"),
            RuleCategory::Packer => write!(f, "Packer"),
            RuleCategory::Webshell => write!(f, "Webshell"),
            RuleCategory::Cryptominer => write!(f, "Cryptominer"),
            RuleCategory::RAT => write!(f, "RAT/Backdoor"),
            RuleCategory::Ransomware => write!(f, "Ransomware"),
            RuleCategory::Rootkit => write!(f, "Rootkit"),
            RuleCategory::PESuspicious => write!(f, "Suspicious PE"),
            RuleCategory::Custom => write!(f, "Custom"),
        }
    }
}

/// Get rules by category
pub fn get_rules_by_category(category: RuleCategory) -> Vec<YaraRule> {
    match category {
        RuleCategory::Malware => {
            let mut rules = get_emotet_rules();
            rules.extend(get_trickbot_rules());
            rules.extend(get_cobalt_strike_rules());
            rules.extend(get_metasploit_rules());
            rules
        }
        RuleCategory::Packer => get_packed_binary_rules(),
        RuleCategory::Webshell => get_webshell_rules(),
        RuleCategory::Cryptominer => get_cryptominer_rules(),
        RuleCategory::RAT => get_rat_rules(),
        RuleCategory::Ransomware => get_ransomware_rules(),
        RuleCategory::Rootkit => get_rootkit_rules(),
        RuleCategory::PESuspicious => get_suspicious_pe_rules(),
        RuleCategory::Custom => Vec::new(),
    }
}

/// Get all available categories
pub fn get_all_categories() -> Vec<RuleCategory> {
    vec![
        RuleCategory::Malware,
        RuleCategory::Packer,
        RuleCategory::Webshell,
        RuleCategory::Cryptominer,
        RuleCategory::RAT,
        RuleCategory::Ransomware,
        RuleCategory::Rootkit,
        RuleCategory::PESuspicious,
    ]
}

/// Get rule count by category
pub fn get_rule_counts() -> std::collections::HashMap<RuleCategory, usize> {
    let mut counts = std::collections::HashMap::new();
    for category in get_all_categories() {
        counts.insert(category.clone(), get_rules_by_category(category).len());
    }
    counts
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_rules_load() {
        let rules = get_builtin_rules();
        assert!(!rules.is_empty());

        // Check that all rules are marked as builtin
        for rule in &rules {
            assert!(rule.is_builtin);
        }
    }

    #[test]
    fn test_rule_categories() {
        let categories = get_all_categories();
        assert!(!categories.is_empty());

        for category in categories {
            let rules = get_rules_by_category(category.clone());
            // All categories should have at least one rule (except Custom)
            assert!(!rules.is_empty() || matches!(category, RuleCategory::Custom));
        }
    }

    #[test]
    fn test_rule_counts() {
        let counts = get_rule_counts();
        let total: usize = counts.values().sum();
        let all_rules = get_builtin_rules();

        // Total from categories should match total builtin rules
        assert_eq!(total, all_rules.len());
    }

    #[test]
    fn test_emotet_rules() {
        let rules = get_emotet_rules();
        assert!(!rules.is_empty());

        for rule in &rules {
            assert!(rule.name.contains("Emotet"));
            assert!(rule.metadata.malware_family == Some("Emotet".to_string()));
        }
    }

    #[test]
    fn test_webshell_rules() {
        let rules = get_webshell_rules();
        assert!(!rules.is_empty());

        let rule_names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        assert!(rule_names.contains(&"PHP_Webshell"));
        assert!(rule_names.contains(&"ASP_Webshell"));
        assert!(rule_names.contains(&"JSP_Webshell"));
    }
}
