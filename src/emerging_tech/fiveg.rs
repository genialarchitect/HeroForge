//! 5G network security assessment

use super::types::*;
use anyhow::Result;

/// Assess 5G network security
pub async fn assess_5g_security(config: &FiveGConfig) -> Result<Vec<FiveGFinding>> {
    let mut findings = Vec::new();

    // Assess network slicing isolation
    findings.extend(assess_network_slicing_security(config));

    // Assess MEC (Multi-access Edge Computing) security
    findings.extend(assess_mec_security(config));

    // Assess fake base station detection
    findings.extend(assess_fake_base_station_risks(config));

    // Assess SS7/Diameter protocol vulnerabilities
    findings.extend(assess_signaling_protocol_security(config));

    // Assess subscriber privacy
    findings.extend(assess_subscriber_privacy(config));

    // Assess core network vulnerabilities
    findings.extend(assess_core_network_security(config));

    // Assess API security (NEF, NWDAF)
    findings.extend(assess_api_security(config));

    // Assess authentication and key agreement (AKA)
    findings.extend(assess_authentication_security(config));

    Ok(findings)
}

/// Assess network slicing security
fn assess_network_slicing_security(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    if !config.network_slices.is_empty() {
        // Basic slice configuration review
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::NetworkSlicingSecurity,
            severity: Severity::Medium,
            affected_component: "Network Slices".to_string(),
            description: format!(
                "Network has {} slices configured: {}. Each slice requires isolation verification.",
                config.network_slices.len(),
                config.network_slices.join(", ")
            ),
            recommendation: "Verify isolation between network slices using dedicated testing. Implement strict access controls per slice.".to_string(),
        });

        // Slice isolation risks
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::NetworkSlicingSecurity,
            severity: Severity::High,
            affected_component: "Slice Isolation".to_string(),
            description: "Cross-slice attacks can occur if isolation is not properly implemented at all layers (RAN, transport, core)".to_string(),
            recommendation: "Implement end-to-end slice isolation with dedicated resources. Use separate VNFs for critical slices.".to_string(),
        });

        // Slice resource exhaustion
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::NetworkSlicingSecurity,
            severity: Severity::Medium,
            affected_component: "Slice Resources".to_string(),
            description: "Resource exhaustion in one slice could affect others if not properly isolated".to_string(),
            recommendation: "Implement resource quotas per slice. Monitor resource usage and set up alerts for anomalies.".to_string(),
        });

        // Slice admission control
        if config.network_slices.len() > 3 {
            findings.push(FiveGFinding {
                finding_type: FiveGRiskType::NetworkSlicingSecurity,
                severity: Severity::Medium,
                affected_component: "Slice Admission".to_string(),
                description: format!("High number of slices ({}) increases management complexity and attack surface", config.network_slices.len()),
                recommendation: "Review slice necessity. Implement automated slice lifecycle management with security policies.".to_string(),
            });
        }
    }

    findings
}

/// Assess Multi-access Edge Computing (MEC) security
fn assess_mec_security(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    if !config.mec_endpoints.is_empty() {
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::MECSecurity,
            severity: Severity::High,
            affected_component: format!("MEC Endpoints: {}", config.mec_endpoints.join(", ")),
            description: "MEC nodes process data at the network edge, creating distributed attack surface".to_string(),
            recommendation: "Implement zero-trust architecture for MEC. Use hardware-based root of trust. Encrypt data at rest and in transit.".to_string(),
        });

        // MEC application security
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::MECSecurity,
            severity: Severity::High,
            affected_component: "MEC Applications".to_string(),
            description: "Third-party MEC applications may introduce vulnerabilities at the network edge".to_string(),
            recommendation: "Implement strict application vetting process. Use containerization with security scanning. Enforce least-privilege access.".to_string(),
        });

        // MEC API exposure
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::APIExposure,
            severity: Severity::Medium,
            affected_component: "MEC APIs".to_string(),
            description: "MEC platform APIs (ETSI MEC APIs) may expose sensitive network information".to_string(),
            recommendation: "Implement OAuth 2.0 for MEC API access. Use API rate limiting and anomaly detection.".to_string(),
        });

        // Physical security of edge nodes
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::MECSecurity,
            severity: Severity::Medium,
            affected_component: "MEC Physical Security".to_string(),
            description: "Edge nodes may be deployed in less secure physical locations than central data centers".to_string(),
            recommendation: "Implement tamper detection. Use remote attestation. Encrypt sensitive data with keys not stored locally.".to_string(),
        });
    }

    findings
}

/// Assess fake base station detection risks
fn assess_fake_base_station_risks(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    if !config.base_stations.is_empty() {
        // IMSI catcher / Stingray risks
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::FakeBaseStation,
            severity: Severity::Critical,
            affected_component: "Radio Access Network".to_string(),
            description: "5G networks remain vulnerable to IMSI catchers and fake base stations if security features are not properly configured".to_string(),
            recommendation: "Enable mandatory encryption (NEA1/NEA2/NEA3). Implement SUPI/SUCI protection. Deploy fake gNB detection systems.".to_string(),
        });

        // Downgrade attacks
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::FakeBaseStation,
            severity: Severity::High,
            affected_component: "Protocol Security".to_string(),
            description: "Attackers may force UE to connect to lower-security 4G/3G networks through bidding-down attacks".to_string(),
            recommendation: "Configure UEs to prefer 5G SA mode. Disable legacy protocols where possible. Monitor for suspicious handovers.".to_string(),
        });

        // gNB authentication
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::FakeBaseStation,
            severity: Severity::High,
            affected_component: "gNB Authentication".to_string(),
            description: format!("Base stations ({}) require proper authentication to prevent rogue gNB attacks", config.base_stations.len()),
            recommendation: "Implement mutual authentication between UE and network. Use certificate-based gNB authentication.".to_string(),
        });
    }

    findings
}

/// Assess SS7/Diameter protocol vulnerabilities
fn assess_signaling_protocol_security(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    // SS7 legacy risks (if interconnecting with legacy networks)
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::SS7Attack,
        severity: Severity::Critical,
        affected_component: "Signaling Interconnect".to_string(),
        description: "SS7 interconnection with legacy networks exposes 5G subscribers to location tracking and call interception".to_string(),
        recommendation: "Implement SS7 firewall. Filter unauthorized MAP/CAP messages. Monitor for anomalous signaling patterns.".to_string(),
    });

    // Diameter vulnerabilities
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::DiameterAttack,
        severity: Severity::High,
        affected_component: "Diameter Protocol".to_string(),
        description: "Diameter protocol used in 4G/5G roaming is vulnerable to spoofing and injection attacks".to_string(),
        recommendation: "Deploy Diameter Edge Agent (DEA) with filtering. Use IPsec for Diameter connections. Implement strict peering policies.".to_string(),
    });

    // HTTP/2 signaling (SBI)
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::High,
        affected_component: "Service Based Interface".to_string(),
        description: "5G SBI uses HTTP/2 which may be vulnerable if not properly secured".to_string(),
        recommendation: "Use mTLS for all SBI communications. Implement OAuth 2.0 for NF authorization. Deploy API gateway with WAF capabilities.".to_string(),
    });

    findings
}

/// Assess subscriber privacy
fn assess_subscriber_privacy(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    // SUPI/SUCI protection
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::SubscriberPrivacy,
        severity: Severity::Critical,
        affected_component: "Subscriber Identity".to_string(),
        description: "SUPI (permanent identity) must be protected using SUCI (concealed identity) to prevent subscriber tracking".to_string(),
        recommendation: "Verify SUCI is enabled for all subscribers. Use ECIES protection scheme. Regularly rotate concealment keys.".to_string(),
    });

    // Location privacy
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::SubscriberPrivacy,
        severity: Severity::High,
        affected_component: "Location Services".to_string(),
        description: "5G enables precise location tracking which can be exploited for surveillance".to_string(),
        recommendation: "Implement location service access controls. Require user consent for location sharing. Audit location API access.".to_string(),
    });

    // User plane encryption
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::SubscriberPrivacy,
        severity: Severity::High,
        affected_component: "User Plane".to_string(),
        description: "User plane traffic must be encrypted to protect subscriber data confidentiality".to_string(),
        recommendation: "Enable mandatory user plane encryption. Verify 5G NR encryption algorithms (NEA1/NEA2/NEA3) are properly configured.".to_string(),
    });

    // GPSI privacy
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::SubscriberPrivacy,
        severity: Severity::Medium,
        affected_component: "GPSI/MSISDN".to_string(),
        description: "GPSI (Generic Public Subscription Identifier) including phone numbers may be exposed through various APIs".to_string(),
        recommendation: "Limit GPSI exposure in APIs. Use privacy-preserving identifiers where possible.".to_string(),
    });

    findings
}

/// Assess core network security
fn assess_core_network_security(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    if let Some(ref core) = config.core_network {
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::CoreNetworkVulnerability,
            severity: Severity::High,
            affected_component: format!("Core Network: {}", core),
            description: "5G core network functions (AMF, SMF, UPF, etc.) require comprehensive security hardening".to_string(),
            recommendation: "Implement network function hardening per 3GPP security specifications. Use NFVI security best practices.".to_string(),
        });
    }

    // AMF security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::Critical,
        affected_component: "AMF (Access and Mobility)".to_string(),
        description: "AMF handles authentication and is a critical security component".to_string(),
        recommendation: "Harden AMF deployment. Implement rate limiting. Monitor for authentication anomalies.".to_string(),
    });

    // SMF security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::High,
        affected_component: "SMF (Session Management)".to_string(),
        description: "SMF manages PDU sessions and QoS which could be exploited for DoS attacks".to_string(),
        recommendation: "Implement session limits per subscriber. Monitor for abnormal session patterns.".to_string(),
    });

    // UPF security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::High,
        affected_component: "UPF (User Plane)".to_string(),
        description: "UPF handles all user traffic and is a high-value target for interception".to_string(),
        recommendation: "Deploy UPF in secure network segments. Implement traffic inspection for malware. Ensure encryption is enforced.".to_string(),
    });

    // UDM/AUSF security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::Critical,
        affected_component: "UDM/AUSF".to_string(),
        description: "UDM and AUSF store and process subscriber credentials and must be protected".to_string(),
        recommendation: "Use HSM for key storage. Implement strict access controls. Encrypt subscriber data at rest.".to_string(),
    });

    findings
}

/// Assess API security (NEF, NWDAF, etc.)
fn assess_api_security(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    // NEF (Network Exposure Function) security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::APIExposure,
        severity: Severity::High,
        affected_component: "NEF (Network Exposure Function)".to_string(),
        description: "NEF exposes network capabilities to external applications, creating API attack surface".to_string(),
        recommendation: "Implement OAuth 2.0 client credentials for NEF APIs. Use API rate limiting. Audit all API access.".to_string(),
    });

    // NWDAF security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::APIExposure,
        severity: Severity::Medium,
        affected_component: "NWDAF (Network Data Analytics)".to_string(),
        description: "NWDAF collects network analytics which could reveal sensitive operational information".to_string(),
        recommendation: "Anonymize analytics data. Implement access controls based on data sensitivity. Monitor data export.".to_string(),
    });

    // SCEF/PCF exposure
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::APIExposure,
        severity: Severity::Medium,
        affected_component: "Policy Control APIs".to_string(),
        description: "Policy control APIs could be abused to modify subscriber QoS or access rights".to_string(),
        recommendation: "Implement strict authorization for policy APIs. Log all policy changes. Use approval workflows for critical policies.".to_string(),
    });

    // Third-party API access
    if !config.mec_endpoints.is_empty() || !config.network_slices.is_empty() {
        findings.push(FiveGFinding {
            finding_type: FiveGRiskType::APIExposure,
            severity: Severity::High,
            affected_component: "Third-Party APIs".to_string(),
            description: "Enterprise and partner API access requires careful security controls".to_string(),
            recommendation: "Use API gateway with threat detection. Implement per-partner rate limits. Require mTLS for B2B APIs.".to_string(),
        });
    }

    findings
}

/// Assess authentication and key agreement security
fn assess_authentication_security(config: &FiveGConfig) -> Vec<FiveGFinding> {
    let mut findings = Vec::new();

    // 5G-AKA security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::Critical,
        affected_component: "5G-AKA".to_string(),
        description: "5G-AKA (Authentication and Key Agreement) must be properly implemented to prevent impersonation".to_string(),
        recommendation: "Verify 5G-AKA implementation follows 3GPP TS 33.501. Test for known AKA vulnerabilities. Enable home network control.".to_string(),
    });

    // EAP-AKA' for untrusted access
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::High,
        affected_component: "EAP-AKA'".to_string(),
        description: "EAP-AKA' used for non-3GPP access (WiFi) requires additional security considerations".to_string(),
        recommendation: "Secure N3IWF/TNGF interfaces. Implement certificate-based authentication where possible.".to_string(),
    });

    // Key derivation and storage
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::CoreNetworkVulnerability,
        severity: Severity::Critical,
        affected_component: "Key Management".to_string(),
        description: "Subscriber keys (K) and derived keys must be protected throughout their lifecycle".to_string(),
        recommendation: "Use HSM for key storage in AUSF. Implement key rotation. Audit key access logs.".to_string(),
    });

    // USIM security
    findings.push(FiveGFinding {
        finding_type: FiveGRiskType::SubscriberPrivacy,
        severity: Severity::High,
        affected_component: "USIM/eSIM".to_string(),
        description: "Subscriber credentials stored in USIM/eSIM are high-value targets".to_string(),
        recommendation: "Use certified USIM with latest security features. Implement eSIM profile encryption. Monitor for SIM swap attacks.".to_string(),
    });

    findings
}

/// Comprehensive 5G security assessment result
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FiveGSecurityAssessment {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub findings_by_type: std::collections::HashMap<String, usize>,
    pub slices_assessed: usize,
    pub mec_nodes_assessed: usize,
    pub recommendations: Vec<String>,
}

/// Generate a comprehensive assessment summary
pub fn generate_assessment_summary(findings: &[FiveGFinding], config: &FiveGConfig) -> FiveGSecurityAssessment {
    let mut assessment = FiveGSecurityAssessment::default();
    assessment.total_findings = findings.len();
    assessment.slices_assessed = config.network_slices.len();
    assessment.mec_nodes_assessed = config.mec_endpoints.len();

    let mut findings_by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for finding in findings {
        match finding.severity {
            Severity::Critical => assessment.critical_findings += 1,
            Severity::High => assessment.high_findings += 1,
            Severity::Medium => assessment.medium_findings += 1,
            Severity::Low | Severity::Info => assessment.low_findings += 1,
        }

        let type_name = format!("{:?}", finding.finding_type);
        *findings_by_type.entry(type_name).or_insert(0) += 1;
    }

    assessment.findings_by_type = findings_by_type;

    // Generate prioritized recommendations
    if assessment.critical_findings > 0 {
        assessment.recommendations.push(
            "CRITICAL: Address authentication and subscriber identity protection immediately.".to_string()
        );
    }
    if assessment.high_findings > 0 {
        assessment.recommendations.push(
            "HIGH: Review network slicing isolation and MEC security configurations.".to_string()
        );
    }
    assessment.recommendations.push(
        "Implement comprehensive 5G security monitoring aligned with 3GPP TS 33.501.".to_string()
    );
    assessment.recommendations.push(
        "Conduct regular security assessments of RAN, core network, and interconnections.".to_string()
    );
    if !config.network_slices.is_empty() {
        assessment.recommendations.push(
            format!("Verify isolation for {} configured network slices.", config.network_slices.len())
        );
    }

    assessment
}
