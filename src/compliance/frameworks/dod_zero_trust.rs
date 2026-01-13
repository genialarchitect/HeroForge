//! DoD Zero Trust Reference Architecture Controls
//!
//! The Department of Defense Zero Trust Reference Architecture defines a security
//! model based on the principle of "never trust, always verify." This framework
//! organizes controls across seven pillars that together create a comprehensive
//! zero trust security posture.
//!
//! ## Seven Pillars of DoD Zero Trust
//!
//! 1. **User** - Identity verification, authentication, and authorization
//! 2. **Device** - Device trust, health validation, and compliance
//! 3. **Network/Environment** - Micro-segmentation and software-defined perimeters
//! 4. **Application & Workload** - Application security and workload protection
//! 5. **Data** - Data classification, encryption, and protection
//! 6. **Visibility & Analytics** - Continuous monitoring and threat detection
//! 7. **Automation & Orchestration** - Security automation and response
//!
//! ## Key Principles
//!
//! - Assume breach: Design systems assuming adversaries are already inside
//! - Verify explicitly: Authenticate and authorize based on all available data
//! - Least privilege access: Limit access to minimum necessary
//! - Encryption everywhere: Protect data in transit and at rest
//! - Continuous monitoring: Monitor and validate security posture continuously

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of DoD Zero Trust controls in this module
pub const CONTROL_COUNT: usize = 50;

/// Get all DoD Zero Trust Reference Architecture controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // Add controls by pillar
    controls.extend(get_user_pillar_controls());
    controls.extend(get_device_pillar_controls());
    controls.extend(get_network_pillar_controls());
    controls.extend(get_application_pillar_controls());
    controls.extend(get_data_pillar_controls());
    controls.extend(get_visibility_pillar_controls());
    controls.extend(get_automation_pillar_controls());

    controls
}

/// Pillar 1: User - Identity verification and access controls
fn get_user_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-USER-001".to_string(),
            control_id: "ZT.1.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Multi-Factor Authentication Required".to_string(),
            description: "All users must authenticate using phishing-resistant multi-factor authentication (MFA) before accessing any resources. This includes hardware tokens, FIDO2 keys, or certificate-based authentication.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "CIS-6.3".to_string()],
            remediation_guidance: Some("Implement phishing-resistant MFA (hardware tokens, FIDO2, PKI) for all user accounts. Disable legacy authentication methods.".to_string()),
        },
        ComplianceControl {
            id: "ZT-USER-002".to_string(),
            control_id: "ZT.1.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Identity Verification at Every Access".to_string(),
            description: "User identity must be verified for every access request, not just at initial login. Session tokens must be validated continuously.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-4".to_string(), "NIST-IA-5".to_string()],
            remediation_guidance: Some("Implement continuous authentication with short-lived tokens. Require re-authentication for sensitive operations.".to_string()),
        },
        ComplianceControl {
            id: "ZT-USER-003".to_string(),
            control_id: "ZT.1.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Least Privilege Access".to_string(),
            description: "Users must be granted the minimum level of access required to perform their duties. Access rights must be reviewed and adjusted regularly.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CIS-3.3".to_string()],
            remediation_guidance: Some("Implement role-based access control (RBAC) with just-in-time (JIT) access provisioning. Conduct quarterly access reviews.".to_string()),
        },
        ComplianceControl {
            id: "ZT-USER-004".to_string(),
            control_id: "ZT.1.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Risk-Based Access Decisions".to_string(),
            description: "Access decisions must incorporate real-time risk assessment including user behavior, location, device health, and threat intelligence.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Deploy conditional access policies that evaluate risk signals before granting access. Integrate with threat intelligence feeds.".to_string()),
        },
        ComplianceControl {
            id: "ZT-USER-005".to_string(),
            control_id: "ZT.1.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Privileged Access Management".to_string(),
            description: "Privileged accounts must have additional protections including dedicated workstations, enhanced monitoring, and time-limited elevation.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-5.4".to_string()],
            remediation_guidance: Some("Implement Privileged Access Management (PAM) solution with privileged access workstations (PAWs) and just-in-time elevation.".to_string()),
        },
        ComplianceControl {
            id: "ZT-USER-006".to_string(),
            control_id: "ZT.1.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Identity Federation and SSO".to_string(),
            description: "Identity services must be centralized through federation and single sign-on to enable consistent policy enforcement and auditability.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-8".to_string()],
            remediation_guidance: Some("Implement enterprise identity provider with SAML 2.0/OIDC federation. Consolidate all application authentication through SSO.".to_string()),
        },
        ComplianceControl {
            id: "ZT-USER-007".to_string(),
            control_id: "ZT.1.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "User Behavior Analytics".to_string(),
            description: "User activities must be monitored for anomalous behavior patterns that may indicate compromised credentials or insider threats.".to_string(),
            category: "User".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string(), "NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy User and Entity Behavior Analytics (UEBA) to detect anomalous access patterns. Configure alerts for deviations from baseline behavior.".to_string()),
        },
    ]
}

/// Pillar 2: Device - Device trust and compliance
fn get_device_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-DEVICE-001".to_string(),
            control_id: "ZT.2.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Device Identity and Authentication".to_string(),
            description: "All devices must have cryptographic identities (certificates or TPM-based attestation) that are verified before network access is granted.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-3".to_string(), "NIST-IA-9".to_string()],
            remediation_guidance: Some("Deploy device certificates or TPM-based attestation. Implement 802.1X for network access control based on device identity.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DEVICE-002".to_string(),
            control_id: "ZT.2.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Device Health Validation".to_string(),
            description: "Device security posture must be continuously validated including OS version, patch level, security software status, and configuration compliance.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "CIS-1.1".to_string()],
            remediation_guidance: Some("Implement endpoint detection and response (EDR) with health attestation. Block non-compliant devices from accessing resources.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DEVICE-003".to_string(),
            control_id: "ZT.2.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Endpoint Protection".to_string(),
            description: "All endpoints must have advanced endpoint protection including anti-malware, host-based firewall, and application control.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CIS-10.1".to_string()],
            remediation_guidance: Some("Deploy next-generation antivirus (NGAV) with EDR capabilities. Enable host-based firewall with default-deny rules.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DEVICE-004".to_string(),
            control_id: "ZT.2.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Device Encryption".to_string(),
            description: "All devices must use full-disk encryption with pre-boot authentication to protect data at rest.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Enable BitLocker (Windows) or FileVault (macOS) with TPM and PIN/password. Use LUKS encryption for Linux endpoints.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DEVICE-005".to_string(),
            control_id: "ZT.2.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Mobile Device Management".to_string(),
            description: "Mobile devices accessing organizational resources must be enrolled in MDM with security policies enforced including remote wipe capability.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Implement MDM/UEM solution. Require device enrollment before resource access. Configure automatic compliance policies.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DEVICE-006".to_string(),
            control_id: "ZT.2.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Device Inventory and Classification".to_string(),
            description: "All devices must be inventoried, classified by sensitivity, and tracked throughout their lifecycle.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "CIS-1.1".to_string()],
            remediation_guidance: Some("Deploy automated asset discovery and management. Tag devices with classification labels based on authorized data access levels.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DEVICE-007".to_string(),
            control_id: "ZT.2.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Secure Boot and Firmware Integrity".to_string(),
            description: "Devices must use secure boot to ensure only trusted firmware and operating system components are loaded.".to_string(),
            category: "Device".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-7".to_string()],
            remediation_guidance: Some("Enable UEFI Secure Boot on all compatible devices. Implement measured boot with TPM attestation for critical systems.".to_string()),
        },
    ]
}

/// Pillar 3: Network/Environment - Micro-segmentation and SDN
fn get_network_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-NET-001".to_string(),
            control_id: "ZT.3.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Micro-Segmentation".to_string(),
            description: "Networks must be segmented at the workload level to limit lateral movement. Each workload should have its own security perimeter.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CIS-12.1".to_string()],
            remediation_guidance: Some("Implement software-defined micro-segmentation. Define granular policies at the workload level with default-deny between segments.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-002".to_string(),
            control_id: "ZT.3.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Software-Defined Perimeter".to_string(),
            description: "Access to resources must be through software-defined perimeters that hide resources from unauthorized users until identity and posture are verified.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Deploy SDP/ZTNA solution that makes resources invisible until after authentication. Eliminate direct internet exposure of applications.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-003".to_string(),
            control_id: "ZT.3.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Encrypted Network Communications".to_string(),
            description: "All network communications must be encrypted using TLS 1.2 or higher, including internal east-west traffic.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "CIS-3.10".to_string()],
            remediation_guidance: Some("Enable TLS 1.2/1.3 for all network communications. Implement mutual TLS (mTLS) for service-to-service communication.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-004".to_string(),
            control_id: "ZT.3.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Network Access Control".to_string(),
            description: "Network access must be controlled at the port level with 802.1X authentication and dynamic VLAN assignment based on identity and posture.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Implement 802.1X with RADIUS for network access. Configure dynamic VLAN assignment based on user role and device compliance.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-005".to_string(),
            control_id: "ZT.3.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "DNS Security".to_string(),
            description: "DNS traffic must be secured using DNSSEC and DNS-over-HTTPS/TLS. Protective DNS filtering must block known malicious domains.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-20".to_string()],
            remediation_guidance: Some("Enable DNSSEC validation. Deploy protective DNS with threat intelligence feeds. Use DNS-over-HTTPS for client DNS resolution.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-006".to_string(),
            control_id: "ZT.3.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Network Traffic Inspection".to_string(),
            description: "All network traffic, including encrypted traffic, must be inspected for threats using TLS inspection where legally and technically feasible.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy next-generation firewalls with TLS inspection capabilities. Configure exemptions for sensitive traffic as required by policy.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-007".to_string(),
            control_id: "ZT.3.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Eliminate Implicit Trust Zones".to_string(),
            description: "There must be no implicit trust based on network location. Internal networks must not be automatically trusted.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Remove assumptions of trust based on network location. Apply the same authentication and authorization requirements regardless of source network.".to_string()),
        },
        ComplianceControl {
            id: "ZT-NET-008".to_string(),
            control_id: "ZT.3.8".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Network Isolation for Sensitive Workloads".to_string(),
            description: "Highly sensitive workloads must be isolated in dedicated network segments with additional security controls.".to_string(),
            category: "Network/Environment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Create isolated network segments for sensitive workloads. Implement additional logging, monitoring, and access controls for these segments.".to_string()),
        },
    ]
}

/// Pillar 4: Application & Workload - Application security
fn get_application_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-APP-001".to_string(),
            control_id: "ZT.4.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Application-Level Access Control".to_string(),
            description: "Access to applications must be controlled at the application layer with fine-grained authorization based on user attributes and context.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Implement application-level authorization using OAuth 2.0/OIDC with fine-grained scopes. Use attribute-based access control (ABAC) where needed.".to_string()),
        },
        ComplianceControl {
            id: "ZT-APP-002".to_string(),
            control_id: "ZT.4.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Secure API Authentication".to_string(),
            description: "All API access must use strong authentication mechanisms such as OAuth 2.0, mutual TLS, or API keys with proper rotation.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-9".to_string()],
            remediation_guidance: Some("Implement OAuth 2.0 for API authentication. Use API gateways to enforce authentication and rate limiting. Rotate API keys regularly.".to_string()),
        },
        ComplianceControl {
            id: "ZT-APP-003".to_string(),
            control_id: "ZT.4.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Application Security Testing".to_string(),
            description: "Applications must undergo regular security testing including SAST, DAST, and IAST throughout the development lifecycle.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string()],
            remediation_guidance: Some("Integrate SAST/DAST tools into CI/CD pipelines. Perform penetration testing before major releases. Remediate critical findings before deployment.".to_string()),
        },
        ComplianceControl {
            id: "ZT-APP-004".to_string(),
            control_id: "ZT.4.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Container Security".to_string(),
            description: "Container images must be scanned for vulnerabilities, signed, and run with minimal privileges in hardened runtime environments.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Implement container image scanning in CI/CD. Use image signing and verification. Run containers as non-root with read-only filesystems.".to_string()),
        },
        ComplianceControl {
            id: "ZT-APP-005".to_string(),
            control_id: "ZT.4.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Workload Identity".to_string(),
            description: "Workloads must have cryptographic identities (SPIFFE/SPIRE or equivalent) for mutual authentication between services.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-9".to_string()],
            remediation_guidance: Some("Deploy workload identity framework (SPIFFE/SPIRE). Implement mutual TLS between all services using workload identities.".to_string()),
        },
        ComplianceControl {
            id: "ZT-APP-006".to_string(),
            control_id: "ZT.4.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Runtime Application Protection".to_string(),
            description: "Applications must have runtime protection including RASP, web application firewall, and API security gateway.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Deploy WAF in front of web applications. Implement RASP for critical applications. Use API gateways with security policies.".to_string()),
        },
        ComplianceControl {
            id: "ZT-APP-007".to_string(),
            control_id: "ZT.4.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Software Supply Chain Security".to_string(),
            description: "Software dependencies must be verified for integrity and scanned for vulnerabilities. SBOM must be maintained for all applications.".to_string(),
            category: "Application & Workload".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-10".to_string()],
            remediation_guidance: Some("Implement SCA scanning in CI/CD pipelines. Generate and maintain SBOMs. Verify signatures on all dependencies.".to_string()),
        },
    ]
}

/// Pillar 5: Data - Data protection and classification
fn get_data_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-DATA-001".to_string(),
            control_id: "ZT.5.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Data Classification".to_string(),
            description: "All data must be classified according to sensitivity and handling requirements. Classification must be enforced through technical controls.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-2".to_string()],
            remediation_guidance: Some("Implement data classification taxonomy. Deploy automated data discovery and classification tools. Label data with sensitivity markings.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DATA-002".to_string(),
            control_id: "ZT.5.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Data Encryption at Rest".to_string(),
            description: "All sensitive data must be encrypted at rest using AES-256 or equivalent, with keys managed through enterprise key management.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Enable encryption at rest for all storage systems. Use enterprise key management system (KMS) with HSM backing for key storage.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DATA-003".to_string(),
            control_id: "ZT.5.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Data Encryption in Transit".to_string(),
            description: "All data in transit must be encrypted using TLS 1.2 or higher with strong cipher suites. Certificate pinning should be used where feasible.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Enforce TLS 1.2+ for all communications. Disable weak cipher suites. Implement certificate pinning for mobile applications.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DATA-004".to_string(),
            control_id: "ZT.5.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Data Loss Prevention".to_string(),
            description: "DLP controls must be implemented to prevent unauthorized exfiltration of sensitive data through email, web, endpoints, and cloud services.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string()],
            remediation_guidance: Some("Deploy DLP solution covering email, web proxy, endpoints, and cloud apps. Create policies based on data classification. Monitor and block violations.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DATA-005".to_string(),
            control_id: "ZT.5.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Data Access Logging".to_string(),
            description: "All access to sensitive data must be logged with sufficient detail for forensic investigation and compliance auditing.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "NIST-AU-3".to_string()],
            remediation_guidance: Some("Enable data access auditing on all data stores. Include user, timestamp, action, and data accessed. Retain logs according to policy requirements.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DATA-006".to_string(),
            control_id: "ZT.5.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Key Management".to_string(),
            description: "Encryption keys must be managed through a centralized enterprise key management system with proper key rotation, backup, and access controls.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string()],
            remediation_guidance: Some("Deploy enterprise KMS with HSM backing. Implement automated key rotation. Maintain key escrow and recovery procedures.".to_string()),
        },
        ComplianceControl {
            id: "ZT-DATA-007".to_string(),
            control_id: "ZT.5.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Data Rights Management".to_string(),
            description: "Sensitive documents must be protected with information rights management (IRM) that persists regardless of where the data travels.".to_string(),
            category: "Data".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Deploy IRM/DRM solution for sensitive documents. Apply persistent protection labels that travel with the data.".to_string()),
        },
    ]
}

/// Pillar 6: Visibility & Analytics - Continuous monitoring
fn get_visibility_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-VIS-001".to_string(),
            control_id: "ZT.6.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Centralized Security Logging".to_string(),
            description: "All security-relevant events must be collected into a centralized SIEM for correlation, analysis, and retention.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Deploy enterprise SIEM. Configure log collection from all security controls, applications, and infrastructure. Define correlation rules for threat detection.".to_string()),
        },
        ComplianceControl {
            id: "ZT-VIS-002".to_string(),
            control_id: "ZT.6.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Continuous Monitoring".to_string(),
            description: "Security posture must be continuously monitored across all pillars with real-time visibility into threats and vulnerabilities.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CA-7".to_string()],
            remediation_guidance: Some("Implement continuous security monitoring dashboards. Deploy automated vulnerability scanning. Integrate threat intelligence feeds.".to_string()),
        },
        ComplianceControl {
            id: "ZT-VIS-003".to_string(),
            control_id: "ZT.6.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Threat Intelligence Integration".to_string(),
            description: "Security tools must be integrated with threat intelligence feeds to enable proactive threat detection and blocking.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-5".to_string()],
            remediation_guidance: Some("Subscribe to commercial and government threat intelligence feeds. Automate indicator ingestion into security tools for blocking and alerting.".to_string()),
        },
        ComplianceControl {
            id: "ZT-VIS-004".to_string(),
            control_id: "ZT.6.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Network Traffic Analysis".to_string(),
            description: "Network traffic must be analyzed for anomalies, lateral movement, and command-and-control communications.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy network detection and response (NDR) solution. Analyze network flows for anomalous patterns. Alert on C2 indicators and lateral movement.".to_string()),
        },
        ComplianceControl {
            id: "ZT-VIS-005".to_string(),
            control_id: "ZT.6.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Security Metrics and Reporting".to_string(),
            description: "Security metrics must be collected and reported to measure the effectiveness of zero trust controls and identify gaps.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-6".to_string()],
            remediation_guidance: Some("Define KPIs for each zero trust pillar. Create automated security dashboards. Report metrics to leadership monthly.".to_string()),
        },
        ComplianceControl {
            id: "ZT-VIS-006".to_string(),
            control_id: "ZT.6.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Security Analytics and ML".to_string(),
            description: "Machine learning and advanced analytics must be used to detect sophisticated threats and anomalous behavior patterns.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy UEBA and ML-based threat detection. Train models on baseline normal behavior. Configure alerts for anomaly detection.".to_string()),
        },
        ComplianceControl {
            id: "ZT-VIS-007".to_string(),
            control_id: "ZT.6.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Cloud Security Posture Management".to_string(),
            description: "Cloud environments must be continuously monitored for misconfigurations, compliance violations, and security risks.".to_string(),
            category: "Visibility & Analytics".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Deploy CSPM solution for all cloud environments. Configure policies aligned with zero trust requirements. Automate remediation of critical findings.".to_string()),
        },
    ]
}

/// Pillar 7: Automation & Orchestration - Security automation
fn get_automation_pillar_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ZT-AUTO-001".to_string(),
            control_id: "ZT.7.1".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Security Orchestration and Response".to_string(),
            description: "Security operations must be supported by SOAR capabilities for automated response to common threats and faster incident handling.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Deploy SOAR platform. Create playbooks for common incident types. Automate initial triage and response actions.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-002".to_string(),
            control_id: "ZT.7.2".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Automated Policy Enforcement".to_string(),
            description: "Security policies must be enforced automatically across all systems through policy-as-code and continuous compliance monitoring.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Implement policy-as-code using OPA or similar. Automate policy deployment through CI/CD. Monitor for drift and auto-remediate.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-003".to_string(),
            control_id: "ZT.7.3".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Automated Threat Response".to_string(),
            description: "High-confidence threat detections must trigger automated response actions such as isolation, blocking, or credential revocation.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Configure automated response actions for high-confidence threats. Implement automatic isolation of compromised endpoints. Enable auto-block for known malicious IPs/domains.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-004".to_string(),
            control_id: "ZT.7.4".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Infrastructure as Code Security".to_string(),
            description: "Infrastructure must be deployed through IaC with security policies embedded and validated before deployment.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-10".to_string()],
            remediation_guidance: Some("Use IaC for all infrastructure deployment. Integrate security scanning into IaC pipelines. Enforce security policies as pre-deployment gates.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-005".to_string(),
            control_id: "ZT.7.5".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Automated Vulnerability Remediation".to_string(),
            description: "Vulnerability remediation must be automated where possible, with automatic patching for approved updates.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string()],
            remediation_guidance: Some("Implement automated patch management. Configure auto-updates for approved patches. Automate container image updates when base images are patched.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-006".to_string(),
            control_id: "ZT.7.6".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "DevSecOps Integration".to_string(),
            description: "Security must be integrated into the software development lifecycle with automated security testing and policy enforcement in CI/CD pipelines.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string()],
            remediation_guidance: Some("Integrate SAST, DAST, and SCA into CI/CD pipelines. Enforce security gates that block deployment of vulnerable code. Provide developer security training.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-007".to_string(),
            control_id: "ZT.7.7".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Zero Trust Policy Engine".to_string(),
            description: "A centralized policy decision point must evaluate all access requests using real-time context from identity, device, network, and threat signals.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Deploy centralized policy engine (PDP) that integrates signals from all zero trust pillars. Route all access decisions through the policy engine.".to_string()),
        },
        ComplianceControl {
            id: "ZT-AUTO-008".to_string(),
            control_id: "ZT.7.8".to_string(),
            framework: ComplianceFramework::DodZeroTrust,
            title: "Configuration Management Automation".to_string(),
            description: "System configurations must be managed through automation with drift detection and automatic remediation to maintain security baselines.".to_string(),
            category: "Automation & Orchestration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Implement configuration management (Ansible, Puppet, Chef). Define security baselines as code. Enable drift detection with auto-remediation.".to_string()),
        },
    ]
}

/// Get all DoD Zero Trust pillar names
pub fn get_pillars() -> Vec<&'static str> {
    vec![
        "User",
        "Device",
        "Network/Environment",
        "Application & Workload",
        "Data",
        "Visibility & Analytics",
        "Automation & Orchestration",
    ]
}

/// Get controls by pillar
pub fn get_controls_by_pillar(pillar: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(pillar))
        .collect()
}

/// Map a vulnerability to relevant DoD Zero Trust controls (with severity)
/// Used by the compliance control mapping system
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // User Pillar - Authentication and Identity
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("credential")
        || title_lower.contains("mfa")
        || title_lower.contains("multi-factor")
    {
        mappings.push(("ZT.1.1".to_string(), Severity::Critical)); // MFA Required
        mappings.push(("ZT.1.2".to_string(), Severity::High)); // Identity Verification
    }

    if title_lower.contains("privilege")
        || title_lower.contains("escalation")
        || title_lower.contains("admin")
        || title_lower.contains("root")
    {
        mappings.push(("ZT.1.3".to_string(), Severity::Critical)); // Least Privilege
        mappings.push(("ZT.1.5".to_string(), Severity::Critical)); // PAM
    }

    if title_lower.contains("session")
        || title_lower.contains("token")
        || title_lower.contains("jwt")
    {
        mappings.push(("ZT.1.2".to_string(), Severity::High)); // Identity Verification
        mappings.push(("ZT.1.4".to_string(), Severity::Medium)); // Risk-Based Access
    }

    // Device Pillar
    if title_lower.contains("endpoint")
        || title_lower.contains("device")
        || title_lower.contains("workstation")
    {
        mappings.push(("ZT.2.2".to_string(), Severity::High)); // Device Health
        mappings.push(("ZT.2.3".to_string(), Severity::High)); // Endpoint Protection
    }

    if title_lower.contains("antivirus")
        || title_lower.contains("malware")
        || title_lower.contains("edr")
    {
        mappings.push(("ZT.2.3".to_string(), Severity::Critical)); // Endpoint Protection
    }

    if title_lower.contains("disk encryption")
        || title_lower.contains("bitlocker")
        || title_lower.contains("filevault")
    {
        mappings.push(("ZT.2.4".to_string(), Severity::Critical)); // Device Encryption
    }

    if title_lower.contains("secure boot")
        || title_lower.contains("firmware")
        || title_lower.contains("uefi")
    {
        mappings.push(("ZT.2.7".to_string(), Severity::High)); // Secure Boot
    }

    // Network Pillar
    if title_lower.contains("segment")
        || title_lower.contains("lateral")
        || title_lower.contains("network isolation")
    {
        mappings.push(("ZT.3.1".to_string(), Severity::Critical)); // Micro-Segmentation
        mappings.push(("ZT.3.7".to_string(), Severity::High)); // Eliminate Trust Zones
    }

    if title_lower.contains("tls")
        || title_lower.contains("ssl")
        || title_lower.contains("certificate")
        || title_lower.contains("https")
    {
        mappings.push(("ZT.3.3".to_string(), Severity::Critical)); // Encrypted Communications
    }

    if title_lower.contains("firewall")
        || title_lower.contains("acl")
        || title_lower.contains("access control list")
    {
        mappings.push(("ZT.3.1".to_string(), Severity::High)); // Micro-Segmentation
        mappings.push(("ZT.3.4".to_string(), Severity::High)); // Network Access Control
    }

    if title_lower.contains("dns")
        || title_lower.contains("dnssec")
    {
        mappings.push(("ZT.3.5".to_string(), Severity::High)); // DNS Security
    }

    // Application Pillar
    if title_lower.contains("api")
        || title_lower.contains("oauth")
        || title_lower.contains("authorization")
    {
        mappings.push(("ZT.4.1".to_string(), Severity::High)); // App-Level Access Control
        mappings.push(("ZT.4.2".to_string(), Severity::High)); // Secure API Auth
    }

    if title_lower.contains("container")
        || title_lower.contains("docker")
        || title_lower.contains("kubernetes")
    {
        mappings.push(("ZT.4.4".to_string(), Severity::High)); // Container Security
    }

    if title_lower.contains("xss")
        || title_lower.contains("injection")
        || title_lower.contains("sqli")
        || title_lower.contains("csrf")
    {
        mappings.push(("ZT.4.3".to_string(), Severity::Critical)); // Application Security Testing
        mappings.push(("ZT.4.6".to_string(), Severity::High)); // Runtime Protection
    }

    if title_lower.contains("supply chain")
        || title_lower.contains("dependency")
        || title_lower.contains("sbom")
    {
        mappings.push(("ZT.4.7".to_string(), Severity::High)); // Supply Chain Security
    }

    // Data Pillar
    if title_lower.contains("encrypt")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
    {
        mappings.push(("ZT.5.2".to_string(), Severity::Critical)); // Encryption at Rest
        mappings.push(("ZT.5.3".to_string(), Severity::Critical)); // Encryption in Transit
    }

    if title_lower.contains("data leak")
        || title_lower.contains("data loss")
        || title_lower.contains("dlp")
        || title_lower.contains("exfiltration")
    {
        mappings.push(("ZT.5.4".to_string(), Severity::Critical)); // DLP
    }

    if title_lower.contains("key management")
        || title_lower.contains("kms")
        || title_lower.contains("encryption key")
    {
        mappings.push(("ZT.5.6".to_string(), Severity::Critical)); // Key Management
    }

    if title_lower.contains("classification")
        || title_lower.contains("sensitive data")
    {
        mappings.push(("ZT.5.1".to_string(), Severity::High)); // Data Classification
    }

    // Visibility Pillar
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("siem")
    {
        mappings.push(("ZT.6.1".to_string(), Severity::High)); // Centralized Logging
        mappings.push(("ZT.5.5".to_string(), Severity::High)); // Data Access Logging
    }

    if title_lower.contains("monitoring")
        || title_lower.contains("detection")
        || title_lower.contains("visibility")
    {
        mappings.push(("ZT.6.2".to_string(), Severity::High)); // Continuous Monitoring
    }

    if title_lower.contains("threat intel")
        || title_lower.contains("indicator")
        || title_lower.contains("ioc")
    {
        mappings.push(("ZT.6.3".to_string(), Severity::Medium)); // Threat Intelligence
    }

    if title_lower.contains("network traffic")
        || title_lower.contains("ndr")
        || title_lower.contains("netflow")
    {
        mappings.push(("ZT.6.4".to_string(), Severity::High)); // Network Traffic Analysis
    }

    if title_lower.contains("cloud")
        || title_lower.contains("cspm")
        || title_lower.contains("misconfiguration")
    {
        mappings.push(("ZT.6.7".to_string(), Severity::High)); // CSPM
    }

    // Automation Pillar
    if title_lower.contains("soar")
        || title_lower.contains("automation")
        || title_lower.contains("playbook")
    {
        mappings.push(("ZT.7.1".to_string(), Severity::Medium)); // SOAR
    }

    if title_lower.contains("patch")
        || title_lower.contains("update")
        || title_lower.contains("outdated")
    {
        mappings.push(("ZT.7.5".to_string(), Severity::High)); // Automated Vulnerability Remediation
    }

    if title_lower.contains("devsecops")
        || title_lower.contains("ci/cd")
        || title_lower.contains("pipeline")
    {
        mappings.push(("ZT.7.6".to_string(), Severity::High)); // DevSecOps Integration
    }

    if title_lower.contains("policy")
        || title_lower.contains("compliance")
    {
        mappings.push(("ZT.7.2".to_string(), Severity::Medium)); // Automated Policy Enforcement
        mappings.push(("ZT.7.7".to_string(), Severity::High)); // Zero Trust Policy Engine
    }

    if title_lower.contains("configuration")
        || title_lower.contains("baseline")
        || title_lower.contains("drift")
    {
        mappings.push(("ZT.7.8".to_string(), Severity::High)); // Configuration Management Automation
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_count() {
        let controls = get_controls();
        assert_eq!(controls.len(), CONTROL_COUNT,
            "Expected {} controls but found {}", CONTROL_COUNT, controls.len());
    }

    #[test]
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty(), "Control ID is empty");
            assert!(!control.control_id.is_empty(), "Control control_id is empty");
            assert!(!control.title.is_empty(), "Control title is empty: {}", control.id);
            assert!(!control.description.is_empty(), "Control description is empty: {}", control.id);
            assert!(!control.category.is_empty(), "Control category is empty: {}", control.id);
            assert!(control.remediation_guidance.is_some(), "Control missing remediation: {}", control.id);
        }
    }

    #[test]
    fn test_all_pillars_have_controls() {
        let pillars = get_pillars();
        for pillar in pillars {
            let controls = get_controls_by_pillar(pillar);
            assert!(!controls.is_empty(), "Pillar {} has no controls", pillar);
        }
    }

    #[test]
    fn test_pillar_control_distribution() {
        // Verify each pillar has reasonable number of controls
        let user_controls = get_controls_by_pillar("User");
        let device_controls = get_controls_by_pillar("Device");
        let network_controls = get_controls_by_pillar("Network/Environment");
        let app_controls = get_controls_by_pillar("Application & Workload");
        let data_controls = get_controls_by_pillar("Data");
        let visibility_controls = get_controls_by_pillar("Visibility & Analytics");
        let automation_controls = get_controls_by_pillar("Automation & Orchestration");

        assert_eq!(user_controls.len(), 7);
        assert_eq!(device_controls.len(), 7);
        assert_eq!(network_controls.len(), 8);
        assert_eq!(app_controls.len(), 7);
        assert_eq!(data_controls.len(), 7);
        assert_eq!(visibility_controls.len(), 7);
        assert_eq!(automation_controls.len(), 8);
    }

    #[test]
    fn test_vulnerability_mapping() {
        // Test authentication vulnerability mapping
        let auth_mappings = map_vulnerability("Weak MFA configuration", None, None, None);
        assert!(!auth_mappings.is_empty());
        assert!(auth_mappings.iter().any(|(id, _)| id == "ZT.1.1"));

        // Test encryption vulnerability mapping
        let enc_mappings = map_vulnerability("Unencrypted database connection", None, None, None);
        assert!(!enc_mappings.is_empty());
        assert!(enc_mappings.iter().any(|(id, _)| id == "ZT.5.2" || id == "ZT.5.3"));

        // Test network vulnerability mapping
        let net_mappings = map_vulnerability("Insufficient network segmentation", None, None, None);
        assert!(!net_mappings.is_empty());
        assert!(net_mappings.iter().any(|(id, _)| id == "ZT.3.1"));
    }

    #[test]
    fn test_control_framework() {
        for control in get_controls() {
            assert_eq!(control.framework, ComplianceFramework::DodZeroTrust);
        }
    }

    #[test]
    fn test_control_id_format() {
        for control in get_controls() {
            // Control IDs should follow ZT.X.Y format
            assert!(control.control_id.starts_with("ZT."),
                "Control ID {} doesn't start with ZT.", control.control_id);
        }
    }

    #[test]
    fn test_unique_control_ids() {
        let controls = get_controls();
        let mut ids: Vec<&String> = controls.iter().map(|c| &c.control_id).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Duplicate control IDs found");
    }
}
