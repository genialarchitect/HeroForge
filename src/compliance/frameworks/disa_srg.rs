//! DISA Cloud Computing Security Requirements Guide (CC SRG)
//!
//! The DISA Cloud Computing Security Requirements Guide provides security
//! requirements for DoD mission owners to evaluate Cloud Service Offerings (CSOs)
//! and Cloud Service Providers (CSPs). It defines security controls based on
//! Impact Levels (IL) that correspond to data sensitivity.
//!
//! ## Impact Levels
//!
//! - **IL2 (Public)**: Non-Controlled Unclassified Information (Non-CUI)
//! - **IL4 (CUI)**: Controlled Unclassified Information requiring protection
//! - **IL5 (CUI/NSS)**: CUI and National Security Systems requiring higher protection
//! - **IL6 (Classified)**: Classified information up to SECRET
//!
//! This module focuses on IL4 and IL5 requirements which cover the majority of
//! DoD cloud deployments. Controls are organized by security control family:
//!
//! - Access Control (AC)
//! - Audit and Accountability (AU)
//! - Configuration Management (CM)
//! - Identification and Authentication (IA)
//! - Incident Response (IR)
//! - System and Communications Protection (SC)
//! - System and Information Integrity (SI)
//! - Personnel Security (PS)
//! - Physical and Environmental Protection (PE)
//! - Risk Assessment (RA)
//!
//! ## Cross-References
//!
//! DISA CC SRG controls map to:
//! - FedRAMP Moderate/High baselines
//! - NIST 800-53 Rev 5 controls
//! - DoD STIGs for specific technologies

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of DISA Cloud SRG controls in this module
pub const CONTROL_COUNT: usize = 56;

/// DISA Cloud SRG Impact Level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactLevel {
    /// IL2 - Public, Non-CUI data
    IL2,
    /// IL4 - Controlled Unclassified Information
    IL4,
    /// IL5 - CUI and National Security Systems
    IL5,
    /// IL6 - Classified up to SECRET
    IL6,
}

impl ImpactLevel {
    /// Get minimum required control priority for this impact level
    pub fn min_priority(self) -> ControlPriority {
        match self {
            ImpactLevel::IL2 => ControlPriority::Medium,
            ImpactLevel::IL4 => ControlPriority::High,
            ImpactLevel::IL5 => ControlPriority::Critical,
            ImpactLevel::IL6 => ControlPriority::Critical,
        }
    }

    /// Check if a control applies at this impact level
    pub fn control_applies(self, control_il: ImpactLevel) -> bool {
        match (self, control_il) {
            (ImpactLevel::IL6, _) => true,
            (ImpactLevel::IL5, ImpactLevel::IL6) => false,
            (ImpactLevel::IL5, _) => true,
            (ImpactLevel::IL4, ImpactLevel::IL5 | ImpactLevel::IL6) => false,
            (ImpactLevel::IL4, _) => true,
            (ImpactLevel::IL2, ImpactLevel::IL2) => true,
            (ImpactLevel::IL2, _) => false,
        }
    }
}

/// Get all DISA Cloud SRG controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    controls.extend(get_access_control_requirements());
    controls.extend(get_audit_requirements());
    controls.extend(get_data_protection_requirements());
    controls.extend(get_incident_response_requirements());
    controls.extend(get_configuration_management_requirements());
    controls.extend(get_system_protection_requirements());
    controls.extend(get_personnel_security_requirements());
    controls.extend(get_risk_assessment_requirements());

    controls
}

/// Access Control (AC) requirements for IL4/IL5
fn get_access_control_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-AC-001".to_string(),
            control_id: "SRG-AC-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Multi-Factor Authentication for Privileged Access".to_string(),
            description: "The CSP must enforce MFA for all privileged user access to cloud infrastructure and management consoles. IL4/IL5 systems require CAC/PIV or approved MFA.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IA-2".to_string(),
                "NIST-IA-2(1)".to_string(),
                "STIG-CLOUD-001".to_string(),
            ],
            remediation_guidance: Some("Implement DoD-approved MFA (CAC/PIV for IL5+, FIDO2/PIV for IL4). Configure identity provider to require MFA for all administrative access.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-002".to_string(),
            control_id: "SRG-AC-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "CAC/PKI Authentication for IL5 Systems".to_string(),
            description: "IL5 systems must enforce Common Access Card (CAC) or approved PKI certificate-based authentication for all user access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IA-2(12)".to_string(),
                "NIST-IA-2(12)".to_string(),
                "STIG-GEN-013".to_string(),
            ],
            remediation_guidance: Some("Deploy DoD PKI infrastructure. Configure all systems to accept only DoD-issued certificates. Implement OCSP/CRL checking for certificate validation.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-003".to_string(),
            control_id: "SRG-AC-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Least Privilege Access Model".to_string(),
            description: "The CSP must implement Role-Based Access Control (RBAC) with least privilege principles for all cloud resources and services.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AC-6".to_string(),
                "NIST-AC-6".to_string(),
                "STIG-CLOUD-005".to_string(),
            ],
            remediation_guidance: Some("Define role hierarchy based on job functions. Implement just-in-time (JIT) access for privileged operations. Review access grants quarterly.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-004".to_string(),
            control_id: "SRG-AC-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Session Termination and Timeout".to_string(),
            description: "Cloud sessions must automatically terminate after a period of inactivity (15 minutes for IL4, 10 minutes for IL5).".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AC-12".to_string(),
                "NIST-AC-12".to_string(),
                "STIG-LNX-012".to_string(),
            ],
            remediation_guidance: Some("Configure session timeout policies: 15 min for IL4, 10 min for IL5. Implement session lock on inactivity. Force re-authentication after timeout.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-005".to_string(),
            control_id: "SRG-AC-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Remote Access via Approved Channels".to_string(),
            description: "All remote access to DoD cloud systems must traverse DoD-approved connection points (BCAP/SCAP) with appropriate encryption.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AC-17".to_string(),
                "NIST-AC-17".to_string(),
                "STIG-NET-004".to_string(),
            ],
            remediation_guidance: Some("Route all traffic through approved BCAP/SCAP connections. Implement VPN with DoD-approved cryptography. Document all remote access paths in SSP.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-006".to_string(),
            control_id: "SRG-AC-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Account Lockout After Failed Attempts".to_string(),
            description: "Cloud systems must lock accounts after 3 consecutive failed authentication attempts and require administrator intervention for IL5.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AC-7".to_string(),
                "NIST-AC-7".to_string(),
                "STIG-GEN-001".to_string(),
            ],
            remediation_guidance: Some("Configure account lockout threshold to 3 attempts. Set lockout duration to 30+ minutes for IL4, require admin unlock for IL5.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-007".to_string(),
            control_id: "SRG-AC-007".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Separation of Duties".to_string(),
            description: "The CSP must enforce separation of duties for security-critical functions including access management, audit review, and system administration.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AC-5".to_string(),
                "NIST-AC-5".to_string(),
            ],
            remediation_guidance: Some("Define separate roles for: security admin, system admin, auditor, and operator. Prevent single user from having conflicting duties. Document role matrix.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AC-008".to_string(),
            control_id: "SRG-AC-008".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "US Person Access Restriction for IL5".to_string(),
            description: "IL5 systems must restrict administrative access to U.S. persons only. Non-U.S. persons may not have privileged access to IL5+ systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PS-3".to_string(),
            ],
            remediation_guidance: Some("Implement personnel vetting for all administrators. Document citizenship verification process. Maintain access roster with citizenship status.".to_string()),
        },
    ]
}

/// Audit and Accountability (AU) requirements
fn get_audit_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-AU-001".to_string(),
            control_id: "SRG-AU-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Comprehensive Audit Logging".to_string(),
            description: "The CSP must capture audit logs for all security-relevant events including authentication, authorization, data access, and configuration changes.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-2".to_string(),
                "NIST-AU-2".to_string(),
                "STIG-GEN-011".to_string(),
            ],
            remediation_guidance: Some("Enable logging for: successful/failed logins, privilege escalation, data access, API calls, configuration changes. Configure centralized log aggregation.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-002".to_string(),
            control_id: "SRG-AU-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Audit Log Content Requirements".to_string(),
            description: "Audit records must include: timestamp, user/system identity, event type, event outcome, source/destination addresses, and affected resources.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-3".to_string(),
                "NIST-AU-3".to_string(),
                "STIG-GEN-012".to_string(),
            ],
            remediation_guidance: Some("Configure log format to include all required fields. Use structured logging (JSON/CEF). Validate log content meets requirements.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-003".to_string(),
            control_id: "SRG-AU-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Audit Log Retention".to_string(),
            description: "Audit logs must be retained for minimum 1 year online and 6 years total for IL4/IL5 systems in compliance with DoD records management.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-11".to_string(),
                "NIST-AU-11".to_string(),
                "STIG-GEN-009".to_string(),
            ],
            remediation_guidance: Some("Configure log retention: 1 year online storage, 6 years archived. Implement log archival to compliant storage. Document retention policy.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-004".to_string(),
            control_id: "SRG-AU-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Audit Log Protection".to_string(),
            description: "Audit logs must be protected from unauthorized modification or deletion using write-once storage or cryptographic integrity verification.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-9".to_string(),
                "NIST-AU-9".to_string(),
                "STIG-GEN-010".to_string(),
            ],
            remediation_guidance: Some("Implement immutable log storage (WORM). Enable log integrity verification. Restrict log access to security personnel only.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-005".to_string(),
            control_id: "SRG-AU-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Time Synchronization".to_string(),
            description: "All cloud systems must synchronize time to authoritative DoD time sources (GPS or DoD NTP) with accuracy within 1 second.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-8".to_string(),
                "NIST-AU-8".to_string(),
            ],
            remediation_guidance: Some("Configure NTP to use DoD-approved time sources. Monitor time drift. Alert on synchronization failures.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-006".to_string(),
            control_id: "SRG-AU-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Audit Review and Analysis".to_string(),
            description: "Security personnel must review audit logs at least weekly for IL4 and daily for IL5 to identify potential security incidents.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-6".to_string(),
                "NIST-AU-6".to_string(),
            ],
            remediation_guidance: Some("Establish log review procedures. Deploy SIEM for automated analysis. Document review findings and actions taken.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-007".to_string(),
            control_id: "SRG-AU-007".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Audit Failure Alerting".to_string(),
            description: "The CSP must alert security personnel immediately upon detection of audit logging failures and take corrective action.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-5".to_string(),
                "NIST-AU-5".to_string(),
            ],
            remediation_guidance: Some("Configure alerts for: log service failures, storage capacity warnings, transmission failures. Implement fail-secure behavior.".to_string()),
        },
        ComplianceControl {
            id: "SRG-AU-008".to_string(),
            control_id: "SRG-AU-008".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Log Transmission Security".to_string(),
            description: "Audit logs transmitted across networks must be encrypted using FIPS 140-2/3 validated cryptographic modules.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AU-9(2)".to_string(),
                "NIST-AU-9(2)".to_string(),
                "STIG-GEN-015".to_string(),
            ],
            remediation_guidance: Some("Enable TLS 1.2+ for log transmission. Use FIPS-validated modules. Implement mutual TLS for log collectors.".to_string()),
        },
    ]
}

/// Data Protection (SC/MP) requirements
fn get_data_protection_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-DP-001".to_string(),
            control_id: "SRG-DP-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Data-at-Rest Encryption".to_string(),
            description: "All CUI data at rest must be encrypted using AES-256 or equivalent with FIPS 140-2/3 validated cryptographic modules.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-28".to_string(),
                "NIST-SC-28".to_string(),
                "STIG-GEN-014".to_string(),
            ],
            remediation_guidance: Some("Enable encryption for all storage volumes, databases, and object storage. Use customer-managed keys (CMK). Enable FIPS mode on all systems.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-002".to_string(),
            control_id: "SRG-DP-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Data-in-Transit Encryption".to_string(),
            description: "All data in transit must use TLS 1.2 or higher with FIPS-approved cipher suites. TLS 1.3 required for IL5.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-8".to_string(),
                "NIST-SC-8".to_string(),
                "STIG-GEN-015".to_string(),
            ],
            remediation_guidance: Some("Configure minimum TLS version: 1.2 for IL4, 1.3 preferred for IL5. Disable weak ciphers. Implement certificate pinning where applicable.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-003".to_string(),
            control_id: "SRG-DP-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "FIPS 140-2/3 Cryptographic Module Validation".to_string(),
            description: "All cryptographic operations must use NIST FIPS 140-2 (or 140-3 when available) validated cryptographic modules.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-13".to_string(),
                "NIST-SC-13".to_string(),
                "STIG-GEN-013".to_string(),
            ],
            remediation_guidance: Some("Enable FIPS mode on operating systems. Verify cryptographic libraries are FIPS-validated. Document CMVP certificate numbers in SSP.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-004".to_string(),
            control_id: "SRG-DP-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Key Management".to_string(),
            description: "Cryptographic keys must be managed using DoD-approved key management practices including secure generation, storage, rotation, and destruction.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-12".to_string(),
                "NIST-SC-12".to_string(),
                "STIG-CLOUD-004".to_string(),
            ],
            remediation_guidance: Some("Use HSM for key storage. Implement key rotation annually minimum. Document key custodians. Use split knowledge for master keys.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-005".to_string(),
            control_id: "SRG-DP-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Data Sovereignty - CONUS Location".to_string(),
            description: "IL4/IL5 data must be processed and stored only in CONUS (Continental United States) facilities. IL5 requires dedicated infrastructure.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "STIG-CLOUD-007".to_string(),
            ],
            remediation_guidance: Some("Configure cloud regions to CONUS only. Implement geo-restriction policies. Verify CSP data center locations. Document in SSP.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-006".to_string(),
            control_id: "SRG-DP-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Data Spillage Prevention".to_string(),
            description: "The CSP must implement Data Loss Prevention (DLP) controls to prevent unauthorized disclosure or spillage of CUI.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-7(8)".to_string(),
                "NIST-SC-7(8)".to_string(),
            ],
            remediation_guidance: Some("Deploy DLP at egress points. Configure data classification rules. Monitor for unauthorized data transfers. Alert on policy violations.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-007".to_string(),
            control_id: "SRG-DP-007".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Media Sanitization".to_string(),
            description: "Storage media must be sanitized according to DoD 5220.22-M or NIST SP 800-88 before reuse or disposal.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-MP-6".to_string(),
                "NIST-MP-6".to_string(),
            ],
            remediation_guidance: Some("Implement cryptographic erasure for encrypted media. Maintain sanitization records. Use approved destruction methods for IL5 media.".to_string()),
        },
        ComplianceControl {
            id: "SRG-DP-008".to_string(),
            control_id: "SRG-DP-008".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Public Access Prevention".to_string(),
            description: "Cloud storage resources must not be publicly accessible. All data access must require authentication and authorization.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AC-3".to_string(),
                "STIG-CLOUD-002".to_string(),
            ],
            remediation_guidance: Some("Block public access on all storage accounts/buckets. Implement private endpoints. Audit for public exposure regularly.".to_string()),
        },
    ]
}

/// Incident Response (IR) requirements
fn get_incident_response_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-IR-001".to_string(),
            control_id: "SRG-IR-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Incident Response Plan".to_string(),
            description: "The CSP must maintain an incident response plan aligned with DoD requirements including reporting procedures to US-CERT and DC3.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IR-1".to_string(),
                "NIST-IR-1".to_string(),
            ],
            remediation_guidance: Some("Develop IRP aligned with CISA requirements. Include DoD reporting timelines. Test plan annually. Maintain 24/7 incident response capability.".to_string()),
        },
        ComplianceControl {
            id: "SRG-IR-002".to_string(),
            control_id: "SRG-IR-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Incident Reporting Timelines".to_string(),
            description: "Security incidents must be reported within 1 hour for IL5 and 72 hours for IL4 systems to designated DoD incident response teams.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IR-6".to_string(),
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some("Establish reporting procedures: 1 hour for IL5, 72 hours for IL4. Pre-configure reporting templates. Maintain current POC lists.".to_string()),
        },
        ComplianceControl {
            id: "SRG-IR-003".to_string(),
            control_id: "SRG-IR-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Incident Monitoring and Detection".to_string(),
            description: "The CSP must implement continuous monitoring and automated detection capabilities for security incidents across all IL4/IL5 systems.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IR-5".to_string(),
                "NIST-IR-5".to_string(),
            ],
            remediation_guidance: Some("Deploy SIEM with correlation rules. Implement EDR on all endpoints. Configure automated alerting. Maintain 24/7 SOC coverage.".to_string()),
        },
        ComplianceControl {
            id: "SRG-IR-004".to_string(),
            control_id: "SRG-IR-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Evidence Preservation".to_string(),
            description: "The CSP must preserve forensic evidence for security incidents including system images, logs, and network captures for DoD investigation.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IR-4".to_string(),
                "NIST-IR-4".to_string(),
            ],
            remediation_guidance: Some("Implement forensic imaging capability. Preserve evidence with chain of custody. Retain incident artifacts for 6 years minimum.".to_string()),
        },
        ComplianceControl {
            id: "SRG-IR-005".to_string(),
            control_id: "SRG-IR-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Incident Response Testing".to_string(),
            description: "The CSP must test incident response capabilities annually through tabletop exercises and practical drills.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-IR-3".to_string(),
                "NIST-IR-3".to_string(),
            ],
            remediation_guidance: Some("Conduct annual tabletop exercises. Perform quarterly technical drills. Document lessons learned. Update IRP based on findings.".to_string()),
        },
        ComplianceControl {
            id: "SRG-IR-006".to_string(),
            control_id: "SRG-IR-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Malware Incident Response".to_string(),
            description: "The CSP must have specific procedures for malware incidents including isolation, analysis, eradication, and recovery.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SI-3".to_string(),
                "NIST-SI-3".to_string(),
            ],
            remediation_guidance: Some("Document malware response procedures. Maintain malware analysis capability. Implement automated isolation. Coordinate with DoD malware labs.".to_string()),
        },
    ]
}

/// Configuration Management (CM) requirements
fn get_configuration_management_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-CM-001".to_string(),
            control_id: "SRG-CM-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "STIG Compliance Baseline".to_string(),
            description: "All cloud systems must be configured according to applicable DoD STIGs and Security Technical Implementation Guides.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CM-6".to_string(),
                "NIST-CM-6".to_string(),
            ],
            remediation_guidance: Some("Apply applicable STIGs to all systems. Scan weekly with STIG compliance tools. Document deviations with POA&M. Maintain 95%+ compliance.".to_string()),
        },
        ComplianceControl {
            id: "SRG-CM-002".to_string(),
            control_id: "SRG-CM-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Configuration Change Control".to_string(),
            description: "All configuration changes to IL4/IL5 systems must go through formal change control including security impact analysis.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CM-3".to_string(),
                "NIST-CM-3".to_string(),
            ],
            remediation_guidance: Some("Implement CAB approval process. Require security review for all changes. Maintain change history. Document rollback procedures.".to_string()),
        },
        ComplianceControl {
            id: "SRG-CM-003".to_string(),
            control_id: "SRG-CM-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Vulnerability and Patch Management".to_string(),
            description: "Critical vulnerabilities must be patched within 30 days. High within 60 days. All patches applied within 90 days.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SI-2".to_string(),
                "NIST-SI-2".to_string(),
            ],
            remediation_guidance: Some("Implement automated vulnerability scanning. Track patching SLAs: Critical 30d, High 60d, Moderate 90d. Document exceptions in POA&M.".to_string()),
        },
        ComplianceControl {
            id: "SRG-CM-004".to_string(),
            control_id: "SRG-CM-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Least Functionality".to_string(),
            description: "Cloud systems must be configured with minimal services, ports, and protocols. All unnecessary components must be disabled or removed.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CM-7".to_string(),
                "NIST-CM-7".to_string(),
                "STIG-NET-005".to_string(),
            ],
            remediation_guidance: Some("Disable unnecessary services and protocols. Remove unused software. Document required ports/services. Implement application whitelisting.".to_string()),
        },
        ComplianceControl {
            id: "SRG-CM-005".to_string(),
            control_id: "SRG-CM-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Asset Inventory".to_string(),
            description: "The CSP must maintain a complete inventory of all hardware and software assets including cloud resources, with automated discovery.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CM-8".to_string(),
                "NIST-CM-8".to_string(),
            ],
            remediation_guidance: Some("Deploy automated asset discovery. Maintain CMDB with all resources. Track software versions. Update inventory continuously.".to_string()),
        },
        ComplianceControl {
            id: "SRG-CM-006".to_string(),
            control_id: "SRG-CM-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Configuration Monitoring".to_string(),
            description: "Continuous monitoring must detect unauthorized configuration changes and alert security personnel within 15 minutes.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CM-3(2)".to_string(),
                "NIST-CM-3(2)".to_string(),
            ],
            remediation_guidance: Some("Deploy configuration drift detection. Implement file integrity monitoring. Alert on unauthorized changes. Automate remediation where possible.".to_string()),
        },
        ComplianceControl {
            id: "SRG-CM-007".to_string(),
            control_id: "SRG-CM-007".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Software Restriction Policies".to_string(),
            description: "Only authorized software may execute on IL4/IL5 systems. Application whitelisting must be implemented where technically feasible.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CM-7(5)".to_string(),
                "NIST-CM-7(5)".to_string(),
            ],
            remediation_guidance: Some("Implement application whitelisting (AppLocker, SELinux). Maintain approved software list. Block unauthorized executables.".to_string()),
        },
    ]
}

/// System and Communications Protection (SC) requirements
fn get_system_protection_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-SP-001".to_string(),
            control_id: "SRG-SP-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Network Segmentation".to_string(),
            description: "IL4/IL5 systems must be logically or physically segmented from lower impact level systems and the public internet.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-7".to_string(),
                "NIST-SC-7".to_string(),
                "STIG-VIRT-002".to_string(),
            ],
            remediation_guidance: Some("Implement network segmentation by impact level. Use dedicated VPCs/VNets for IL4/IL5. Deploy firewalls at segment boundaries.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-002".to_string(),
            control_id: "SRG-SP-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Boundary Protection".to_string(),
            description: "All network traffic entering or leaving IL4/IL5 boundaries must pass through managed interfaces with security monitoring.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-7(4)".to_string(),
                "NIST-SC-7(4)".to_string(),
            ],
            remediation_guidance: Some("Implement centralized egress points. Deploy IDS/IPS at boundaries. Monitor all ingress/egress traffic. Block unapproved protocols.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-003".to_string(),
            control_id: "SRG-SP-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "DoD DMZ Architecture".to_string(),
            description: "Internet-facing systems must be deployed in a DMZ with defense-in-depth protections separating them from internal systems.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-7(5)".to_string(),
                "NIST-SC-7(5)".to_string(),
            ],
            remediation_guidance: Some("Implement DMZ architecture with multiple security zones. Deploy WAF for web applications. Use reverse proxies. Limit DMZ to internal connectivity.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-004".to_string(),
            control_id: "SRG-SP-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Intrusion Detection/Prevention".to_string(),
            description: "Network and host-based intrusion detection and prevention systems must be deployed and monitored 24/7.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SI-4".to_string(),
                "NIST-SI-4".to_string(),
            ],
            remediation_guidance: Some("Deploy NIDS/NIPS at network boundaries. Install HIDS on all servers. Tune signatures for environment. Monitor alerts 24/7.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-005".to_string(),
            control_id: "SRG-SP-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Malware Protection".to_string(),
            description: "All systems must have anti-malware protection with signatures updated at least daily and real-time scanning enabled.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SI-3".to_string(),
                "NIST-SI-3".to_string(),
                "STIG-WIN-009".to_string(),
            ],
            remediation_guidance: Some("Deploy EDR/antimalware on all endpoints. Update signatures at least daily. Enable real-time scanning. Report detections to central console.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-006".to_string(),
            control_id: "SRG-SP-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Denial of Service Protection".to_string(),
            description: "The CSP must implement protections against denial of service attacks including volumetric, protocol, and application layer attacks.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-5".to_string(),
                "NIST-SC-5".to_string(),
            ],
            remediation_guidance: Some("Deploy DDoS protection service. Implement rate limiting. Configure auto-scaling for legitimate traffic spikes. Document DDoS response procedures.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-007".to_string(),
            control_id: "SRG-SP-007".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Virtual Machine Isolation".to_string(),
            description: "Virtual machines hosting IL4/IL5 workloads must be isolated from lower impact level VMs using dedicated hosts or approved isolation technologies.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "STIG-VIRT-002".to_string(),
                "STIG-VIRT-005".to_string(),
            ],
            remediation_guidance: Some("Use dedicated hosts for IL5. Implement VM isolation controls. Disable VM-to-VM communication where not required. Use separate storage.".to_string()),
        },
        ComplianceControl {
            id: "SRG-SP-008".to_string(),
            control_id: "SRG-SP-008".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Session Authenticity".to_string(),
            description: "All sessions must be authenticated and session tokens protected from hijacking through secure transmission and proper validation.".to_string(),
            category: "System Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-SC-23".to_string(),
                "NIST-SC-23".to_string(),
                "STIG-APP-004".to_string(),
            ],
            remediation_guidance: Some("Implement secure session management. Use HttpOnly and Secure cookie flags. Regenerate session IDs after authentication. Implement CSRF protection.".to_string()),
        },
    ]
}

/// Personnel Security (PS) requirements
fn get_personnel_security_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-PS-001".to_string(),
            control_id: "SRG-PS-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Personnel Screening".to_string(),
            description: "All personnel with access to IL4/IL5 systems must have appropriate background investigations (NACI for IL4, T3/T5 for IL5).".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-PS-3".to_string(),
                "NIST-PS-3".to_string(),
            ],
            remediation_guidance: Some("Verify background investigation status for all personnel. Maintain investigation tracking. Ensure investigations are current (5 year reinvestigation).".to_string()),
        },
        ComplianceControl {
            id: "SRG-PS-002".to_string(),
            control_id: "SRG-PS-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Access Agreement".to_string(),
            description: "All personnel must sign access agreements acknowledging security responsibilities before being granted access to IL4/IL5 systems.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-PS-6".to_string(),
                "NIST-PS-6".to_string(),
            ],
            remediation_guidance: Some("Develop access agreements per DoD requirements. Require annual re-acknowledgment. Maintain signed agreements on file.".to_string()),
        },
        ComplianceControl {
            id: "SRG-PS-003".to_string(),
            control_id: "SRG-PS-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Security Awareness Training".to_string(),
            description: "All personnel must complete DoD-approved security awareness training annually before accessing IL4/IL5 systems.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-AT-2".to_string(),
                "NIST-AT-2".to_string(),
            ],
            remediation_guidance: Some("Implement DoD Cyber Awareness Challenge or equivalent. Track training completion. Require training before access. Conduct annual refresh.".to_string()),
        },
        ComplianceControl {
            id: "SRG-PS-004".to_string(),
            control_id: "SRG-PS-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Personnel Termination Procedures".to_string(),
            description: "Access must be revoked within 8 hours of personnel termination. Physical access tokens and credentials must be retrieved immediately.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-PS-4".to_string(),
                "NIST-PS-4".to_string(),
            ],
            remediation_guidance: Some("Implement immediate termination process. Disable accounts within 8 hours. Retrieve physical tokens. Conduct exit interviews. Review terminated user activity.".to_string()),
        },
    ]
}

/// Risk Assessment (RA) requirements
fn get_risk_assessment_requirements() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "SRG-RA-001".to_string(),
            control_id: "SRG-RA-001".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Vulnerability Scanning".to_string(),
            description: "Vulnerability scanning must be performed weekly for IL4 and daily for IL5 systems using DoD-approved scanning tools.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-RA-5".to_string(),
                "NIST-RA-5".to_string(),
            ],
            remediation_guidance: Some("Deploy ACAS/Tenable for scanning. Scan IL4 weekly, IL5 daily. Track vulnerabilities in POA&M. Report results to DoD ISSM.".to_string()),
        },
        ComplianceControl {
            id: "SRG-RA-002".to_string(),
            control_id: "SRG-RA-002".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Penetration Testing".to_string(),
            description: "Annual penetration testing must be conducted by qualified assessors. Additional testing required after significant changes.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CA-8".to_string(),
                "NIST-CA-8".to_string(),
            ],
            remediation_guidance: Some("Conduct annual penetration tests. Use 3PAO or qualified DoD team. Test after major changes. Remediate findings per patching timeline.".to_string()),
        },
        ComplianceControl {
            id: "SRG-RA-003".to_string(),
            control_id: "SRG-RA-003".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Risk Assessment".to_string(),
            description: "A comprehensive risk assessment must be conducted annually and updated when significant changes occur to the system or threat landscape.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-RA-3".to_string(),
                "NIST-RA-3".to_string(),
            ],
            remediation_guidance: Some("Conduct annual risk assessment. Document threats, vulnerabilities, and impacts. Update after significant changes. Report to AO.".to_string()),
        },
        ComplianceControl {
            id: "SRG-RA-004".to_string(),
            control_id: "SRG-RA-004".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Security Assessment and Authorization".to_string(),
            description: "Systems must obtain Authorization to Operate (ATO) from the DoD Authorizing Official before processing DoD data.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CA-6".to_string(),
                "NIST-CA-6".to_string(),
            ],
            remediation_guidance: Some("Complete FedRAMP authorization. Obtain DoD PA. Submit authorization package to AO. Maintain continuous monitoring.".to_string()),
        },
        ComplianceControl {
            id: "SRG-RA-005".to_string(),
            control_id: "SRG-RA-005".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Plan of Action and Milestones (POA&M)".to_string(),
            description: "All identified vulnerabilities and deficiencies must be tracked in a POA&M with remediation timelines and responsible parties.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CA-5".to_string(),
                "NIST-CA-5".to_string(),
            ],
            remediation_guidance: Some("Maintain POA&M with all findings. Update monthly. Include remediation milestones. Report to ISSM. Close items timely.".to_string()),
        },
        ComplianceControl {
            id: "SRG-RA-006".to_string(),
            control_id: "SRG-RA-006".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Continuous Monitoring".to_string(),
            description: "Continuous monitoring must be implemented per DoD ConMon requirements including automated security status reporting.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CA-7".to_string(),
                "NIST-CA-7".to_string(),
            ],
            remediation_guidance: Some("Implement continuous monitoring tools. Report to DoD Dashboard. Automate vulnerability reporting. Maintain security posture metrics.".to_string()),
        },
        ComplianceControl {
            id: "SRG-RA-007".to_string(),
            control_id: "SRG-RA-007".to_string(),
            framework: ComplianceFramework::DisaCloudSrg,
            title: "Third-Party Security Assessment".to_string(),
            description: "Independent third-party assessments (3PAO) must validate security control implementation before authorization.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-CA-2".to_string(),
                "NIST-CA-2".to_string(),
            ],
            remediation_guidance: Some("Engage FedRAMP-approved 3PAO. Complete security assessment. Address findings before ATO. Conduct annual reassessments.".to_string()),
        },
    ]
}

/// Get controls by impact level (returns controls applicable at that level and below)
pub fn get_controls_by_impact_level(level: ImpactLevel) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| {
            // Map priority back to approximate impact level for filtering
            let control_level = match c.priority {
                ControlPriority::Critical => ImpactLevel::IL5,
                ControlPriority::High => ImpactLevel::IL4,
                ControlPriority::Medium => ImpactLevel::IL4,
                ControlPriority::Low => ImpactLevel::IL2,
            };
            level.control_applies(control_level)
        })
        .collect()
}

/// Get controls by category
pub fn get_controls_by_category(category: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all categories in this framework
pub fn get_categories() -> Vec<&'static str> {
    vec![
        "Access Control",
        "Audit and Accountability",
        "Data Protection",
        "Incident Response",
        "Configuration Management",
        "System Protection",
        "Personnel Security",
        "Risk Assessment",
    ]
}

/// Map a vulnerability to relevant DISA Cloud SRG controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Multi-factor authentication vulnerabilities
    if title_lower.contains("mfa")
        || title_lower.contains("multi-factor")
        || title_lower.contains("two-factor")
        || title_lower.contains("2fa")
    {
        mappings.push(("SRG-AC-001".to_string(), Severity::Critical));
        mappings.push(("SRG-AC-002".to_string(), Severity::Critical));
    }

    // Authentication and access control vulnerabilities
    if title_lower.contains("authentication")
        || title_lower.contains("unauthorized access")
        || title_lower.contains("privilege escalation")
        || title_lower.contains("access control")
    {
        mappings.push(("SRG-AC-001".to_string(), Severity::Critical));
        mappings.push(("SRG-AC-003".to_string(), Severity::High));
        mappings.push(("SRG-AC-006".to_string(), Severity::High));
    }

    // Session management vulnerabilities
    if title_lower.contains("session")
        || title_lower.contains("timeout")
        || title_lower.contains("cookie")
    {
        mappings.push(("SRG-AC-004".to_string(), Severity::High));
        mappings.push(("SRG-SP-008".to_string(), Severity::High));
    }

    // Encryption vulnerabilities
    if title_lower.contains("encryption")
        || title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("tls")
        || title_lower.contains("ssl")
    {
        mappings.push(("SRG-DP-001".to_string(), Severity::Critical));
        mappings.push(("SRG-DP-002".to_string(), Severity::Critical));
        mappings.push(("SRG-DP-003".to_string(), Severity::Critical));
    }

    // FIPS compliance issues
    if title_lower.contains("fips")
        || title_lower.contains("cryptographic module")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("SRG-DP-003".to_string(), Severity::Critical));
    }

    // Key management vulnerabilities
    if title_lower.contains("key management")
        || title_lower.contains("encryption key")
        || title_lower.contains("hardcoded key")
        || title_lower.contains("key exposure")
    {
        mappings.push(("SRG-DP-004".to_string(), Severity::Critical));
    }

    // Data exposure vulnerabilities
    if title_lower.contains("data exposure")
        || title_lower.contains("data leak")
        || title_lower.contains("public access")
        || title_lower.contains("s3 bucket")
        || title_lower.contains("blob storage")
    {
        mappings.push(("SRG-DP-006".to_string(), Severity::Critical));
        mappings.push(("SRG-DP-008".to_string(), Severity::Critical));
    }

    // Logging and audit vulnerabilities
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("no logs")
        || title_lower.contains("log tampering")
    {
        mappings.push(("SRG-AU-001".to_string(), Severity::High));
        mappings.push(("SRG-AU-004".to_string(), Severity::Critical));
    }

    // Configuration vulnerabilities
    if title_lower.contains("misconfiguration")
        || title_lower.contains("stig")
        || title_lower.contains("hardening")
        || title_lower.contains("default configuration")
    {
        mappings.push(("SRG-CM-001".to_string(), Severity::High));
        mappings.push(("SRG-CM-004".to_string(), Severity::High));
    }

    // Patching vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("missing patch")
        || title_lower.contains("end of life")
        || title_lower.contains("eol")
    {
        mappings.push(("SRG-CM-003".to_string(), Severity::Critical));
    }

    // Network security vulnerabilities
    if title_lower.contains("network segmentation")
        || title_lower.contains("firewall")
        || title_lower.contains("boundary")
        || title_lower.contains("open port")
    {
        mappings.push(("SRG-SP-001".to_string(), Severity::High));
        mappings.push(("SRG-SP-002".to_string(), Severity::High));
    }

    // Intrusion detection
    if title_lower.contains("ids")
        || title_lower.contains("ips")
        || title_lower.contains("intrusion")
        || title_lower.contains("detection")
    {
        mappings.push(("SRG-SP-004".to_string(), Severity::High));
    }

    // Malware related
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("antivirus")
        || title_lower.contains("endpoint protection")
    {
        mappings.push(("SRG-SP-005".to_string(), Severity::Critical));
        mappings.push(("SRG-IR-006".to_string(), Severity::High));
    }

    // DDoS vulnerabilities
    if title_lower.contains("denial of service")
        || title_lower.contains("ddos")
        || title_lower.contains("rate limit")
    {
        mappings.push(("SRG-SP-006".to_string(), Severity::High));
    }

    // Virtualization vulnerabilities
    if title_lower.contains("vm escape")
        || title_lower.contains("hypervisor")
        || title_lower.contains("container escape")
        || title_lower.contains("isolation")
    {
        mappings.push(("SRG-SP-007".to_string(), Severity::Critical));
    }

    // Vulnerability scanning issues
    if title_lower.contains("vulnerability scan")
        || title_lower.contains("unscanned")
        || title_lower.contains("scan coverage")
    {
        mappings.push(("SRG-RA-001".to_string(), Severity::High));
    }

    // Incident response gaps
    if title_lower.contains("incident response")
        || title_lower.contains("security incident")
        || title_lower.contains("breach")
    {
        mappings.push(("SRG-IR-001".to_string(), Severity::High));
        mappings.push(("SRG-IR-002".to_string(), Severity::High));
    }

    mappings
}

/// Get cross-references to FedRAMP controls
pub fn get_fedramp_mapping(control_id: &str) -> Option<Vec<&'static str>> {
    match control_id {
        "SRG-AC-001" => Some(vec!["IA-2", "IA-2(1)", "IA-2(2)"]),
        "SRG-AC-002" => Some(vec!["IA-2(12)"]),
        "SRG-AC-003" => Some(vec!["AC-2", "AC-6", "AC-6(1)"]),
        "SRG-AC-004" => Some(vec!["AC-12", "SC-10"]),
        "SRG-AC-005" => Some(vec!["AC-17", "AC-17(1)", "AC-17(2)"]),
        "SRG-AC-006" => Some(vec!["AC-7"]),
        "SRG-AC-007" => Some(vec!["AC-5"]),
        "SRG-AU-001" => Some(vec!["AU-2", "AU-12"]),
        "SRG-AU-002" => Some(vec!["AU-3", "AU-3(1)"]),
        "SRG-AU-003" => Some(vec!["AU-11"]),
        "SRG-AU-004" => Some(vec!["AU-9", "AU-9(2)"]),
        "SRG-AU-005" => Some(vec!["AU-8", "AU-8(1)"]),
        "SRG-AU-006" => Some(vec!["AU-6", "AU-6(1)"]),
        "SRG-DP-001" => Some(vec!["SC-28", "SC-28(1)"]),
        "SRG-DP-002" => Some(vec!["SC-8", "SC-8(1)"]),
        "SRG-DP-003" => Some(vec!["SC-13"]),
        "SRG-DP-004" => Some(vec!["SC-12", "SC-12(1)"]),
        "SRG-CM-001" => Some(vec!["CM-6"]),
        "SRG-CM-003" => Some(vec!["SI-2"]),
        "SRG-SP-001" => Some(vec!["SC-7"]),
        "SRG-SP-004" => Some(vec!["SI-4"]),
        "SRG-SP-005" => Some(vec!["SI-3"]),
        "SRG-RA-001" => Some(vec!["RA-5"]),
        _ => None,
    }
}

/// Get cross-references to DoD STIG controls
pub fn get_stig_mapping(control_id: &str) -> Option<Vec<&'static str>> {
    match control_id {
        "SRG-AC-001" => Some(vec!["STIG-CLOUD-001", "V-221200"]),
        "SRG-AC-006" => Some(vec!["STIG-GEN-001", "V-220706"]),
        "SRG-DP-001" => Some(vec!["STIG-GEN-014", "V-220719"]),
        "SRG-DP-002" => Some(vec!["STIG-GEN-015", "V-220720"]),
        "SRG-DP-003" => Some(vec!["STIG-GEN-013", "V-220718"]),
        "SRG-AU-003" => Some(vec!["STIG-GEN-009", "V-220714"]),
        "SRG-AU-004" => Some(vec!["STIG-GEN-010", "V-220715"]),
        "SRG-SP-005" => Some(vec!["STIG-WIN-009", "V-220705"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_count() {
        let controls = get_controls();
        assert_eq!(controls.len(), CONTROL_COUNT);
    }

    #[test]
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert_eq!(control.framework, ComplianceFramework::DisaCloudSrg);
        }
    }

    #[test]
    fn test_categories() {
        let categories = get_categories();
        assert_eq!(categories.len(), 8);
        assert!(categories.contains(&"Access Control"));
        assert!(categories.contains(&"Data Protection"));
        assert!(categories.contains(&"Incident Response"));
    }

    #[test]
    fn test_vulnerability_mapping_encryption() {
        let mappings = map_vulnerability("Unencrypted data transmission detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SRG-DP-002"));
    }

    #[test]
    fn test_vulnerability_mapping_mfa() {
        let mappings = map_vulnerability("Missing MFA on admin console", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SRG-AC-001"));
    }

    #[test]
    fn test_vulnerability_mapping_patching() {
        let mappings = map_vulnerability("Outdated software version detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SRG-CM-003"));
    }

    #[test]
    fn test_impact_level_filtering() {
        let il4_controls = get_controls_by_impact_level(ImpactLevel::IL4);
        let il5_controls = get_controls_by_impact_level(ImpactLevel::IL5);
        assert!(il5_controls.len() >= il4_controls.len());
    }

    #[test]
    fn test_fedramp_mapping() {
        let mapping = get_fedramp_mapping("SRG-DP-001");
        assert!(mapping.is_some());
        assert!(mapping.unwrap().contains(&"SC-28"));
    }

    #[test]
    fn test_stig_mapping() {
        let mapping = get_stig_mapping("SRG-AC-001");
        assert!(mapping.is_some());
        assert!(mapping.unwrap().contains(&"STIG-CLOUD-001"));
    }

    #[test]
    fn test_controls_by_category() {
        let ac_controls = get_controls_by_category("Access Control");
        assert!(!ac_controls.is_empty());
        for control in ac_controls {
            assert_eq!(control.category, "Access Control");
        }
    }
}
