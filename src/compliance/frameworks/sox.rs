//! Sarbanes-Oxley (SOX) IT General Controls Module
//!
//! This module implements IT controls relevant to SOX Section 404 compliance,
//! focused on financial reporting integrity and internal control over
//! financial reporting (ICFR).
//!
//! SOX IT controls are organized into three categories:
//! - IT General Controls (ITGC): Access controls, change management,
//!   computer operations, program development, backup/recovery
//! - Application Controls: Input, processing, and output controls
//! - Entity-Level Controls: IT governance, risk management, monitoring
//!
//! Cross-references are provided to COBIT 2019 and ISO 27001:2022.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of SOX IT controls in this module
pub const CONTROL_COUNT: usize = 50;

/// Get all SOX IT controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ========================================================================
        // IT General Controls (ITGC) - Access Controls for Financial Systems
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-AC-01".to_string(),
            control_id: "ITGC-AC-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "User Access Provisioning for Financial Systems".to_string(),
            description: "Access to financial systems and applications shall be granted based on documented approvals, job responsibilities, and the principle of least privilege.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.18".to_string(),
                "ISO27001-A.8.2".to_string(),
            ],
            remediation_guidance: Some("Implement formal access request and approval workflow with documented authorization for all financial system access.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-AC-02".to_string(),
            control_id: "ITGC-AC-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "User Access Modification and Termination".to_string(),
            description: "User access to financial systems shall be promptly modified upon role change and removed upon termination or transfer.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.18".to_string(),
            ],
            remediation_guidance: Some("Implement automated deprovisioning integrated with HR systems and conduct periodic access reviews.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-AC-03".to_string(),
            control_id: "ITGC-AC-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Periodic User Access Reviews".to_string(),
            description: "Management shall periodically review user access rights to financial systems to ensure appropriateness and adherence to the principle of least privilege.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.18".to_string(),
            ],
            remediation_guidance: Some("Conduct quarterly access reviews with business owner attestation and documented remediation of exceptions.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-AC-04".to_string(),
            control_id: "ITGC-AC-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Privileged Access Management".to_string(),
            description: "Privileged access to financial systems shall be restricted to authorized personnel and monitored for appropriateness.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.8.2".to_string(),
            ],
            remediation_guidance: Some("Implement privileged access management (PAM) solution with session recording and just-in-time access.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-AC-05".to_string(),
            control_id: "ITGC-AC-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Authentication Controls".to_string(),
            description: "Strong authentication mechanisms shall be implemented for access to financial systems, including password complexity and multi-factor authentication.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.8.5".to_string(),
            ],
            remediation_guidance: Some("Enforce MFA for all financial system access with password policies meeting industry standards.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-AC-06".to_string(),
            control_id: "ITGC-AC-06".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Service Account Management".to_string(),
            description: "Service accounts used by financial applications shall be inventoried, have unique credentials, and be subject to periodic review.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.17".to_string(),
            ],
            remediation_guidance: Some("Maintain service account inventory with ownership, rotate credentials periodically, and disable interactive logon.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Change Management
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-CM-01".to_string(),
            control_id: "ITGC-CM-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Change Management Policy and Procedures".to_string(),
            description: "Formal change management policies and procedures shall govern all changes to financial systems, applications, and infrastructure.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI06.01".to_string(),
                "ISO27001-A.8.32".to_string(),
            ],
            remediation_guidance: Some("Document and implement formal change management procedures with defined roles, approval workflows, and escalation paths.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CM-02".to_string(),
            control_id: "ITGC-CM-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Change Request and Approval".to_string(),
            description: "All changes to financial systems shall be documented, tested, and approved by appropriate stakeholders before implementation.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI06.01".to_string(),
                "ISO27001-A.8.32".to_string(),
            ],
            remediation_guidance: Some("Use change management system with mandatory approval workflows and documented business justification.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CM-03".to_string(),
            control_id: "ITGC-CM-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Change Testing and Validation".to_string(),
            description: "Changes to financial systems shall be tested in a non-production environment prior to production deployment.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI06.02".to_string(),
                "ISO27001-A.8.29".to_string(),
            ],
            remediation_guidance: Some("Maintain separate test environments, require test evidence before approval, and conduct user acceptance testing.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CM-04".to_string(),
            control_id: "ITGC-CM-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Emergency Change Procedures".to_string(),
            description: "Emergency changes to financial systems shall follow documented expedited procedures with post-implementation review and approval.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI06.01".to_string(),
                "ISO27001-A.8.32".to_string(),
            ],
            remediation_guidance: Some("Define emergency change criteria, require manager notification, and mandate post-implementation CAB review.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CM-05".to_string(),
            control_id: "ITGC-CM-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Change Rollback Procedures".to_string(),
            description: "Documented rollback procedures shall exist for all changes to financial systems to enable recovery from failed implementations.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI06.03".to_string(),
                "ISO27001-A.8.32".to_string(),
            ],
            remediation_guidance: Some("Require documented rollback plans as part of change approval, test rollback procedures periodically.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Computer Operations
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-CO-01".to_string(),
            control_id: "ITGC-CO-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Job Scheduling and Monitoring".to_string(),
            description: "Batch jobs and scheduled processes affecting financial data shall be monitored for successful completion with alerts for failures.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS01.03".to_string(),
                "ISO27001-A.8.16".to_string(),
            ],
            remediation_guidance: Some("Implement centralized job scheduling with automated monitoring, alerting, and documented resolution procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CO-02".to_string(),
            control_id: "ITGC-CO-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "System Availability Monitoring".to_string(),
            description: "Financial systems shall be continuously monitored for availability with defined thresholds and escalation procedures.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS01.03".to_string(),
                "ISO27001-A.8.16".to_string(),
            ],
            remediation_guidance: Some("Deploy monitoring solutions with SLA-based alerting and documented incident response procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CO-03".to_string(),
            control_id: "ITGC-CO-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Incident Management".to_string(),
            description: "Incidents affecting financial systems shall be logged, tracked, and resolved according to defined procedures with root cause analysis.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS02.01".to_string(),
                "ISO27001-A.5.24".to_string(),
            ],
            remediation_guidance: Some("Implement ITSM ticketing system with severity classification, SLA tracking, and post-incident review process.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CO-04".to_string(),
            control_id: "ITGC-CO-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Problem Management".to_string(),
            description: "Recurring incidents and systemic issues shall be tracked, analyzed for root cause, and resolved to prevent future occurrences.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS03.01".to_string(),
                "ISO27001-A.5.27".to_string(),
            ],
            remediation_guidance: Some("Implement problem management process with known error database and trend analysis reporting.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-CO-05".to_string(),
            control_id: "ITGC-CO-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "System Performance Management".to_string(),
            description: "Financial system performance shall be monitored against defined thresholds with capacity planning to ensure adequate resources.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS01.04".to_string(),
                "ISO27001-A.8.6".to_string(),
            ],
            remediation_guidance: Some("Implement performance monitoring with trend analysis, capacity forecasting, and documented threshold baselines.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Program Development
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-PD-01".to_string(),
            control_id: "ITGC-PD-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "System Development Life Cycle".to_string(),
            description: "Financial applications shall be developed following a documented SDLC methodology with defined phases, deliverables, and controls.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI03.01".to_string(),
                "ISO27001-A.8.25".to_string(),
            ],
            remediation_guidance: Some("Document and enforce SDLC methodology with security checkpoints, design reviews, and required deliverables.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-PD-02".to_string(),
            control_id: "ITGC-PD-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Code Review and Security Testing".to_string(),
            description: "Financial application code shall undergo security review and testing before deployment to production.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI03.05".to_string(),
                "ISO27001-A.8.28".to_string(),
                "ISO27001-A.8.29".to_string(),
            ],
            remediation_guidance: Some("Implement mandatory code reviews, SAST/DAST scanning in CI/CD pipeline, and penetration testing for major releases.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-PD-03".to_string(),
            control_id: "ITGC-PD-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Environment Segregation".to_string(),
            description: "Development, testing, and production environments for financial systems shall be logically or physically segregated.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI03.04".to_string(),
                "ISO27001-A.8.31".to_string(),
            ],
            remediation_guidance: Some("Implement network segmentation between environments with restricted access and no production data in lower environments.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-PD-04".to_string(),
            control_id: "ITGC-PD-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Source Code Management".to_string(),
            description: "Source code for financial applications shall be maintained in version control with access restrictions and audit trails.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI03.02".to_string(),
                "ISO27001-A.8.4".to_string(),
            ],
            remediation_guidance: Some("Use enterprise version control (Git) with branch protection, required reviews, and audit logging of all changes.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-PD-05".to_string(),
            control_id: "ITGC-PD-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Vendor/Third-Party Software Management".to_string(),
            description: "Third-party software used in financial systems shall be assessed for security, maintained under support, and patched regularly.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-BAI03.06".to_string(),
                "ISO27001-A.5.21".to_string(),
            ],
            remediation_guidance: Some("Maintain software inventory, track vendor support dates, implement vulnerability scanning for third-party components.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Data Backup and Recovery
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-BR-01".to_string(),
            control_id: "ITGC-BR-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Backup Policy and Procedures".to_string(),
            description: "Formal backup policies and procedures shall define retention periods, backup types, and responsibilities for financial data.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS04.07".to_string(),
                "ISO27001-A.8.13".to_string(),
            ],
            remediation_guidance: Some("Document backup policy with RPO/RTO requirements, retention periods, and roles/responsibilities.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-BR-02".to_string(),
            control_id: "ITGC-BR-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Backup Execution and Monitoring".to_string(),
            description: "Backups of financial systems shall be performed according to schedule with automated monitoring and alerting for failures.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS04.07".to_string(),
                "ISO27001-A.8.13".to_string(),
            ],
            remediation_guidance: Some("Implement automated backup solution with success/failure monitoring, alerting, and documented resolution procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-BR-03".to_string(),
            control_id: "ITGC-BR-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Backup Media Protection".to_string(),
            description: "Backup media containing financial data shall be encrypted, securely stored, and protected from unauthorized access.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS04.07".to_string(),
                "ISO27001-A.8.24".to_string(),
            ],
            remediation_guidance: Some("Encrypt backup data at rest and in transit, store offsite copies in secure facilities, implement access logging.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-BR-04".to_string(),
            control_id: "ITGC-BR-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Backup Restoration Testing".to_string(),
            description: "Restoration of financial system backups shall be tested periodically to validate recoverability.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS04.08".to_string(),
                "ISO27001-A.8.13".to_string(),
            ],
            remediation_guidance: Some("Conduct quarterly restore tests with documented results, validate data integrity, and address failures.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-BR-05".to_string(),
            control_id: "ITGC-BR-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Disaster Recovery Planning".to_string(),
            description: "Documented disaster recovery plans shall exist for financial systems with defined RTO/RPO and tested recovery procedures.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS04.04".to_string(),
                "ISO27001-A.5.30".to_string(),
            ],
            remediation_guidance: Some("Maintain DR plans with annual testing, document recovery procedures, and update contact information quarterly.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Logical Security
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-LS-01".to_string(),
            control_id: "ITGC-LS-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Network Security Controls".to_string(),
            description: "Network security controls shall protect financial systems including firewalls, intrusion detection, and network segmentation.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.02".to_string(),
                "ISO27001-A.8.20".to_string(),
                "ISO27001-A.8.22".to_string(),
            ],
            remediation_guidance: Some("Implement defense-in-depth network security with firewalls, IDS/IPS, and network segmentation for financial systems.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-LS-02".to_string(),
            control_id: "ITGC-LS-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Encryption of Sensitive Data".to_string(),
            description: "Financial data shall be encrypted at rest and in transit using industry-standard cryptographic controls.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.03".to_string(),
                "ISO27001-A.8.24".to_string(),
            ],
            remediation_guidance: Some("Implement TLS 1.2+ for data in transit, AES-256 for data at rest, with proper key management procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-LS-03".to_string(),
            control_id: "ITGC-LS-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Malware Protection".to_string(),
            description: "Anti-malware controls shall be deployed and maintained on all systems accessing or processing financial data.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.01".to_string(),
                "ISO27001-A.8.7".to_string(),
            ],
            remediation_guidance: Some("Deploy EDR/AV solution on all endpoints with real-time protection, automatic updates, and centralized management.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-LS-04".to_string(),
            control_id: "ITGC-LS-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Vulnerability Management".to_string(),
            description: "Systems processing financial data shall be regularly scanned for vulnerabilities with timely remediation of identified issues.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.02".to_string(),
                "ISO27001-A.8.8".to_string(),
            ],
            remediation_guidance: Some("Conduct monthly vulnerability scans, remediate critical/high within 30 days, maintain risk acceptance documentation.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-LS-05".to_string(),
            control_id: "ITGC-LS-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Security Logging and Monitoring".to_string(),
            description: "Security events from financial systems shall be logged, monitored, and reviewed for indicators of compromise or misuse.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.07".to_string(),
                "ISO27001-A.8.15".to_string(),
                "ISO27001-A.8.16".to_string(),
            ],
            remediation_guidance: Some("Implement SIEM for log aggregation, define correlation rules, conduct regular log reviews, and establish alerting thresholds.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Physical Security
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-PS-01".to_string(),
            control_id: "ITGC-PS-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Data Center Physical Access".to_string(),
            description: "Physical access to data centers housing financial systems shall be restricted and monitored with access logs.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.05".to_string(),
                "ISO27001-A.7.2".to_string(),
            ],
            remediation_guidance: Some("Implement badge access, visitor logs, security cameras, and periodic access reviews for data center facilities.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-PS-02".to_string(),
            control_id: "ITGC-PS-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Environmental Controls".to_string(),
            description: "Data centers shall have environmental controls including fire suppression, HVAC, and power conditioning to protect financial systems.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS01.04".to_string(),
                "ISO27001-A.7.5".to_string(),
            ],
            remediation_guidance: Some("Implement fire suppression, redundant HVAC, UPS, and generator backup with regular testing and maintenance.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-PS-03".to_string(),
            control_id: "ITGC-PS-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Media Handling and Disposal".to_string(),
            description: "Media containing financial data shall be securely handled, transported, and disposed of according to documented procedures.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.06".to_string(),
                "ISO27001-A.7.10".to_string(),
                "ISO27001-A.7.14".to_string(),
            ],
            remediation_guidance: Some("Implement media handling procedures with chain of custody, secure transport, and certified destruction with certificates.".to_string()),
        },

        // ========================================================================
        // IT General Controls (ITGC) - Segregation of Duties
        // ========================================================================
        ComplianceControl {
            id: "SOX-ITGC-SD-01".to_string(),
            control_id: "ITGC-SD-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Segregation of Duties Matrix".to_string(),
            description: "A segregation of duties matrix shall define incompatible functions that must be performed by different individuals.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.3".to_string(),
            ],
            remediation_guidance: Some("Document SoD matrix for IT and business functions, implement preventive controls, and conduct periodic reviews.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-SD-02".to_string(),
            control_id: "ITGC-SD-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Developer Access to Production".to_string(),
            description: "Developers shall not have access to production financial systems, or such access shall be monitored with compensating controls.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.3".to_string(),
            ],
            remediation_guidance: Some("Remove permanent developer production access, implement break-glass procedures with logging and review.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ITGC-SD-03".to_string(),
            control_id: "ITGC-SD-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "SoD Violation Monitoring".to_string(),
            description: "Segregation of duties violations shall be detected, logged, and reviewed with appropriate management escalation.".to_string(),
            category: "IT General Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.04".to_string(),
                "ISO27001-A.5.3".to_string(),
            ],
            remediation_guidance: Some("Implement automated SoD monitoring in IAM/GRC systems with alerting and documented exception process.".to_string()),
        },

        // ========================================================================
        // Application Controls
        // ========================================================================
        ComplianceControl {
            id: "SOX-AC-01".to_string(),
            control_id: "AC-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Input Validation Controls".to_string(),
            description: "Financial applications shall validate all input data for completeness, accuracy, and authorization before processing.".to_string(),
            category: "Application Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO12.05".to_string(),
                "ISO27001-A.8.26".to_string(),
            ],
            remediation_guidance: Some("Implement input validation, edit checks, authorization verification, and duplicate detection controls.".to_string()),
        },
        ComplianceControl {
            id: "SOX-AC-02".to_string(),
            control_id: "AC-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Processing Controls".to_string(),
            description: "Financial applications shall include controls to ensure complete, accurate, and authorized processing of transactions.".to_string(),
            category: "Application Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO12.05".to_string(),
                "ISO27001-A.8.26".to_string(),
            ],
            remediation_guidance: Some("Implement batch/hash totals, run-to-run controls, and automated reconciliation with exception reporting.".to_string()),
        },
        ComplianceControl {
            id: "SOX-AC-03".to_string(),
            control_id: "AC-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Output Controls".to_string(),
            description: "Financial application outputs shall be validated for completeness, accuracy, and proper distribution to authorized recipients.".to_string(),
            category: "Application Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO12.05".to_string(),
                "ISO27001-A.8.26".to_string(),
            ],
            remediation_guidance: Some("Implement output validation, distribution controls, reconciliation with source data, and report logging.".to_string()),
        },
        ComplianceControl {
            id: "SOX-AC-04".to_string(),
            control_id: "AC-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Interface Controls".to_string(),
            description: "Data interfaces between financial systems shall include controls to ensure complete, accurate, and timely data transfer.".to_string(),
            category: "Application Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-DSS05.02".to_string(),
                "ISO27001-A.5.14".to_string(),
            ],
            remediation_guidance: Some("Implement interface reconciliation, record counts, hash totals, and automated monitoring with exception alerting.".to_string()),
        },
        ComplianceControl {
            id: "SOX-AC-05".to_string(),
            control_id: "AC-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Automated Calculations".to_string(),
            description: "Automated calculations in financial applications shall be validated upon implementation and periodically thereafter.".to_string(),
            category: "Application Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO12.05".to_string(),
                "ISO27001-A.8.29".to_string(),
            ],
            remediation_guidance: Some("Test automated calculations during development and after changes, conduct periodic validation with manual recalculation.".to_string()),
        },

        // ========================================================================
        // Entity-Level Controls
        // ========================================================================
        ComplianceControl {
            id: "SOX-ELC-01".to_string(),
            control_id: "ELC-01".to_string(),
            framework: ComplianceFramework::Sox,
            title: "IT Governance Structure".to_string(),
            description: "An IT governance structure shall be established with defined roles, responsibilities, and accountability for IT controls.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-EDM01.02".to_string(),
                "ISO27001-A.5.1".to_string(),
                "ISO27001-A.5.2".to_string(),
            ],
            remediation_guidance: Some("Establish IT steering committee, define RACI matrix, and document IT governance charter and policies.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-02".to_string(),
            control_id: "ELC-02".to_string(),
            framework: ComplianceFramework::Sox,
            title: "IT Risk Assessment".to_string(),
            description: "IT risks to financial reporting shall be periodically assessed and documented with defined risk treatment strategies.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO12.02".to_string(),
                "ISO27001-A.5.7".to_string(),
            ],
            remediation_guidance: Some("Conduct annual IT risk assessment, maintain risk register, and implement risk treatment plans with tracking.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-03".to_string(),
            control_id: "ELC-03".to_string(),
            framework: ComplianceFramework::Sox,
            title: "IT Policies and Standards".to_string(),
            description: "IT policies and standards shall be documented, approved by management, and communicated to relevant personnel.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO01.03".to_string(),
                "ISO27001-A.5.1".to_string(),
            ],
            remediation_guidance: Some("Document IT policies, obtain management approval, communicate to employees, and require acknowledgment.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-04".to_string(),
            control_id: "ELC-04".to_string(),
            framework: ComplianceFramework::Sox,
            title: "IT Control Monitoring".to_string(),
            description: "IT controls shall be monitored through ongoing activities and periodic evaluations to ensure continued effectiveness.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-MEA02.01".to_string(),
                "ISO27001-A.5.36".to_string(),
            ],
            remediation_guidance: Some("Implement continuous control monitoring, conduct periodic control testing, and track remediation of deficiencies.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-05".to_string(),
            control_id: "ELC-05".to_string(),
            framework: ComplianceFramework::Sox,
            title: "IT Audit and Compliance".to_string(),
            description: "Internal and external IT audits shall be performed to assess compliance with policies, standards, and regulatory requirements.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-MEA03.01".to_string(),
                "ISO27001-A.5.35".to_string(),
            ],
            remediation_guidance: Some("Conduct annual IT audits, track findings to remediation, and report status to audit committee.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-06".to_string(),
            control_id: "ELC-06".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Third-Party Risk Management".to_string(),
            description: "Third parties with access to financial systems or data shall be assessed for security and compliance requirements.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO10.01".to_string(),
                "ISO27001-A.5.19".to_string(),
                "ISO27001-A.5.20".to_string(),
            ],
            remediation_guidance: Some("Implement vendor risk assessment process, include security requirements in contracts, and conduct periodic reviews.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-07".to_string(),
            control_id: "ELC-07".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Security Awareness Training".to_string(),
            description: "Personnel with access to financial systems shall receive security awareness training upon hire and annually thereafter.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "COBIT-APO07.03".to_string(),
                "ISO27001-A.6.3".to_string(),
            ],
            remediation_guidance: Some("Implement security awareness program with annual training, phishing simulations, and completion tracking.".to_string()),
        },
        ComplianceControl {
            id: "SOX-ELC-08".to_string(),
            control_id: "ELC-08".to_string(),
            framework: ComplianceFramework::Sox,
            title: "Management Review of IT Controls".to_string(),
            description: "Management shall periodically review the design and operating effectiveness of IT controls over financial reporting.".to_string(),
            category: "Entity-Level Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "COBIT-MEA02.03".to_string(),
                "ISO27001-A.5.35".to_string(),
            ],
            remediation_guidance: Some("Conduct quarterly management review of IT controls, document control testing results, and report to audit committee.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant SOX IT controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control and authentication vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("authentication bypass")
        || title_lower.contains("privilege escalation")
    {
        mappings.push(("SOX-ITGC-AC-01".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-AC-04".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-SD-02".to_string(), Severity::High));
    }

    // Credential and password issues
    if title_lower.contains("default password")
        || title_lower.contains("weak password")
        || title_lower.contains("credential")
        || title_lower.contains("hardcoded password")
    {
        mappings.push(("SOX-ITGC-AC-05".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-AC-06".to_string(), Severity::High));
    }

    // Encryption and TLS issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("SOX-ITGC-LS-02".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-BR-03".to_string(), Severity::High));
    }

    // Malware and endpoint protection
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("ransomware")
        || title_lower.contains("trojan")
    {
        mappings.push(("SOX-ITGC-LS-03".to_string(), Severity::Critical));
    }

    // Vulnerability and patching issues
    if title_lower.contains("cve")
        || title_lower.contains("vulnerability")
        || title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
    {
        mappings.push(("SOX-ITGC-LS-04".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-PD-05".to_string(), Severity::High));
    }

    // Logging and monitoring issues
    if title_lower.contains("logging")
        || title_lower.contains("monitoring")
        || title_lower.contains("audit")
        || title_lower.contains("no logs")
    {
        mappings.push(("SOX-ITGC-LS-05".to_string(), Severity::High));
        mappings.push(("SOX-ELC-04".to_string(), Severity::Medium));
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("network")
        || title_lower.contains("open port")
        || title_lower.contains("segmentation")
    {
        mappings.push(("SOX-ITGC-LS-01".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-PD-03".to_string(), Severity::High));
    }

    // Change management issues
    if title_lower.contains("unauthorized change")
        || title_lower.contains("configuration drift")
        || title_lower.contains("unapproved")
    {
        mappings.push(("SOX-ITGC-CM-01".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-CM-02".to_string(), Severity::High));
    }

    // Configuration and misconfiguration issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("default config")
        || title_lower.contains("insecure configuration")
    {
        mappings.push(("SOX-ITGC-CM-03".to_string(), Severity::Medium));
        mappings.push(("SOX-ITGC-PD-03".to_string(), Severity::Medium));
    }

    // Input validation and injection vulnerabilities
    if title_lower.contains("injection")
        || title_lower.contains("xss")
        || title_lower.contains("sql injection")
        || title_lower.contains("command injection")
    {
        mappings.push(("SOX-AC-01".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-PD-02".to_string(), Severity::High));
    }

    // Backup and recovery issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
        || title_lower.contains("disaster")
    {
        mappings.push(("SOX-ITGC-BR-01".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-BR-02".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-BR-05".to_string(), Severity::High));
    }

    // Data integrity issues
    if title_lower.contains("data integrity")
        || title_lower.contains("data corruption")
        || title_lower.contains("data loss")
    {
        mappings.push(("SOX-AC-02".to_string(), Severity::Critical));
        mappings.push(("SOX-AC-03".to_string(), Severity::High));
    }

    // Third-party and vendor issues
    if title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("supply chain")
    {
        mappings.push(("SOX-ELC-06".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-PD-05".to_string(), Severity::Medium));
    }

    // Physical security issues
    if title_lower.contains("physical access")
        || title_lower.contains("data center")
        || title_lower.contains("media disposal")
    {
        mappings.push(("SOX-ITGC-PS-01".to_string(), Severity::Medium));
        mappings.push(("SOX-ITGC-PS-03".to_string(), Severity::Medium));
    }

    // Segregation of duties violations
    if title_lower.contains("segregation of duties")
        || title_lower.contains("sod violation")
        || title_lower.contains("conflicting access")
    {
        mappings.push(("SOX-ITGC-SD-01".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-SD-02".to_string(), Severity::Critical));
        mappings.push(("SOX-ITGC-SD-03".to_string(), Severity::High));
    }

    // Interface and data transfer issues
    if title_lower.contains("interface")
        || title_lower.contains("data transfer")
        || title_lower.contains("api security")
    {
        mappings.push(("SOX-AC-04".to_string(), Severity::High));
    }

    // Source code and development issues
    if title_lower.contains("source code")
        || title_lower.contains("code repository")
        || title_lower.contains("development")
    {
        mappings.push(("SOX-ITGC-PD-04".to_string(), Severity::High));
        mappings.push(("SOX-ITGC-PD-01".to_string(), Severity::Medium));
    }

    // Default fallback for general security issues
    if mappings.is_empty() {
        if title_lower.contains("security")
            || title_lower.contains("risk")
        {
            mappings.push(("SOX-ELC-02".to_string(), Severity::Medium));
            mappings.push(("SOX-ELC-04".to_string(), Severity::Medium));
        }
    }

    mappings
}

/// Map a vulnerability type to relevant SOX IT controls (control IDs only)
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "authentication" | "password" | "mfa" | "credential" => vec![
            "ITGC-AC-05".to_string(),
            "ITGC-AC-06".to_string(),
        ],
        "access_control" | "authorization" | "privilege" => vec![
            "ITGC-AC-01".to_string(),
            "ITGC-AC-04".to_string(),
            "ITGC-SD-02".to_string(),
        ],
        "encryption" | "cryptography" | "tls" | "ssl" => vec![
            "ITGC-LS-02".to_string(),
            "ITGC-BR-03".to_string(),
        ],
        "malware" | "virus" | "ransomware" => vec![
            "ITGC-LS-03".to_string(),
        ],
        "vulnerability" | "patching" | "update" => vec![
            "ITGC-LS-04".to_string(),
            "ITGC-PD-05".to_string(),
        ],
        "logging" | "monitoring" | "audit" => vec![
            "ITGC-LS-05".to_string(),
            "ELC-04".to_string(),
        ],
        "network" | "firewall" | "segmentation" => vec![
            "ITGC-LS-01".to_string(),
            "ITGC-PD-03".to_string(),
        ],
        "change_management" | "configuration" => vec![
            "ITGC-CM-01".to_string(),
            "ITGC-CM-02".to_string(),
            "ITGC-CM-03".to_string(),
        ],
        "injection" | "xss" | "input_validation" => vec![
            "AC-01".to_string(),
            "ITGC-PD-02".to_string(),
        ],
        "backup" | "recovery" | "disaster_recovery" => vec![
            "ITGC-BR-01".to_string(),
            "ITGC-BR-02".to_string(),
            "ITGC-BR-05".to_string(),
        ],
        "data_integrity" | "processing" => vec![
            "AC-02".to_string(),
            "AC-03".to_string(),
        ],
        "vendor" | "third_party" | "supply_chain" => vec![
            "ELC-06".to_string(),
            "ITGC-PD-05".to_string(),
        ],
        "segregation_of_duties" | "sod" => vec![
            "ITGC-SD-01".to_string(),
            "ITGC-SD-02".to_string(),
            "ITGC-SD-03".to_string(),
        ],
        "physical" | "data_center" | "media" => vec![
            "ITGC-PS-01".to_string(),
            "ITGC-PS-02".to_string(),
            "ITGC-PS-03".to_string(),
        ],
        "development" | "sdlc" | "code" => vec![
            "ITGC-PD-01".to_string(),
            "ITGC-PD-02".to_string(),
            "ITGC-PD-04".to_string(),
        ],
        "governance" | "policy" | "risk" => vec![
            "ELC-01".to_string(),
            "ELC-02".to_string(),
            "ELC-03".to_string(),
        ],
        _ => vec!["ELC-04".to_string()],
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
            assert!(!control.id.is_empty(), "Control ID should not be empty");
            assert!(!control.control_id.is_empty(), "Control ID should not be empty");
            assert!(!control.title.is_empty(), "Title should not be empty");
            assert!(!control.description.is_empty(), "Description should not be empty");
            assert!(!control.category.is_empty(), "Category should not be empty");
            assert!(control.remediation_guidance.is_some(), "Remediation guidance should be present");
        }
    }

    #[test]
    fn test_all_controls_use_sox_framework() {
        for control in get_controls() {
            assert_eq!(control.framework, ComplianceFramework::Sox);
        }
    }

    #[test]
    fn test_control_categories() {
        let controls = get_controls();
        let categories: Vec<&str> = controls.iter().map(|c| c.category.as_str()).collect();

        assert!(categories.contains(&"IT General Controls"));
        assert!(categories.contains(&"Application Controls"));
        assert!(categories.contains(&"Entity-Level Controls"));
    }

    #[test]
    fn test_cross_references_present() {
        let controls = get_controls();
        let controls_with_refs: Vec<_> = controls
            .iter()
            .filter(|c| !c.cross_references.is_empty())
            .collect();

        // Most controls should have cross-references
        assert!(
            controls_with_refs.len() > 40,
            "Expected most controls to have cross-references, found {}",
            controls_with_refs.len()
        );
    }

    #[test]
    fn test_vulnerability_mapping() {
        // Test access control mapping
        let mappings = map_vulnerability("Unauthorized access to financial system", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("AC-01") || id.contains("AC-04")));

        // Test encryption mapping
        let mappings = map_vulnerability("Unencrypted data transmission", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("LS-02")));

        // Test injection mapping
        let mappings = map_vulnerability("SQL Injection vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SOX-AC-01"));
    }

    #[test]
    fn test_vulnerability_to_controls_mapping() {
        let controls = map_vulnerability_to_controls("authentication");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"ITGC-AC-05".to_string()));

        let controls = map_vulnerability_to_controls("segregation_of_duties");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"ITGC-SD-01".to_string()));
    }

    #[test]
    fn test_cobit_cross_references() {
        let controls = get_controls();
        let cobit_refs: Vec<_> = controls
            .iter()
            .flat_map(|c| c.cross_references.iter())
            .filter(|r| r.starts_with("COBIT"))
            .collect();

        assert!(
            !cobit_refs.is_empty(),
            "Should have COBIT cross-references"
        );
    }

    #[test]
    fn test_iso27001_cross_references() {
        let controls = get_controls();
        let iso_refs: Vec<_> = controls
            .iter()
            .flat_map(|c| c.cross_references.iter())
            .filter(|r| r.starts_with("ISO27001"))
            .collect();

        assert!(
            !iso_refs.is_empty(),
            "Should have ISO 27001 cross-references"
        );
    }

    #[test]
    fn test_critical_controls_identified() {
        let controls = get_controls();
        let critical_controls: Vec<_> = controls
            .iter()
            .filter(|c| c.priority == ControlPriority::Critical)
            .collect();

        // SOX should have several critical controls
        assert!(
            critical_controls.len() >= 10,
            "Expected at least 10 critical controls, found {}",
            critical_controls.len()
        );
    }

    #[test]
    fn test_automated_checks() {
        let controls = get_controls();
        let automated: Vec<_> = controls
            .iter()
            .filter(|c| c.automated_check)
            .collect();

        // Should have a good number of automatable controls
        assert!(
            automated.len() >= 20,
            "Expected at least 20 automated controls, found {}",
            automated.len()
        );
    }
}
