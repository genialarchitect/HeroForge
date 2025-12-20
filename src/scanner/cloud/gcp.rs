//! GCP Cloud Infrastructure Scanner
//!
//! This module provides scanning capabilities for Google Cloud Platform resources including:
//! - IAM: Service accounts, IAM bindings, roles
//! - Storage: Cloud Storage buckets
//! - Compute: Compute Engine instances
//! - Network: Firewall rules, VPC networks
//! - Database: Cloud SQL instances

use super::types::*;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// GCP Cloud Scanner implementation
pub struct GcpScanner {
    /// Whether to use demo/mock mode (no real API calls)
    demo_mode: bool,
}

impl GcpScanner {
    /// Create a new GCP scanner
    pub fn new(demo_mode: bool) -> Self {
        Self { demo_mode }
    }

    /// Generate demo IAM findings for testing
    fn generate_demo_iam_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Service Account with issues
        let sa_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: sa_id.clone(),
            resource_id: "default-compute-sa".to_string(),
            resource_type: CloudResourceType::ServiceAccount,
            provider: CloudProvider::Gcp,
            region: Some("global".to_string()),
            name: Some("Default Compute Service Account".to_string()),
            arn: Some("projects/my-project/serviceAccounts/123456789-compute@developer.gserviceaccount.com".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "email": "123456789-compute@developer.gserviceaccount.com",
                "unique_id": "123456789012345678901",
                "roles": ["roles/editor", "roles/owner"],
                "keys": [
                    {
                        "key_id": "key123",
                        "valid_after": "2022-01-01T00:00:00Z",
                        "valid_before": "2024-01-01T00:00:00Z"
                    }
                ],
                "is_default": true
            }),
            state: Some("Enabled".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sa_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::Critical,
            title: "Default Compute Service Account with Owner Role".to_string(),
            description: "The default Compute Engine service account has been granted the Owner role. Default service accounts should have minimal permissions.".to_string(),
            remediation: Some("Remove the Owner role from the default service account. Create custom service accounts with specific roles following the principle of least privilege.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "1.5".to_string(),
                    control_title: Some("Ensure that Service Account has no admin privileges".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/serviceAccounts/123456789-compute@developer.gserviceaccount.com".to_string()),
            evidence: Some(FindingEvidence {
                description: "Default service account has Owner role".to_string(),
                raw_data: Some(serde_json::json!({
                    "roles": ["roles/editor", "roles/owner"]
                })),
                expected: Some("Minimal roles".to_string()),
                actual: Some("Owner role assigned".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sa_id.clone()),
            finding_type: FindingType::BestPractice,
            severity: FindingSeverity::High,
            title: "Service Account with User-Managed Keys".to_string(),
            description: "Service account 'Default Compute Service Account' has user-managed keys. User-managed keys require manual rotation and can be a security risk.".to_string(),
            remediation: Some("Use Google-managed keys when possible. If user-managed keys are required, implement automatic key rotation.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "1.7".to_string(),
                    control_title: Some("Ensure user-managed/external keys for service accounts are rotated every 90 days or less".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/serviceAccounts/123456789-compute@developer.gserviceaccount.com".to_string()),
            evidence: Some(FindingEvidence {
                description: "User-managed keys present".to_string(),
                raw_data: Some(serde_json::json!({
                    "key_count": 1,
                    "oldest_key_age_days": 730
                })),
                expected: Some("No user-managed keys or keys < 90 days old".to_string()),
                actual: Some("User-managed keys 730 days old".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        // Demo IAM Binding with allUsers
        let binding_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: binding_id.clone(),
            resource_id: "public-bucket-binding".to_string(),
            resource_type: CloudResourceType::IamBinding,
            provider: CloudProvider::Gcp,
            region: Some("global".to_string()),
            name: Some("Public Bucket IAM Binding".to_string()),
            arn: Some("projects/my-project/iamPolicies/bucket-public".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "role": "roles/storage.objectViewer",
                "members": ["allUsers"]
            }),
            state: Some("Active".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(binding_id),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "IAM Binding Grants Access to allUsers".to_string(),
            description: "An IAM binding grants the Storage Object Viewer role to 'allUsers', making the resource publicly accessible.".to_string(),
            remediation: Some("Remove 'allUsers' from the IAM binding. Grant access only to specific users, groups, or service accounts.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "5.1".to_string(),
                    control_title: Some("Ensure that Cloud Storage bucket is not anonymously or publicly accessible".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/iamPolicies/bucket-public".to_string()),
            evidence: Some(FindingEvidence {
                description: "IAM binding includes allUsers".to_string(),
                raw_data: Some(serde_json::json!({
                    "members": ["allUsers"]
                })),
                expected: Some("Specific users/groups/service accounts".to_string()),
                actual: Some("allUsers".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo Cloud Storage findings for testing
    fn generate_demo_storage_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Cloud Storage bucket with issues
        let bucket_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: bucket_id.clone(),
            resource_id: "prod-data-bucket".to_string(),
            resource_type: CloudResourceType::CloudStorage,
            provider: CloudProvider::Gcp,
            region: Some("us-central1".to_string()),
            name: Some("prod-data-bucket".to_string()),
            arn: Some("gs://prod-data-bucket".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("environment".to_string(), "production".to_string());
                tags
            },
            metadata: serde_json::json!({
                "storage_class": "STANDARD",
                "location_type": "region",
                "uniform_bucket_level_access": false,
                "public_access_prevention": "inherited",
                "versioning_enabled": false,
                "lifecycle_rules": [],
                "encryption": "Google-managed"
            }),
            state: Some("Active".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(bucket_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Cloud Storage Bucket Without Uniform Bucket-Level Access".to_string(),
            description: "Cloud Storage bucket 'prod-data-bucket' does not have uniform bucket-level access enabled. This allows object-level ACLs which can lead to inconsistent access controls.".to_string(),
            remediation: Some("Enable uniform bucket-level access to ensure consistent permissions are applied through IAM only.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "5.2".to_string(),
                    control_title: Some("Ensure that Cloud Storage buckets have uniform bucket-level access enabled".to_string()),
                },
            ],
            affected_resource_arn: Some("gs://prod-data-bucket".to_string()),
            evidence: Some(FindingEvidence {
                description: "Uniform bucket-level access is not enabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "uniform_bucket_level_access": false
                })),
                expected: Some("uniform_bucket_level_access: true".to_string()),
                actual: Some("uniform_bucket_level_access: false".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(bucket_id.clone()),
            finding_type: FindingType::BestPractice,
            severity: FindingSeverity::Medium,
            title: "Cloud Storage Bucket Without Versioning".to_string(),
            description: "Cloud Storage bucket 'prod-data-bucket' does not have versioning enabled. Versioning protects against accidental deletion and modification.".to_string(),
            remediation: Some("Enable object versioning to maintain a history of object changes and allow recovery from accidental deletions.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("gs://prod-data-bucket".to_string()),
            evidence: Some(FindingEvidence {
                description: "Versioning is not enabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "versioning_enabled": false
                })),
                expected: Some("Versioning enabled".to_string()),
                actual: Some("Versioning disabled".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo Compute Engine findings for testing
    fn generate_demo_compute_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Compute Engine instance with issues
        let instance_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: instance_id.clone(),
            resource_id: "web-server-1".to_string(),
            resource_type: CloudResourceType::ComputeInstance,
            provider: CloudProvider::Gcp,
            region: Some("us-central1-a".to_string()),
            name: Some("web-server-1".to_string()),
            arn: Some("projects/my-project/zones/us-central1-a/instances/web-server-1".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("environment".to_string(), "production".to_string());
                tags
            },
            metadata: serde_json::json!({
                "machine_type": "n1-standard-2",
                "external_ip": "35.192.0.1",
                "internal_ip": "10.128.0.2",
                "service_account": "default",
                "service_account_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "shielded_vm": false,
                "os_login": false,
                "serial_port_logging": true,
                "disk_encryption": "Google-managed"
            }),
            state: Some("RUNNING".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(instance_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::Critical,
            title: "Compute Instance with Full Cloud Platform Scope".to_string(),
            description: "Compute instance 'web-server-1' uses the 'cloud-platform' scope which grants access to all GCP APIs. This violates the principle of least privilege.".to_string(),
            remediation: Some("Replace the cloud-platform scope with specific scopes required by the application. Consider using custom service accounts with minimal IAM roles.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "4.2".to_string(),
                    control_title: Some("Ensure that instances are not configured to use default service account with full access to all Cloud APIs".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/zones/us-central1-a/instances/web-server-1".to_string()),
            evidence: Some(FindingEvidence {
                description: "Instance uses cloud-platform scope".to_string(),
                raw_data: Some(serde_json::json!({
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
                })),
                expected: Some("Minimal required scopes".to_string()),
                actual: Some("Full cloud-platform scope".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(instance_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Compute Instance Using Default Service Account".to_string(),
            description: "Compute instance 'web-server-1' uses the default service account. Default service accounts often have more permissions than needed.".to_string(),
            remediation: Some("Create and use a custom service account with only the minimum required permissions.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "4.1".to_string(),
                    control_title: Some("Ensure that instances are not configured to use default service account".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/zones/us-central1-a/instances/web-server-1".to_string()),
            evidence: Some(FindingEvidence {
                description: "Uses default service account".to_string(),
                raw_data: Some(serde_json::json!({
                    "service_account": "default"
                })),
                expected: Some("Custom service account".to_string()),
                actual: Some("Default service account".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(instance_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::Medium,
            title: "Compute Instance Without Shielded VM".to_string(),
            description: "Compute instance 'web-server-1' does not have Shielded VM features enabled. Shielded VMs provide protection against rootkits and bootkits.".to_string(),
            remediation: Some("Enable Shielded VM features including Secure Boot, vTPM, and Integrity Monitoring.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "4.8".to_string(),
                    control_title: Some("Ensure Compute instances are launched with Shielded VM enabled".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/zones/us-central1-a/instances/web-server-1".to_string()),
            evidence: Some(FindingEvidence {
                description: "Shielded VM is not enabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "shielded_vm": false
                })),
                expected: Some("Shielded VM enabled".to_string()),
                actual: Some("Shielded VM disabled".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo Firewall findings for testing
    fn generate_demo_network_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Firewall rule with issues
        let fw_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: fw_id.clone(),
            resource_id: "allow-all-ssh".to_string(),
            resource_type: CloudResourceType::FirewallRule,
            provider: CloudProvider::Gcp,
            region: Some("global".to_string()),
            name: Some("allow-all-ssh".to_string()),
            arn: Some("projects/my-project/global/firewalls/allow-all-ssh".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "network": "default",
                "direction": "INGRESS",
                "priority": 1000,
                "source_ranges": ["0.0.0.0/0"],
                "allowed": [
                    {
                        "IPProtocol": "tcp",
                        "ports": ["22"]
                    }
                ],
                "disabled": false
            }),
            state: Some("Active".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(fw_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "Firewall Rule Allows SSH from Any IP".to_string(),
            description: "Firewall rule 'allow-all-ssh' allows SSH access from 0.0.0.0/0 (any IP address). This exposes SSH to the entire internet.".to_string(),
            remediation: Some("Restrict the source range to specific IP addresses or CIDR blocks. Consider using Identity-Aware Proxy (IAP) for SSH access.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "3.6".to_string(),
                    control_title: Some("Ensure that SSH access is restricted from the internet".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/global/firewalls/allow-all-ssh".to_string()),
            evidence: Some(FindingEvidence {
                description: "SSH allowed from any IP".to_string(),
                raw_data: Some(serde_json::json!({
                    "source_ranges": ["0.0.0.0/0"],
                    "port": "22"
                })),
                expected: Some("Specific IP ranges".to_string()),
                actual: Some("0.0.0.0/0".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        // Demo Firewall rule with RDP
        let fw_rdp_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: fw_rdp_id.clone(),
            resource_id: "allow-all-rdp".to_string(),
            resource_type: CloudResourceType::FirewallRule,
            provider: CloudProvider::Gcp,
            region: Some("global".to_string()),
            name: Some("allow-all-rdp".to_string()),
            arn: Some("projects/my-project/global/firewalls/allow-all-rdp".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "network": "default",
                "direction": "INGRESS",
                "priority": 1000,
                "source_ranges": ["0.0.0.0/0"],
                "allowed": [
                    {
                        "IPProtocol": "tcp",
                        "ports": ["3389"]
                    }
                ],
                "disabled": false
            }),
            state: Some("Active".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(fw_rdp_id),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "Firewall Rule Allows RDP from Any IP".to_string(),
            description: "Firewall rule 'allow-all-rdp' allows RDP access from 0.0.0.0/0 (any IP address). This exposes RDP to the entire internet.".to_string(),
            remediation: Some("Restrict the source range to specific IP addresses or CIDR blocks. Consider using Identity-Aware Proxy (IAP) for RDP access.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "3.7".to_string(),
                    control_title: Some("Ensure that RDP access is restricted from the Internet".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/global/firewalls/allow-all-rdp".to_string()),
            evidence: Some(FindingEvidence {
                description: "RDP allowed from any IP".to_string(),
                raw_data: Some(serde_json::json!({
                    "source_ranges": ["0.0.0.0/0"],
                    "port": "3389"
                })),
                expected: Some("Specific IP ranges".to_string()),
                actual: Some("0.0.0.0/0".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo Cloud SQL findings for testing
    fn generate_demo_database_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Cloud SQL instance with issues
        let sql_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: sql_id.clone(),
            resource_id: "prod-mysql".to_string(),
            resource_type: CloudResourceType::CloudSql,
            provider: CloudProvider::Gcp,
            region: Some("us-central1".to_string()),
            name: Some("prod-mysql".to_string()),
            arn: Some("projects/my-project/instances/prod-mysql".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("environment".to_string(), "production".to_string());
                tags
            },
            metadata: serde_json::json!({
                "database_version": "MYSQL_5_7",
                "tier": "db-n1-standard-2",
                "public_ip": "35.192.0.100",
                "private_ip": null,
                "authorized_networks": [
                    {
                        "name": "allow-all",
                        "value": "0.0.0.0/0"
                    }
                ],
                "ssl_required": false,
                "backup_enabled": false,
                "availability_type": "ZONAL",
                "binary_log_enabled": false
            }),
            state: Some("RUNNABLE".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sql_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "Cloud SQL Instance Allows All IPs".to_string(),
            description: "Cloud SQL instance 'prod-mysql' has an authorized network entry allowing 0.0.0.0/0. This exposes the database to the entire internet.".to_string(),
            remediation: Some("Remove the 0.0.0.0/0 entry and only authorize specific IP addresses. Consider using Cloud SQL Proxy or private IP for connections.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "6.5".to_string(),
                    control_title: Some("Ensure that Cloud SQL database instances do not have public IPs".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/instances/prod-mysql".to_string()),
            evidence: Some(FindingEvidence {
                description: "Authorized network allows all IPs".to_string(),
                raw_data: Some(serde_json::json!({
                    "authorized_networks": ["0.0.0.0/0"]
                })),
                expected: Some("Specific IP ranges".to_string()),
                actual: Some("0.0.0.0/0".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sql_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Cloud SQL Instance Without SSL Required".to_string(),
            description: "Cloud SQL instance 'prod-mysql' does not require SSL for connections. This allows unencrypted database connections.".to_string(),
            remediation: Some("Enable 'Require SSL' to enforce encrypted connections for all clients.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "6.1".to_string(),
                    control_title: Some("Ensure that Cloud SQL database instance requires all incoming connections to use SSL".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/instances/prod-mysql".to_string()),
            evidence: Some(FindingEvidence {
                description: "SSL is not required".to_string(),
                raw_data: Some(serde_json::json!({
                    "ssl_required": false
                })),
                expected: Some("SSL required".to_string()),
                actual: Some("SSL not required".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sql_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Cloud SQL Instance Without Automated Backups".to_string(),
            description: "Cloud SQL instance 'prod-mysql' does not have automated backups enabled. This could result in data loss.".to_string(),
            remediation: Some("Enable automated backups with an appropriate retention period for production databases.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS GCP".to_string(),
                    control_id: "6.7".to_string(),
                    control_title: Some("Ensure that Cloud SQL database instances are configured with automated backups".to_string()),
                },
            ],
            affected_resource_arn: Some("projects/my-project/instances/prod-mysql".to_string()),
            evidence: Some(FindingEvidence {
                description: "Automated backups are disabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "backup_enabled": false
                })),
                expected: Some("Backups enabled".to_string()),
                actual: Some("Backups disabled".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }
}

#[async_trait::async_trait]
impl CloudScanner for GcpScanner {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    async fn scan_iam(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("GCP IAM scan running in demo mode");
            return Ok(self.generate_demo_iam_resources());
        }

        // TODO: Implement real GCP IAM scanning using google-cloud-rust
        log::warn!("Real GCP IAM scanning not yet implemented - returning empty results");
        Ok((Vec::new(), Vec::new()))
    }

    async fn scan_storage(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("GCP Storage scan running in demo mode");
            return Ok(self.generate_demo_storage_resources());
        }

        // TODO: Implement real GCP Cloud Storage scanning
        log::warn!("Real GCP Storage scanning not yet implemented - returning empty results");
        Ok((Vec::new(), Vec::new()))
    }

    async fn scan_compute(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("GCP Compute scan running in demo mode");
            return Ok(self.generate_demo_compute_resources());
        }

        // TODO: Implement real GCP Compute Engine scanning
        log::warn!("Real GCP Compute scanning not yet implemented - returning empty results");
        Ok((Vec::new(), Vec::new()))
    }

    async fn scan_network(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("GCP Network scan running in demo mode");
            return Ok(self.generate_demo_network_resources());
        }

        // TODO: Implement real GCP Firewall scanning
        log::warn!("Real GCP Network scanning not yet implemented - returning empty results");
        Ok((Vec::new(), Vec::new()))
    }

    async fn scan_database(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("GCP Database scan running in demo mode");
            return Ok(self.generate_demo_database_resources());
        }

        // TODO: Implement real GCP Cloud SQL scanning
        log::warn!("Real GCP Database scanning not yet implemented - returning empty results");
        Ok((Vec::new(), Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gcp_demo_scan() {
        let scanner = GcpScanner::new(true);
        let config = CloudScanConfig {
            provider: CloudProvider::Gcp,
            regions: vec!["us-central1".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
            demo_mode: true,
        };

        let (resources, findings) = scanner.run_scan(&config).await.unwrap();

        assert!(!resources.is_empty(), "Demo scan should return resources");
        assert!(!findings.is_empty(), "Demo scan should return findings");
    }
}
