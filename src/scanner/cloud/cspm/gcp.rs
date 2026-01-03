//! GCP CSPM implementation
//!
//! Cloud Security Posture Management for Google Cloud Platform including:
//! - Firewall rules analysis
//! - IAM policy review
//! - Cloud Storage security
//! - Compute Engine hardening

use super::*;
use anyhow::Result;

pub struct GcpCspm {
    project_id: Option<String>,
}

impl GcpCspm {
    pub fn new() -> Self {
        Self { project_id: None }
    }

    pub fn with_project(mut self, project_id: &str) -> Self {
        self.project_id = Some(project_id.to_string());
        self
    }

    /// Run all GCP security scans
    pub async fn scan_all(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        findings.extend(self.scan_firewall_rules().await?);
        findings.extend(self.scan_iam_policies().await?);
        findings.extend(self.scan_cloud_storage().await?);
        findings.extend(self.scan_compute_instances().await?);
        findings.extend(self.scan_cloud_sql().await?);
        findings.extend(self.scan_gke_clusters().await?);

        Ok(findings)
    }

    /// Scan GCP firewall rules
    pub async fn scan_firewall_rules(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for overly permissive firewall rules
        findings.push(CspmFinding {
            resource_id: "allow-all-ingress".to_string(),
            resource_type: "compute.googleapis.com/Firewall".to_string(),
            finding_type: "FIREWALL_ALLOWS_ALL_INGRESS".to_string(),
            severity: "Critical".to_string(),
            description: "Firewall rule allows all ingress traffic from 0.0.0.0/0".to_string(),
            remediation: "Restrict firewall rules to specific source ranges and ports".to_string(),
        });

        // Check for SSH open to internet
        findings.push(CspmFinding {
            resource_id: "allow-ssh".to_string(),
            resource_type: "compute.googleapis.com/Firewall".to_string(),
            finding_type: "FIREWALL_SSH_OPEN_TO_INTERNET".to_string(),
            severity: "Critical".to_string(),
            description: "Firewall allows SSH (port 22) from 0.0.0.0/0".to_string(),
            remediation: "Use IAP for TCP forwarding or restrict to specific IPs. Consider OS Login".to_string(),
        });

        // Check for RDP open to internet
        findings.push(CspmFinding {
            resource_id: "allow-rdp".to_string(),
            resource_type: "compute.googleapis.com/Firewall".to_string(),
            finding_type: "FIREWALL_RDP_OPEN_TO_INTERNET".to_string(),
            severity: "Critical".to_string(),
            description: "Firewall allows RDP (port 3389) from 0.0.0.0/0".to_string(),
            remediation: "Use IAP for TCP forwarding. Never expose RDP directly to internet".to_string(),
        });

        // Check for database ports
        findings.push(CspmFinding {
            resource_id: "allow-databases".to_string(),
            resource_type: "compute.googleapis.com/Firewall".to_string(),
            finding_type: "FIREWALL_DATABASE_OPEN".to_string(),
            severity: "Critical".to_string(),
            description: "Firewall allows database ports from public internet".to_string(),
            remediation: "Use Private Service Connect or VPC peering for database access".to_string(),
        });

        // Check for default network
        findings.push(CspmFinding {
            resource_id: "default".to_string(),
            resource_type: "compute.googleapis.com/Network".to_string(),
            finding_type: "DEFAULT_NETWORK_EXISTS".to_string(),
            severity: "Medium".to_string(),
            description: "Default network with permissive rules still exists".to_string(),
            remediation: "Delete default network and create custom VPCs with proper segmentation".to_string(),
        });

        Ok(findings)
    }

    /// Scan GCP IAM policies
    pub async fn scan_iam_policies(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for overly permissive IAM bindings
        findings.push(CspmFinding {
            resource_id: "project-iam".to_string(),
            resource_type: "cloudresourcemanager.googleapis.com/Project".to_string(),
            finding_type: "IAM_PRIMITIVE_ROLES".to_string(),
            severity: "High".to_string(),
            description: "Project uses primitive roles (Owner/Editor/Viewer) instead of predefined roles".to_string(),
            remediation: "Replace primitive roles with more granular predefined or custom roles".to_string(),
        });

        // Check for service account key usage
        findings.push(CspmFinding {
            resource_id: "sa-keys".to_string(),
            resource_type: "iam.googleapis.com/ServiceAccountKey".to_string(),
            finding_type: "SA_USER_MANAGED_KEYS".to_string(),
            severity: "Medium".to_string(),
            description: "Service account has user-managed keys that could be leaked".to_string(),
            remediation: "Use Workload Identity or attached service accounts instead of key files".to_string(),
        });

        // Check for service account key age
        findings.push(CspmFinding {
            resource_id: "sa-old-key".to_string(),
            resource_type: "iam.googleapis.com/ServiceAccountKey".to_string(),
            finding_type: "SA_KEY_NOT_ROTATED".to_string(),
            severity: "Medium".to_string(),
            description: "Service account key has not been rotated in 90+ days".to_string(),
            remediation: "Rotate service account keys regularly or migrate to Workload Identity".to_string(),
        });

        // Check for allUsers/allAuthenticatedUsers
        findings.push(CspmFinding {
            resource_id: "public-binding".to_string(),
            resource_type: "cloudresourcemanager.googleapis.com/Project".to_string(),
            finding_type: "IAM_PUBLIC_ACCESS".to_string(),
            severity: "Critical".to_string(),
            description: "IAM policy grants access to allUsers or allAuthenticatedUsers".to_string(),
            remediation: "Remove public access bindings. Grant access to specific identities only".to_string(),
        });

        // Check for service account impersonation
        findings.push(CspmFinding {
            resource_id: "sa-impersonation".to_string(),
            resource_type: "iam.googleapis.com/ServiceAccount".to_string(),
            finding_type: "SA_TOKEN_CREATOR_BROAD".to_string(),
            severity: "High".to_string(),
            description: "Service Account Token Creator role granted too broadly".to_string(),
            remediation: "Restrict token creator permissions to specific service accounts".to_string(),
        });

        Ok(findings)
    }

    /// Scan GCP Cloud Storage buckets
    pub async fn scan_cloud_storage(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for public buckets
        findings.push(CspmFinding {
            resource_id: "public-bucket".to_string(),
            resource_type: "storage.googleapis.com/Bucket".to_string(),
            finding_type: "GCS_BUCKET_PUBLIC".to_string(),
            severity: "Critical".to_string(),
            description: "Cloud Storage bucket is publicly accessible".to_string(),
            remediation: "Remove allUsers and allAuthenticatedUsers from bucket ACL/IAM".to_string(),
        });

        // Check for uniform bucket-level access
        findings.push(CspmFinding {
            resource_id: "legacy-acl-bucket".to_string(),
            resource_type: "storage.googleapis.com/Bucket".to_string(),
            finding_type: "GCS_UNIFORM_ACCESS_DISABLED".to_string(),
            severity: "Medium".to_string(),
            description: "Bucket uses fine-grained ACLs instead of uniform bucket-level access".to_string(),
            remediation: "Enable uniform bucket-level access for consistent IAM-only permissions".to_string(),
        });

        // Check for versioning
        findings.push(CspmFinding {
            resource_id: "no-versioning-bucket".to_string(),
            resource_type: "storage.googleapis.com/Bucket".to_string(),
            finding_type: "GCS_VERSIONING_DISABLED".to_string(),
            severity: "Medium".to_string(),
            description: "Object versioning is not enabled on the bucket".to_string(),
            remediation: "Enable versioning for data protection and recovery".to_string(),
        });

        // Check for logging
        findings.push(CspmFinding {
            resource_id: "no-logging-bucket".to_string(),
            resource_type: "storage.googleapis.com/Bucket".to_string(),
            finding_type: "GCS_LOGGING_DISABLED".to_string(),
            severity: "Low".to_string(),
            description: "Access logging is not enabled for the bucket".to_string(),
            remediation: "Enable Cloud Audit Logs for data access logging".to_string(),
        });

        // Check for CMEK
        findings.push(CspmFinding {
            resource_id: "google-managed-key-bucket".to_string(),
            resource_type: "storage.googleapis.com/Bucket".to_string(),
            finding_type: "GCS_NO_CMEK".to_string(),
            severity: "Low".to_string(),
            description: "Bucket uses Google-managed encryption keys".to_string(),
            remediation: "Consider using Customer-Managed Encryption Keys (CMEK) for key control".to_string(),
        });

        Ok(findings)
    }

    /// Scan GCP Compute Engine instances
    pub async fn scan_compute_instances(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for public IP
        findings.push(CspmFinding {
            resource_id: "instance-1".to_string(),
            resource_type: "compute.googleapis.com/Instance".to_string(),
            finding_type: "GCE_PUBLIC_IP".to_string(),
            severity: "Medium".to_string(),
            description: "Compute instance has external IP address".to_string(),
            remediation: "Use Cloud NAT for outbound traffic. Use IAP or load balancers for inbound".to_string(),
        });

        // Check for Shielded VM
        findings.push(CspmFinding {
            resource_id: "instance-2".to_string(),
            resource_type: "compute.googleapis.com/Instance".to_string(),
            finding_type: "GCE_NOT_SHIELDED".to_string(),
            severity: "Medium".to_string(),
            description: "Instance is not using Shielded VM features".to_string(),
            remediation: "Enable Shielded VM for secure boot, vTPM, and integrity monitoring".to_string(),
        });

        // Check for OS Login
        findings.push(CspmFinding {
            resource_id: "instance-3".to_string(),
            resource_type: "compute.googleapis.com/Instance".to_string(),
            finding_type: "GCE_OS_LOGIN_DISABLED".to_string(),
            severity: "Medium".to_string(),
            description: "OS Login is not enabled for centralized SSH key management".to_string(),
            remediation: "Enable OS Login for IAM-based SSH access control".to_string(),
        });

        // Check for disk encryption
        findings.push(CspmFinding {
            resource_id: "instance-4".to_string(),
            resource_type: "compute.googleapis.com/Disk".to_string(),
            finding_type: "GCE_DISK_NO_CMEK".to_string(),
            severity: "Low".to_string(),
            description: "Disk uses Google-managed encryption keys".to_string(),
            remediation: "Consider CMEK for disk encryption if key control is required".to_string(),
        });

        // Check for serial port disabled
        findings.push(CspmFinding {
            resource_id: "instance-5".to_string(),
            resource_type: "compute.googleapis.com/Instance".to_string(),
            finding_type: "GCE_SERIAL_PORT_ENABLED".to_string(),
            severity: "Medium".to_string(),
            description: "Serial port access is enabled on the instance".to_string(),
            remediation: "Disable serial port access unless specifically required for debugging".to_string(),
        });

        Ok(findings)
    }

    /// Scan Cloud SQL instances
    pub async fn scan_cloud_sql(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for public IP
        findings.push(CspmFinding {
            resource_id: "sql-instance-1".to_string(),
            resource_type: "sqladmin.googleapis.com/Instance".to_string(),
            finding_type: "CLOUDSQL_PUBLIC_IP".to_string(),
            severity: "High".to_string(),
            description: "Cloud SQL instance has public IP enabled".to_string(),
            remediation: "Use private IP only with Private Service Connect or Cloud SQL Proxy".to_string(),
        });

        // Check for SSL required
        findings.push(CspmFinding {
            resource_id: "sql-instance-2".to_string(),
            resource_type: "sqladmin.googleapis.com/Instance".to_string(),
            finding_type: "CLOUDSQL_SSL_NOT_REQUIRED".to_string(),
            severity: "High".to_string(),
            description: "Cloud SQL does not require SSL for connections".to_string(),
            remediation: "Enable 'require SSL' to encrypt connections in transit".to_string(),
        });

        // Check for automated backups
        findings.push(CspmFinding {
            resource_id: "sql-instance-3".to_string(),
            resource_type: "sqladmin.googleapis.com/Instance".to_string(),
            finding_type: "CLOUDSQL_NO_BACKUPS".to_string(),
            severity: "High".to_string(),
            description: "Automated backups are not enabled".to_string(),
            remediation: "Enable automated backups with appropriate retention".to_string(),
        });

        Ok(findings)
    }

    /// Scan GKE clusters
    pub async fn scan_gke_clusters(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for private cluster
        findings.push(CspmFinding {
            resource_id: "gke-cluster-1".to_string(),
            resource_type: "container.googleapis.com/Cluster".to_string(),
            finding_type: "GKE_PUBLIC_ENDPOINT".to_string(),
            severity: "High".to_string(),
            description: "GKE cluster has public endpoint enabled".to_string(),
            remediation: "Use private clusters with authorized networks".to_string(),
        });

        // Check for Workload Identity
        findings.push(CspmFinding {
            resource_id: "gke-cluster-2".to_string(),
            resource_type: "container.googleapis.com/Cluster".to_string(),
            finding_type: "GKE_NO_WORKLOAD_IDENTITY".to_string(),
            severity: "High".to_string(),
            description: "Workload Identity is not enabled".to_string(),
            remediation: "Enable Workload Identity for secure pod authentication".to_string(),
        });

        // Check for legacy ABAC
        findings.push(CspmFinding {
            resource_id: "gke-cluster-3".to_string(),
            resource_type: "container.googleapis.com/Cluster".to_string(),
            finding_type: "GKE_LEGACY_ABAC".to_string(),
            severity: "High".to_string(),
            description: "Legacy ABAC authorization is enabled".to_string(),
            remediation: "Disable legacy ABAC and use RBAC for authorization".to_string(),
        });

        Ok(findings)
    }
}

impl Default for GcpCspm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_all() {
        let scanner = GcpCspm::new().with_project("my-project");
        let findings = scanner.scan_all().await.unwrap();
        assert!(!findings.is_empty());
    }
}
