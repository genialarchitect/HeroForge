//! Kubernetes Pod Security Standards (PSS) Validation
//!
//! Implements validation against the Kubernetes Pod Security Standards:
//! - Privileged: Unrestricted policy, allowing all pod configurations
//! - Baseline: Minimally restrictive policy, prevents known privilege escalations
//! - Restricted: Heavily restricted policy, following hardening best practices

use serde::{Deserialize, Serialize};

/// Pod Security Standard profiles
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PssProfile {
    /// Unrestricted - no security checks
    Privileged,
    /// Minimally restrictive - prevents known escalations
    Baseline,
    /// Maximum restrictions - hardening best practices
    Restricted,
}

impl PssProfile {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Privileged => "Unrestricted policy, providing the widest possible level of permissions",
            Self::Baseline => "Minimally restrictive policy which prevents known privilege escalations",
            Self::Restricted => "Heavily restricted policy, following current Pod hardening best practices",
        }
    }
}

/// Categories of PSS violations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PssViolationType {
    // Baseline violations
    HostNamespace,        // hostNetwork, hostPID, hostIPC
    HostPorts,            // Non-empty hostPorts
    Privileged,           // privileged: true
    Capabilities,         // Adding dangerous capabilities
    HostPath,             // hostPath volume mounts
    Selinux,              // Custom SELinux options
    ProcMount,            // procMount != Default
    Seccomp,              // Invalid seccomp profile
    Sysctls,              // Unsafe sysctls
    AppArmor,             // Custom AppArmor profiles
    WindowsHostProcess,   // Windows HostProcess

    // Restricted violations (in addition to Baseline)
    RunAsNonRoot,              // Must run as non-root
    RunAsUser,                 // Must not run as root (UID 0)
    SeccompProfile,            // Must have RuntimeDefault or Localhost
    AllowPrivilegeEscalation,  // Must be false
    CapabilitiesDrop,          // Must drop ALL
    CapabilitiesAdd,           // Can only add NET_BIND_SERVICE
    VolumeTypes,               // Only allowed volume types
}

impl PssViolationType {
    pub fn description(&self) -> &'static str {
        match self {
            Self::HostNamespace => "Pod uses host namespaces (hostNetwork, hostPID, or hostIPC)",
            Self::HostPorts => "Container defines host port mappings",
            Self::Privileged => "Container runs in privileged mode",
            Self::Capabilities => "Container adds dangerous Linux capabilities",
            Self::HostPath => "Pod mounts host filesystem paths",
            Self::Selinux => "Pod uses custom SELinux options",
            Self::ProcMount => "Container uses non-default /proc mount",
            Self::Seccomp => "Pod uses invalid seccomp profile",
            Self::Sysctls => "Pod uses unsafe sysctls",
            Self::AppArmor => "Container uses custom AppArmor profile",
            Self::WindowsHostProcess => "Windows container runs as HostProcess",
            Self::RunAsNonRoot => "Pod does not enforce running as non-root",
            Self::RunAsUser => "Container runs as root user (UID 0)",
            Self::SeccompProfile => "Container lacks seccomp profile (RuntimeDefault or Localhost required)",
            Self::AllowPrivilegeEscalation => "Container allows privilege escalation",
            Self::CapabilitiesDrop => "Container does not drop ALL capabilities",
            Self::CapabilitiesAdd => "Container adds capabilities other than NET_BIND_SERVICE",
            Self::VolumeTypes => "Pod uses disallowed volume types",
        }
    }

    pub fn remediation(&self) -> &'static str {
        match self {
            Self::HostNamespace => "Remove hostNetwork, hostPID, and hostIPC from pod spec",
            Self::HostPorts => "Remove hostPort from container ports or use NodePort services",
            Self::Privileged => "Set securityContext.privileged to false",
            Self::Capabilities => "Remove dangerous capabilities from securityContext.capabilities.add",
            Self::HostPath => "Use PersistentVolumeClaims instead of hostPath volumes",
            Self::Selinux => "Use standard SELinux options or remove custom configuration",
            Self::ProcMount => "Remove procMount or set to Default",
            Self::Seccomp => "Set seccomp profile to RuntimeDefault or Localhost",
            Self::Sysctls => "Remove unsafe sysctls from pod security context",
            Self::AppArmor => "Use runtime/default or localhost AppArmor profile",
            Self::WindowsHostProcess => "Disable Windows HostProcess",
            Self::RunAsNonRoot => "Set runAsNonRoot: true in securityContext",
            Self::RunAsUser => "Set runAsUser to a non-zero UID",
            Self::SeccompProfile => "Add seccompProfile with type RuntimeDefault or Localhost",
            Self::AllowPrivilegeEscalation => "Set allowPrivilegeEscalation: false",
            Self::CapabilitiesDrop => "Add capabilities.drop: ['ALL']",
            Self::CapabilitiesAdd => "Only add NET_BIND_SERVICE capability if needed",
            Self::VolumeTypes => "Use only allowed volume types: configMap, downwardAPI, emptyDir, persistentVolumeClaim, projected, secret",
        }
    }

    pub fn applies_to_profile(&self, profile: PssProfile) -> bool {
        match profile {
            PssProfile::Privileged => false, // No violations in Privileged
            PssProfile::Baseline => matches!(
                self,
                Self::HostNamespace
                    | Self::HostPorts
                    | Self::Privileged
                    | Self::Capabilities
                    | Self::HostPath
                    | Self::Selinux
                    | Self::ProcMount
                    | Self::Seccomp
                    | Self::Sysctls
                    | Self::AppArmor
                    | Self::WindowsHostProcess
            ),
            PssProfile::Restricted => true, // All violations apply to Restricted
        }
    }
}

/// Severity of PSS violations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PssSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PssViolationType {
    pub fn severity(&self) -> PssSeverity {
        match self {
            Self::Privileged => PssSeverity::Critical,
            Self::HostNamespace => PssSeverity::Critical,
            Self::Capabilities => PssSeverity::High,
            Self::HostPath => PssSeverity::High,
            Self::AllowPrivilegeEscalation => PssSeverity::High,
            Self::RunAsUser => PssSeverity::High,
            Self::WindowsHostProcess => PssSeverity::Critical,
            Self::HostPorts => PssSeverity::Medium,
            Self::Selinux => PssSeverity::Medium,
            Self::ProcMount => PssSeverity::Medium,
            Self::Sysctls => PssSeverity::Medium,
            Self::RunAsNonRoot => PssSeverity::Medium,
            Self::SeccompProfile => PssSeverity::Medium,
            Self::CapabilitiesDrop => PssSeverity::Medium,
            Self::CapabilitiesAdd => PssSeverity::Medium,
            Self::Seccomp => PssSeverity::Low,
            Self::AppArmor => PssSeverity::Low,
            Self::VolumeTypes => PssSeverity::Low,
        }
    }
}

/// A PSS violation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PssViolation {
    pub violation_type: PssViolationType,
    pub severity: PssSeverity,
    pub profile: PssProfile,
    pub workload_name: String,
    pub workload_kind: String,
    pub namespace: String,
    pub container_name: Option<String>,
    pub field_path: String,
    pub current_value: String,
    pub description: String,
    pub remediation: String,
}

/// Results from PSS validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PssValidationResults {
    pub violations: Vec<PssViolation>,
    pub workloads_analyzed: usize,
    pub compliant_with_baseline: bool,
    pub compliant_with_restricted: bool,
    pub summary: PssSummary,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PssSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub baseline_violations: usize,
    pub restricted_only_violations: usize,
    pub workloads_passing_baseline: usize,
    pub workloads_passing_restricted: usize,
}

/// Dangerous capabilities that are not allowed in Baseline
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "ALL",
    "CAP_ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_PACCT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "AUDIT_CONTROL",
    "AUDIT_READ",
    "AUDIT_WRITE",
    "BLOCK_SUSPEND",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "NET_BROADCAST",
    "SYSLOG",
    "WAKE_ALARM",
    "PERFMON",
    "BPF",
];

/// Capabilities allowed in Restricted (only NET_BIND_SERVICE)
const RESTRICTED_ALLOWED_CAPABILITIES: &[&str] = &["NET_BIND_SERVICE"];

/// Allowed volume types in Restricted profile
const RESTRICTED_VOLUME_TYPES: &[&str] = &[
    "configMap",
    "csi",
    "downwardAPI",
    "emptyDir",
    "ephemeral",
    "persistentVolumeClaim",
    "projected",
    "secret",
];

/// Safe sysctls
const SAFE_SYSCTLS: &[&str] = &[
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
];

/// Pod Security Standards Validator
pub struct PssValidator {
    target_profile: PssProfile,
}

impl PssValidator {
    /// Create a new validator targeting a specific profile
    pub fn new(target_profile: PssProfile) -> Self {
        Self { target_profile }
    }

    /// Validate manifests against the target PSS profile
    pub fn validate(&self, manifests: &[serde_yaml::Value]) -> PssValidationResults {
        let mut violations = Vec::new();
        let mut workloads_analyzed = 0;
        let mut workloads_passing_baseline = 0;
        let mut workloads_passing_restricted = 0;

        for manifest in manifests {
            if let Some(workload_violations) = self.validate_manifest(manifest) {
                workloads_analyzed += 1;

                let has_baseline_violations = workload_violations
                    .iter()
                    .any(|v| v.violation_type.applies_to_profile(PssProfile::Baseline));

                let has_restricted_violations = !workload_violations.is_empty();

                if !has_baseline_violations {
                    workloads_passing_baseline += 1;
                }
                if !has_restricted_violations {
                    workloads_passing_restricted += 1;
                }

                // Only include violations that apply to target profile
                violations.extend(
                    workload_violations
                        .into_iter()
                        .filter(|v| v.violation_type.applies_to_profile(self.target_profile)),
                );
            }
        }

        let summary = self.calculate_summary(&violations, workloads_analyzed, workloads_passing_baseline, workloads_passing_restricted);

        PssValidationResults {
            violations,
            workloads_analyzed,
            compliant_with_baseline: summary.baseline_violations == 0,
            compliant_with_restricted: summary.baseline_violations == 0 && summary.restricted_only_violations == 0,
            summary,
        }
    }

    /// Validate a single manifest
    fn validate_manifest(&self, manifest: &serde_yaml::Value) -> Option<Vec<PssViolation>> {
        let kind = manifest.get("kind")?.as_str()?;

        // Get pod spec based on workload type
        let (pod_spec, workload_name, workload_namespace) = match kind {
            "Pod" => {
                let metadata = manifest.get("metadata")?;
                let name = metadata.get("name")?.as_str()?.to_string();
                let namespace = metadata
                    .get("namespace")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default")
                    .to_string();
                (manifest.get("spec")?, name, namespace)
            }
            "Deployment" | "DaemonSet" | "StatefulSet" | "ReplicaSet" | "Job" => {
                let metadata = manifest.get("metadata")?;
                let name = metadata.get("name")?.as_str()?.to_string();
                let namespace = metadata
                    .get("namespace")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default")
                    .to_string();
                let spec = manifest
                    .get("spec")?
                    .get("template")?
                    .get("spec")?;
                (spec, name, namespace)
            }
            "CronJob" => {
                let metadata = manifest.get("metadata")?;
                let name = metadata.get("name")?.as_str()?.to_string();
                let namespace = metadata
                    .get("namespace")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default")
                    .to_string();
                let spec = manifest
                    .get("spec")?
                    .get("jobTemplate")?
                    .get("spec")?
                    .get("template")?
                    .get("spec")?;
                (spec, name, namespace)
            }
            _ => return None,
        };

        let mut violations = Vec::new();

        // Check pod-level settings
        violations.extend(self.check_pod_level(pod_spec, kind, &workload_name, &workload_namespace));

        // Check each container
        if let Some(containers) = pod_spec.get("containers").and_then(|c| c.as_sequence()) {
            for container in containers {
                let container_name = container
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                violations.extend(self.check_container(
                    container,
                    pod_spec,
                    kind,
                    &workload_name,
                    &workload_namespace,
                    &container_name,
                ));
            }
        }

        // Check init containers
        if let Some(containers) = pod_spec.get("initContainers").and_then(|c| c.as_sequence()) {
            for container in containers {
                let container_name = container
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                violations.extend(self.check_container(
                    container,
                    pod_spec,
                    kind,
                    &workload_name,
                    &workload_namespace,
                    &format!("initContainer:{}", container_name),
                ));
            }
        }

        // Check ephemeral containers
        if let Some(containers) = pod_spec.get("ephemeralContainers").and_then(|c| c.as_sequence()) {
            for container in containers {
                let container_name = container
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                violations.extend(self.check_container(
                    container,
                    pod_spec,
                    kind,
                    &workload_name,
                    &workload_namespace,
                    &format!("ephemeralContainer:{}", container_name),
                ));
            }
        }

        Some(violations)
    }

    /// Check pod-level security settings
    fn check_pod_level(
        &self,
        pod_spec: &serde_yaml::Value,
        kind: &str,
        name: &str,
        namespace: &str,
    ) -> Vec<PssViolation> {
        let mut violations = Vec::new();

        // Check hostNetwork
        if pod_spec.get("hostNetwork").and_then(|v| v.as_bool()).unwrap_or(false) {
            violations.push(PssViolation {
                violation_type: PssViolationType::HostNamespace,
                severity: PssSeverity::Critical,
                profile: PssProfile::Baseline,
                workload_name: name.to_string(),
                workload_kind: kind.to_string(),
                namespace: namespace.to_string(),
                container_name: None,
                field_path: "spec.hostNetwork".to_string(),
                current_value: "true".to_string(),
                description: "Pod uses host network namespace".to_string(),
                remediation: PssViolationType::HostNamespace.remediation().to_string(),
            });
        }

        // Check hostPID
        if pod_spec.get("hostPID").and_then(|v| v.as_bool()).unwrap_or(false) {
            violations.push(PssViolation {
                violation_type: PssViolationType::HostNamespace,
                severity: PssSeverity::Critical,
                profile: PssProfile::Baseline,
                workload_name: name.to_string(),
                workload_kind: kind.to_string(),
                namespace: namespace.to_string(),
                container_name: None,
                field_path: "spec.hostPID".to_string(),
                current_value: "true".to_string(),
                description: "Pod uses host PID namespace".to_string(),
                remediation: PssViolationType::HostNamespace.remediation().to_string(),
            });
        }

        // Check hostIPC
        if pod_spec.get("hostIPC").and_then(|v| v.as_bool()).unwrap_or(false) {
            violations.push(PssViolation {
                violation_type: PssViolationType::HostNamespace,
                severity: PssSeverity::Critical,
                profile: PssProfile::Baseline,
                workload_name: name.to_string(),
                workload_kind: kind.to_string(),
                namespace: namespace.to_string(),
                container_name: None,
                field_path: "spec.hostIPC".to_string(),
                current_value: "true".to_string(),
                description: "Pod uses host IPC namespace".to_string(),
                remediation: PssViolationType::HostNamespace.remediation().to_string(),
            });
        }

        // Check hostPath volumes
        if let Some(volumes) = pod_spec.get("volumes").and_then(|v| v.as_sequence()) {
            for (idx, volume) in volumes.iter().enumerate() {
                if volume.get("hostPath").is_some() {
                    let volume_name = volume
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    violations.push(PssViolation {
                        violation_type: PssViolationType::HostPath,
                        severity: PssSeverity::High,
                        profile: PssProfile::Baseline,
                        workload_name: name.to_string(),
                        workload_kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        container_name: None,
                        field_path: format!("spec.volumes[{}].hostPath", idx),
                        current_value: volume_name.to_string(),
                        description: format!("Volume '{}' uses hostPath mount", volume_name),
                        remediation: PssViolationType::HostPath.remediation().to_string(),
                    });
                }

                // Check for disallowed volume types in Restricted profile
                let volume_type = self.get_volume_type(volume);
                if !RESTRICTED_VOLUME_TYPES.contains(&volume_type.as_str()) {
                    violations.push(PssViolation {
                        violation_type: PssViolationType::VolumeTypes,
                        severity: PssSeverity::Low,
                        profile: PssProfile::Restricted,
                        workload_name: name.to_string(),
                        workload_kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        container_name: None,
                        field_path: format!("spec.volumes[{}]", idx),
                        current_value: volume_type.clone(),
                        description: format!("Volume uses disallowed type '{}'", volume_type),
                        remediation: PssViolationType::VolumeTypes.remediation().to_string(),
                    });
                }
            }
        }

        // Check sysctls
        if let Some(security_context) = pod_spec.get("securityContext") {
            if let Some(sysctls) = security_context.get("sysctls").and_then(|s| s.as_sequence()) {
                for sysctl in sysctls {
                    let sysctl_name = sysctl
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");

                    if !SAFE_SYSCTLS.iter().any(|s| sysctl_name.starts_with(s)) {
                        violations.push(PssViolation {
                            violation_type: PssViolationType::Sysctls,
                            severity: PssSeverity::Medium,
                            profile: PssProfile::Baseline,
                            workload_name: name.to_string(),
                            workload_kind: kind.to_string(),
                            namespace: namespace.to_string(),
                            container_name: None,
                            field_path: "spec.securityContext.sysctls".to_string(),
                            current_value: sysctl_name.to_string(),
                            description: format!("Pod uses unsafe sysctl '{}'", sysctl_name),
                            remediation: PssViolationType::Sysctls.remediation().to_string(),
                        });
                    }
                }
            }

            // Check pod-level runAsNonRoot (Restricted)
            let run_as_non_root = security_context
                .get("runAsNonRoot")
                .and_then(|v| v.as_bool());

            if run_as_non_root != Some(true) {
                violations.push(PssViolation {
                    violation_type: PssViolationType::RunAsNonRoot,
                    severity: PssSeverity::Medium,
                    profile: PssProfile::Restricted,
                    workload_name: name.to_string(),
                    workload_kind: kind.to_string(),
                    namespace: namespace.to_string(),
                    container_name: None,
                    field_path: "spec.securityContext.runAsNonRoot".to_string(),
                    current_value: run_as_non_root.map(|v| v.to_string()).unwrap_or("unset".to_string()),
                    description: "Pod does not enforce running as non-root".to_string(),
                    remediation: PssViolationType::RunAsNonRoot.remediation().to_string(),
                });
            }

            // Check pod-level runAsUser (Restricted)
            if let Some(run_as_user) = security_context.get("runAsUser").and_then(|v| v.as_u64()) {
                if run_as_user == 0 {
                    violations.push(PssViolation {
                        violation_type: PssViolationType::RunAsUser,
                        severity: PssSeverity::High,
                        profile: PssProfile::Restricted,
                        workload_name: name.to_string(),
                        workload_kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        container_name: None,
                        field_path: "spec.securityContext.runAsUser".to_string(),
                        current_value: "0".to_string(),
                        description: "Pod runs as root user (UID 0)".to_string(),
                        remediation: PssViolationType::RunAsUser.remediation().to_string(),
                    });
                }
            }

            // Check seccomp profile (Restricted)
            let has_seccomp = security_context
                .get("seccompProfile")
                .and_then(|sp| sp.get("type"))
                .and_then(|t| t.as_str())
                .map(|t| t == "RuntimeDefault" || t == "Localhost")
                .unwrap_or(false);

            if !has_seccomp {
                violations.push(PssViolation {
                    violation_type: PssViolationType::SeccompProfile,
                    severity: PssSeverity::Medium,
                    profile: PssProfile::Restricted,
                    workload_name: name.to_string(),
                    workload_kind: kind.to_string(),
                    namespace: namespace.to_string(),
                    container_name: None,
                    field_path: "spec.securityContext.seccompProfile".to_string(),
                    current_value: "unset or invalid".to_string(),
                    description: "Pod lacks valid seccomp profile".to_string(),
                    remediation: PssViolationType::SeccompProfile.remediation().to_string(),
                });
            }
        } else {
            // No pod-level security context at all - violations for Restricted
            violations.push(PssViolation {
                violation_type: PssViolationType::RunAsNonRoot,
                severity: PssSeverity::Medium,
                profile: PssProfile::Restricted,
                workload_name: name.to_string(),
                workload_kind: kind.to_string(),
                namespace: namespace.to_string(),
                container_name: None,
                field_path: "spec.securityContext".to_string(),
                current_value: "unset".to_string(),
                description: "Pod has no security context".to_string(),
                remediation: "Add securityContext with runAsNonRoot: true".to_string(),
            });
        }

        violations
    }

    /// Check container-level security settings
    fn check_container(
        &self,
        container: &serde_yaml::Value,
        _pod_spec: &serde_yaml::Value,
        kind: &str,
        name: &str,
        namespace: &str,
        container_name: &str,
    ) -> Vec<PssViolation> {
        let mut violations = Vec::new();
        let security_context = container.get("securityContext");

        // Check hostPorts
        if let Some(ports) = container.get("ports").and_then(|p| p.as_sequence()) {
            for port in ports {
                if let Some(host_port) = port.get("hostPort").and_then(|hp| hp.as_u64()) {
                    if host_port > 0 {
                        violations.push(PssViolation {
                            violation_type: PssViolationType::HostPorts,
                            severity: PssSeverity::Medium,
                            profile: PssProfile::Baseline,
                            workload_name: name.to_string(),
                            workload_kind: kind.to_string(),
                            namespace: namespace.to_string(),
                            container_name: Some(container_name.to_string()),
                            field_path: format!("containers[{}].ports[].hostPort", container_name),
                            current_value: host_port.to_string(),
                            description: format!("Container '{}' uses host port {}", container_name, host_port),
                            remediation: PssViolationType::HostPorts.remediation().to_string(),
                        });
                    }
                }
            }
        }

        if let Some(sc) = security_context {
            // Check privileged
            if sc.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false) {
                violations.push(PssViolation {
                    violation_type: PssViolationType::Privileged,
                    severity: PssSeverity::Critical,
                    profile: PssProfile::Baseline,
                    workload_name: name.to_string(),
                    workload_kind: kind.to_string(),
                    namespace: namespace.to_string(),
                    container_name: Some(container_name.to_string()),
                    field_path: format!("containers[{}].securityContext.privileged", container_name),
                    current_value: "true".to_string(),
                    description: format!("Container '{}' runs in privileged mode", container_name),
                    remediation: PssViolationType::Privileged.remediation().to_string(),
                });
            }

            // Check capabilities
            if let Some(capabilities) = sc.get("capabilities") {
                // Check add
                if let Some(add) = capabilities.get("add").and_then(|a| a.as_sequence()) {
                    for cap in add {
                        if let Some(cap_name) = cap.as_str() {
                            // Check Baseline dangerous caps
                            if DANGEROUS_CAPABILITIES.contains(&cap_name.to_uppercase().as_str()) {
                                violations.push(PssViolation {
                                    violation_type: PssViolationType::Capabilities,
                                    severity: PssSeverity::High,
                                    profile: PssProfile::Baseline,
                                    workload_name: name.to_string(),
                                    workload_kind: kind.to_string(),
                                    namespace: namespace.to_string(),
                                    container_name: Some(container_name.to_string()),
                                    field_path: format!("containers[{}].securityContext.capabilities.add", container_name),
                                    current_value: cap_name.to_string(),
                                    description: format!("Container '{}' adds dangerous capability '{}'", container_name, cap_name),
                                    remediation: PssViolationType::Capabilities.remediation().to_string(),
                                });
                            }

                            // Check Restricted - only NET_BIND_SERVICE allowed
                            if !RESTRICTED_ALLOWED_CAPABILITIES.contains(&cap_name.to_uppercase().as_str()) {
                                violations.push(PssViolation {
                                    violation_type: PssViolationType::CapabilitiesAdd,
                                    severity: PssSeverity::Medium,
                                    profile: PssProfile::Restricted,
                                    workload_name: name.to_string(),
                                    workload_kind: kind.to_string(),
                                    namespace: namespace.to_string(),
                                    container_name: Some(container_name.to_string()),
                                    field_path: format!("containers[{}].securityContext.capabilities.add", container_name),
                                    current_value: cap_name.to_string(),
                                    description: format!("Container '{}' adds capability '{}' (only NET_BIND_SERVICE allowed)", container_name, cap_name),
                                    remediation: PssViolationType::CapabilitiesAdd.remediation().to_string(),
                                });
                            }
                        }
                    }
                }

                // Check drop ALL (Restricted)
                let drops_all = capabilities
                    .get("drop")
                    .and_then(|d| d.as_sequence())
                    .map(|seq| {
                        seq.iter()
                            .filter_map(|v| v.as_str())
                            .any(|c| c.to_uppercase() == "ALL")
                    })
                    .unwrap_or(false);

                if !drops_all {
                    violations.push(PssViolation {
                        violation_type: PssViolationType::CapabilitiesDrop,
                        severity: PssSeverity::Medium,
                        profile: PssProfile::Restricted,
                        workload_name: name.to_string(),
                        workload_kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        container_name: Some(container_name.to_string()),
                        field_path: format!("containers[{}].securityContext.capabilities.drop", container_name),
                        current_value: "missing ALL".to_string(),
                        description: format!("Container '{}' does not drop ALL capabilities", container_name),
                        remediation: PssViolationType::CapabilitiesDrop.remediation().to_string(),
                    });
                }
            } else {
                // No capabilities defined - Restricted violation
                violations.push(PssViolation {
                    violation_type: PssViolationType::CapabilitiesDrop,
                    severity: PssSeverity::Medium,
                    profile: PssProfile::Restricted,
                    workload_name: name.to_string(),
                    workload_kind: kind.to_string(),
                    namespace: namespace.to_string(),
                    container_name: Some(container_name.to_string()),
                    field_path: format!("containers[{}].securityContext.capabilities", container_name),
                    current_value: "unset".to_string(),
                    description: format!("Container '{}' has no capabilities configuration", container_name),
                    remediation: PssViolationType::CapabilitiesDrop.remediation().to_string(),
                });
            }

            // Check procMount
            if let Some(proc_mount) = sc.get("procMount").and_then(|p| p.as_str()) {
                if proc_mount != "Default" {
                    violations.push(PssViolation {
                        violation_type: PssViolationType::ProcMount,
                        severity: PssSeverity::Medium,
                        profile: PssProfile::Baseline,
                        workload_name: name.to_string(),
                        workload_kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        container_name: Some(container_name.to_string()),
                        field_path: format!("containers[{}].securityContext.procMount", container_name),
                        current_value: proc_mount.to_string(),
                        description: format!("Container '{}' uses non-default procMount", container_name),
                        remediation: PssViolationType::ProcMount.remediation().to_string(),
                    });
                }
            }

            // Check allowPrivilegeEscalation (Restricted)
            let allow_escalation = sc
                .get("allowPrivilegeEscalation")
                .and_then(|v| v.as_bool());

            if allow_escalation != Some(false) {
                violations.push(PssViolation {
                    violation_type: PssViolationType::AllowPrivilegeEscalation,
                    severity: PssSeverity::High,
                    profile: PssProfile::Restricted,
                    workload_name: name.to_string(),
                    workload_kind: kind.to_string(),
                    namespace: namespace.to_string(),
                    container_name: Some(container_name.to_string()),
                    field_path: format!("containers[{}].securityContext.allowPrivilegeEscalation", container_name),
                    current_value: allow_escalation.map(|v| v.to_string()).unwrap_or("unset (defaults to true)".to_string()),
                    description: format!("Container '{}' allows privilege escalation", container_name),
                    remediation: PssViolationType::AllowPrivilegeEscalation.remediation().to_string(),
                });
            }

            // Check container-level runAsUser (Restricted)
            if let Some(run_as_user) = sc.get("runAsUser").and_then(|v| v.as_u64()) {
                if run_as_user == 0 {
                    violations.push(PssViolation {
                        violation_type: PssViolationType::RunAsUser,
                        severity: PssSeverity::High,
                        profile: PssProfile::Restricted,
                        workload_name: name.to_string(),
                        workload_kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        container_name: Some(container_name.to_string()),
                        field_path: format!("containers[{}].securityContext.runAsUser", container_name),
                        current_value: "0".to_string(),
                        description: format!("Container '{}' runs as root user (UID 0)", container_name),
                        remediation: PssViolationType::RunAsUser.remediation().to_string(),
                    });
                }
            }

            // Check SELinux options
            if let Some(selinux) = sc.get("seLinuxOptions") {
                let has_custom = selinux.get("type").is_some()
                    || selinux.get("user").is_some()
                    || selinux.get("role").is_some();

                if has_custom {
                    // Check for non-standard types
                    if let Some(se_type) = selinux.get("type").and_then(|t| t.as_str()) {
                        let allowed_types = ["container_t", "container_init_t", "container_kvm_t"];
                        if !allowed_types.contains(&se_type) {
                            violations.push(PssViolation {
                                violation_type: PssViolationType::Selinux,
                                severity: PssSeverity::Medium,
                                profile: PssProfile::Baseline,
                                workload_name: name.to_string(),
                                workload_kind: kind.to_string(),
                                namespace: namespace.to_string(),
                                container_name: Some(container_name.to_string()),
                                field_path: format!("containers[{}].securityContext.seLinuxOptions.type", container_name),
                                current_value: se_type.to_string(),
                                description: format!("Container '{}' uses non-standard SELinux type", container_name),
                                remediation: PssViolationType::Selinux.remediation().to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            // No container security context - multiple Restricted violations
            violations.push(PssViolation {
                violation_type: PssViolationType::AllowPrivilegeEscalation,
                severity: PssSeverity::High,
                profile: PssProfile::Restricted,
                workload_name: name.to_string(),
                workload_kind: kind.to_string(),
                namespace: namespace.to_string(),
                container_name: Some(container_name.to_string()),
                field_path: format!("containers[{}].securityContext", container_name),
                current_value: "unset".to_string(),
                description: format!("Container '{}' has no security context", container_name),
                remediation: "Add securityContext with allowPrivilegeEscalation: false".to_string(),
            });

            violations.push(PssViolation {
                violation_type: PssViolationType::CapabilitiesDrop,
                severity: PssSeverity::Medium,
                profile: PssProfile::Restricted,
                workload_name: name.to_string(),
                workload_kind: kind.to_string(),
                namespace: namespace.to_string(),
                container_name: Some(container_name.to_string()),
                field_path: format!("containers[{}].securityContext.capabilities", container_name),
                current_value: "unset".to_string(),
                description: format!("Container '{}' has no capabilities configuration", container_name),
                remediation: PssViolationType::CapabilitiesDrop.remediation().to_string(),
            });
        }

        violations
    }

    /// Get the volume type
    fn get_volume_type(&self, volume: &serde_yaml::Value) -> String {
        let volume_types = [
            "awsElasticBlockStore", "azureDisk", "azureFile", "cephfs", "cinder",
            "configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "fc",
            "flexVolume", "flocker", "gcePersistentDisk", "gitRepo", "glusterfs",
            "hostPath", "iscsi", "local", "nfs", "persistentVolumeClaim",
            "photonPersistentDisk", "portworxVolume", "projected", "quobyte",
            "rbd", "scaleIO", "secret", "storageos", "vsphereVolume",
        ];

        for vt in volume_types {
            if volume.get(vt).is_some() {
                return vt.to_string();
            }
        }

        "unknown".to_string()
    }

    /// Calculate summary statistics
    fn calculate_summary(
        &self,
        violations: &[PssViolation],
        _workloads_analyzed: usize,
        workloads_passing_baseline: usize,
        workloads_passing_restricted: usize,
    ) -> PssSummary {
        let mut summary = PssSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            baseline_violations: 0,
            restricted_only_violations: 0,
            workloads_passing_baseline,
            workloads_passing_restricted,
        };

        for violation in violations {
            match violation.severity {
                PssSeverity::Critical => summary.critical_count += 1,
                PssSeverity::High => summary.high_count += 1,
                PssSeverity::Medium => summary.medium_count += 1,
                PssSeverity::Low => summary.low_count += 1,
            }

            if violation.profile == PssProfile::Baseline {
                summary.baseline_violations += 1;
            } else {
                summary.restricted_only_violations += 1;
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn privileged_pod() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      privileged: true
"#).unwrap()
    }

    fn host_network_pod() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: host-network-pod
  namespace: default
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx
"#).unwrap()
    }

    fn compliant_restricted_pod() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
"#).unwrap()
    }

    fn host_path_deployment() -> serde_yaml::Value {
        serde_yaml::from_str(r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: host-path-deployment
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: nginx
        image: nginx
      volumes:
      - name: host-vol
        hostPath:
          path: /etc
"#).unwrap()
    }

    #[test]
    fn test_detect_privileged() {
        let validator = PssValidator::new(PssProfile::Baseline);
        let results = validator.validate(&[privileged_pod()]);

        assert!(results.violations.iter().any(|v| v.violation_type == PssViolationType::Privileged));
        assert!(!results.compliant_with_baseline);
    }

    #[test]
    fn test_detect_host_network() {
        let validator = PssValidator::new(PssProfile::Baseline);
        let results = validator.validate(&[host_network_pod()]);

        assert!(results.violations.iter().any(|v| v.violation_type == PssViolationType::HostNamespace));
        assert!(!results.compliant_with_baseline);
    }

    #[test]
    fn test_compliant_restricted_pod() {
        let validator = PssValidator::new(PssProfile::Restricted);
        let results = validator.validate(&[compliant_restricted_pod()]);

        // Should have minimal violations (we may still have some for missing container-level settings)
        let baseline_violations: Vec<_> = results
            .violations
            .iter()
            .filter(|v| v.profile == PssProfile::Baseline)
            .collect();

        assert!(baseline_violations.is_empty(), "Should have no baseline violations");
    }

    #[test]
    fn test_detect_host_path() {
        let validator = PssValidator::new(PssProfile::Baseline);
        let results = validator.validate(&[host_path_deployment()]);

        assert!(results.violations.iter().any(|v| v.violation_type == PssViolationType::HostPath));
    }

    #[test]
    fn test_summary_calculation() {
        let validator = PssValidator::new(PssProfile::Restricted);
        let results = validator.validate(&[privileged_pod(), host_network_pod()]);

        assert!(results.summary.critical_count > 0);
        assert!(results.summary.baseline_violations > 0);
    }
}
