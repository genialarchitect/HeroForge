//! Automated remediation suggestions

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub vulnerability_id: String,
    pub vulnerability_type: String,
    pub steps: Vec<RemediationStep>,
    pub estimated_time_minutes: u32,
    pub risk_reduction_percent: f32,
    pub confidence: f32,
    pub alternative_approaches: Vec<AlternativeApproach>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub order: u32,
    pub description: String,
    pub command: Option<String>,
    pub requires_approval: bool,
    pub rollback_command: Option<String>,
    pub verification_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeApproach {
    pub name: String,
    pub description: String,
    pub trade_offs: String,
}

/// Remediation knowledge base for common vulnerabilities
struct RemediationKnowledgeBase {
    patterns: HashMap<String, VulnerabilityPattern>,
}

#[derive(Clone)]
struct VulnerabilityPattern {
    vuln_type: String,
    keywords: Vec<String>,
    base_steps: Vec<RemediationStep>,
    base_time: u32,
    base_risk_reduction: f32,
}

impl RemediationKnowledgeBase {
    fn new() -> Self {
        let mut patterns = HashMap::new();

        // SSH-related vulnerabilities
        patterns.insert(
            "ssh".to_string(),
            VulnerabilityPattern {
                vuln_type: "SSH Configuration".to_string(),
                keywords: vec!["ssh".to_string(), "openssh".to_string(), "sshd".to_string()],
                base_steps: vec![
                    RemediationStep {
                        order: 1,
                        description: "Backup SSH configuration".to_string(),
                        command: Some("cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup".to_string()),
                        requires_approval: false,
                        rollback_command: Some("cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config".to_string()),
                        verification_command: Some("diff /etc/ssh/sshd_config /etc/ssh/sshd_config.backup".to_string()),
                    },
                    RemediationStep {
                        order: 2,
                        description: "Update SSH configuration to disable weak algorithms".to_string(),
                        command: Some("sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config".to_string()),
                        requires_approval: true,
                        rollback_command: Some("cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config".to_string()),
                        verification_command: Some("grep PermitRootLogin /etc/ssh/sshd_config".to_string()),
                    },
                    RemediationStep {
                        order: 3,
                        description: "Restart SSH service".to_string(),
                        command: Some("systemctl restart sshd".to_string()),
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: Some("systemctl status sshd".to_string()),
                    },
                ],
                base_time: 10,
                base_risk_reduction: 75.0,
            },
        );

        // SSL/TLS vulnerabilities
        patterns.insert(
            "ssl".to_string(),
            VulnerabilityPattern {
                vuln_type: "SSL/TLS Configuration".to_string(),
                keywords: vec!["ssl".to_string(), "tls".to_string(), "certificate".to_string(), "cipher".to_string()],
                base_steps: vec![
                    RemediationStep {
                        order: 1,
                        description: "Backup web server configuration".to_string(),
                        command: Some("cp -r /etc/nginx/sites-available /etc/nginx/sites-available.backup".to_string()),
                        requires_approval: false,
                        rollback_command: Some("cp -r /etc/nginx/sites-available.backup /etc/nginx/sites-available".to_string()),
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 2,
                        description: "Update TLS configuration to use modern protocols".to_string(),
                        command: Some("echo 'ssl_protocols TLSv1.2 TLSv1.3;' >> /etc/nginx/conf.d/ssl.conf".to_string()),
                        requires_approval: true,
                        rollback_command: Some("rm /etc/nginx/conf.d/ssl.conf".to_string()),
                        verification_command: Some("nginx -t".to_string()),
                    },
                    RemediationStep {
                        order: 3,
                        description: "Configure strong cipher suites".to_string(),
                        command: Some("echo 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;' >> /etc/nginx/conf.d/ssl.conf".to_string()),
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: Some("openssl ciphers -v".to_string()),
                    },
                    RemediationStep {
                        order: 4,
                        description: "Reload web server".to_string(),
                        command: Some("systemctl reload nginx".to_string()),
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: Some("systemctl status nginx".to_string()),
                    },
                ],
                base_time: 20,
                base_risk_reduction: 80.0,
            },
        );

        // SQL Injection vulnerabilities
        patterns.insert(
            "sqli".to_string(),
            VulnerabilityPattern {
                vuln_type: "SQL Injection".to_string(),
                keywords: vec!["sql".to_string(), "injection".to_string(), "sqli".to_string(), "database".to_string()],
                base_steps: vec![
                    RemediationStep {
                        order: 1,
                        description: "Identify affected endpoints and parameters".to_string(),
                        command: None,
                        requires_approval: false,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 2,
                        description: "Implement parameterized queries/prepared statements".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 3,
                        description: "Add input validation for all user-supplied data".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 4,
                        description: "Deploy and test updated application".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                ],
                base_time: 120,
                base_risk_reduction: 95.0,
            },
        );

        // XSS vulnerabilities
        patterns.insert(
            "xss".to_string(),
            VulnerabilityPattern {
                vuln_type: "Cross-Site Scripting (XSS)".to_string(),
                keywords: vec!["xss".to_string(), "cross-site".to_string(), "script".to_string()],
                base_steps: vec![
                    RemediationStep {
                        order: 1,
                        description: "Identify affected input/output points".to_string(),
                        command: None,
                        requires_approval: false,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 2,
                        description: "Implement output encoding for all user-supplied data".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 3,
                        description: "Add Content-Security-Policy header".to_string(),
                        command: Some("echo \"add_header Content-Security-Policy \\\"default-src 'self';\\\";\" >> /etc/nginx/conf.d/security.conf".to_string()),
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: Some("curl -I https://example.com | grep -i content-security".to_string()),
                    },
                    RemediationStep {
                        order: 4,
                        description: "Deploy and test updated application".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                ],
                base_time: 90,
                base_risk_reduction: 90.0,
            },
        );

        // Outdated software
        patterns.insert(
            "outdated".to_string(),
            VulnerabilityPattern {
                vuln_type: "Outdated Software".to_string(),
                keywords: vec!["outdated".to_string(), "update".to_string(), "upgrade".to_string(), "version".to_string(), "patch".to_string()],
                base_steps: vec![
                    RemediationStep {
                        order: 1,
                        description: "Create system backup".to_string(),
                        command: Some("tar -czf /backup/system-$(date +%Y%m%d).tar.gz /etc /var/www".to_string()),
                        requires_approval: false,
                        rollback_command: None,
                        verification_command: Some("ls -la /backup/".to_string()),
                    },
                    RemediationStep {
                        order: 2,
                        description: "Update package manager cache".to_string(),
                        command: Some("apt-get update".to_string()),
                        requires_approval: false,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 3,
                        description: "Apply security patches".to_string(),
                        command: Some("apt-get upgrade -y --only-upgrade".to_string()),
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: Some("apt list --upgradable".to_string()),
                    },
                    RemediationStep {
                        order: 4,
                        description: "Restart affected services".to_string(),
                        command: Some("systemctl daemon-reload".to_string()),
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: Some("systemctl status".to_string()),
                    },
                ],
                base_time: 30,
                base_risk_reduction: 70.0,
            },
        );

        // Default/weak credentials
        patterns.insert(
            "credentials".to_string(),
            VulnerabilityPattern {
                vuln_type: "Weak Credentials".to_string(),
                keywords: vec!["password".to_string(), "credential".to_string(), "default".to_string(), "weak".to_string(), "authentication".to_string()],
                base_steps: vec![
                    RemediationStep {
                        order: 1,
                        description: "Identify affected accounts and services".to_string(),
                        command: None,
                        requires_approval: false,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 2,
                        description: "Generate strong passwords for affected accounts".to_string(),
                        command: Some("openssl rand -base64 32".to_string()),
                        requires_approval: false,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 3,
                        description: "Update credentials in affected systems".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                    RemediationStep {
                        order: 4,
                        description: "Update credential storage and documentation".to_string(),
                        command: None,
                        requires_approval: true,
                        rollback_command: None,
                        verification_command: None,
                    },
                ],
                base_time: 45,
                base_risk_reduction: 85.0,
            },
        );

        Self { patterns }
    }

    fn find_pattern(&self, vuln_id: &str) -> Option<&VulnerabilityPattern> {
        let vuln_lower = vuln_id.to_lowercase();

        for (_, pattern) in &self.patterns {
            for keyword in &pattern.keywords {
                if vuln_lower.contains(keyword) {
                    return Some(pattern);
                }
            }
        }

        None
    }
}

pub async fn generate_remediation_plan(vuln_id: &str) -> Result<RemediationPlan> {
    let kb = RemediationKnowledgeBase::new();

    // Use pattern matching to find relevant remediation steps
    let (steps, vuln_type, base_time, risk_reduction, confidence) =
        if let Some(pattern) = kb.find_pattern(vuln_id) {
            // Found a matching pattern - use knowledge base
            let mut steps = pattern.base_steps.clone();

            // Adjust step numbering
            for (i, step) in steps.iter_mut().enumerate() {
                step.order = (i + 1) as u32;
            }

            (
                steps,
                pattern.vuln_type.clone(),
                pattern.base_time,
                pattern.base_risk_reduction,
                0.85, // High confidence when pattern matches
            )
        } else {
            // No specific pattern - generate generic remediation plan
            generate_generic_remediation(vuln_id)
        };

    // Generate alternative approaches based on vulnerability type
    let alternatives = generate_alternatives(&vuln_type);

    Ok(RemediationPlan {
        vulnerability_id: vuln_id.to_string(),
        vulnerability_type: vuln_type,
        steps,
        estimated_time_minutes: base_time,
        risk_reduction_percent: risk_reduction,
        confidence,
        alternative_approaches: alternatives,
    })
}

/// Generate a generic remediation plan for unknown vulnerability types
fn generate_generic_remediation(vuln_id: &str) -> (Vec<RemediationStep>, String, u32, f32, f32) {
    let steps = vec![
        RemediationStep {
            order: 1,
            description: "Document the vulnerability and affected systems".to_string(),
            command: None,
            requires_approval: false,
            rollback_command: None,
            verification_command: None,
        },
        RemediationStep {
            order: 2,
            description: "Create backup of affected systems and configurations".to_string(),
            command: Some("tar -czf backup.tar.gz /etc/".to_string()),
            requires_approval: false,
            rollback_command: Some("tar -xzf backup.tar.gz -C /".to_string()),
            verification_command: Some("ls -la backup.tar.gz".to_string()),
        },
        RemediationStep {
            order: 3,
            description: "Research vendor advisories and patches".to_string(),
            command: None,
            requires_approval: false,
            rollback_command: None,
            verification_command: None,
        },
        RemediationStep {
            order: 4,
            description: "Apply vendor-recommended patches or mitigations".to_string(),
            command: Some("apt-get update && apt-get upgrade".to_string()),
            requires_approval: true,
            rollback_command: None,
            verification_command: None,
        },
        RemediationStep {
            order: 5,
            description: "Verify remediation effectiveness".to_string(),
            command: None,
            requires_approval: false,
            rollback_command: None,
            verification_command: None,
        },
    ];

    (
        steps,
        format!("Generic Vulnerability: {}", vuln_id),
        30,   // Default 30 minutes
        65.0, // Conservative risk reduction estimate
        0.5,  // Lower confidence for generic plans
    )
}

/// Generate alternative remediation approaches
fn generate_alternatives(vuln_type: &str) -> Vec<AlternativeApproach> {
    let mut alternatives = Vec::new();

    // Add common alternative approaches based on vulnerability type
    if vuln_type.contains("SSL") || vuln_type.contains("TLS") {
        alternatives.push(AlternativeApproach {
            name: "WAF Protection".to_string(),
            description: "Deploy a Web Application Firewall to filter malicious requests".to_string(),
            trade_offs: "May introduce latency; requires ongoing rule management".to_string(),
        });
        alternatives.push(AlternativeApproach {
            name: "Certificate Rotation".to_string(),
            description: "Replace existing certificates with new ones using stronger algorithms".to_string(),
            trade_offs: "Requires coordinated rollout; may break pinned certificates".to_string(),
        });
    }

    if vuln_type.contains("SQL") || vuln_type.contains("XSS") {
        alternatives.push(AlternativeApproach {
            name: "Virtual Patching".to_string(),
            description: "Apply WAF rules to block exploit patterns without code changes".to_string(),
            trade_offs: "Temporary solution; may cause false positives".to_string(),
        });
    }

    if vuln_type.contains("SSH") {
        alternatives.push(AlternativeApproach {
            name: "Bastion Host".to_string(),
            description: "Route all SSH access through a hardened bastion/jump server".to_string(),
            trade_offs: "Additional infrastructure; single point of access".to_string(),
        });
        alternatives.push(AlternativeApproach {
            name: "SSH Key Only".to_string(),
            description: "Disable password authentication entirely".to_string(),
            trade_offs: "Requires key distribution; may lock out users without keys".to_string(),
        });
    }

    // Always add network segmentation as an option
    alternatives.push(AlternativeApproach {
        name: "Network Segmentation".to_string(),
        description: "Isolate vulnerable systems to limit blast radius".to_string(),
        trade_offs: "May impact connectivity; requires network reconfiguration".to_string(),
    });

    alternatives
}

/// Validate that remediation steps can be safely executed
pub fn validate_remediation_plan(plan: &RemediationPlan) -> Vec<String> {
    let mut warnings = Vec::new();

    for step in &plan.steps {
        // Check for dangerous commands
        if let Some(cmd) = &step.command {
            if cmd.contains("rm -rf") || cmd.contains("dd if=") {
                warnings.push(format!(
                    "Step {}: Contains potentially destructive command",
                    step.order
                ));
            }

            if cmd.contains("chmod 777") || cmd.contains("chmod 666") {
                warnings.push(format!(
                    "Step {}: Sets overly permissive file permissions",
                    step.order
                ));
            }

            if step.requires_approval && step.rollback_command.is_none() {
                warnings.push(format!(
                    "Step {}: Requires approval but has no rollback command",
                    step.order
                ));
            }
        }
    }

    if plan.confidence < 0.6 {
        warnings.push("Low confidence remediation plan - manual review strongly recommended".to_string());
    }

    warnings
}
