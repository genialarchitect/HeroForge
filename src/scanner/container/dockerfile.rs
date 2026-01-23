//! Dockerfile Security Analyzer
//!
//! This module analyzes Dockerfiles for security best practices violations:
//! - Running as root
//! - Using latest tag
//! - Hardcoded secrets/passwords
//! - Privileged instructions
//! - Missing health checks
//! - Insecure package installations

use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use uuid::Uuid;

use super::types::{
    ContainerFinding, ContainerFindingSeverity, ContainerFindingType, DockerfileAnalysis,
    DockerfileInstruction, FindingStatus,
};

/// Analyze a Dockerfile for security issues
pub async fn analyze_dockerfile(
    content: &str,
) -> Result<DockerfileAnalysis> {
    let instructions = parse_dockerfile(content)?;
    let findings = analyze_instructions(&instructions, content)?;

    // Extract metadata from instructions
    let mut base_image = None;
    let mut base_image_tag = None;
    let mut exposed_ports = Vec::new();
    let mut env_vars = Vec::new();
    let mut volumes = Vec::new();
    let mut user = None;
    let mut workdir = None;
    let mut entrypoint = None;
    let mut cmd = None;
    let mut labels = HashMap::new();

    for instr in &instructions {
        match instr.instruction.as_str() {
            "FROM" => {
                let parts: Vec<&str> = instr.arguments.split(':').collect();
                base_image = Some(parts[0].to_string());
                base_image_tag = parts.get(1).map(|s| s.to_string());
            }
            "EXPOSE" => {
                for port in instr.arguments.split_whitespace() {
                    if let Ok(p) = port.trim_end_matches("/tcp").trim_end_matches("/udp").parse::<u16>() {
                        exposed_ports.push(p);
                    }
                }
            }
            "ENV" => {
                // Extract just the variable name
                let parts: Vec<&str> = instr.arguments.splitn(2, '=').collect();
                if let Some(name) = parts.first() {
                    let name = name.split_whitespace().next().unwrap_or(*name);
                    env_vars.push(name.to_string());
                }
            }
            "VOLUME" => {
                volumes.push(instr.arguments.clone());
            }
            "USER" => {
                user = Some(instr.arguments.clone());
            }
            "WORKDIR" => {
                workdir = Some(instr.arguments.clone());
            }
            "ENTRYPOINT" => {
                entrypoint = Some(instr.arguments.clone());
            }
            "CMD" => {
                cmd = Some(instr.arguments.clone());
            }
            "LABEL" => {
                // Parse LABEL key=value pairs
                for pair in instr.arguments.split_whitespace() {
                    let parts: Vec<&str> = pair.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        labels.insert(
                            parts[0].trim_matches('"').to_string(),
                            parts[1].trim_matches('"').to_string(),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    Ok(DockerfileAnalysis {
        base_image,
        base_image_tag,
        instructions,
        exposed_ports,
        env_vars,
        volumes,
        user,
        workdir,
        entrypoint,
        cmd,
        labels,
        findings,
    })
}

/// Parse Dockerfile into instructions
fn parse_dockerfile(content: &str) -> Result<Vec<DockerfileInstruction>> {
    let mut instructions = Vec::new();
    let mut current_instruction = String::new();
    let mut current_line_start = 1;
    let mut line_number = 0;

    for line in content.lines() {
        line_number += 1;
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Handle line continuation
        if trimmed.ends_with('\\') {
            if current_instruction.is_empty() {
                current_line_start = line_number;
            }
            current_instruction.push_str(&trimmed[..trimmed.len() - 1]);
            current_instruction.push(' ');
            continue;
        }

        // Complete the instruction
        if !current_instruction.is_empty() {
            current_instruction.push_str(trimmed);
            let full_line = std::mem::take(&mut current_instruction);
            if let Some(instr) = parse_instruction(&full_line, current_line_start)? {
                instructions.push(instr);
            }
        } else if let Some(instr) = parse_instruction(trimmed, line_number)? {
            instructions.push(instr);
        }
    }

    // Handle any remaining instruction
    if !current_instruction.is_empty() {
        if let Some(instr) = parse_instruction(&current_instruction, current_line_start)? {
            instructions.push(instr);
        }
    }

    Ok(instructions)
}

/// Parse a single instruction line
fn parse_instruction(line: &str, line_number: i32) -> Result<Option<DockerfileInstruction>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    // Split into instruction and arguments
    let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
    let instruction = parts[0].to_uppercase();
    let arguments = parts.get(1).map(|s| s.trim().to_string()).unwrap_or_default();

    Ok(Some(DockerfileInstruction {
        line: line_number,
        instruction,
        arguments,
        original: line.to_string(),
    }))
}

/// Analyze instructions for security issues
fn analyze_instructions(
    instructions: &[DockerfileInstruction],
    _content: &str,
) -> Result<Vec<ContainerFinding>> {
    let scan_id = Uuid::new_v4().to_string();
    let mut findings = Vec::new();

    // Track state
    let mut has_user = false;
    let mut user_is_root = false;
    let mut has_healthcheck = false;

    for instr in instructions {
        match instr.instruction.as_str() {
            "FROM" => {
                // Check for latest tag or missing tag
                let args = instr.arguments.to_lowercase();
                if args == "scratch" {
                    continue;
                }

                if !args.contains(':') || args.ends_with(":latest") {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.clone(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::BestPractice,
                        severity: ContainerFindingSeverity::Medium,
                        title: "Base image uses 'latest' tag".to_string(),
                        description: "Using 'latest' or omitting a tag can lead to unpredictable builds. \
                            The image may change without notice, potentially introducing \
                            vulnerabilities or breaking changes.".to_string(),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec!["CWE-1104".to_string()],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: Some("Dockerfile".to_string()),
                        line_number: Some(instr.line),
                        remediation: Some(
                            "Pin the base image to a specific version (e.g., 'nginx:1.21.0' \
                            or 'node:18.17.1-alpine')".to_string()
                        ),
                        references: vec![
                            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/".to_string(),
                        ],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }
            }
            "RUN" => {
                let args = &instr.arguments;

                // Check for apt-get/apk without cache cleanup
                if (args.contains("apt-get install") || args.contains("apk add"))
                    && !args.contains("rm -rf /var/lib/apt/lists")
                    && !args.contains("--no-cache")
                {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.clone(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::BestPractice,
                        severity: ContainerFindingSeverity::Low,
                        title: "Package manager cache not cleaned".to_string(),
                        description: "The package manager cache is not cleaned after installation, \
                            increasing the image size unnecessarily.".to_string(),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec![],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: Some("Dockerfile".to_string()),
                        line_number: Some(instr.line),
                        remediation: Some(
                            "For apt-get: add '&& rm -rf /var/lib/apt/lists/*' at the end. \
                            For apk: use 'apk add --no-cache'".to_string()
                        ),
                        references: vec![],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }

                // Check for chmod 777
                if args.contains("chmod 777") || args.contains("chmod -R 777") {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.clone(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::Misconfiguration,
                        severity: ContainerFindingSeverity::High,
                        title: "Overly permissive file permissions (777)".to_string(),
                        description: "Setting file permissions to 777 allows all users to read, \
                            write, and execute files, which is a security risk.".to_string(),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec!["CWE-732".to_string()],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: Some("Dockerfile".to_string()),
                        line_number: Some(instr.line),
                        remediation: Some(
                            "Use more restrictive permissions. For executables: 755, \
                            for files: 644, for sensitive files: 600".to_string()
                        ),
                        references: vec![
                            "https://cwe.mitre.org/data/definitions/732.html".to_string(),
                        ],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }

                // Check for curl pipe to shell
                if (args.contains("curl") || args.contains("wget"))
                    && (args.contains("| sh") || args.contains("| bash") || args.contains("|sh") || args.contains("|bash"))
                {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.clone(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::Misconfiguration,
                        severity: ContainerFindingSeverity::High,
                        title: "Remote script execution via pipe".to_string(),
                        description: "Piping downloaded content directly to a shell is dangerous. \
                            The script could be modified in transit or at the source.".to_string(),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec!["CWE-829".to_string()],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: Some("Dockerfile".to_string()),
                        line_number: Some(instr.line),
                        remediation: Some(
                            "Download the script first, verify its checksum, then execute. \
                            Or use a package manager instead.".to_string()
                        ),
                        references: vec![],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }

                // Check for sudo usage
                if args.contains("sudo ") {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.clone(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::BestPractice,
                        severity: ContainerFindingSeverity::Medium,
                        title: "Unnecessary use of sudo".to_string(),
                        description: "Using sudo in a Dockerfile is usually unnecessary since \
                            commands run as root by default. Sudo can also cause caching issues.".to_string(),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec![],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: Some("Dockerfile".to_string()),
                        line_number: Some(instr.line),
                        remediation: Some(
                            "Remove sudo from the command. Docker runs as root by default.".to_string()
                        ),
                        references: vec![],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }
            }
            "USER" => {
                has_user = true;
                let user_arg = instr.arguments.trim().to_lowercase();
                if user_arg == "root" || user_arg == "0" {
                    user_is_root = true;
                }
            }
            "EXPOSE" => {
                // Check for sensitive ports
                let sensitive_ports = vec!["22", "23", "3389", "5432", "3306", "27017", "6379"];
                for port in instr.arguments.split_whitespace() {
                    let port_num = port.trim_end_matches("/tcp").trim_end_matches("/udp");
                    if sensitive_ports.contains(&port_num) {
                        findings.push(ContainerFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: scan_id.clone(),
                            image_id: None,
                            resource_id: None,
                            finding_type: ContainerFindingType::NetworkExposure,
                            severity: ContainerFindingSeverity::Medium,
                            title: format!("Sensitive port {} exposed", port_num),
                            description: format!(
                                "Port {} is commonly associated with sensitive services \
                                (SSH, Telnet, RDP, databases). Exposing these ports increases \
                                the attack surface.", port_num
                            ),
                            cve_id: None,
                            cvss_score: None,
                            cwe_ids: vec!["CWE-200".to_string()],
                            package_name: None,
                            package_version: None,
                            fixed_version: None,
                            file_path: Some("Dockerfile".to_string()),
                            line_number: Some(instr.line),
                            remediation: Some(
                                "Consider if this port needs to be exposed. Use internal \
                                networks or SSH tunnels for administrative access.".to_string()
                            ),
                            references: vec![],
                            status: FindingStatus::Open,
                            created_at: Utc::now(),
                        });
                    }
                }
            }
            "ENV" => {
                // Check for secrets in ENV
                check_for_secrets(&instr.arguments, instr.line, &scan_id, &mut findings);
            }
            "ARG" => {
                // Check for secrets in ARG (build-time)
                check_for_secrets(&instr.arguments, instr.line, &scan_id, &mut findings);
            }
            "HEALTHCHECK" => {
                has_healthcheck = true;
            }
            "ADD" => {
                // Prefer COPY over ADD unless extracting archives
                if !instr.arguments.ends_with(".tar")
                    && !instr.arguments.ends_with(".tar.gz")
                    && !instr.arguments.ends_with(".tgz")
                    && !instr.arguments.contains("http://")
                    && !instr.arguments.contains("https://")
                {
                    findings.push(ContainerFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.clone(),
                        image_id: None,
                        resource_id: None,
                        finding_type: ContainerFindingType::BestPractice,
                        severity: ContainerFindingSeverity::Low,
                        title: "Use COPY instead of ADD".to_string(),
                        description: "ADD has extra features (auto-extraction, URL support) that \
                            can introduce unexpected behavior. Use COPY for simple file copies.".to_string(),
                        cve_id: None,
                        cvss_score: None,
                        cwe_ids: vec![],
                        package_name: None,
                        package_version: None,
                        fixed_version: None,
                        file_path: Some("Dockerfile".to_string()),
                        line_number: Some(instr.line),
                        remediation: Some(
                            "Replace ADD with COPY unless you need archive extraction or URL fetching.".to_string()
                        ),
                        references: vec![],
                        status: FindingStatus::Open,
                        created_at: Utc::now(),
                    });
                }
            }
            _ => {}
        }
    }

    // Check for running as root (final USER or no USER instruction)
    if !has_user || user_is_root {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::PrivilegeEscalation,
            severity: ContainerFindingSeverity::High,
            title: "Container runs as root".to_string(),
            description: "The container runs as root, which increases the impact of any \
                container escape vulnerability. If the container is compromised, the attacker \
                has root access.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec!["CWE-250".to_string()],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: Some("Dockerfile".to_string()),
            line_number: None,
            remediation: Some(
                "Add a USER instruction to run as a non-root user: \
                'RUN adduser -D appuser && USER appuser'".to_string()
            ),
            references: vec![
                "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user".to_string(),
            ],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    // Check for missing HEALTHCHECK
    if !has_healthcheck {
        findings.push(ContainerFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.clone(),
            image_id: None,
            resource_id: None,
            finding_type: ContainerFindingType::BestPractice,
            severity: ContainerFindingSeverity::Low,
            title: "Missing HEALTHCHECK instruction".to_string(),
            description: "No HEALTHCHECK instruction found. Health checks allow Docker to \
                determine if the container is still working properly.".to_string(),
            cve_id: None,
            cvss_score: None,
            cwe_ids: vec![],
            package_name: None,
            package_version: None,
            fixed_version: None,
            file_path: Some("Dockerfile".to_string()),
            line_number: None,
            remediation: Some(
                "Add a HEALTHCHECK instruction: \
                'HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1'".to_string()
            ),
            references: vec![],
            status: FindingStatus::Open,
            created_at: Utc::now(),
        });
    }

    Ok(findings)
}

/// Check for hardcoded secrets in environment variables or arguments
fn check_for_secrets(
    value: &str,
    line_number: i32,
    scan_id: &str,
    findings: &mut Vec<ContainerFinding>,
) {
    let secret_patterns = [
        (r"(?i)(password|passwd|pwd)\s*=\s*\S+", "password"),
        (r"(?i)(secret|api_key|apikey|auth_token|authtoken)\s*=\s*\S+", "secret/API key"),
        (r"(?i)(access_key|accesskey|aws_access_key)\s*=\s*\S+", "access key"),
        (r"(?i)(private_key|privatekey)\s*=\s*\S+", "private key"),
        (r"(?i)(db_password|database_password|mysql_password|postgres_password)\s*=\s*\S+", "database password"),
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    ];

    for (pattern, secret_type) in &secret_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(value) {
                findings.push(ContainerFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    image_id: None,
                    resource_id: None,
                    finding_type: ContainerFindingType::SecretExposure,
                    severity: ContainerFindingSeverity::Critical,
                    title: format!("Hardcoded {} in Dockerfile", secret_type),
                    description: format!(
                        "A {} appears to be hardcoded in the Dockerfile. \
                        This secret will be visible in the image history and layer contents.",
                        secret_type
                    ),
                    cve_id: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-798".to_string(), "CWE-259".to_string()],
                    package_name: None,
                    package_version: None,
                    fixed_version: None,
                    file_path: Some("Dockerfile".to_string()),
                    line_number: Some(line_number),
                    remediation: Some(
                        "Use Docker secrets, environment variables at runtime, or a secrets \
                        management solution. Never hardcode secrets in Dockerfiles.".to_string()
                    ),
                    references: vec![
                        "https://docs.docker.com/engine/swarm/secrets/".to_string(),
                        "https://cwe.mitre.org/data/definitions/798.html".to_string(),
                    ],
                    status: FindingStatus::Open,
                    created_at: Utc::now(),
                });
                break; // Only report once per line
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_dockerfile_basic() {
        let dockerfile = r#"
FROM nginx:latest
RUN apt-get update && apt-get install -y curl
COPY . /app
USER root
EXPOSE 80
"#;

        let analysis = analyze_dockerfile(dockerfile, false).await.unwrap();

        assert_eq!(analysis.base_image, Some("nginx".to_string()));
        assert_eq!(analysis.base_image_tag, Some("latest".to_string()));
        assert!(!analysis.findings.is_empty());

        // Should have findings for: latest tag, no cache cleanup, running as root
        let finding_titles: Vec<_> = analysis.findings.iter().map(|f| &f.title).collect();
        assert!(finding_titles.iter().any(|t| t.contains("latest")));
    }

    #[tokio::test]
    async fn test_detect_hardcoded_secrets() {
        let dockerfile = r#"
FROM alpine:3.14
ENV API_KEY=sk-secret123
ENV DB_PASSWORD=supersecret
"#;

        let analysis = analyze_dockerfile(dockerfile, false).await.unwrap();

        let secret_findings: Vec<_> = analysis.findings.iter()
            .filter(|f| f.finding_type == ContainerFindingType::SecretExposure)
            .collect();

        assert!(!secret_findings.is_empty());
    }

    #[tokio::test]
    async fn test_detect_chmod_777() {
        let dockerfile = r#"
FROM alpine:3.14
RUN chmod 777 /app
"#;

        let analysis = analyze_dockerfile(dockerfile, false).await.unwrap();

        let permission_findings: Vec<_> = analysis.findings.iter()
            .filter(|f| f.title.contains("777"))
            .collect();

        assert!(!permission_findings.is_empty());
    }
}
