//! Virtual Patching
//!
//! Generates and manages virtual patches (WAF rules, IPS signatures, network
//! controls) as compensating controls when vendor patches aren't immediately
//! available or deployable.

use super::types::*;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

/// Generate a WAF rule based on CVE vulnerability details
pub async fn create_waf_rule(cve_id: &str, vuln_details: &serde_json::Value) -> Result<VirtualPatch> {
    let rule = generate_waf_rule_content(cve_id, vuln_details);

    Ok(VirtualPatch {
        id: Uuid::new_v4().to_string(),
        cve_id: cve_id.to_string(),
        patch_type: "WAF".to_string(),
        rule_content: rule,
        enabled: true,
        created_at: Utc::now(),
    })
}

/// Generate an IPS signature for network-level blocking
pub async fn create_ips_signature(cve_id: &str, vuln_details: &serde_json::Value) -> Result<VirtualPatch> {
    let signature = generate_ips_signature_content(cve_id, vuln_details);

    Ok(VirtualPatch {
        id: Uuid::new_v4().to_string(),
        cve_id: cve_id.to_string(),
        patch_type: "IPS".to_string(),
        rule_content: signature,
        enabled: true,
        created_at: Utc::now(),
    })
}

/// Create a network segmentation rule as a compensating control
pub async fn create_network_segmentation(cve_id: &str, affected_hosts: &[String]) -> Result<VirtualPatch> {
    let mut rules = Vec::new();

    for host in affected_hosts {
        rules.push(format!("# Isolate vulnerable host: {}", host));
        rules.push(format!("iptables -I FORWARD -s {} -j DROP", host));
        rules.push(format!("iptables -I FORWARD -d {} -p tcp --dport 0:1023 -j DROP", host));
        // Allow only essential management access
        rules.push(format!("iptables -I FORWARD -d {} -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT", host));
    }

    let rule_content = rules.join("\n");

    Ok(VirtualPatch {
        id: Uuid::new_v4().to_string(),
        cve_id: cve_id.to_string(),
        patch_type: "NetworkSegmentation".to_string(),
        rule_content,
        enabled: true,
        created_at: Utc::now(),
    })
}

/// Deploy compensating controls for a CVE across all available mechanisms
pub async fn deploy_compensating_controls(
    cve_id: &str,
    vuln_details: &serde_json::Value,
    affected_hosts: &[String],
) -> Result<Vec<VirtualPatch>> {
    let mut patches = Vec::new();

    // Determine which virtual patch types are appropriate based on the vulnerability
    let vuln_type = vuln_details.get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    let attack_vector = vuln_details.get("attack_vector")
        .and_then(|v| v.as_str())
        .unwrap_or("network");

    // Web-facing vulnerabilities get WAF rules
    if vuln_type == "injection" || vuln_type == "xss" || vuln_type == "rce"
        || attack_vector == "network" {
        let waf_patch = create_waf_rule(cve_id, vuln_details).await?;
        patches.push(waf_patch);
    }

    // Network-exploitable vulnerabilities get IPS signatures
    if attack_vector == "network" || attack_vector == "adjacent" {
        let ips_patch = create_ips_signature(cve_id, vuln_details).await?;
        patches.push(ips_patch);
    }

    // High-severity vulnerabilities with known affected hosts get segmentation
    let cvss = vuln_details.get("cvss_score")
        .and_then(|s| s.as_f64())
        .unwrap_or(0.0);

    if cvss >= 7.0 && !affected_hosts.is_empty() {
        let seg_patch = create_network_segmentation(cve_id, affected_hosts).await?;
        patches.push(seg_patch);
    }

    log::info!(
        "Deployed {} compensating controls for {}",
        patches.len(),
        cve_id
    );

    Ok(patches)
}

// --- Internal rule generation ---

fn generate_waf_rule_content(cve_id: &str, vuln_details: &serde_json::Value) -> String {
    let vuln_type = vuln_details.get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    let affected_path = vuln_details.get("affected_path")
        .and_then(|p| p.as_str())
        .unwrap_or("/*");

    let severity = vuln_details.get("cvss_score")
        .and_then(|s| s.as_f64())
        .map(|s| if s >= 9.0 { "CRITICAL" } else if s >= 7.0 { "HIGH" } else { "MEDIUM" })
        .unwrap_or("MEDIUM");

    match vuln_type {
        "injection" | "sqli" => format!(
            r#"# Virtual Patch for {cve_id} - SQL Injection
# Severity: {severity}
SecRule REQUEST_URI "{affected_path}" \
    "id:1000001,\
     phase:2,\
     deny,\
     status:403,\
     msg:'Virtual Patch: {cve_id} - SQL Injection attempt blocked',\
     chain"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY \
    "@rx (?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table|;.*--|'\s*or\s+'1)" \
    "t:none,t:urlDecodeUni,t:lowercase"
"#),
        "xss" => format!(
            r#"# Virtual Patch for {cve_id} - Cross-Site Scripting
# Severity: {severity}
SecRule REQUEST_URI "{affected_path}" \
    "id:1000002,\
     phase:2,\
     deny,\
     status:403,\
     msg:'Virtual Patch: {cve_id} - XSS attempt blocked',\
     chain"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY \
    "@rx (?i)(<script|javascript:|on\w+\s*=|<\s*img[^>]+src\s*=)" \
    "t:none,t:urlDecodeUni,t:htmlEntityDecode"
"#),
        "rce" | "command_injection" => format!(
            r#"# Virtual Patch for {cve_id} - Remote Code Execution
# Severity: {severity}
SecRule REQUEST_URI "{affected_path}" \
    "id:1000003,\
     phase:2,\
     deny,\
     status:403,\
     msg:'Virtual Patch: {cve_id} - RCE attempt blocked',\
     chain"
SecRule ARGS|ARGS_NAMES|REQUEST_BODY \
    "@rx (?i)(;|\||`|\\$\(|\\$\\{{|&&|\\.\\./|/etc/passwd|/bin/(?:sh|bash|cmd))" \
    "t:none,t:urlDecodeUni"
"#),
        "path_traversal" | "lfi" => format!(
            r#"# Virtual Patch for {cve_id} - Path Traversal
# Severity: {severity}
SecRule REQUEST_URI "{affected_path}" \
    "id:1000004,\
     phase:2,\
     deny,\
     status:403,\
     msg:'Virtual Patch: {cve_id} - Path traversal blocked',\
     chain"
SecRule ARGS|REQUEST_URI \
    "@rx (?i)(\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|/etc/|/proc/|c:\\\\)" \
    "t:none,t:urlDecodeUni"
"#),
        _ => format!(
            r#"# Virtual Patch for {cve_id} - Generic Protection
# Severity: {severity}
# Type: {vuln_type}
SecRule REQUEST_URI "{affected_path}" \
    "id:1000099,\
     phase:2,\
     deny,\
     status:403,\
     msg:'Virtual Patch: {cve_id} - Suspicious request blocked',\
     severity:'{severity}'"
"#),
    }
}

fn generate_ips_signature_content(cve_id: &str, vuln_details: &serde_json::Value) -> String {
    let vuln_type = vuln_details.get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    let affected_port = vuln_details.get("affected_port")
        .and_then(|p| p.as_u64())
        .unwrap_or(0);

    let protocol = vuln_details.get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("tcp");

    let port_clause = if affected_port > 0 {
        format!("dst_port:{};", affected_port)
    } else {
        String::new()
    };

    match vuln_type {
        "overflow" | "buffer_overflow" => format!(
            r#"# IPS Signature for {cve_id} - Buffer Overflow
alert {protocol} any any -> any any (\
    msg:"{cve_id} - Buffer overflow exploit attempt";\
    {port_clause}\
    content:"|90 90 90 90 90|";\
    byte_test:4,>,1024,0,relative;\
    reference:cve,{cve_id};\
    classtype:attempted-admin;\
    sid:3000001;\
    rev:1;\
)
"#),
        "rce" | "command_injection" => format!(
            r#"# IPS Signature for {cve_id} - Remote Code Execution
alert {protocol} any any -> any any (\
    msg:"{cve_id} - RCE exploit attempt";\
    {port_clause}\
    content:"/bin/sh"; nocase;\
    content:"exec"; nocase;\
    reference:cve,{cve_id};\
    classtype:attempted-admin;\
    sid:3000002;\
    rev:1;\
)
"#),
        "injection" | "sqli" => format!(
            r#"# IPS Signature for {cve_id} - Injection Attack
alert {protocol} any any -> any any (\
    msg:"{cve_id} - Injection exploit attempt";\
    {port_clause}\
    content:"UNION"; nocase;\
    content:"SELECT"; nocase; distance:0;\
    reference:cve,{cve_id};\
    classtype:web-application-attack;\
    sid:3000003;\
    rev:1;\
)
"#),
        _ => format!(
            r#"# IPS Signature for {cve_id} - Generic Detection
alert {protocol} any any -> any any (\
    msg:"{cve_id} - Exploit attempt detected";\
    {port_clause}\
    reference:cve,{cve_id};\
    classtype:attempted-admin;\
    sid:3000099;\
    rev:1;\
)
"#),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_waf_rule_sqli() {
        let details = serde_json::json!({
            "type": "sqli",
            "affected_path": "/api/users",
            "cvss_score": 8.5
        });

        let patch = create_waf_rule("CVE-2024-1234", &details).await.unwrap();

        assert_eq!(patch.patch_type, "WAF");
        assert_eq!(patch.cve_id, "CVE-2024-1234");
        assert!(patch.rule_content.contains("SQL Injection"));
        assert!(patch.rule_content.contains("/api/users"));
        assert!(patch.enabled);
    }

    #[tokio::test]
    async fn test_create_ips_signature_rce() {
        let details = serde_json::json!({
            "type": "rce",
            "affected_port": 8080,
            "protocol": "tcp"
        });

        let patch = create_ips_signature("CVE-2024-5678", &details).await.unwrap();

        assert_eq!(patch.patch_type, "IPS");
        assert!(patch.rule_content.contains("RCE"));
        assert!(patch.rule_content.contains("dst_port:8080"));
    }

    #[tokio::test]
    async fn test_create_network_segmentation() {
        let hosts = vec!["192.168.1.100".to_string(), "192.168.1.101".to_string()];
        let patch = create_network_segmentation("CVE-2024-9999", &hosts).await.unwrap();

        assert_eq!(patch.patch_type, "NetworkSegmentation");
        assert!(patch.rule_content.contains("192.168.1.100"));
        assert!(patch.rule_content.contains("192.168.1.101"));
        assert!(patch.rule_content.contains("iptables"));
    }

    #[tokio::test]
    async fn test_deploy_compensating_controls() {
        let details = serde_json::json!({
            "type": "rce",
            "attack_vector": "network",
            "cvss_score": 9.8,
            "affected_path": "/api/exec"
        });

        let hosts = vec!["10.0.0.5".to_string()];
        let patches = deploy_compensating_controls("CVE-2024-0001", &details, &hosts).await.unwrap();

        // Should generate WAF + IPS + Segmentation for high-severity network RCE
        assert!(patches.len() >= 2);
        let types: Vec<&str> = patches.iter().map(|p| p.patch_type.as_str()).collect();
        assert!(types.contains(&"WAF"));
        assert!(types.contains(&"IPS"));
    }
}
