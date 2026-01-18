//! Engagement Templates for Quick Setup
//!
//! Pre-configured templates for common engagement types:
//! - External Pentest
//! - Web Application Assessment
//! - Cloud Security Assessment
//! - Internal Network Assessment
//! - Red Team Engagement
//! - Social Engineering Campaign
//! - Wireless Assessment

use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use super::crm::{
    create_engagement, create_milestone, CreateEngagementRequest, CreateMilestoneRequest,
    Engagement, EngagementMilestone,
};

// ============================================================================
// Types
// ============================================================================

/// Engagement template definition
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EngagementTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub engagement_type: String,
    pub default_duration_days: i32,
    pub default_budget: Option<f64>,
    pub scope_template: Option<String>,
    pub compliance_frameworks: Option<String>, // JSON array
    pub milestones_template: Option<String>,   // JSON array
    pub scan_config_template: Option<String>,  // JSON object
    pub is_system: bool, // Built-in templates cannot be deleted
    pub created_at: String,
    pub updated_at: String,
}

/// Milestone template (part of engagement template)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MilestoneTemplate {
    pub name: String,
    pub description: Option<String>,
    pub days_offset: i32, // Days from engagement start
    pub is_required: bool,
}

/// Scan configuration template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigTemplate {
    pub scan_types: Vec<String>,
    pub port_ranges: Option<String>,
    pub intensity: String, // light, normal, aggressive
    pub include_web_scan: bool,
    pub include_vuln_scan: bool,
    pub enumeration_depth: String, // passive, light, aggressive
}

/// Request to create an engagement from a template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFromTemplateRequest {
    pub template_id: String,
    pub customer_id: String,
    pub engagement_name: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub budget: Option<f64>,
    pub scope: Option<String>,
    pub notes: Option<String>,
    pub compliance_frameworks: Option<Vec<String>>,
    pub auto_create_portal_user: bool,
    pub create_default_milestones: bool,
}

/// Result of creating an engagement from template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementSetupResult {
    pub engagement: Engagement,
    pub milestones: Vec<EngagementMilestone>,
    pub portal_user_created: bool,
    pub scan_config: Option<ScanConfigTemplate>,
}

/// Request to create/update a template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub description: String,
    pub engagement_type: String,
    pub default_duration_days: i32,
    pub default_budget: Option<f64>,
    pub scope_template: Option<String>,
    pub compliance_frameworks: Option<Vec<String>>,
    pub milestones: Option<Vec<MilestoneTemplate>>,
    pub scan_config: Option<ScanConfigTemplate>,
}

// ============================================================================
// Built-in Templates
// ============================================================================

/// Get the built-in system templates
pub fn get_builtin_templates() -> Vec<CreateTemplateRequest> {
    vec![
        // External Penetration Test
        CreateTemplateRequest {
            name: "External Penetration Test".to_string(),
            description: "Full external network penetration testing including reconnaissance, vulnerability assessment, and exploitation attempts".to_string(),
            engagement_type: "external_pentest".to_string(),
            default_duration_days: 14,
            default_budget: Some(25000.0),
            scope_template: Some("External IP ranges and domains:\n- \n\nExcluded systems:\n- Production databases\n- Customer-facing payment systems".to_string()),
            compliance_frameworks: Some(vec!["NIST CSF".to_string(), "PCI-DSS".to_string()]),
            milestones: Some(vec![
                MilestoneTemplate {
                    name: "Kickoff Meeting".to_string(),
                    description: Some("Initial meeting to discuss scope, rules of engagement, and timelines".to_string()),
                    days_offset: 0,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Reconnaissance Complete".to_string(),
                    description: Some("OSINT and passive reconnaissance phase completed".to_string()),
                    days_offset: 3,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Vulnerability Assessment".to_string(),
                    description: Some("Active scanning and vulnerability identification".to_string()),
                    days_offset: 7,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Exploitation Phase".to_string(),
                    description: Some("Attempted exploitation of identified vulnerabilities".to_string()),
                    days_offset: 10,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Draft Report".to_string(),
                    description: Some("Preliminary findings report for review".to_string()),
                    days_offset: 12,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Final Report & Debrief".to_string(),
                    description: Some("Finalized report and client debrief meeting".to_string()),
                    days_offset: 14,
                    is_required: true,
                },
            ]),
            scan_config: Some(ScanConfigTemplate {
                scan_types: vec!["tcp-syn".to_string(), "udp".to_string()],
                port_ranges: Some("1-65535".to_string()),
                intensity: "aggressive".to_string(),
                include_web_scan: true,
                include_vuln_scan: true,
                enumeration_depth: "aggressive".to_string(),
            }),
        },

        // Web Application Assessment
        CreateTemplateRequest {
            name: "Web Application Assessment".to_string(),
            description: "Comprehensive web application security testing including OWASP Top 10, business logic, and API security".to_string(),
            engagement_type: "webapp_pentest".to_string(),
            default_duration_days: 10,
            default_budget: Some(18000.0),
            scope_template: Some("Target Application(s):\n- \n\nAuthentication Provided:\n- Test accounts with various roles\n\nOut of Scope:\n- Denial of Service testing".to_string()),
            compliance_frameworks: Some(vec!["OWASP Top 10".to_string(), "OWASP ASVS".to_string()]),
            milestones: Some(vec![
                MilestoneTemplate {
                    name: "Kickoff & Environment Setup".to_string(),
                    description: Some("Initial meeting and test environment access verification".to_string()),
                    days_offset: 0,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Automated Scanning".to_string(),
                    description: Some("Automated vulnerability scanning and crawling".to_string()),
                    days_offset: 2,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Manual Testing".to_string(),
                    description: Some("Manual testing for business logic and complex vulnerabilities".to_string()),
                    days_offset: 6,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "API Security Review".to_string(),
                    description: Some("API endpoint security testing".to_string()),
                    days_offset: 7,
                    is_required: false,
                },
                MilestoneTemplate {
                    name: "Report Delivery".to_string(),
                    description: Some("Final report and remediation guidance".to_string()),
                    days_offset: 10,
                    is_required: true,
                },
            ]),
            scan_config: Some(ScanConfigTemplate {
                scan_types: vec!["tcp-connect".to_string()],
                port_ranges: Some("80,443,8080,8443".to_string()),
                intensity: "normal".to_string(),
                include_web_scan: true,
                include_vuln_scan: true,
                enumeration_depth: "aggressive".to_string(),
            }),
        },

        // Cloud Security Assessment
        CreateTemplateRequest {
            name: "Cloud Security Assessment".to_string(),
            description: "Cloud infrastructure security review for AWS, Azure, or GCP environments".to_string(),
            engagement_type: "cloud_assessment".to_string(),
            default_duration_days: 7,
            default_budget: Some(15000.0),
            scope_template: Some("Cloud Provider: [AWS/Azure/GCP]\n\nAccounts/Subscriptions:\n- \n\nServices to Review:\n- IAM\n- Compute\n- Storage\n- Networking\n- Databases".to_string()),
            compliance_frameworks: Some(vec!["CIS Benchmarks".to_string(), "CSA CCM".to_string(), "NIST 800-53".to_string()]),
            milestones: Some(vec![
                MilestoneTemplate {
                    name: "Access Setup".to_string(),
                    description: Some("Read-only access provisioned and verified".to_string()),
                    days_offset: 0,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "IAM Review".to_string(),
                    description: Some("Identity and access management configuration review".to_string()),
                    days_offset: 2,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Resource Configuration Review".to_string(),
                    description: Some("Compute, storage, and database configuration assessment".to_string()),
                    days_offset: 4,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Network Security Review".to_string(),
                    description: Some("VPC, security groups, and network ACL review".to_string()),
                    days_offset: 5,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Report Delivery".to_string(),
                    description: Some("Findings report with CIS benchmark mapping".to_string()),
                    days_offset: 7,
                    is_required: true,
                },
            ]),
            scan_config: Some(ScanConfigTemplate {
                scan_types: vec!["cloud".to_string()],
                port_ranges: None,
                intensity: "light".to_string(),
                include_web_scan: false,
                include_vuln_scan: true,
                enumeration_depth: "aggressive".to_string(),
            }),
        },

        // Internal Network Assessment
        CreateTemplateRequest {
            name: "Internal Network Assessment".to_string(),
            description: "Internal network penetration testing simulating an insider threat or compromised endpoint".to_string(),
            engagement_type: "internal_pentest".to_string(),
            default_duration_days: 14,
            default_budget: Some(30000.0),
            scope_template: Some("Internal Network Ranges:\n- \n\nVPN Access: [Yes/No]\n\nDomain Credentials Provided: [Yes/No]\n\nExcluded Systems:\n- ".to_string()),
            compliance_frameworks: Some(vec!["NIST 800-53".to_string(), "SOC 2".to_string()]),
            milestones: Some(vec![
                MilestoneTemplate {
                    name: "Access Setup".to_string(),
                    description: Some("VPN/remote access configured and tested".to_string()),
                    days_offset: 0,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Network Discovery".to_string(),
                    description: Some("Host discovery and network mapping".to_string()),
                    days_offset: 2,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Active Directory Assessment".to_string(),
                    description: Some("AD enumeration and attack path analysis".to_string()),
                    days_offset: 5,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Lateral Movement".to_string(),
                    description: Some("Privilege escalation and lateral movement attempts".to_string()),
                    days_offset: 9,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Domain Dominance".to_string(),
                    description: Some("Attempt to achieve domain admin access".to_string()),
                    days_offset: 11,
                    is_required: false,
                },
                MilestoneTemplate {
                    name: "Report & Debrief".to_string(),
                    description: Some("Final report with attack path diagrams".to_string()),
                    days_offset: 14,
                    is_required: true,
                },
            ]),
            scan_config: Some(ScanConfigTemplate {
                scan_types: vec!["tcp-syn".to_string(), "udp".to_string()],
                port_ranges: Some("1-65535".to_string()),
                intensity: "aggressive".to_string(),
                include_web_scan: true,
                include_vuln_scan: true,
                enumeration_depth: "aggressive".to_string(),
            }),
        },

        // Red Team Engagement
        CreateTemplateRequest {
            name: "Red Team Engagement".to_string(),
            description: "Full-scope adversary simulation with physical, social, and technical attack vectors".to_string(),
            engagement_type: "red_team".to_string(),
            default_duration_days: 30,
            default_budget: Some(75000.0),
            scope_template: Some("Objectives:\n- [Define crown jewels]\n\nAllowed Attack Vectors:\n- Physical access attempts\n- Social engineering\n- Technical exploitation\n\nRules of Engagement:\n- ".to_string()),
            compliance_frameworks: Some(vec!["MITRE ATT&CK".to_string()]),
            milestones: Some(vec![
                MilestoneTemplate {
                    name: "Planning & Reconnaissance".to_string(),
                    description: Some("Target intelligence gathering and attack planning".to_string()),
                    days_offset: 5,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Initial Access Attempts".to_string(),
                    description: Some("Phishing, physical access, or external exploitation".to_string()),
                    days_offset: 12,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Establish Persistence".to_string(),
                    description: Some("Maintain access and establish C2 infrastructure".to_string()),
                    days_offset: 18,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Objective Achievement".to_string(),
                    description: Some("Attempt to achieve engagement objectives".to_string()),
                    days_offset: 25,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Executive Report & Purple Team Session".to_string(),
                    description: Some("Findings presentation with blue team collaboration".to_string()),
                    days_offset: 30,
                    is_required: true,
                },
            ]),
            scan_config: Some(ScanConfigTemplate {
                scan_types: vec!["tcp-connect".to_string()],
                port_ranges: Some("21,22,80,443,445,3389".to_string()),
                intensity: "light".to_string(), // Evasive
                include_web_scan: true,
                include_vuln_scan: false, // Focused exploitation
                enumeration_depth: "passive".to_string(),
            }),
        },

        // Social Engineering Campaign
        CreateTemplateRequest {
            name: "Social Engineering Campaign".to_string(),
            description: "Phishing simulation and security awareness assessment".to_string(),
            engagement_type: "social_engineering".to_string(),
            default_duration_days: 21,
            default_budget: Some(12000.0),
            scope_template: Some("Target Employees:\n- [All / Department / Sample]\n\nPhishing Scenarios:\n- Credential harvesting\n- Malware simulation\n- USB drop test (optional)\n\nExclusions:\n- C-suite (optional)".to_string()),
            compliance_frameworks: Some(vec!["NIST 800-53 AT Controls".to_string()]),
            milestones: Some(vec![
                MilestoneTemplate {
                    name: "Campaign Setup".to_string(),
                    description: Some("Email templates, landing pages, and targeting".to_string()),
                    days_offset: 3,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Wave 1 - Credential Harvest".to_string(),
                    description: Some("First phishing wave targeting credentials".to_string()),
                    days_offset: 7,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Wave 2 - Malware Simulation".to_string(),
                    description: Some("Second wave with attachment/link payloads".to_string()),
                    days_offset: 14,
                    is_required: true,
                },
                MilestoneTemplate {
                    name: "Analysis & Reporting".to_string(),
                    description: Some("Campaign metrics and training recommendations".to_string()),
                    days_offset: 21,
                    is_required: true,
                },
            ]),
            scan_config: None, // No network scanning for SE campaigns
        },
    ]
}

// ============================================================================
// Database Operations
// ============================================================================

/// Initialize built-in templates
pub async fn initialize_builtin_templates(pool: &SqlitePool) -> Result<()> {
    let builtin = get_builtin_templates();

    for template in builtin {
        // Check if template already exists
        let exists: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM engagement_templates WHERE name = ? AND is_system = 1"
        )
        .bind(&template.name)
        .fetch_one(pool)
        .await?;

        if exists.0 == 0 {
            create_template(pool, template, true).await?;
        }
    }

    Ok(())
}

/// Create a new engagement template
pub async fn create_template(
    pool: &SqlitePool,
    req: CreateTemplateRequest,
    is_system: bool,
) -> Result<EngagementTemplate> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let compliance_frameworks = req.compliance_frameworks
        .map(|f| serde_json::to_string(&f).unwrap_or_default());
    let milestones_template = req.milestones
        .map(|m| serde_json::to_string(&m).unwrap_or_default());
    let scan_config_template = req.scan_config
        .map(|s| serde_json::to_string(&s).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO engagement_templates (
            id, name, description, engagement_type, default_duration_days,
            default_budget, scope_template, compliance_frameworks,
            milestones_template, scan_config_template, is_system,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.engagement_type)
    .bind(req.default_duration_days)
    .bind(&req.default_budget)
    .bind(&req.scope_template)
    .bind(&compliance_frameworks)
    .bind(&milestones_template)
    .bind(&scan_config_template)
    .bind(is_system)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_template_by_id(pool, &id).await
}

/// Get template by ID
pub async fn get_template_by_id(pool: &SqlitePool, id: &str) -> Result<EngagementTemplate> {
    let template = sqlx::query_as::<_, EngagementTemplate>(
        "SELECT * FROM engagement_templates WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get all templates
pub async fn get_all_templates(pool: &SqlitePool) -> Result<Vec<EngagementTemplate>> {
    let templates = sqlx::query_as::<_, EngagementTemplate>(
        "SELECT * FROM engagement_templates ORDER BY is_system DESC, name ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get templates by type
pub async fn get_templates_by_type(
    pool: &SqlitePool,
    engagement_type: &str,
) -> Result<Vec<EngagementTemplate>> {
    let templates = sqlx::query_as::<_, EngagementTemplate>(
        "SELECT * FROM engagement_templates WHERE engagement_type = ? ORDER BY name"
    )
    .bind(engagement_type)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Delete a template (only non-system templates)
pub async fn delete_template(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM engagement_templates WHERE id = ? AND is_system = 0"
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Create an engagement from a template
pub async fn create_engagement_from_template(
    pool: &SqlitePool,
    req: CreateFromTemplateRequest,
) -> Result<EngagementSetupResult> {
    // Get the template
    let template = get_template_by_id(pool, &req.template_id).await?;

    // Calculate dates
    let start = req.start_date.clone().unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let end = req.end_date.clone().unwrap_or_else(|| {
        let start_date = chrono::NaiveDate::parse_from_str(&start, "%Y-%m-%d")
            .unwrap_or_else(|_| Utc::now().date_naive());
        let end_date = start_date + Duration::days(template.default_duration_days as i64);
        end_date.format("%Y-%m-%d").to_string()
    });

    // Create the engagement
    let engagement_req = CreateEngagementRequest {
        name: req.engagement_name,
        engagement_type: template.engagement_type.clone(),
        status: Some("planning".to_string()),
        scope: req.scope.or(template.scope_template),
        start_date: Some(start.clone()),
        end_date: Some(end),
        budget: req.budget.or(template.default_budget),
        notes: req.notes,
    };

    let engagement = create_engagement(pool, &req.customer_id, engagement_req).await?;

    // Create milestones if requested
    let mut milestones = Vec::new();
    if req.create_default_milestones {
        if let Some(ref milestones_json) = template.milestones_template {
            let milestone_templates: Vec<MilestoneTemplate> =
                serde_json::from_str(milestones_json).unwrap_or_default();

            let start_date = chrono::NaiveDate::parse_from_str(&start, "%Y-%m-%d")
                .unwrap_or_else(|_| Utc::now().date_naive());

            for mt in milestone_templates {
                let due_date = start_date + Duration::days(mt.days_offset as i64);

                let milestone = create_milestone(
                    pool,
                    &engagement.id,
                    CreateMilestoneRequest {
                        name: mt.name,
                        description: mt.description,
                        due_date: Some(due_date.format("%Y-%m-%d").to_string()),
                        status: Some("pending".to_string()),
                    },
                ).await?;

                milestones.push(milestone);
            }
        }
    }

    // Parse scan config if available
    let scan_config = template.scan_config_template
        .and_then(|json| serde_json::from_str(&json).ok());

    // TODO: Create portal user if requested
    let portal_user_created = false; // Would integrate with portal user creation

    Ok(EngagementSetupResult {
        engagement,
        milestones,
        portal_user_created,
        scan_config,
    })
}
