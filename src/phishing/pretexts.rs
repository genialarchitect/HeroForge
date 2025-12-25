//! Pretexting Templates
//!
//! Provides a library of pretexting scenarios for social engineering awareness
//! training and authorized penetration testing.
//!
//! # Security Notice
//!
//! These templates are intended for:
//! - Security awareness training programs
//! - Authorized penetration testing engagements
//! - Red team assessments with proper authorization
//!
//! Unauthorized social engineering is illegal. Always obtain proper authorization.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pretext category for organizing templates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PretextCategory {
    /// IT Support pretexts (password reset, software update, security incident)
    ItSupport,
    /// HR pretexts (benefits enrollment, policy update, survey)
    HumanResources,
    /// Executive pretexts (urgent wire transfer, confidential project)
    Executive,
    /// Vendor pretexts (invoice verification, contract renewal)
    Vendor,
    /// Tech Support pretexts (computer virus, subscription expiring)
    TechSupport,
    /// Financial pretexts (tax, banking, payroll)
    Financial,
    /// Delivery pretexts (package delivery, shipping issues)
    Delivery,
    /// Legal pretexts (compliance, legal notice)
    Legal,
    /// Custom category
    Custom,
}

impl std::fmt::Display for PretextCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PretextCategory::ItSupport => write!(f, "it_support"),
            PretextCategory::HumanResources => write!(f, "human_resources"),
            PretextCategory::Executive => write!(f, "executive"),
            PretextCategory::Vendor => write!(f, "vendor"),
            PretextCategory::TechSupport => write!(f, "tech_support"),
            PretextCategory::Financial => write!(f, "financial"),
            PretextCategory::Delivery => write!(f, "delivery"),
            PretextCategory::Legal => write!(f, "legal"),
            PretextCategory::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for PretextCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "it_support" => Ok(PretextCategory::ItSupport),
            "human_resources" | "hr" => Ok(PretextCategory::HumanResources),
            "executive" => Ok(PretextCategory::Executive),
            "vendor" => Ok(PretextCategory::Vendor),
            "tech_support" => Ok(PretextCategory::TechSupport),
            "financial" => Ok(PretextCategory::Financial),
            "delivery" => Ok(PretextCategory::Delivery),
            "legal" => Ok(PretextCategory::Legal),
            "custom" => Ok(PretextCategory::Custom),
            _ => Err(format!("Unknown pretext category: {}", s)),
        }
    }
}

/// Difficulty level for pretext execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PretextDifficulty {
    /// Easy - simple, common scenarios
    Easy,
    /// Medium - requires some social engineering skill
    Medium,
    /// Hard - complex scenarios requiring rapport building
    Hard,
    /// Expert - sophisticated multi-stage pretexts
    Expert,
}

impl std::fmt::Display for PretextDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PretextDifficulty::Easy => write!(f, "easy"),
            PretextDifficulty::Medium => write!(f, "medium"),
            PretextDifficulty::Hard => write!(f, "hard"),
            PretextDifficulty::Expert => write!(f, "expert"),
        }
    }
}

impl std::str::FromStr for PretextDifficulty {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "easy" => Ok(PretextDifficulty::Easy),
            "medium" => Ok(PretextDifficulty::Medium),
            "hard" => Ok(PretextDifficulty::Hard),
            "expert" => Ok(PretextDifficulty::Expert),
            _ => Err(format!("Unknown difficulty: {}", s)),
        }
    }
}

/// Pretext template for social engineering scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PretextTemplate {
    /// Unique identifier
    pub id: String,
    /// User ID who created the template (None for built-in)
    pub user_id: Option<String>,
    /// Template name
    pub name: String,
    /// Template description
    pub description: String,
    /// Category of the pretext
    pub category: PretextCategory,
    /// Difficulty level
    pub difficulty: PretextDifficulty,
    /// The scenario description - what situation is being simulated
    pub scenario: String,
    /// Primary objectives of the pretext
    pub objectives: Vec<String>,
    /// Call script with suggested dialogue
    pub script: PretextScript,
    /// Required information before executing pretext
    pub prerequisites: Vec<String>,
    /// Success indicators
    pub success_criteria: Vec<String>,
    /// Red flags that might trigger suspicion
    pub red_flags: Vec<String>,
    /// Tips for executing the pretext effectively
    pub tips: Vec<String>,
    /// Tags for searching
    pub tags: Vec<String>,
    /// Whether this is a built-in template
    pub is_builtin: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Script structure for pretext scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PretextScript {
    /// Opening statement/greeting
    pub opening: String,
    /// Key talking points
    pub talking_points: Vec<String>,
    /// Common objections and how to handle them
    pub objection_handling: HashMap<String, String>,
    /// Information to gather during the call
    pub information_to_gather: Vec<String>,
    /// Closing statement
    pub closing: String,
    /// Follow-up actions
    pub follow_up: Option<String>,
}

/// Request to create a custom pretext template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePretextRequest {
    pub name: String,
    pub description: String,
    pub category: PretextCategory,
    pub difficulty: Option<PretextDifficulty>,
    pub scenario: String,
    pub objectives: Vec<String>,
    pub script: PretextScript,
    pub prerequisites: Option<Vec<String>>,
    pub success_criteria: Option<Vec<String>>,
    pub red_flags: Option<Vec<String>>,
    pub tips: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

/// Built-in pretext templates library
pub struct PretextLibrary;

impl PretextLibrary {
    /// Get all built-in pretext templates
    pub fn get_all() -> Vec<PretextTemplate> {
        let now = Utc::now();
        vec![
            // IT Support Category
            Self::password_reset_pretext(now),
            Self::software_update_pretext(now),
            Self::security_incident_pretext(now),
            Self::new_employee_setup_pretext(now),
            Self::vpn_troubleshooting_pretext(now),
            // HR Category
            Self::benefits_enrollment_pretext(now),
            Self::policy_update_pretext(now),
            Self::employee_survey_pretext(now),
            Self::payroll_verification_pretext(now),
            // Executive Category
            Self::urgent_wire_transfer_pretext(now),
            Self::confidential_project_pretext(now),
            Self::executive_assistant_pretext(now),
            // Vendor Category
            Self::invoice_verification_pretext(now),
            Self::contract_renewal_pretext(now),
            Self::vendor_audit_pretext(now),
            // Tech Support Category
            Self::computer_virus_pretext(now),
            Self::subscription_expiring_pretext(now),
            Self::software_license_pretext(now),
            // Financial Category
            Self::tax_document_pretext(now),
            Self::banking_verification_pretext(now),
            // Delivery Category
            Self::package_delivery_pretext(now),
            // Legal Category
            Self::compliance_audit_pretext(now),
        ]
    }

    /// Get templates by category
    pub fn get_by_category(category: &PretextCategory) -> Vec<PretextTemplate> {
        Self::get_all()
            .into_iter()
            .filter(|t| &t.category == category)
            .collect()
    }

    /// Get template by ID
    pub fn get_by_id(id: &str) -> Option<PretextTemplate> {
        Self::get_all().into_iter().find(|t| t.id == id)
    }

    // =========================================================================
    // IT Support Pretexts
    // =========================================================================

    fn password_reset_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-it-password-reset".to_string(),
            user_id: None,
            name: "IT Help Desk - Password Reset".to_string(),
            description: "Caller poses as IT help desk requesting password verification or reset assistance".to_string(),
            category: PretextCategory::ItSupport,
            difficulty: PretextDifficulty::Easy,
            scenario: "An IT help desk technician calls about a password reset request that was allegedly submitted. The goal is to gather credentials or get the target to reveal security information.".to_string(),
            objectives: vec![
                "Obtain current password or get user to change to attacker-controlled password".to_string(),
                "Gather security question answers".to_string(),
                "Confirm employee ID or other identifying information".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from the IT Help Desk. I'm calling about a password reset request that was submitted from your account. Did you submit a request today?".to_string(),
                talking_points: vec![
                    "We received a password reset request and need to verify it's legitimate".to_string(),
                    "For security purposes, I need to verify some information".to_string(),
                    "I can help you complete the reset right now to save you time".to_string(),
                    "Our system shows some suspicious activity on your account".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I didn't submit a request".to_string(),
                     "That's concerning - someone may have tried to access your account. Let me help secure it right away. Can you verify your current password so I can check if it's been compromised?".to_string()),
                    ("I'll call you back".to_string(),
                     "I understand, but this is time-sensitive. Our records show potential unauthorized access. If you want, I can give you my direct extension and employee ID for verification.".to_string()),
                    ("What's your employee ID?".to_string(),
                     "Of course, it's [fabricated ID]. You can also verify me in the company directory under IT Support.".to_string()),
                ]),
                information_to_gather: vec![
                    "Current password".to_string(),
                    "Employee ID".to_string(),
                    "Department and manager name".to_string(),
                    "Security question answers".to_string(),
                    "Typical working hours".to_string(),
                ],
                closing: "Great, I've noted your information. I'll complete the security check and send you a confirmation email. If you have any issues, call the main help desk number.".to_string(),
                follow_up: Some("Send a follow-up email appearing to be from IT with a malicious link".to_string()),
            },
            prerequisites: vec![
                "Target's name and department".to_string(),
                "Company's IT help desk naming convention".to_string(),
                "General knowledge of company's password policies".to_string(),
            ],
            success_criteria: vec![
                "Obtained password or password hint".to_string(),
                "Gathered security question answers".to_string(),
                "Target agreed to click a link or install software".to_string(),
            ],
            red_flags: vec![
                "Target asks to verify through official channels".to_string(),
                "Target requests callback number verification".to_string(),
                "Target asks for supervisor contact".to_string(),
            ],
            tips: vec![
                "Use urgency but don't be pushy".to_string(),
                "Have realistic background noise if possible".to_string(),
                "Know the company's actual IT support structure".to_string(),
                "Be prepared to provide fake employee ID".to_string(),
            ],
            tags: vec!["password".to_string(), "credentials".to_string(), "help desk".to_string(), "it".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn software_update_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-it-software-update".to_string(),
            user_id: None,
            name: "IT Help Desk - Critical Software Update".to_string(),
            description: "Caller poses as IT requesting urgent software update installation".to_string(),
            category: PretextCategory::ItSupport,
            difficulty: PretextDifficulty::Medium,
            scenario: "An IT technician calls about a critical security patch that must be installed immediately. The goal is to get the user to download and install malware.".to_string(),
            objectives: vec![
                "Get user to download and run a file".to_string(),
                "Obtain remote access to the target's computer".to_string(),
                "Gather system information".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from IT. We're rolling out a critical security update and I'm calling to help you install it. This is mandatory for all employees.".to_string(),
                talking_points: vec![
                    "A critical vulnerability has been discovered that affects all Windows computers".to_string(),
                    "Management has mandated this update be completed by end of day".to_string(),
                    "I can walk you through the installation - it only takes a few minutes".to_string(),
                    "If you don't install this, your computer may be blocked from the network".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I'll wait for the regular update cycle".to_string(),
                     "Unfortunately, this can't wait. We've already seen compromises in other departments. I need to help you get this done now.".to_string()),
                    ("Can you send me a link instead?".to_string(),
                     "Absolutely, what's your email? I'll send the download link right now and stay on the line to help you through the installation.".to_string()),
                    ("I need to check with my manager".to_string(),
                     "Your manager should have received the memo from IT leadership. This is company-wide and time-sensitive. I can provide the ticket number if that helps.".to_string()),
                ]),
                information_to_gather: vec![
                    "Operating system version".to_string(),
                    "Antivirus software in use".to_string(),
                    "Whether user has admin rights".to_string(),
                    "Network access level".to_string(),
                ],
                closing: "Perfect, the update is installing. You might see some prompts - just click 'Allow' or 'Yes' to everything. I'll check back in 10 minutes to make sure everything is working.".to_string(),
                follow_up: Some("Send malicious 'update' file via email".to_string()),
            },
            prerequisites: vec![
                "Knowledge of company's update procedures".to_string(),
                "Understanding of target's operating system".to_string(),
                "Prepared malware package or test file".to_string(),
            ],
            success_criteria: vec![
                "Target downloaded and executed file".to_string(),
                "Target provided admin credentials".to_string(),
                "Obtained remote access to system".to_string(),
            ],
            red_flags: vec![
                "Target refuses to download anything".to_string(),
                "Target escalates to IT management".to_string(),
                "Target recognizes social engineering attempt".to_string(),
            ],
            tips: vec![
                "Reference real recent vulnerabilities for credibility".to_string(),
                "Have a legitimate-looking download ready".to_string(),
                "Use technical jargon appropriately".to_string(),
                "Create urgency without causing panic".to_string(),
            ],
            tags: vec!["software".to_string(), "update".to_string(), "malware".to_string(), "installation".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn security_incident_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-it-security-incident".to_string(),
            user_id: None,
            name: "IT Security - Active Breach Investigation".to_string(),
            description: "Caller poses as IT Security investigating an active security incident".to_string(),
            category: PretextCategory::ItSupport,
            difficulty: PretextDifficulty::Hard,
            scenario: "An IT Security team member calls urgently about an active breach, creating fear and urgency to bypass normal verification procedures.".to_string(),
            objectives: vec![
                "Obtain credentials under guise of investigation".to_string(),
                "Get remote access for 'forensic analysis'".to_string(),
                "Gather information about security controls".to_string(),
            ],
            script: PretextScript {
                opening: "This is [Name] from the IT Security team. I'm calling about a serious matter - we've detected unauthorized access to your account and I need your immediate cooperation.".to_string(),
                talking_points: vec![
                    "We detected login attempts from an unusual location - possibly overseas".to_string(),
                    "Your credentials may have been compromised in a data breach".to_string(),
                    "I need to verify it's really you and not the attacker".to_string(),
                    "This is time-critical - the attacker may be accessing systems right now".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("How do I know you're really from IT?".to_string(),
                     "I completely understand your caution - that's exactly the right instinct. Here's my employee ID: [fake ID]. I can also have my manager call you back on your desk phone if that helps.".to_string()),
                    ("I want to verify this through official channels".to_string(),
                     "Normally that's the right approach, but every minute we delay, the attacker could be accessing more sensitive data. Can we at least change your password immediately while you verify?".to_string()),
                ]),
                information_to_gather: vec![
                    "Current password for 'verification'".to_string(),
                    "Recent login times and locations".to_string(),
                    "What systems the user has access to".to_string(),
                    "Security software in use".to_string(),
                ],
                closing: "Thank you for your cooperation. I've flagged your account for monitoring. You should receive a follow-up email from our team. Please don't share details of this call as it's an ongoing investigation.".to_string(),
                follow_up: Some("Send phishing email posing as security team follow-up".to_string()),
            },
            prerequisites: vec![
                "Basic knowledge of company's security team structure".to_string(),
                "Recent security incidents to reference".to_string(),
                "Understanding of company's incident response procedures".to_string(),
            ],
            success_criteria: vec![
                "Target disclosed credentials".to_string(),
                "Target allowed remote access".to_string(),
                "Target revealed security control information".to_string(),
            ],
            red_flags: vec![
                "Target insists on calling back through switchboard".to_string(),
                "Target reports call to actual IT Security".to_string(),
            ],
            tips: vec![
                "Sound urgent but professional".to_string(),
                "Use security terminology correctly".to_string(),
                "Create fear without panic".to_string(),
                "Emphasize confidentiality to prevent verification".to_string(),
            ],
            tags: vec!["security".to_string(), "incident".to_string(), "breach".to_string(), "investigation".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn new_employee_setup_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-it-new-employee".to_string(),
            user_id: None,
            name: "IT Help Desk - New Employee Verification".to_string(),
            description: "Caller poses as IT verifying new employee setup".to_string(),
            category: PretextCategory::ItSupport,
            difficulty: PretextDifficulty::Easy,
            scenario: "An IT technician calls to verify account setup for a 'new employee', gathering information about the target or asking them to assist with verification.".to_string(),
            objectives: vec![
                "Gather organizational structure information".to_string(),
                "Identify system access patterns".to_string(),
                "Build relationship for follow-up attacks".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from IT. I'm setting up a new employee who will be joining your department and I need to verify a few things about the standard configuration.".to_string(),
                talking_points: vec![
                    "I want to make sure the new person has the right access from day one".to_string(),
                    "Can you tell me what systems your department typically uses?".to_string(),
                    "Who should I contact for approval of access requests?".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("Who's the new employee?".to_string(),
                     "I have them listed as [name] starting next week. Your manager should have the details.".to_string()),
                    ("Check with HR".to_string(),
                     "I already coordinated with HR, they told me to contact someone in your department for the technical details.".to_string()),
                ]),
                information_to_gather: vec![
                    "Systems and applications used by department".to_string(),
                    "Manager and team structure".to_string(),
                    "Standard access levels".to_string(),
                    "Shared resources and drive mappings".to_string(),
                ],
                closing: "This is really helpful. I'll get everything configured. If the new person has any issues, they may reach out to you for help in their first week.".to_string(),
                follow_up: Some("Use gathered info for more targeted attacks".to_string()),
            },
            prerequisites: vec![
                "Target department information".to_string(),
                "Plausible new employee name".to_string(),
            ],
            success_criteria: vec![
                "Mapped department systems and access".to_string(),
                "Identified key personnel".to_string(),
            ],
            red_flags: vec![
                "Target verifies with HR".to_string(),
                "Target asks for ticket number".to_string(),
            ],
            tips: vec![
                "Be friendly and conversational".to_string(),
                "Make it feel like helping a colleague".to_string(),
            ],
            tags: vec!["reconnaissance".to_string(), "new hire".to_string(), "information gathering".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn vpn_troubleshooting_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-it-vpn-troubleshooting".to_string(),
            user_id: None,
            name: "IT Help Desk - VPN Troubleshooting".to_string(),
            description: "Caller poses as IT helping troubleshoot VPN connectivity issues".to_string(),
            category: PretextCategory::ItSupport,
            difficulty: PretextDifficulty::Medium,
            scenario: "An IT technician calls about reported VPN issues, using the opportunity to gather credentials or install remote access tools.".to_string(),
            objectives: vec![
                "Obtain VPN credentials".to_string(),
                "Install remote access software".to_string(),
                "Map network access".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from IT. We're seeing some VPN connection issues on our end and your account was flagged. Are you having any trouble connecting remotely?".to_string(),
                talking_points: vec![
                    "We're updating our VPN infrastructure and some accounts need reconfiguration".to_string(),
                    "I can help you update your VPN settings right now".to_string(),
                    "I'll need your current credentials to test the new configuration".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("My VPN is working fine".to_string(),
                     "That's good, but the backend changes might affect you soon. Let me verify your configuration to prevent future issues.".to_string()),
                ]),
                information_to_gather: vec![
                    "VPN credentials".to_string(),
                    "VPN client version".to_string(),
                    "Remote access patterns".to_string(),
                ],
                closing: "Great, I've updated your configuration. You should be all set. If you have any issues, call the help desk.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Knowledge of company's VPN solution".to_string(),
                "Target's remote work status".to_string(),
            ],
            success_criteria: vec![
                "Obtained VPN credentials".to_string(),
                "Installed remote access tool".to_string(),
            ],
            red_flags: vec![
                "Target refuses to share credentials over phone".to_string(),
            ],
            tips: vec![
                "Know the specific VPN product the company uses".to_string(),
                "Have realistic troubleshooting steps ready".to_string(),
            ],
            tags: vec!["vpn".to_string(), "remote access".to_string(), "credentials".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // HR Category Pretexts
    // =========================================================================

    fn benefits_enrollment_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-hr-benefits".to_string(),
            user_id: None,
            name: "HR - Open Enrollment Benefits Update".to_string(),
            description: "Caller poses as HR representative helping with benefits enrollment".to_string(),
            category: PretextCategory::HumanResources,
            difficulty: PretextDifficulty::Easy,
            scenario: "An HR representative calls about open enrollment, requesting personal information to 'update records' or 'process elections'.".to_string(),
            objectives: vec![
                "Gather personal identifiable information (PII)".to_string(),
                "Obtain SSN or partial SSN".to_string(),
                "Get bank account information for 'direct deposit'".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from Human Resources. I'm calling about the open enrollment period that ends this week. We need to verify your information before we can process your elections.".to_string(),
                talking_points: vec![
                    "Open enrollment ends Friday and we need to finalize your selections".to_string(),
                    "I need to verify your personal information for the insurance carrier".to_string(),
                    "There's a new HSA option that requires updated banking information".to_string(),
                    "If we don't update this, you may lose your current coverage".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I already completed enrollment online".to_string(),
                     "I see that, but there's a discrepancy in our records. I just need to verify a few things to make sure everything matches.".to_string()),
                    ("I'll come to HR in person".to_string(),
                     "That works too, but the deadline is tomorrow. I can take care of it right now over the phone if that's easier.".to_string()),
                ]),
                information_to_gather: vec![
                    "Full legal name and date of birth".to_string(),
                    "Social Security Number".to_string(),
                    "Home address".to_string(),
                    "Bank account and routing numbers".to_string(),
                    "Dependent information".to_string(),
                ],
                closing: "Perfect, I've updated your records. You'll receive a confirmation email within 24 hours. If you don't see it, just reply to this call.".to_string(),
                follow_up: Some("Send phishing email with 'benefits confirmation' link".to_string()),
            },
            prerequisites: vec![
                "Knowledge of company's benefits provider".to_string(),
                "Timing around actual open enrollment".to_string(),
            ],
            success_criteria: vec![
                "Obtained SSN".to_string(),
                "Gathered banking information".to_string(),
                "Collected dependent PII".to_string(),
            ],
            red_flags: vec![
                "Target asks to use online portal instead".to_string(),
                "Target refuses to provide SSN over phone".to_string(),
            ],
            tips: vec![
                "Time this during actual enrollment periods".to_string(),
                "Reference real benefits provider names".to_string(),
                "Create urgency with deadlines".to_string(),
            ],
            tags: vec!["hr".to_string(), "benefits".to_string(), "pii".to_string(), "enrollment".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn policy_update_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-hr-policy".to_string(),
            user_id: None,
            name: "HR - Policy Acknowledgment Required".to_string(),
            description: "Caller poses as HR requiring policy acknowledgment".to_string(),
            category: PretextCategory::HumanResources,
            difficulty: PretextDifficulty::Easy,
            scenario: "HR calls about new policies requiring acknowledgment, directing user to a malicious link or gathering credentials.".to_string(),
            objectives: vec![
                "Direct user to phishing page".to_string(),
                "Gather employee credentials".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from HR. We've updated our security and acceptable use policies, and all employees need to review and acknowledge them by end of day.".to_string(),
                talking_points: vec![
                    "This is mandatory for all employees".to_string(),
                    "I'll send you the link right now - you'll need to log in to acknowledge".to_string(),
                    "Failure to complete may affect your network access".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I'll do it later".to_string(),
                     "I understand you're busy, but compliance has a hard deadline. It only takes 2 minutes. I can stay on the line while you do it.".to_string()),
                ]),
                information_to_gather: vec![
                    "Work email".to_string(),
                    "Credentials through phishing page".to_string(),
                ],
                closing: "Thank you for taking care of this. You should see a confirmation once you complete the acknowledgment.".to_string(),
                follow_up: Some("Send phishing link for policy portal".to_string()),
            },
            prerequisites: vec![
                "Target's email address".to_string(),
                "Phishing page ready".to_string(),
            ],
            success_criteria: vec![
                "Target clicked phishing link".to_string(),
                "Credentials captured".to_string(),
            ],
            red_flags: vec![
                "Target navigates to portal directly instead of using link".to_string(),
            ],
            tips: vec![
                "Reference real recent policy changes if known".to_string(),
                "Use urgency around compliance deadlines".to_string(),
            ],
            tags: vec!["hr".to_string(), "policy".to_string(), "phishing".to_string(), "compliance".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn employee_survey_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-hr-survey".to_string(),
            user_id: None,
            name: "HR - Employee Satisfaction Survey".to_string(),
            description: "Caller conducts a fake employee survey to gather information".to_string(),
            category: PretextCategory::HumanResources,
            difficulty: PretextDifficulty::Easy,
            scenario: "HR conducts a phone survey about employee satisfaction, using it to gather information about security practices and internal processes.".to_string(),
            objectives: vec![
                "Gather information about internal processes".to_string(),
                "Identify security weaknesses through casual conversation".to_string(),
                "Build rapport for future attacks".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from HR. We're conducting our annual employee satisfaction survey. Do you have 5 minutes to answer a few questions?".to_string(),
                talking_points: vec![
                    "Your responses are completely confidential".to_string(),
                    "We want to understand how employees feel about company tools and processes".to_string(),
                    "This helps us improve the work environment".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I'm too busy".to_string(),
                     "I completely understand. When would be a better time to call back? This only takes about 5 minutes.".to_string()),
                ]),
                information_to_gather: vec![
                    "Software and tools used daily".to_string(),
                    "Security training received".to_string(),
                    "Remote work setup".to_string(),
                    "Team structure and reporting".to_string(),
                ],
                closing: "Thank you so much for your feedback. This is really valuable. You may receive a follow-up email with additional questions.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Target's name and department".to_string(),
            ],
            success_criteria: vec![
                "Gathered organizational intelligence".to_string(),
                "Identified security gaps".to_string(),
            ],
            red_flags: vec![
                "Target asks for survey ID or verification".to_string(),
            ],
            tips: vec![
                "Keep questions casual and non-threatening".to_string(),
                "Mix reconnaissance questions with legitimate-sounding ones".to_string(),
            ],
            tags: vec!["hr".to_string(), "survey".to_string(), "reconnaissance".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn payroll_verification_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-hr-payroll".to_string(),
            user_id: None,
            name: "HR/Payroll - Direct Deposit Verification".to_string(),
            description: "Caller poses as payroll verifying banking information".to_string(),
            category: PretextCategory::HumanResources,
            difficulty: PretextDifficulty::Medium,
            scenario: "Payroll department calls about a 'failed' direct deposit or system migration requiring banking verification.".to_string(),
            objectives: vec![
                "Obtain bank account information".to_string(),
                "Gather SSN for 'verification'".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from Payroll. We had an issue processing your last direct deposit and I need to verify your banking information.".to_string(),
                talking_points: vec![
                    "Our banking system was upgraded and some accounts need reverification".to_string(),
                    "I just need to confirm your routing and account numbers".to_string(),
                    "This will ensure your next paycheck goes through without issues".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I got paid fine".to_string(),
                     "That's good to hear, but we still need to update our records to prevent future issues with the new system.".to_string()),
                ]),
                information_to_gather: vec![
                    "Bank name".to_string(),
                    "Routing number".to_string(),
                    "Account number".to_string(),
                    "Last 4 of SSN".to_string(),
                ],
                closing: "Perfect, I've updated your records. Your next deposit should process normally.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Knowledge of pay schedule".to_string(),
            ],
            success_criteria: vec![
                "Obtained banking information".to_string(),
            ],
            red_flags: vec![
                "Target offers to come to HR in person".to_string(),
                "Target asks to update through employee portal".to_string(),
            ],
            tips: vec![
                "Time around pay dates for credibility".to_string(),
                "Know the company's actual payroll provider".to_string(),
            ],
            tags: vec!["payroll".to_string(), "banking".to_string(), "pii".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // Executive Category Pretexts
    // =========================================================================

    fn urgent_wire_transfer_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-exec-wire-transfer".to_string(),
            user_id: None,
            name: "Executive - Urgent Wire Transfer Request".to_string(),
            description: "Caller impersonates executive requesting urgent wire transfer".to_string(),
            category: PretextCategory::Executive,
            difficulty: PretextDifficulty::Expert,
            scenario: "Someone impersonates a senior executive (CEO, CFO) urgently requesting a wire transfer for a confidential acquisition or deal.".to_string(),
            objectives: vec![
                "Initiate fraudulent wire transfer".to_string(),
                "Bypass normal approval processes using executive authority".to_string(),
            ],
            script: PretextScript {
                opening: "Hi [Name], this is [Executive Name]. I'm in meetings all day but I need your help with something urgent and confidential.".to_string(),
                talking_points: vec![
                    "We're finalizing an acquisition and I need a wire transfer processed today".to_string(),
                    "This needs to stay confidential until the deal is announced".to_string(),
                    "I can't go through normal channels because of the sensitivity".to_string(),
                    "I'm counting on you to handle this discreetly".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I need manager approval".to_string(),
                     "I am giving you authorization directly. This is too sensitive to involve others. I'll send you email confirmation after I finish these meetings.".to_string()),
                    ("Can I call you back?".to_string(),
                     "I'm between meetings and my phone is going straight to voicemail. Just process this and I'll follow up with documentation today.".to_string()),
                ]),
                information_to_gather: vec![
                    "Wire transfer procedures".to_string(),
                    "Approval limits".to_string(),
                    "Verification requirements".to_string(),
                ],
                closing: "I appreciate you handling this. Remember, complete confidentiality until the announcement. I'll send you the confirmation as soon as I'm out of meetings.".to_string(),
                follow_up: Some("Send spoofed email from executive to reinforce request".to_string()),
            },
            prerequisites: vec![
                "Executive's name and communication style".to_string(),
                "Target's role in financial processes".to_string(),
                "Knowledge of approval thresholds".to_string(),
            ],
            success_criteria: vec![
                "Wire transfer initiated".to_string(),
                "Normal approval process bypassed".to_string(),
            ],
            red_flags: vec![
                "Target insists on callback to known number".to_string(),
                "Target requires documented approval".to_string(),
                "Target contacts executive's assistant".to_string(),
            ],
            tips: vec![
                "Study executive's communication patterns".to_string(),
                "Create urgency with deal deadlines".to_string(),
                "Emphasize confidentiality to prevent verification".to_string(),
                "Know typical wire amounts that don't trigger extra scrutiny".to_string(),
            ],
            tags: vec!["executive".to_string(), "bec".to_string(), "wire fraud".to_string(), "financial".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn confidential_project_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-exec-confidential".to_string(),
            user_id: None,
            name: "Executive - Confidential Project".to_string(),
            description: "Caller claims to work on a confidential executive project".to_string(),
            category: PretextCategory::Executive,
            difficulty: PretextDifficulty::Hard,
            scenario: "Someone claims to be working on a highly confidential project for the CEO/executive, requesting access or information that bypasses normal procedures.".to_string(),
            objectives: vec![
                "Gain unauthorized access to systems or data".to_string(),
                "Obtain confidential information".to_string(),
                "Bypass normal verification procedures".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name]. I'm a consultant working directly with [Executive] on Project Phoenix. I need some information from your department.".to_string(),
                talking_points: vec![
                    "This is a highly confidential initiative".to_string(),
                    "[Executive] personally asked me to contact you".to_string(),
                    "We need to move quickly on this".to_string(),
                    "Please don't discuss this with others".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I need to verify this".to_string(),
                     "[Executive] specifically asked to keep this under wraps. If you need to verify, please email them directly but mention it's regarding Phoenix.".to_string()),
                ]),
                information_to_gather: vec![
                    "Sensitive business information".to_string(),
                    "System access credentials".to_string(),
                    "Internal processes and procedures".to_string(),
                ],
                closing: "Thank you for your cooperation. Remember, this stays between us. [Executive] appreciates your discretion.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Executive's name and reputation".to_string(),
                "Knowledge of company structure".to_string(),
            ],
            success_criteria: vec![
                "Obtained sensitive information".to_string(),
                "Gained system access".to_string(),
            ],
            red_flags: vec![
                "Target verifies with executive".to_string(),
                "Target requests written authorization".to_string(),
            ],
            tips: vec![
                "Use realistic project codenames".to_string(),
                "Leverage executive authority and secrecy".to_string(),
            ],
            tags: vec!["executive".to_string(), "confidential".to_string(), "social engineering".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn executive_assistant_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-exec-assistant".to_string(),
            user_id: None,
            name: "Executive Assistant - Urgent Request".to_string(),
            description: "Caller poses as executive's assistant with urgent request".to_string(),
            category: PretextCategory::Executive,
            difficulty: PretextDifficulty::Medium,
            scenario: "The executive's assistant calls on their behalf with an urgent request, leveraging the implied authority.".to_string(),
            objectives: vec![
                "Obtain information on behalf of 'executive'".to_string(),
                "Request actions with implied executive authority".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name], I'm [Executive]'s assistant. They've asked me to follow up on something urgent.".to_string(),
                talking_points: vec![
                    "[Executive] is in back-to-back meetings but needs this handled now".to_string(),
                    "They specifically asked me to contact you".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("Can I speak to [Executive] directly?".to_string(),
                     "They're unavailable until this evening. I can have them call you tomorrow, but this really can't wait.".to_string()),
                ]),
                information_to_gather: vec![
                    "Target-specific based on request".to_string(),
                ],
                closing: "Thank you, I'll let [Executive] know this is handled. They really appreciate it.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Executive and assistant names".to_string(),
                "Executive's schedule patterns".to_string(),
            ],
            success_criteria: vec![
                "Request completed without verification".to_string(),
            ],
            red_flags: vec![
                "Target asks for callback number".to_string(),
            ],
            tips: vec![
                "Know the actual assistant's name and voice".to_string(),
                "Reference real meetings or travel".to_string(),
            ],
            tags: vec!["executive".to_string(), "assistant".to_string(), "authority".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // Vendor Category Pretexts
    // =========================================================================

    fn invoice_verification_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-vendor-invoice".to_string(),
            user_id: None,
            name: "Vendor - Invoice Verification".to_string(),
            description: "Caller poses as vendor verifying invoice details".to_string(),
            category: PretextCategory::Vendor,
            difficulty: PretextDifficulty::Medium,
            scenario: "A vendor calls to 'verify' an invoice, gathering payment process information or attempting to redirect payments.".to_string(),
            objectives: vec![
                "Gather accounts payable procedures".to_string(),
                "Redirect payments to attacker-controlled accounts".to_string(),
                "Identify key personnel in payment process".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Vendor Company] accounts receivable. I'm calling about invoice #[number] - we show it as outstanding and wanted to check on the payment status.".to_string(),
                talking_points: vec![
                    "Our records show this invoice is past due".to_string(),
                    "I want to make sure you have our correct banking information".to_string(),
                    "We've recently changed banks and want to confirm you have our new details".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("Let me check our records".to_string(),
                     "Sure, I'll hold. While you're looking, can you confirm the account we're set up under?".to_string()),
                    ("We'll need updated W-9 and banking info in writing".to_string(),
                     "Absolutely, I can send that over. What email should I use?".to_string()),
                ]),
                information_to_gather: vec![
                    "Payment procedures".to_string(),
                    "Payment timeline".to_string(),
                    "Accounts payable contact names".to_string(),
                    "Verification requirements for vendor changes".to_string(),
                ],
                closing: "Thank you for your help. I'll send over updated banking information today. Please process the payment to our new account.".to_string(),
                follow_up: Some("Send fraudulent banking update letter".to_string()),
            },
            prerequisites: vec![
                "Actual vendor name company uses".to_string(),
                "Approximate invoice amounts".to_string(),
            ],
            success_criteria: vec![
                "Payment redirected to new account".to_string(),
                "Mapped payment procedures".to_string(),
            ],
            red_flags: vec![
                "Target requires formal vendor change process".to_string(),
                "Target calls vendor at known number".to_string(),
            ],
            tips: vec![
                "Research actual vendors the company uses".to_string(),
                "Use realistic invoice numbers and amounts".to_string(),
            ],
            tags: vec!["vendor".to_string(), "invoice".to_string(), "payment fraud".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn contract_renewal_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-vendor-contract".to_string(),
            user_id: None,
            name: "Vendor - Contract Renewal".to_string(),
            description: "Caller poses as vendor regarding contract renewal".to_string(),
            category: PretextCategory::Vendor,
            difficulty: PretextDifficulty::Medium,
            scenario: "A vendor calls about an upcoming contract renewal, gathering information about internal processes and decision makers.".to_string(),
            objectives: vec![
                "Identify procurement decision makers".to_string(),
                "Gather competitive intelligence".to_string(),
                "Build rapport for future attacks".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Vendor]. Your contract is up for renewal next quarter and I wanted to discuss your needs.".to_string(),
                talking_points: vec![
                    "We want to make sure you're getting the best value".to_string(),
                    "Are there any pain points we should address?".to_string(),
                    "Who else should I include in renewal discussions?".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("Contact our procurement team".to_string(),
                     "I will, but I wanted to get end-user feedback first. Who in procurement handles your contracts?".to_string()),
                ]),
                information_to_gather: vec![
                    "Procurement contacts".to_string(),
                    "Contract values".to_string(),
                    "Competitive solutions in use".to_string(),
                ],
                closing: "I appreciate your input. I'll reach out to your procurement team. Can I mention our conversation?".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Vendor name and general service type".to_string(),
            ],
            success_criteria: vec![
                "Identified key decision makers".to_string(),
                "Gathered procurement process information".to_string(),
            ],
            red_flags: vec![
                "Target redirects to formal channels only".to_string(),
            ],
            tips: vec![
                "Research the actual vendor relationship".to_string(),
                "Ask open-ended questions".to_string(),
            ],
            tags: vec!["vendor".to_string(), "contract".to_string(), "reconnaissance".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn vendor_audit_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-vendor-audit".to_string(),
            user_id: None,
            name: "Vendor - Security Audit Requirements".to_string(),
            description: "Caller poses as vendor requiring security audit information".to_string(),
            category: PretextCategory::Vendor,
            difficulty: PretextDifficulty::Hard,
            scenario: "A vendor's security/compliance team calls requesting information for their annual audit, gathering security details.".to_string(),
            objectives: vec![
                "Gather security control information".to_string(),
                "Map authentication mechanisms".to_string(),
                "Identify security tools in use".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Vendor] Security. We're conducting our annual vendor security review and need to verify some controls on your end.".to_string(),
                talking_points: vec![
                    "This is required for our SOC 2 compliance".to_string(),
                    "We need to document the security of our integration points".to_string(),
                    "Can you tell me about your authentication and access controls?".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("Send a formal request".to_string(),
                     "I can do that. What's the best email? I just wanted to give you a heads up first.".to_string()),
                ]),
                information_to_gather: vec![
                    "Security tools and controls".to_string(),
                    "Authentication mechanisms".to_string(),
                    "Network security measures".to_string(),
                ],
                closing: "Thank you for the information. I'll document this for our audit file.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Knowledge of vendor's products/services".to_string(),
            ],
            success_criteria: vec![
                "Gathered security architecture details".to_string(),
            ],
            red_flags: vec![
                "Target escalates to security team".to_string(),
            ],
            tips: vec![
                "Use legitimate compliance frameworks as cover".to_string(),
                "Be knowledgeable about security concepts".to_string(),
            ],
            tags: vec!["vendor".to_string(), "audit".to_string(), "security".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // Tech Support Category Pretexts
    // =========================================================================

    fn computer_virus_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-tech-virus".to_string(),
            user_id: None,
            name: "Tech Support - Virus Detected".to_string(),
            description: "Caller claims to be tech support who detected a virus".to_string(),
            category: PretextCategory::TechSupport,
            difficulty: PretextDifficulty::Easy,
            scenario: "Tech support calls claiming they've detected a virus on the target's computer, requiring immediate remote access to fix.".to_string(),
            objectives: vec![
                "Gain remote access to target's computer".to_string(),
                "Install malware or remote access tools".to_string(),
                "Gather credentials".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from Microsoft/Windows Technical Support. We've detected that your computer is infected with a serious virus and is sending out malicious traffic.".to_string(),
                talking_points: vec![
                    "Our monitoring systems detected the infection".to_string(),
                    "If not fixed immediately, your computer could be used for attacks".to_string(),
                    "I can help you remove the virus right now for free".to_string(),
                    "I'll need remote access to run our cleaning tools".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("How did you get my number?".to_string(),
                     "Our systems flagged your IP address, which we can trace to your phone number through your internet provider.".to_string()),
                    ("I'll call Microsoft directly".to_string(),
                     "This is the direct support line. I can give you my employee ID: [fake ID]. Time is critical though.".to_string()),
                ]),
                information_to_gather: vec![
                    "Operating system".to_string(),
                    "Antivirus software".to_string(),
                    "Remote access granted".to_string(),
                ],
                closing: "I've cleaned the infection. For future protection, I recommend our premium support plan at...".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Target phone number".to_string(),
            ],
            success_criteria: vec![
                "Remote access obtained".to_string(),
                "Malware installed".to_string(),
            ],
            red_flags: vec![
                "Target knows Microsoft doesn't call proactively".to_string(),
                "Target asks to verify through official Microsoft site".to_string(),
            ],
            tips: vec![
                "Create urgency about virus spreading".to_string(),
                "Use technical-sounding jargon".to_string(),
                "Be prepared for remote access tools".to_string(),
            ],
            tags: vec!["tech support".to_string(), "scam".to_string(), "remote access".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn subscription_expiring_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-tech-subscription".to_string(),
            user_id: None,
            name: "Tech Support - Subscription Expiring".to_string(),
            description: "Caller claims software subscription is expiring".to_string(),
            category: PretextCategory::TechSupport,
            difficulty: PretextDifficulty::Easy,
            scenario: "Support calls about an expiring software subscription requiring immediate renewal to prevent service disruption.".to_string(),
            objectives: vec![
                "Obtain payment card information".to_string(),
                "Install software under guise of 'renewal'".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Software Company] renewals department. Your subscription is set to expire in 24 hours and I wanted to help you renew.".to_string(),
                talking_points: vec![
                    "If not renewed, you'll lose access to all features".to_string(),
                    "I can process the renewal right now over the phone".to_string(),
                    "We have a special discount for renewing today".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I'll renew through the website".to_string(),
                     "That works, but the phone discount expires today. I can save you 30% right now.".to_string()),
                ]),
                information_to_gather: vec![
                    "Credit card number".to_string(),
                    "Expiration date".to_string(),
                    "CVV".to_string(),
                    "Billing address".to_string(),
                ],
                closing: "Perfect, your subscription is renewed. You'll receive a confirmation email shortly.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Knowledge of software target uses".to_string(),
            ],
            success_criteria: vec![
                "Obtained payment information".to_string(),
            ],
            red_flags: vec![
                "Target checks subscription status independently".to_string(),
            ],
            tips: vec![
                "Research what software the company actually uses".to_string(),
                "Offer convincing discounts".to_string(),
            ],
            tags: vec!["subscription".to_string(), "payment".to_string(), "renewal".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn software_license_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-tech-license".to_string(),
            user_id: None,
            name: "Tech Support - License Compliance".to_string(),
            description: "Caller claims to be from software company checking license compliance".to_string(),
            category: PretextCategory::TechSupport,
            difficulty: PretextDifficulty::Medium,
            scenario: "A software company's licensing team calls to verify compliance, gathering information about software deployment.".to_string(),
            objectives: vec![
                "Map software deployment across organization".to_string(),
                "Identify potential targets for exploitation".to_string(),
                "Gather IT infrastructure information".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Software Company] License Compliance. We're conducting a routine audit of your organization's software licenses.".to_string(),
                talking_points: vec![
                    "This is a standard annual compliance review".to_string(),
                    "We need to verify the number of installations".to_string(),
                    "Non-compliance can result in significant penalties".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("Send us formal documentation".to_string(),
                     "Absolutely, I'll send the audit notice. But I can answer questions now if you're concerned about compliance.".to_string()),
                ]),
                information_to_gather: vec![
                    "Number of software installations".to_string(),
                    "Server infrastructure".to_string(),
                    "IT contact names".to_string(),
                ],
                closing: "Thank you for your cooperation. We'll send the formal audit results.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Software vendor name".to_string(),
            ],
            success_criteria: vec![
                "Mapped software deployment".to_string(),
                "Gathered infrastructure information".to_string(),
            ],
            red_flags: vec![
                "Target requests verification through official channels".to_string(),
            ],
            tips: vec![
                "Reference real licensing terms".to_string(),
                "Create compliance concern".to_string(),
            ],
            tags: vec!["license".to_string(), "compliance".to_string(), "audit".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // Financial Category Pretexts
    // =========================================================================

    fn tax_document_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-financial-tax".to_string(),
            user_id: None,
            name: "Financial - Tax Document Request".to_string(),
            description: "Caller requests tax documents or information".to_string(),
            category: PretextCategory::Financial,
            difficulty: PretextDifficulty::Medium,
            scenario: "IRS, accountant, or payroll calls requesting tax information or documents for 'verification'.".to_string(),
            objectives: vec![
                "Obtain W-2 or tax documents".to_string(),
                "Gather SSN and personal information".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Company] accounting. We need to verify your tax information for our year-end filings.".to_string(),
                talking_points: vec![
                    "There's a discrepancy in our records".to_string(),
                    "We need to verify your SSN and address".to_string(),
                    "This is required for W-2 processing".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I'll come to the office".to_string(),
                     "That works, but I'm trying to complete this batch today. It will only take a minute.".to_string()),
                ]),
                information_to_gather: vec![
                    "SSN".to_string(),
                    "Home address".to_string(),
                    "Date of birth".to_string(),
                ],
                closing: "Thank you, I've updated our records. You'll receive your W-2 by the deadline.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Target's name".to_string(),
                "Timing during tax season".to_string(),
            ],
            success_criteria: vec![
                "Obtained SSN".to_string(),
                "Gathered tax-related PII".to_string(),
            ],
            red_flags: vec![
                "Target refuses to provide SSN over phone".to_string(),
            ],
            tips: vec![
                "Time during tax filing season".to_string(),
                "Reference actual tax deadlines".to_string(),
            ],
            tags: vec!["tax".to_string(), "financial".to_string(), "pii".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn banking_verification_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-financial-banking".to_string(),
            user_id: None,
            name: "Financial - Bank Verification".to_string(),
            description: "Caller poses as bank representative verifying account".to_string(),
            category: PretextCategory::Financial,
            difficulty: PretextDifficulty::Medium,
            scenario: "Bank calls about suspicious activity requiring verification of account details.".to_string(),
            objectives: vec![
                "Obtain banking credentials".to_string(),
                "Gather account information".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Bank] fraud prevention. We've detected unusual activity on your account and need to verify some information.".to_string(),
                talking_points: vec![
                    "There were attempted transactions from an unusual location".to_string(),
                    "We need to verify you made these transactions".to_string(),
                    "For your protection, I need to verify your identity".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I'll call the bank directly".to_string(),
                     "That's smart. Before you do, can you confirm your account number so I can flag it? Time is critical.".to_string()),
                ]),
                information_to_gather: vec![
                    "Account number".to_string(),
                    "PIN or password".to_string(),
                    "Security questions".to_string(),
                ],
                closing: "I've secured your account. You should receive a confirmation email.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Bank name target uses".to_string(),
            ],
            success_criteria: vec![
                "Obtained banking credentials".to_string(),
            ],
            red_flags: vec![
                "Target calls bank at known number".to_string(),
            ],
            tips: vec![
                "Create urgency about fraud".to_string(),
                "Know bank's actual procedures".to_string(),
            ],
            tags: vec!["banking".to_string(), "fraud".to_string(), "credentials".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // Delivery Category Pretexts
    // =========================================================================

    fn package_delivery_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-delivery-package".to_string(),
            user_id: None,
            name: "Delivery - Package Delivery Issue".to_string(),
            description: "Caller claims issue with package delivery requiring verification".to_string(),
            category: PretextCategory::Delivery,
            difficulty: PretextDifficulty::Easy,
            scenario: "Delivery company calls about a failed delivery requiring address verification or payment for redelivery.".to_string(),
            objectives: vec![
                "Verify physical address".to_string(),
                "Obtain payment information for 'fees'".to_string(),
                "Gather personal information".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Delivery Company]. We attempted delivery of your package today but the address was incomplete. Can you help me verify?".to_string(),
                talking_points: vec![
                    "The package is being held at our facility".to_string(),
                    "I need to verify the complete address for redelivery".to_string(),
                    "There may be a small redelivery fee".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I didn't order anything".to_string(),
                     "It shows as a gift. Would you like me to describe the package?".to_string()),
                ]),
                information_to_gather: vec![
                    "Full address".to_string(),
                    "Phone number".to_string(),
                    "Credit card for 'fees'".to_string(),
                ],
                closing: "I've scheduled redelivery for tomorrow. You'll receive tracking information.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Target's name".to_string(),
            ],
            success_criteria: vec![
                "Verified address".to_string(),
                "Obtained payment info".to_string(),
            ],
            red_flags: vec![
                "Target checks tracking directly".to_string(),
            ],
            tips: vec![
                "Time during busy shopping seasons".to_string(),
                "Use real delivery company names".to_string(),
            ],
            tags: vec!["delivery".to_string(), "package".to_string(), "shipping".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }

    // =========================================================================
    // Legal Category Pretexts
    // =========================================================================

    fn compliance_audit_pretext(now: DateTime<Utc>) -> PretextTemplate {
        PretextTemplate {
            id: "builtin-legal-compliance".to_string(),
            user_id: None,
            name: "Legal - Regulatory Compliance Audit".to_string(),
            description: "Caller poses as regulator conducting compliance audit".to_string(),
            category: PretextCategory::Legal,
            difficulty: PretextDifficulty::Hard,
            scenario: "A regulatory body calls about a compliance audit, requesting information about internal controls and processes.".to_string(),
            objectives: vec![
                "Gather compliance and security information".to_string(),
                "Map internal controls".to_string(),
                "Identify security weaknesses".to_string(),
            ],
            script: PretextScript {
                opening: "Hi, this is [Name] from [Regulatory Body]. We're conducting routine compliance verification and need to ask a few questions.".to_string(),
                talking_points: vec![
                    "This is a standard industry audit".to_string(),
                    "We need to verify your data protection practices".to_string(),
                    "Non-compliance can result in penalties".to_string(),
                ],
                objection_handling: HashMap::from([
                    ("I need to verify your identity".to_string(),
                     "Absolutely, here's my badge number and you can verify through our public website. However, time is limited for this review cycle.".to_string()),
                ]),
                information_to_gather: vec![
                    "Data handling procedures".to_string(),
                    "Security controls".to_string(),
                    "Compliance status".to_string(),
                ],
                closing: "Thank you for your cooperation. We'll send the formal audit report.".to_string(),
                follow_up: None,
            },
            prerequisites: vec![
                "Relevant regulatory framework".to_string(),
                "Industry-specific compliance requirements".to_string(),
            ],
            success_criteria: vec![
                "Gathered compliance information".to_string(),
                "Mapped security controls".to_string(),
            ],
            red_flags: vec![
                "Target escalates to legal department".to_string(),
            ],
            tips: vec![
                "Know the actual regulatory landscape".to_string(),
                "Use proper compliance terminology".to_string(),
            ],
            tags: vec!["legal".to_string(), "compliance".to_string(), "regulatory".to_string(), "audit".to_string()],
            is_builtin: true,
            created_at: now,
            updated_at: now,
        }
    }
}
