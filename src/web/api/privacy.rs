use actix_web::{HttpResponse, Result};
use serde_json::json;

/// Privacy policy endpoint (no authentication required - GDPR transparency requirement)
pub async fn get_privacy_policy() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "version": "1.0",
        "last_updated": "2025-01-01",
        "policy": {
            "data_controller": {
                "organization": "Genial Architect",
                "contact_email": "privacy@heroforge.security",
                "contact_address": "Please contact us via email for our physical address"
            },
            "data_collected": [
                {
                    "category": "Account Information",
                    "data_points": ["Username", "Email address", "Encrypted password"],
                    "purpose": "User authentication and account management",
                    "legal_basis": "Contractual necessity"
                },
                {
                    "category": "Scan Data",
                    "data_points": ["Network scan results", "Target IP addresses", "Port information", "Service details", "Vulnerability findings"],
                    "purpose": "Providing the core security scanning service",
                    "legal_basis": "Contractual necessity"
                },
                {
                    "category": "Usage Data",
                    "data_points": ["Login attempts", "IP addresses", "User agent strings", "Scan timestamps"],
                    "purpose": "Security monitoring, abuse prevention, and service improvement",
                    "legal_basis": "Legitimate interest in security and fraud prevention"
                },
                {
                    "category": "Reports and Templates",
                    "data_points": ["Generated reports", "Scan templates", "Target groups", "Scheduled scans"],
                    "purpose": "Providing report generation and scan automation features",
                    "legal_basis": "Contractual necessity"
                },
                {
                    "category": "Communication Preferences",
                    "data_points": ["Notification settings", "Email preferences"],
                    "purpose": "Sending scan completion and security alerts",
                    "legal_basis": "User consent"
                }
            ],
            "data_retention": {
                "account_data": "Retained for the duration of your account plus 30 days after deletion request",
                "scan_results": "Configurable retention period (default: 90 days), or until account deletion",
                "reports": "Retained until account deletion or manual deletion",
                "login_attempts": "Retained for 90 days for security audit purposes",
                "audit_logs": "Retained for 1 year for compliance and security purposes"
            },
            "data_sharing": {
                "third_parties": "We do not sell or share your personal data with third parties",
                "service_providers": "We may use trusted service providers for hosting and infrastructure, all bound by data protection agreements",
                "legal_requirements": "We may disclose data when required by law, court order, or to protect our rights and safety"
            },
            "user_rights": {
                "access": {
                    "description": "Right to access your personal data",
                    "how_to_exercise": "Use the GET /api/auth/export endpoint or contact privacy@heroforge.security"
                },
                "rectification": {
                    "description": "Right to correct inaccurate personal data",
                    "how_to_exercise": "Update your profile via the Settings page or API"
                },
                "erasure": {
                    "description": "Right to be forgotten - delete your account and all associated data",
                    "how_to_exercise": "Use the DELETE /api/auth/account endpoint or contact privacy@heroforge.security"
                },
                "portability": {
                    "description": "Right to receive your data in a machine-readable format",
                    "how_to_exercise": "Use the GET /api/auth/export endpoint to download your data as JSON"
                },
                "objection": {
                    "description": "Right to object to processing of your personal data",
                    "how_to_exercise": "Contact privacy@heroforge.security to discuss your concerns"
                },
                "withdraw_consent": {
                    "description": "Right to withdraw consent for data processing",
                    "how_to_exercise": "Update notification settings or delete your account"
                }
            },
            "security_measures": {
                "encryption": {
                    "in_transit": "All data transmitted via HTTPS/TLS encryption",
                    "at_rest": "Passwords stored using bcrypt hashing, optional database encryption with SQLCipher AES-256"
                },
                "access_control": {
                    "authentication": "JWT-based authentication with secure password requirements (NIST 800-63B)",
                    "authorization": "Role-based access control (RBAC)",
                    "account_lockout": "Automatic account lockout after 5 failed login attempts (15-minute lockout)"
                },
                "monitoring": {
                    "audit_logs": "Comprehensive audit logging of all administrative actions",
                    "login_tracking": "Login attempt tracking with IP address and user agent logging"
                }
            },
            "cookies_and_tracking": {
                "authentication_tokens": "JWT tokens stored in browser for session management (required for service functionality)",
                "analytics": "We do not use third-party analytics or tracking cookies",
                "advertising": "We do not use advertising cookies or trackers"
            },
            "international_transfers": {
                "description": "Data is stored and processed in the region where the service is deployed",
                "safeguards": "If data is transferred internationally, we ensure appropriate safeguards such as Standard Contractual Clauses (SCCs)"
            },
            "children_privacy": {
                "description": "This service is not intended for users under 18 years of age",
                "policy": "We do not knowingly collect personal information from children"
            },
            "changes_to_policy": {
                "notification": "Users will be notified of material changes via email and in-app notification",
                "acceptance": "Continued use of the service after changes constitutes acceptance of the updated policy"
            },
            "contact_information": {
                "data_protection_officer": "privacy@heroforge.security",
                "general_inquiries": "support@heroforge.security",
                "supervisory_authority": "Users in the EU may file complaints with their local data protection authority"
            },
            "automated_decision_making": {
                "description": "We do not use automated decision-making or profiling that produces legal or similarly significant effects"
            }
        }
    })))
}
