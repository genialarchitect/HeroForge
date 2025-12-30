//! Certificate generation for course completion

use crate::orange_team::types::*;
use chrono::{Duration, Utc};
use uuid::Uuid;

/// Certificate generator
pub struct CertificateGenerator {
    certificates: Vec<TrainingCertificate>,
}

impl CertificateGenerator {
    /// Create a new certificate generator
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
        }
    }

    /// Generate a certificate for course completion
    pub fn generate_certificate(
        &mut self,
        user_id: Uuid,
        course_id: Uuid,
        validity_years: Option<u32>,
    ) -> TrainingCertificate {
        let cert_number = generate_certificate_number();

        let expires_at = validity_years.map(|years| {
            Utc::now() + Duration::days(365 * years as i64)
        });

        let certificate = TrainingCertificate {
            id: Uuid::new_v4(),
            user_id,
            course_id,
            certificate_number: cert_number,
            issued_at: Utc::now(),
            expires_at,
            pdf_path: None,
        };

        self.certificates.push(certificate.clone());
        certificate
    }

    /// Verify a certificate by number
    pub fn verify_certificate(&self, certificate_number: &str) -> Option<CertificateVerification> {
        self.certificates
            .iter()
            .find(|c| c.certificate_number == certificate_number)
            .map(|cert| {
                let is_valid = cert.expires_at.map(|exp| exp > Utc::now()).unwrap_or(true);

                CertificateVerification {
                    certificate_number: cert.certificate_number.clone(),
                    is_valid,
                    issued_at: cert.issued_at,
                    expires_at: cert.expires_at,
                    user_id: cert.user_id,
                    course_id: cert.course_id,
                    status: if is_valid {
                        CertificateStatus::Valid
                    } else {
                        CertificateStatus::Expired
                    },
                }
            })
    }

    /// Get user's certificates
    pub fn get_user_certificates(&self, user_id: Uuid) -> Vec<&TrainingCertificate> {
        self.certificates
            .iter()
            .filter(|c| c.user_id == user_id)
            .collect()
    }

    /// Get certificates expiring soon
    pub fn get_expiring_certificates(&self, days_until_expiry: u32) -> Vec<&TrainingCertificate> {
        let threshold = Utc::now() + Duration::days(days_until_expiry as i64);

        self.certificates
            .iter()
            .filter(|c| {
                c.expires_at
                    .map(|exp| exp <= threshold && exp > Utc::now())
                    .unwrap_or(false)
            })
            .collect()
    }
}

impl Default for CertificateGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Certificate verification result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertificateVerification {
    pub certificate_number: String,
    pub is_valid: bool,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
    pub user_id: Uuid,
    pub course_id: Uuid,
    pub status: CertificateStatus,
}

/// Certificate status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Valid,
    Expired,
    Revoked,
    NotFound,
}

/// Generate a unique certificate number
fn generate_certificate_number() -> String {
    let uuid = Uuid::new_v4().to_string();
    let short = uuid.split('-').next().unwrap_or("000000");
    let timestamp = Utc::now().format("%Y%m%d");
    format!("CERT-{}-{}", timestamp, short.to_uppercase())
}

/// Certificate template data for PDF generation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertificateTemplate {
    pub title: String,
    pub recipient_name: String,
    pub course_name: String,
    pub completion_date: String,
    pub certificate_number: String,
    pub expires_date: Option<String>,
    pub organization_name: String,
    pub signature_name: String,
    pub signature_title: String,
}

impl CertificateTemplate {
    /// Create a new certificate template
    pub fn new(
        recipient_name: &str,
        course_name: &str,
        certificate_number: &str,
        completion_date: chrono::DateTime<Utc>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Self {
        Self {
            title: "Certificate of Completion".to_string(),
            recipient_name: recipient_name.to_string(),
            course_name: course_name.to_string(),
            completion_date: completion_date.format("%B %d, %Y").to_string(),
            certificate_number: certificate_number.to_string(),
            expires_date: expires_at.map(|d| d.format("%B %d, %Y").to_string()),
            organization_name: "Genial Architect Training".to_string(),
            signature_name: "Training Director".to_string(),
            signature_title: "Director of Security Awareness".to_string(),
        }
    }

    /// Generate HTML representation of the certificate
    pub fn to_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Georgia, serif; text-align: center; padding: 50px; }}
        .certificate {{ border: 3px double #2c5f2d; padding: 50px; max-width: 800px; margin: auto; }}
        .title {{ font-size: 36px; color: #2c5f2d; margin-bottom: 30px; }}
        .subtitle {{ font-size: 18px; color: #666; }}
        .recipient {{ font-size: 28px; font-weight: bold; margin: 30px 0; }}
        .course {{ font-size: 22px; margin: 20px 0; }}
        .details {{ font-size: 14px; color: #888; margin-top: 40px; }}
        .signature {{ margin-top: 60px; }}
    </style>
</head>
<body>
    <div class="certificate">
        <div class="title">{}</div>
        <div class="subtitle">This is to certify that</div>
        <div class="recipient">{}</div>
        <div class="subtitle">has successfully completed</div>
        <div class="course">{}</div>
        <div class="details">
            <p>Completed on: {}</p>
            <p>Certificate Number: {}</p>
            {}
        </div>
        <div class="signature">
            <p>{}</p>
            <p>{}</p>
        </div>
    </div>
</body>
</html>"#,
            self.title,
            self.recipient_name,
            self.course_name,
            self.completion_date,
            self.certificate_number,
            self.expires_date
                .as_ref()
                .map(|d| format!("<p>Valid until: {}</p>", d))
                .unwrap_or_default(),
            self.signature_name,
            self.signature_title
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let mut generator = CertificateGenerator::new();
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        let cert = generator.generate_certificate(user_id, course_id, Some(2));

        assert_eq!(cert.user_id, user_id);
        assert_eq!(cert.course_id, course_id);
        assert!(cert.certificate_number.starts_with("CERT-"));
        assert!(cert.expires_at.is_some());
    }

    #[test]
    fn test_verify_certificate() {
        let mut generator = CertificateGenerator::new();
        let user_id = Uuid::new_v4();
        let course_id = Uuid::new_v4();

        let cert = generator.generate_certificate(user_id, course_id, Some(1));
        let verification = generator.verify_certificate(&cert.certificate_number);

        assert!(verification.is_some());
        let v = verification.unwrap();
        assert!(v.is_valid);
        assert_eq!(v.status, CertificateStatus::Valid);
    }
}
