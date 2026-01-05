//! Email verification service for registration flow
//!
//! Handles:
//! - Verification token generation and validation
//! - Email duplicate detection
//! - Registration state management

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Email verification record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerification {
    pub id: String,
    pub email: String,
    pub token: String,
    pub tier_id: String,
    pub billing_cycle: String,
    pub stripe_session_id: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub pending_data: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub payment_verified_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Pending registration data stored with verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRegistrationData {
    pub username: Option<String>,
    pub password_hash: Option<String>,
}

/// Email verification service
pub struct VerificationService;

impl VerificationService {
    /// Generate a secure verification token
    pub fn generate_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        hex::encode(bytes)
    }

    /// Create a new email verification record
    pub async fn create_verification(
        pool: &SqlitePool,
        email: &str,
        tier_id: &str,
        billing_cycle: &str,
    ) -> Result<EmailVerification> {
        let id = uuid::Uuid::new_v4().to_string();
        let token = Self::generate_token();
        let now = Utc::now();
        let expires_at = now + Duration::hours(24); // 24-hour expiry

        sqlx::query(
            r#"
            INSERT INTO email_verifications (
                id, email, token, tier_id, billing_cycle, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(email)
        .bind(&token)
        .bind(tier_id)
        .bind(billing_cycle)
        .bind(expires_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(pool)
        .await?;

        Ok(EmailVerification {
            id,
            email: email.to_string(),
            token,
            tier_id: tier_id.to_string(),
            billing_cycle: billing_cycle.to_string(),
            stripe_session_id: None,
            stripe_customer_id: None,
            pending_data: None,
            verified_at: None,
            payment_verified_at: None,
            expires_at,
            created_at: now,
        })
    }

    /// Get verification by token
    pub async fn get_by_token(
        pool: &SqlitePool,
        token: &str,
    ) -> Result<Option<EmailVerification>> {
        let row = sqlx::query_as::<_, VerificationRow>(
            r#"
            SELECT id, email, token, tier_id, billing_cycle,
                   stripe_session_id, stripe_customer_id, pending_data,
                   verified_at, payment_verified_at, expires_at, created_at
            FROM email_verifications
            WHERE token = ?
            "#,
        )
        .bind(token)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Get verification by email (most recent)
    pub async fn get_by_email(
        pool: &SqlitePool,
        email: &str,
    ) -> Result<Option<EmailVerification>> {
        let row = sqlx::query_as::<_, VerificationRow>(
            r#"
            SELECT id, email, token, tier_id, billing_cycle,
                   stripe_session_id, stripe_customer_id, pending_data,
                   verified_at, payment_verified_at, expires_at, created_at
            FROM email_verifications
            WHERE email = ?
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Update Stripe session info
    pub async fn update_stripe_session(
        pool: &SqlitePool,
        verification_id: &str,
        session_id: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE email_verifications
            SET stripe_session_id = ?
            WHERE id = ?
            "#,
        )
        .bind(session_id)
        .bind(verification_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark email as verified
    pub async fn mark_email_verified(pool: &SqlitePool, verification_id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            UPDATE email_verifications
            SET verified_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&now)
        .bind(verification_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark payment as verified
    pub async fn mark_payment_verified(
        pool: &SqlitePool,
        verification_id: &str,
        customer_id: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            UPDATE email_verifications
            SET payment_verified_at = ?, stripe_customer_id = ?
            WHERE id = ?
            "#,
        )
        .bind(&now)
        .bind(customer_id)
        .bind(verification_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Store pending registration data
    pub async fn store_pending_data(
        pool: &SqlitePool,
        verification_id: &str,
        data: &PendingRegistrationData,
    ) -> Result<()> {
        let json_data = serde_json::to_string(data)?;
        sqlx::query(
            r#"
            UPDATE email_verifications
            SET pending_data = ?
            WHERE id = ?
            "#,
        )
        .bind(&json_data)
        .bind(verification_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Check if verification is valid and not expired
    pub fn is_valid(verification: &EmailVerification) -> bool {
        let now = Utc::now();
        verification.expires_at > now
    }

    /// Check if verification is complete (email + payment verified)
    pub fn is_complete(verification: &EmailVerification) -> bool {
        verification.verified_at.is_some() && verification.payment_verified_at.is_some()
    }

    /// Check if email is already registered
    pub async fn is_email_registered(pool: &SqlitePool, email: &str) -> Result<bool> {
        let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(pool)
            .await?;

        Ok(count > 0)
    }

    /// Delete expired verifications
    pub async fn cleanup_expired(pool: &SqlitePool) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            r#"
            DELETE FROM email_verifications
            WHERE expires_at < ? AND verified_at IS NULL
            "#,
        )
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete verification by ID
    pub async fn delete_verification(pool: &SqlitePool, verification_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM email_verifications WHERE id = ?")
            .bind(verification_id)
            .execute(pool)
            .await?;

        Ok(())
    }
}

// Internal row type for database mapping
#[derive(sqlx::FromRow)]
struct VerificationRow {
    id: String,
    email: String,
    token: String,
    tier_id: String,
    billing_cycle: String,
    stripe_session_id: Option<String>,
    stripe_customer_id: Option<String>,
    pending_data: Option<String>,
    verified_at: Option<String>,
    payment_verified_at: Option<String>,
    expires_at: String,
    created_at: String,
}

impl From<VerificationRow> for EmailVerification {
    fn from(row: VerificationRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            token: row.token,
            tier_id: row.tier_id,
            billing_cycle: row.billing_cycle,
            stripe_session_id: row.stripe_session_id,
            stripe_customer_id: row.stripe_customer_id,
            pending_data: row.pending_data,
            verified_at: row.verified_at.and_then(|s| s.parse().ok()),
            payment_verified_at: row.payment_verified_at.and_then(|s| s.parse().ok()),
            expires_at: row.expires_at.parse().unwrap_or_else(|_| Utc::now()),
            created_at: row.created_at.parse().unwrap_or_else(|_| Utc::now()),
        }
    }
}

/// Enterprise inquiry record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseInquiry {
    pub id: String,
    pub email: String,
    pub company_name: String,
    pub contact_name: String,
    pub phone: Option<String>,
    pub job_title: Option<String>,
    pub company_size: Option<String>,
    pub message: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Create an enterprise inquiry
pub async fn create_enterprise_inquiry(
    pool: &SqlitePool,
    email: &str,
    company_name: &str,
    contact_name: &str,
    phone: Option<&str>,
    job_title: Option<&str>,
    company_size: Option<&str>,
    message: Option<&str>,
) -> Result<EnterpriseInquiry> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO enterprise_inquiries (
            id, email, company_name, contact_name, phone,
            job_title, company_size, message, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        "#,
    )
    .bind(&id)
    .bind(email)
    .bind(company_name)
    .bind(contact_name)
    .bind(phone)
    .bind(job_title)
    .bind(company_size)
    .bind(message)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(EnterpriseInquiry {
        id,
        email: email.to_string(),
        company_name: company_name.to_string(),
        contact_name: contact_name.to_string(),
        phone: phone.map(String::from),
        job_title: job_title.map(String::from),
        company_size: company_size.map(String::from),
        message: message.map(String::from),
        status: "pending".to_string(),
        created_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token = VerificationService::generate_token();
        assert_eq!(token.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_is_valid() {
        let mut verification = EmailVerification {
            id: "test".to_string(),
            email: "test@example.com".to_string(),
            token: "token".to_string(),
            tier_id: "tier_solo".to_string(),
            billing_cycle: "monthly".to_string(),
            stripe_session_id: None,
            stripe_customer_id: None,
            pending_data: None,
            verified_at: None,
            payment_verified_at: None,
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
        };

        assert!(VerificationService::is_valid(&verification));

        // Expired
        verification.expires_at = Utc::now() - Duration::hours(1);
        assert!(!VerificationService::is_valid(&verification));
    }
}
