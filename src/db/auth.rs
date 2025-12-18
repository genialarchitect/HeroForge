//! Authentication-related database operations
//! Includes refresh tokens, account lockout, MFA, and password history

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use base64::Engine;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use rand::RngCore;

use super::models;
use super::BCRYPT_COST;

// ============================================================================
// Refresh Token Management Functions (NIST 800-63B)
// ============================================================================

/// Hash a token with SHA-256 for secure storage
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Store a refresh token in the database (hashes token with SHA-256 before storing)
pub async fn store_refresh_token(
    pool: &SqlitePool,
    user_id: &str,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<models::RefreshToken> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Hash the token with SHA-256 before storing
    let token_hash = hash_token(token);

    let stored_token = sqlx::query_as::<_, models::RefreshToken>(
        r#"
        INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(stored_token)
}

/// Get a refresh token by its hash (hashes the provided token before lookup)
pub async fn get_refresh_token(
    pool: &SqlitePool,
    token: &str,
) -> Result<Option<models::RefreshToken>> {
    // Hash the token with SHA-256 before comparing
    let token_hash = hash_token(token);

    let token = sqlx::query_as::<_, models::RefreshToken>(
        "SELECT * FROM refresh_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(token)
}

/// Revoke a specific refresh token (hashes the provided token before revoking)
pub async fn revoke_refresh_token(pool: &SqlitePool, token: &str) -> Result<()> {
    let now = Utc::now();

    // Hash the token with SHA-256 before revoking
    let token_hash = hash_token(token);

    sqlx::query("UPDATE refresh_tokens SET revoked_at = ?1 WHERE token_hash = ?2")
        .bind(now)
        .bind(&token_hash)
        .execute(pool)
        .await?;

    Ok(())
}

/// Revoke all refresh tokens for a user (useful for logout all sessions)
pub async fn revoke_all_user_refresh_tokens(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE refresh_tokens SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Clean up expired refresh tokens (can be called periodically)
pub async fn cleanup_expired_refresh_tokens(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now();

    sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < ?1")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Account Lockout and Login Attempt Tracking (NIST 800-53 AC-7, CIS Controls 16.11)
// ============================================================================

/// Record a login attempt (both successful and failed) for audit and security purposes
pub async fn record_login_attempt(
    pool: &SqlitePool,
    username: &str,
    success: bool,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO login_attempts (username, attempt_time, success, ip_address, user_agent)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(username)
    .bind(now)
    .bind(success)
    .bind(ip_address)
    .bind(user_agent)
    .execute(pool)
    .await?;

    Ok(())
}

/// Check if an account is currently locked
/// Returns (is_locked, locked_until, attempt_count)
pub async fn check_account_locked(
    pool: &SqlitePool,
    username: &str,
) -> Result<(bool, Option<DateTime<Utc>>, i32)> {
    let now = Utc::now();

    // First, try to get lockout record
    let lockout: Option<(DateTime<Utc>, i32)> = sqlx::query_as(
        "SELECT locked_until, attempt_count FROM account_lockouts WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    if let Some((locked_until, attempt_count)) = lockout {
        // Check if lockout has expired
        if locked_until > now {
            // Account is still locked
            return Ok((true, Some(locked_until), attempt_count));
        } else {
            // Lockout has expired, clean up the record
            sqlx::query("DELETE FROM account_lockouts WHERE username = ?1")
                .bind(username)
                .execute(pool)
                .await?;
            return Ok((false, None, 0));
        }
    }

    Ok((false, None, 0))
}

/// Increment failed login attempts and lock account if threshold is reached
/// Returns (is_now_locked, locked_until, attempt_count)
pub async fn increment_failed_attempts(
    pool: &SqlitePool,
    username: &str,
) -> Result<(bool, Option<DateTime<Utc>>, i32)> {
    const MAX_ATTEMPTS: i32 = 5;
    const LOCKOUT_DURATION_MINUTES: i64 = 15;

    let now = Utc::now();

    // Get current lockout status
    let existing: Option<(i32, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT attempt_count, first_failed_attempt, last_failed_attempt FROM account_lockouts WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    if let Some((current_count, _first_attempt, _last_attempt)) = existing {
        let new_count = current_count + 1;

        if new_count >= MAX_ATTEMPTS {
            // Lock the account
            let locked_until = now + chrono::Duration::minutes(LOCKOUT_DURATION_MINUTES);

            sqlx::query(
                r#"
                UPDATE account_lockouts
                SET attempt_count = ?1, last_failed_attempt = ?2, locked_until = ?3,
                    lockout_reason = ?4
                WHERE username = ?5
                "#,
            )
            .bind(new_count)
            .bind(now)
            .bind(locked_until)
            .bind(format!("Account locked due to {} consecutive failed login attempts", new_count))
            .bind(username)
            .execute(pool)
            .await?;

            return Ok((true, Some(locked_until), new_count));
        } else {
            // Increment attempt count but don't lock yet
            sqlx::query(
                "UPDATE account_lockouts SET attempt_count = ?1, last_failed_attempt = ?2 WHERE username = ?3",
            )
            .bind(new_count)
            .bind(now)
            .bind(username)
            .execute(pool)
            .await?;

            return Ok((false, None, new_count));
        }
    } else {
        // First failed attempt, create new record
        // Set locked_until to epoch (past) since account isn't locked yet
        let not_locked = DateTime::<Utc>::from_timestamp(0, 0).unwrap_or(now);

        sqlx::query(
            r#"
            INSERT INTO account_lockouts (username, locked_until, attempt_count, first_failed_attempt, last_failed_attempt, lockout_reason)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(username)
        .bind(not_locked)
        .bind(1)
        .bind(now)
        .bind(now)
        .bind("Tracking failed login attempts")
        .execute(pool)
        .await?;

        return Ok((false, None, 1));
    }
}

/// Reset failed login attempts after successful login
pub async fn reset_failed_attempts(pool: &SqlitePool, username: &str) -> Result<()> {
    sqlx::query("DELETE FROM account_lockouts WHERE username = ?1")
        .bind(username)
        .execute(pool)
        .await?;

    Ok(())
}

/// Unlock a user account (admin function)
pub async fn unlock_user_account(pool: &SqlitePool, username: &str) -> Result<()> {
    sqlx::query("DELETE FROM account_lockouts WHERE username = ?1")
        .bind(username)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get lockout status for a user by user_id
pub async fn get_user_lockout_status(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<models::AccountLockout>> {
    let lockout = sqlx::query_as::<_, models::AccountLockout>(
        "SELECT * FROM account_lockouts WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(lockout)
}

/// Get all locked accounts
pub async fn get_all_locked_accounts(pool: &SqlitePool) -> Result<Vec<models::AccountLockout>> {
    let now = Utc::now();
    let lockouts = sqlx::query_as::<_, models::AccountLockout>(
        "SELECT * FROM account_lockouts WHERE locked_until > ?1 ORDER BY locked_until DESC",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    Ok(lockouts)
}

/// Get recent login attempts for a username (for audit purposes)
pub async fn get_recent_login_attempts(
    pool: &SqlitePool,
    username: &str,
    limit: i64,
) -> Result<Vec<models::LoginAttempt>> {
    let attempts = sqlx::query_as::<_, models::LoginAttempt>(
        "SELECT * FROM login_attempts WHERE username = ?1 ORDER BY attempt_time DESC LIMIT ?2",
    )
    .bind(username)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(attempts)
}

// ============================================================================
// MFA (Two-Factor Authentication) Database Functions
// ============================================================================

/// Get the encryption key for TOTP secrets from environment variable
fn get_totp_encryption_key() -> Result<[u8; 32]> {
    let key_str = std::env::var("TOTP_ENCRYPTION_KEY")
        .map_err(|_| anyhow::anyhow!("TOTP_ENCRYPTION_KEY environment variable not set. Generate one with: openssl rand -hex 32"))?;

    // Decode hex key to bytes
    let key_bytes = hex::decode(&key_str)
        .map_err(|_| anyhow::anyhow!("TOTP_ENCRYPTION_KEY must be a valid hex string (64 characters)"))?;

    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Encrypt TOTP secret with AES-256-GCM
fn encrypt_totp_secret(secret: &str) -> Result<String> {
    let key_bytes = get_totp_encryption_key()?;
    let cipher = Aes256Gcm::new(key_bytes.as_ref().into());

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the secret
    let ciphertext = cipher.encrypt(nonce, secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt TOTP secret with AES-256-GCM
fn decrypt_totp_secret(encrypted: &str) -> Result<String> {
    let key_bytes = get_totp_encryption_key()?;
    let cipher = Aes256Gcm::new(key_bytes.as_ref().into());

    // Decode from base64
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to decode encrypted TOTP secret: {}", e))?;

    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted TOTP secret: too short"));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    let secret = String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted TOTP secret: {}", e))?;

    Ok(secret)
}

/// Store TOTP secret for a user (encrypts with AES-256-GCM before storing)
pub async fn store_totp_secret(pool: &SqlitePool, user_id: &str, secret: &str) -> Result<()> {
    // Encrypt the secret with AES-256-GCM
    let encrypted_secret = encrypt_totp_secret(secret)?;

    sqlx::query("UPDATE users SET totp_secret = ?1 WHERE id = ?2")
        .bind(&encrypted_secret)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get TOTP secret for a user (decrypts after retrieving)
pub async fn get_totp_secret(pool: &SqlitePool, user_id: &str) -> Result<Option<String>> {
    let result: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT totp_secret FROM users WHERE id = ?1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if let Some((Some(encrypted_secret),)) = result {
        // Decrypt the secret with AES-256-GCM
        let secret = decrypt_totp_secret(&encrypted_secret)?;
        Ok(Some(secret))
    } else {
        Ok(None)
    }
}

/// Enable MFA for a user after successful verification
pub async fn enable_mfa(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE users SET totp_enabled = 1, totp_verified_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Disable MFA for a user
pub async fn disable_mfa(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_verified_at = NULL, recovery_codes = NULL WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Check if MFA is enabled for a user
pub async fn is_mfa_enabled(pool: &SqlitePool, user_id: &str) -> Result<bool> {
    let result: Option<(bool,)> = sqlx::query_as(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|(enabled,)| enabled).unwrap_or(false))
}

/// Store hashed recovery codes for a user (JSON array of bcrypt hashes)
pub async fn store_recovery_codes(pool: &SqlitePool, user_id: &str, codes: &[String]) -> Result<()> {
    // Hash each recovery code with bcrypt
    let mut hashed_codes = Vec::new();
    for code in codes {
        let hash = bcrypt::hash(code, *BCRYPT_COST)?;
        hashed_codes.push(hash);
    }

    let codes_json = serde_json::to_string(&hashed_codes)?;

    sqlx::query("UPDATE users SET recovery_codes = ?1 WHERE id = ?2")
        .bind(&codes_json)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Verify and consume a recovery code (removes it after successful verification)
pub async fn verify_and_consume_recovery_code(
    pool: &SqlitePool,
    user_id: &str,
    code: &str,
) -> Result<bool> {
    // Get current recovery codes
    let result: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT recovery_codes FROM users WHERE id = ?1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if let Some((Some(codes_json),)) = result {
        let mut hashed_codes: Vec<String> = serde_json::from_str(&codes_json)?;

        // Check each hashed code
        for (i, hashed_code) in hashed_codes.iter().enumerate() {
            if bcrypt::verify(code, hashed_code).unwrap_or(false) {
                // Code is valid - remove it from the list
                hashed_codes.remove(i);

                // Update database with remaining codes
                let updated_json = serde_json::to_string(&hashed_codes)?;
                sqlx::query("UPDATE users SET recovery_codes = ?1 WHERE id = ?2")
                    .bind(&updated_json)
                    .bind(user_id)
                    .execute(pool)
                    .await?;

                return Ok(true);
            }
        }
    }

    Ok(false)
}

// ============================================================================
// Password History Functions (NIST 800-63B - prevent password reuse)
// ============================================================================

/// Check if a password was used recently (checks last 5 passwords)
pub async fn check_password_history(
    pool: &SqlitePool,
    user_id: &str,
    new_password: &str,
) -> Result<bool> {
    // Get last 5 password hashes for this user
    let history: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT password_hash FROM password_history
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT 5
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Check if new password matches any recent password
    for (old_hash,) in history {
        if bcrypt::verify(new_password, &old_hash).unwrap_or(false) {
            return Ok(true); // Password was used recently
        }
    }

    Ok(false) // Password is not in recent history
}

/// Add a password hash to history and maintain limit of 5
pub async fn add_password_to_history(
    pool: &SqlitePool,
    user_id: &str,
    password_hash: &str,
) -> Result<()> {
    let now = Utc::now();

    // Insert new password hash
    sqlx::query(
        r#"
        INSERT INTO password_history (user_id, password_hash, created_at)
        VALUES (?1, ?2, ?3)
        "#,
    )
    .bind(user_id)
    .bind(password_hash)
    .bind(now)
    .execute(pool)
    .await?;

    // Get count of password history entries for this user
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM password_history WHERE user_id = ?1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // If more than 5, remove oldest entries
    if count.0 > 5 {
        let to_remove = count.0 - 5;
        sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE id IN (
                SELECT id FROM password_history
                WHERE user_id = ?1
                ORDER BY created_at ASC
                LIMIT ?2
            )
            "#,
        )
        .bind(user_id)
        .bind(to_remove)
        .execute(pool)
        .await?;
    }

    Ok(())
}
