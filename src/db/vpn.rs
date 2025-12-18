//! VPN configuration and connection database operations

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::vpn::types::{VpnConfigRecord, VpnConnectionRecord};

// ============================================================================
// VPN Config Operations
// ============================================================================

/// Create a new VPN configuration
pub async fn create_vpn_config(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    vpn_type: &str,
    config_file_path: &str,
    original_filename: &str,
    encrypted_credentials: Option<&str>,
    requires_credentials: bool,
) -> Result<VpnConfigRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO vpn_configs (
            id, user_id, name, vpn_type, config_file_path, original_filename,
            encrypted_credentials, requires_credentials, is_default,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?9)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(vpn_type)
    .bind(config_file_path)
    .bind(original_filename)
    .bind(encrypted_credentials)
    .bind(requires_credentials)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(VpnConfigRecord {
        id,
        user_id: user_id.to_string(),
        name: name.to_string(),
        vpn_type: vpn_type.to_string(),
        config_file_path: config_file_path.to_string(),
        original_filename: original_filename.to_string(),
        encrypted_credentials: encrypted_credentials.map(String::from),
        requires_credentials,
        is_default: false,
        created_at: now.clone(),
        updated_at: now,
        last_used_at: None,
    })
}

/// Get all VPN configurations for a user
pub async fn get_user_vpn_configs(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<VpnConfigRecord>> {
    let rows: Vec<(
        String, String, String, String, String, String,
        Option<String>, i64, i64, String, String, Option<String>
    )> = sqlx::query_as(
        r#"
        SELECT
            id, user_id, name, vpn_type, config_file_path, original_filename,
            encrypted_credentials, requires_credentials, is_default,
            created_at, updated_at, last_used_at
        FROM vpn_configs
        WHERE user_id = ?1
        ORDER BY is_default DESC, name ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| VpnConfigRecord {
            id: row.0,
            user_id: row.1,
            name: row.2,
            vpn_type: row.3,
            config_file_path: row.4,
            original_filename: row.5,
            encrypted_credentials: row.6,
            requires_credentials: row.7 != 0,
            is_default: row.8 != 0,
            created_at: row.9,
            updated_at: row.10,
            last_used_at: row.11,
        })
        .collect())
}

/// Get a VPN configuration by ID
pub async fn get_vpn_config_by_id(
    pool: &SqlitePool,
    config_id: &str,
) -> Result<Option<VpnConfigRecord>> {
    let row: Option<(
        String, String, String, String, String, String,
        Option<String>, i64, i64, String, String, Option<String>
    )> = sqlx::query_as(
        r#"
        SELECT
            id, user_id, name, vpn_type, config_file_path, original_filename,
            encrypted_credentials, requires_credentials, is_default,
            created_at, updated_at, last_used_at
        FROM vpn_configs
        WHERE id = ?1
        "#,
    )
    .bind(config_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| VpnConfigRecord {
        id: row.0,
        user_id: row.1,
        name: row.2,
        vpn_type: row.3,
        config_file_path: row.4,
        original_filename: row.5,
        encrypted_credentials: row.6,
        requires_credentials: row.7 != 0,
        is_default: row.8 != 0,
        created_at: row.9,
        updated_at: row.10,
        last_used_at: row.11,
    }))
}

/// Update a VPN configuration
pub async fn update_vpn_config(
    pool: &SqlitePool,
    config_id: &str,
    name: Option<&str>,
    encrypted_credentials: Option<&str>,
    is_default: Option<bool>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    if let Some(name) = name {
        sqlx::query("UPDATE vpn_configs SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(&now)
            .bind(config_id)
            .execute(pool)
            .await?;
    }

    if let Some(creds) = encrypted_credentials {
        sqlx::query("UPDATE vpn_configs SET encrypted_credentials = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(creds)
            .bind(&now)
            .bind(config_id)
            .execute(pool)
            .await?;
    }

    if let Some(is_default) = is_default {
        if is_default {
            // Get user_id for this config
            let user_id: Option<(String,)> = sqlx::query_as(
                "SELECT user_id FROM vpn_configs WHERE id = ?1"
            )
            .bind(config_id)
            .fetch_optional(pool)
            .await?;

            if let Some((user_id,)) = user_id {
                // Clear default from all other configs for this user
                sqlx::query("UPDATE vpn_configs SET is_default = 0 WHERE user_id = ?1")
                    .bind(&user_id)
                    .execute(pool)
                    .await?;
            }
        }

        sqlx::query("UPDATE vpn_configs SET is_default = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(is_default)
            .bind(&now)
            .bind(config_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Update last used timestamp for a VPN config
pub async fn update_vpn_config_last_used(pool: &SqlitePool, config_id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE vpn_configs SET last_used_at = ?1, updated_at = ?1 WHERE id = ?2")
        .bind(&now)
        .bind(config_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a VPN configuration
pub async fn delete_vpn_config(pool: &SqlitePool, config_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM vpn_configs WHERE id = ?1")
        .bind(config_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get the default VPN configuration for a user
pub async fn get_default_vpn_config(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<VpnConfigRecord>> {
    let row: Option<(
        String, String, String, String, String, String,
        Option<String>, i64, i64, String, String, Option<String>
    )> = sqlx::query_as(
        r#"
        SELECT
            id, user_id, name, vpn_type, config_file_path, original_filename,
            encrypted_credentials, requires_credentials, is_default,
            created_at, updated_at, last_used_at
        FROM vpn_configs
        WHERE user_id = ?1 AND is_default = 1
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| VpnConfigRecord {
        id: row.0,
        user_id: row.1,
        name: row.2,
        vpn_type: row.3,
        config_file_path: row.4,
        original_filename: row.5,
        encrypted_credentials: row.6,
        requires_credentials: row.7 != 0,
        is_default: row.8 != 0,
        created_at: row.9,
        updated_at: row.10,
        last_used_at: row.11,
    }))
}

// ============================================================================
// VPN Connection Operations
// ============================================================================

/// Create a new VPN connection record
pub async fn create_vpn_connection(
    pool: &SqlitePool,
    vpn_config_id: &str,
    user_id: &str,
    connection_mode: &str,
    scan_id: Option<&str>,
) -> Result<VpnConnectionRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO vpn_connections (
            id, vpn_config_id, user_id, connection_mode, scan_id,
            status, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, 'connecting', ?6)
        "#,
    )
    .bind(&id)
    .bind(vpn_config_id)
    .bind(user_id)
    .bind(connection_mode)
    .bind(scan_id)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(VpnConnectionRecord {
        id,
        vpn_config_id: vpn_config_id.to_string(),
        user_id: user_id.to_string(),
        connection_mode: connection_mode.to_string(),
        scan_id: scan_id.map(String::from),
        status: "connecting".to_string(),
        process_id: None,
        interface_name: None,
        assigned_ip: None,
        connected_at: None,
        disconnected_at: None,
        error_message: None,
        created_at: now,
    })
}

/// Update VPN connection status to connected
pub async fn update_vpn_connection_connected(
    pool: &SqlitePool,
    connection_id: &str,
    process_id: Option<i64>,
    interface_name: &str,
    assigned_ip: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE vpn_connections
        SET status = 'connected',
            process_id = ?1,
            interface_name = ?2,
            assigned_ip = ?3,
            connected_at = ?4
        WHERE id = ?5
        "#,
    )
    .bind(process_id)
    .bind(interface_name)
    .bind(assigned_ip)
    .bind(&now)
    .bind(connection_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update VPN connection status to disconnected
pub async fn update_vpn_connection_disconnected(
    pool: &SqlitePool,
    connection_id: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE vpn_connections
        SET status = 'disconnected',
            disconnected_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(&now)
    .bind(connection_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update VPN connection status to error
pub async fn update_vpn_connection_error(
    pool: &SqlitePool,
    connection_id: &str,
    error_message: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE vpn_connections
        SET status = 'error',
            error_message = ?1,
            disconnected_at = ?2
        WHERE id = ?3
        "#,
    )
    .bind(error_message)
    .bind(&now)
    .bind(connection_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get the active VPN connection for a user
pub async fn get_active_vpn_connection(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<VpnConnectionRecord>> {
    let row: Option<(
        String, String, String, String, Option<String>, String,
        Option<i64>, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, String
    )> = sqlx::query_as(
        r#"
        SELECT
            id, vpn_config_id, user_id, connection_mode, scan_id, status,
            process_id, interface_name, assigned_ip, connected_at,
            disconnected_at, error_message, created_at
        FROM vpn_connections
        WHERE user_id = ?1 AND status IN ('connecting', 'connected')
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| VpnConnectionRecord {
        id: row.0,
        vpn_config_id: row.1,
        user_id: row.2,
        connection_mode: row.3,
        scan_id: row.4,
        status: row.5,
        process_id: row.6,
        interface_name: row.7,
        assigned_ip: row.8,
        connected_at: row.9,
        disconnected_at: row.10,
        error_message: row.11,
        created_at: row.12,
    }))
}

/// Get VPN connection history for a user
pub async fn get_vpn_connection_history(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<VpnConnectionRecord>> {
    let rows: Vec<(
        String, String, String, String, Option<String>, String,
        Option<i64>, Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, String
    )> = sqlx::query_as(
        r#"
        SELECT
            id, vpn_config_id, user_id, connection_mode, scan_id, status,
            process_id, interface_name, assigned_ip, connected_at,
            disconnected_at, error_message, created_at
        FROM vpn_connections
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| VpnConnectionRecord {
            id: row.0,
            vpn_config_id: row.1,
            user_id: row.2,
            connection_mode: row.3,
            scan_id: row.4,
            status: row.5,
            process_id: row.6,
            interface_name: row.7,
            assigned_ip: row.8,
            connected_at: row.9,
            disconnected_at: row.10,
            error_message: row.11,
            created_at: row.12,
        })
        .collect())
}

/// Mark all active connections as disconnected (for cleanup on startup)
pub async fn cleanup_stale_connections(pool: &SqlitePool) -> Result<u64> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"
        UPDATE vpn_connections
        SET status = 'disconnected',
            disconnected_at = ?1,
            error_message = 'Connection lost during server restart'
        WHERE status IN ('connecting', 'connected')
        "#,
    )
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
