//! IoT Database Operations
//!
//! Database operations for IoT device management and scanning.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::iot::types::*;

// ============================================================================
// Database Row Structs
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct IotDeviceRow {
    id: String,
    user_id: String,
    name: Option<String>,
    device_type: String,
    vendor: Option<String>,
    model: Option<String>,
    firmware_version: Option<String>,
    ip_address: Option<String>,
    mac_address: Option<String>,
    hostname: Option<String>,
    protocols: String,
    open_ports: String,
    default_creds_status: String,
    last_seen: Option<String>,
    first_seen: Option<String>,
    risk_score: i32,
    notes: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl IotDeviceRow {
    fn into_iot_device(self) -> IotDevice {
        let protocols: Vec<IotProtocolType> = serde_json::from_str(&self.protocols)
            .unwrap_or_default();
        let open_ports: Vec<u16> = serde_json::from_str(&self.open_ports)
            .unwrap_or_default();

        IotDevice {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            device_type: self.device_type.parse().unwrap_or(IotDeviceType::Unknown),
            vendor: self.vendor,
            model: self.model,
            firmware_version: self.firmware_version,
            ip_address: self.ip_address,
            mac_address: self.mac_address,
            hostname: self.hostname,
            protocols,
            open_ports,
            default_creds_status: self.default_creds_status.parse().unwrap_or(DefaultCredsStatus::Unknown),
            last_seen: self.last_seen.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            first_seen: self.first_seen.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            risk_score: self.risk_score,
            notes: self.notes,
            customer_id: self.customer_id,
            engagement_id: self.engagement_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct IotScanRow {
    id: String,
    user_id: String,
    name: String,
    scan_type: String,
    target_range: Option<String>,
    status: String,
    devices_found: i32,
    vulnerabilities_found: i32,
    started_at: Option<String>,
    completed_at: Option<String>,
    customer_id: Option<String>,
    engagement_id: Option<String>,
    created_at: String,
}

impl IotScanRow {
    fn into_iot_scan(self) -> IotScan {
        IotScan {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            scan_type: self.scan_type.parse().unwrap_or(IotScanType::Discovery),
            target_range: self.target_range,
            status: self.status.parse().unwrap_or(ScanStatus::Pending),
            devices_found: self.devices_found,
            vulnerabilities_found: self.vulnerabilities_found,
            started_at: self.started_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            completed_at: self.completed_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            customer_id: self.customer_id,
            engagement_id: self.engagement_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct IotCredentialRow {
    id: String,
    device_type: String,
    vendor: Option<String>,
    model: Option<String>,
    protocol: String,
    username: String,
    password: String,
    source: String,
    created_at: String,
}

impl IotCredentialRow {
    fn into_iot_credential(self) -> IotCredential {
        IotCredential {
            id: self.id,
            device_type: self.device_type,
            vendor: self.vendor,
            model: self.model,
            protocol: self.protocol,
            username: self.username,
            password: self.password,
            source: self.source,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateIotDeviceRequest {
    pub name: Option<String>,
    pub device_type: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub protocols: Option<Vec<String>>,
    pub open_ports: Option<Vec<u16>>,
    pub notes: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIotDeviceRequest {
    pub name: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub protocols: Option<Vec<String>>,
    pub open_ports: Option<Vec<u16>>,
    pub default_creds_status: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateIotScanRequest {
    pub name: String,
    pub scan_type: String,
    pub target_range: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListIotDevicesQuery {
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub default_creds_status: Option<String>,
    pub customer_id: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ListIotScansQuery {
    pub status: Option<String>,
    pub scan_type: Option<String>,
    pub customer_id: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct SearchCredentialsQuery {
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub protocol: Option<String>,
    pub limit: Option<i32>,
}

// ============================================================================
// Device Operations
// ============================================================================

/// Create a new IoT device
pub async fn create_iot_device(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateIotDeviceRequest,
) -> Result<IotDevice> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let protocols = request.protocols.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());

    let open_ports = request.open_ports.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO iot_devices (
            id, user_id, name, device_type, vendor, model, firmware_version,
            ip_address, mac_address, hostname, protocols, open_ports,
            default_creds_status, first_seen, risk_score, notes,
            customer_id, engagement_id, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', ?, 0, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.device_type)
    .bind(&request.vendor)
    .bind(&request.model)
    .bind(&request.firmware_version)
    .bind(&request.ip_address)
    .bind(&request.mac_address)
    .bind(&request.hostname)
    .bind(&protocols)
    .bind(&open_ports)
    .bind(&now)
    .bind(&request.notes)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_iot_device_by_id(pool, &id, user_id).await
}

/// Get IoT device by ID
pub async fn get_iot_device_by_id(pool: &SqlitePool, id: &str, user_id: &str) -> Result<IotDevice> {
    let row: IotDeviceRow = sqlx::query_as(
        "SELECT * FROM iot_devices WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.into_iot_device())
}

/// List IoT devices for a user
pub async fn list_iot_devices(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListIotDevicesQuery,
) -> Result<Vec<IotDevice>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM iot_devices WHERE user_id = ?");
    let mut bindings: Vec<String> = vec![user_id.to_string()];

    if let Some(device_type) = &query.device_type {
        sql.push_str(" AND device_type = ?");
        bindings.push(device_type.clone());
    }

    if let Some(vendor) = &query.vendor {
        sql.push_str(" AND vendor LIKE ?");
        bindings.push(format!("%{}%", vendor));
    }

    if let Some(status) = &query.default_creds_status {
        sql.push_str(" AND default_creds_status = ?");
        bindings.push(status.clone());
    }

    if let Some(customer_id) = &query.customer_id {
        sql.push_str(" AND customer_id = ?");
        bindings.push(customer_id.clone());
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut query_builder = sqlx::query_as::<_, IotDeviceRow>(&sql);
    for binding in &bindings {
        query_builder = query_builder.bind(binding);
    }
    query_builder = query_builder.bind(limit).bind(offset);

    let rows: Vec<IotDeviceRow> = query_builder.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into_iot_device()).collect())
}

/// Update IoT device
pub async fn update_iot_device(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    request: &UpdateIotDeviceRequest,
) -> Result<IotDevice> {
    let now = Utc::now().to_rfc3339();

    let existing = get_iot_device_by_id(pool, id, user_id).await?;

    let name = request.name.clone().or(existing.name);
    let device_type = request.device_type.clone().unwrap_or(existing.device_type.to_string());
    let vendor = request.vendor.clone().or(existing.vendor);
    let model = request.model.clone().or(existing.model);
    let firmware_version = request.firmware_version.clone().or(existing.firmware_version);
    let ip_address = request.ip_address.clone().or(existing.ip_address);
    let mac_address = request.mac_address.clone().or(existing.mac_address);
    let hostname = request.hostname.clone().or(existing.hostname);
    let protocols = request.protocols.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| serde_json::to_string(&existing.protocols).unwrap_or_default());
    let open_ports = request.open_ports.as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default())
        .unwrap_or_else(|| serde_json::to_string(&existing.open_ports).unwrap_or_default());
    let default_creds_status = request.default_creds_status.clone()
        .unwrap_or(existing.default_creds_status.to_string());
    let notes = request.notes.clone().or(existing.notes);

    sqlx::query(
        r#"
        UPDATE iot_devices SET
            name = ?, device_type = ?, vendor = ?, model = ?, firmware_version = ?,
            ip_address = ?, mac_address = ?, hostname = ?, protocols = ?, open_ports = ?,
            default_creds_status = ?, notes = ?, last_seen = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&name)
    .bind(&device_type)
    .bind(&vendor)
    .bind(&model)
    .bind(&firmware_version)
    .bind(&ip_address)
    .bind(&mac_address)
    .bind(&hostname)
    .bind(&protocols)
    .bind(&open_ports)
    .bind(&default_creds_status)
    .bind(&notes)
    .bind(&now)
    .bind(&now)
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    get_iot_device_by_id(pool, id, user_id).await
}

/// Delete IoT device
pub async fn delete_iot_device(pool: &SqlitePool, id: &str, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM iot_devices WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Create a new IoT scan
pub async fn create_iot_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateIotScanRequest,
) -> Result<IotScan> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO iot_scans (
            id, user_id, name, scan_type, target_range,
            status, devices_found, vulnerabilities_found,
            customer_id, engagement_id, created_at
        )
        VALUES (?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.scan_type)
    .bind(&request.target_range)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_iot_scan_by_id(pool, &id, user_id).await
}

/// Get IoT scan by ID
pub async fn get_iot_scan_by_id(pool: &SqlitePool, id: &str, user_id: &str) -> Result<IotScan> {
    let row: IotScanRow = sqlx::query_as(
        "SELECT * FROM iot_scans WHERE id = ? AND user_id = ?"
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.into_iot_scan())
}

/// List IoT scans for a user
pub async fn list_iot_scans(
    pool: &SqlitePool,
    user_id: &str,
    query: &ListIotScansQuery,
) -> Result<Vec<IotScan>> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from("SELECT * FROM iot_scans WHERE user_id = ?");
    let mut bindings: Vec<String> = vec![user_id.to_string()];

    if let Some(status) = &query.status {
        sql.push_str(" AND status = ?");
        bindings.push(status.clone());
    }

    if let Some(scan_type) = &query.scan_type {
        sql.push_str(" AND scan_type = ?");
        bindings.push(scan_type.clone());
    }

    if let Some(customer_id) = &query.customer_id {
        sql.push_str(" AND customer_id = ?");
        bindings.push(customer_id.clone());
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut query_builder = sqlx::query_as::<_, IotScanRow>(&sql);
    for binding in &bindings {
        query_builder = query_builder.bind(binding);
    }
    query_builder = query_builder.bind(limit).bind(offset);

    let rows: Vec<IotScanRow> = query_builder.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into_iot_scan()).collect())
}

/// Update IoT scan status
pub async fn update_iot_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    match status {
        "running" => {
            sqlx::query("UPDATE iot_scans SET status = ?, started_at = ? WHERE id = ?")
                .bind(status)
                .bind(&now)
                .bind(id)
                .execute(pool)
                .await?;
        }
        "completed" | "failed" | "cancelled" => {
            sqlx::query("UPDATE iot_scans SET status = ?, completed_at = ? WHERE id = ?")
                .bind(status)
                .bind(&now)
                .bind(id)
                .execute(pool)
                .await?;
        }
        _ => {
            sqlx::query("UPDATE iot_scans SET status = ? WHERE id = ?")
                .bind(status)
                .bind(id)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

/// Update IoT scan results
pub async fn update_iot_scan_results(
    pool: &SqlitePool,
    id: &str,
    devices_found: i32,
    vulnerabilities_found: i32,
) -> Result<()> {
    sqlx::query(
        "UPDATE iot_scans SET devices_found = ?, vulnerabilities_found = ? WHERE id = ?"
    )
    .bind(devices_found)
    .bind(vulnerabilities_found)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Credentials Operations
// ============================================================================

/// Search IoT credentials
pub async fn search_iot_credentials(
    pool: &SqlitePool,
    query: &SearchCredentialsQuery,
) -> Result<Vec<IotCredential>> {
    let limit = query.limit.unwrap_or(100);

    let mut sql = String::from("SELECT * FROM iot_credentials WHERE 1=1");
    let mut bindings: Vec<String> = Vec::new();

    if let Some(device_type) = &query.device_type {
        sql.push_str(" AND (device_type = ? OR device_type = 'unknown')");
        bindings.push(device_type.clone());
    }

    if let Some(vendor) = &query.vendor {
        sql.push_str(" AND (vendor LIKE ? OR vendor IS NULL)");
        bindings.push(format!("%{}%", vendor));
    }

    if let Some(protocol) = &query.protocol {
        sql.push_str(" AND protocol = ?");
        bindings.push(protocol.clone());
    }

    sql.push_str(" ORDER BY source, device_type LIMIT ?");

    let mut query_builder = sqlx::query_as::<_, IotCredentialRow>(&sql);
    for binding in &bindings {
        query_builder = query_builder.bind(binding);
    }
    query_builder = query_builder.bind(limit);

    let rows: Vec<IotCredentialRow> = query_builder.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into_iot_credential()).collect())
}

// ============================================================================
// Dashboard Operations
// ============================================================================

/// Get IoT dashboard statistics
pub async fn get_iot_dashboard_stats(pool: &SqlitePool, user_id: &str) -> Result<IotDashboardStats> {
    // Total devices
    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM iot_devices WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Devices by type
    let devices_by_type: Vec<(String, i64)> = sqlx::query_as(
        "SELECT device_type, COUNT(*) FROM iot_devices WHERE user_id = ? GROUP BY device_type"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Devices with default credentials
    let default_creds: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM iot_devices WHERE user_id = ? AND default_creds_status = 'vulnerable'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Devices by vendor
    let devices_by_vendor: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT vendor, COUNT(*) FROM iot_devices WHERE user_id = ? AND vendor IS NOT NULL GROUP BY vendor ORDER BY COUNT(*) DESC LIMIT 10"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Recent scans
    let recent_scans = list_iot_scans(pool, user_id, &ListIotScansQuery {
        status: None,
        scan_type: None,
        customer_id: None,
        limit: Some(5),
        offset: Some(0),
    }).await?;

    // Risk distribution
    let risk_low: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM iot_devices WHERE user_id = ? AND risk_score < 30"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let risk_medium: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM iot_devices WHERE user_id = ? AND risk_score >= 30 AND risk_score < 70"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let risk_high: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM iot_devices WHERE user_id = ? AND risk_score >= 70"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Protocol usage - parse protocols from all devices and count
    let device_protocols: Vec<(String,)> = sqlx::query_as(
        "SELECT protocols FROM iot_devices WHERE user_id = ? AND protocols != '[]'"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut protocol_counts: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    for (protocol_json,) in device_protocols {
        if let Ok(protocols) = serde_json::from_str::<Vec<IotProtocolType>>(&protocol_json) {
            for protocol in protocols {
                let proto_name = format!("{:?}", protocol);
                *protocol_counts.entry(proto_name).or_insert(0) += 1;
            }
        }
    }
    let protocol_usage: Vec<ProtocolCount> = protocol_counts
        .into_iter()
        .map(|(protocol, count)| ProtocolCount { protocol, count })
        .collect();

    Ok(IotDashboardStats {
        total_devices: total.0 as i32,
        devices_by_type: devices_by_type.into_iter()
            .map(|(t, c)| TypeCount { device_type: t, count: c as i32 })
            .collect(),
        devices_with_default_creds: default_creds.0 as i32,
        devices_by_vendor: devices_by_vendor.into_iter()
            .filter_map(|(v, c)| v.map(|vendor| VendorCount { vendor, count: c as i32 }))
            .collect(),
        recent_scans,
        risk_distribution: vec![
            RiskCount { risk_level: "Low".to_string(), count: risk_low.0 as i32 },
            RiskCount { risk_level: "Medium".to_string(), count: risk_medium.0 as i32 },
            RiskCount { risk_level: "High".to_string(), count: risk_high.0 as i32 },
        ],
        protocol_usage,
    })
}
