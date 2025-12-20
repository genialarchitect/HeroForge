//! Scan Exclusions database operations
//!
//! This module handles host/port exclusion rules that can be:
//! - Global (applied to all scans for a user)
//! - Per-scan (specified during scan creation)
//!
//! Exclusion types:
//! - host: Single IP address (e.g., "192.168.1.1")
//! - cidr: CIDR range (e.g., "192.168.1.0/24")
//! - hostname: Hostname pattern (e.g., "*.internal.example.com")
//! - port: Single port (e.g., "22")
//! - port_range: Port range (e.g., "1-1000")

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

/// Exclusion type enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionType {
    Host,
    Cidr,
    Hostname,
    Port,
    PortRange,
}

impl ExclusionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Cidr => "cidr",
            Self::Hostname => "hostname",
            Self::Port => "port",
            Self::PortRange => "port_range",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Self::Host),
            "cidr" => Some(Self::Cidr),
            "hostname" => Some(Self::Hostname),
            "port" => Some(Self::Port),
            "port_range" => Some(Self::PortRange),
            _ => None,
        }
    }
}

impl std::fmt::Display for ExclusionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Scan exclusion rule stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct ScanExclusion {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub exclusion_type: String,
    pub value: String,
    pub is_global: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new exclusion rule
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateExclusionRequest {
    pub name: String,
    pub description: Option<String>,
    pub exclusion_type: String,
    pub value: String,
    pub is_global: bool,
}

/// Request to update an exclusion rule
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateExclusionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub exclusion_type: Option<String>,
    pub value: Option<String>,
    pub is_global: Option<bool>,
}

/// Exclusion rule to apply during scan (lightweight version for scanning)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRule {
    pub exclusion_type: ExclusionType,
    pub value: String,
}

impl From<&ScanExclusion> for ExclusionRule {
    fn from(exc: &ScanExclusion) -> Self {
        Self {
            exclusion_type: ExclusionType::from_str(&exc.exclusion_type)
                .unwrap_or(ExclusionType::Host),
            value: exc.value.clone(),
        }
    }
}

// ============================================================================
// Database Operations
// ============================================================================

/// Create a new exclusion rule
pub async fn create_exclusion(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateExclusionRequest,
) -> Result<ScanExclusion> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Validate exclusion type
    if ExclusionType::from_str(&request.exclusion_type).is_none() {
        return Err(anyhow::anyhow!(
            "Invalid exclusion type: {}. Valid types are: host, cidr, hostname, port, port_range",
            request.exclusion_type
        ));
    }

    // Validate value based on type
    validate_exclusion_value(&request.exclusion_type, &request.value)?;

    sqlx::query(
        r#"
        INSERT INTO scan_exclusions (id, user_id, name, description, exclusion_type, value, is_global, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.exclusion_type)
    .bind(&request.value)
    .bind(request.is_global)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(ScanExclusion {
        id,
        user_id: user_id.to_string(),
        name: request.name.clone(),
        description: request.description.clone(),
        exclusion_type: request.exclusion_type.clone(),
        value: request.value.clone(),
        is_global: request.is_global,
        created_at: now,
        updated_at: now,
    })
}

/// Get all exclusions for a user
pub async fn get_user_exclusions(pool: &SqlitePool, user_id: &str) -> Result<Vec<ScanExclusion>> {
    let exclusions = sqlx::query_as::<_, ScanExclusion>(
        r#"
        SELECT id, user_id, name, description, exclusion_type, value, is_global, created_at, updated_at
        FROM scan_exclusions
        WHERE user_id = ?
        ORDER BY is_global DESC, name ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(exclusions)
}

/// Get global exclusions for a user (to apply automatically to all scans)
pub async fn get_global_exclusions(pool: &SqlitePool, user_id: &str) -> Result<Vec<ScanExclusion>> {
    let exclusions = sqlx::query_as::<_, ScanExclusion>(
        r#"
        SELECT id, user_id, name, description, exclusion_type, value, is_global, created_at, updated_at
        FROM scan_exclusions
        WHERE user_id = ? AND is_global = 1
        ORDER BY name ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(exclusions)
}

/// Get a specific exclusion by ID
pub async fn get_exclusion_by_id(
    pool: &SqlitePool,
    exclusion_id: &str,
) -> Result<Option<ScanExclusion>> {
    let exclusion = sqlx::query_as::<_, ScanExclusion>(
        r#"
        SELECT id, user_id, name, description, exclusion_type, value, is_global, created_at, updated_at
        FROM scan_exclusions
        WHERE id = ?
        "#,
    )
    .bind(exclusion_id)
    .fetch_optional(pool)
    .await?;

    Ok(exclusion)
}

/// Update an exclusion rule
pub async fn update_exclusion(
    pool: &SqlitePool,
    exclusion_id: &str,
    user_id: &str,
    request: &UpdateExclusionRequest,
) -> Result<Option<ScanExclusion>> {
    // First check if exclusion exists and belongs to user
    let existing = get_exclusion_by_id(pool, exclusion_id).await?;
    match existing {
        None => return Ok(None),
        Some(exc) if exc.user_id != user_id => {
            return Err(anyhow::anyhow!("Exclusion not found or access denied"));
        }
        Some(exc) => {
            // Validate new exclusion type if provided
            if let Some(ref exc_type) = request.exclusion_type {
                if ExclusionType::from_str(exc_type).is_none() {
                    return Err(anyhow::anyhow!(
                        "Invalid exclusion type: {}",
                        exc_type
                    ));
                }
            }

            // Validate value if type or value is being updated
            let new_type = request.exclusion_type.as_ref().unwrap_or(&exc.exclusion_type);
            let new_value = request.value.as_ref().unwrap_or(&exc.value);
            validate_exclusion_value(new_type, new_value)?;

            let now = Utc::now();
            let new_name = request.name.as_ref().unwrap_or(&exc.name);
            let new_description = request.description.as_ref().or(exc.description.as_ref());
            let new_is_global = request.is_global.unwrap_or(exc.is_global);

            sqlx::query(
                r#"
                UPDATE scan_exclusions
                SET name = ?, description = ?, exclusion_type = ?, value = ?, is_global = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                "#,
            )
            .bind(new_name)
            .bind(new_description)
            .bind(new_type)
            .bind(new_value)
            .bind(new_is_global)
            .bind(now)
            .bind(exclusion_id)
            .bind(user_id)
            .execute(pool)
            .await?;

            Ok(Some(ScanExclusion {
                id: exc.id,
                user_id: exc.user_id,
                name: new_name.clone(),
                description: new_description.cloned(),
                exclusion_type: new_type.clone(),
                value: new_value.clone(),
                is_global: new_is_global,
                created_at: exc.created_at,
                updated_at: now,
            }))
        }
    }
}

/// Delete an exclusion rule
pub async fn delete_exclusion(pool: &SqlitePool, exclusion_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM scan_exclusions
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(exclusion_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get exclusions by IDs (for per-scan exclusion selection)
pub async fn get_exclusions_by_ids(
    pool: &SqlitePool,
    user_id: &str,
    exclusion_ids: &[String],
) -> Result<Vec<ScanExclusion>> {
    if exclusion_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Build placeholders for IN clause
    let placeholders: Vec<String> = exclusion_ids.iter().map(|_| "?".to_string()).collect();
    let placeholder_str = placeholders.join(", ");

    let query = format!(
        r#"
        SELECT id, user_id, name, description, exclusion_type, value, is_global, created_at, updated_at
        FROM scan_exclusions
        WHERE user_id = ? AND id IN ({})
        "#,
        placeholder_str
    );

    let mut query_builder = sqlx::query_as::<_, ScanExclusion>(&query).bind(user_id);

    for id in exclusion_ids {
        query_builder = query_builder.bind(id);
    }

    let exclusions = query_builder.fetch_all(pool).await?;
    Ok(exclusions)
}

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate exclusion value based on type
fn validate_exclusion_value(exclusion_type: &str, value: &str) -> Result<()> {
    let value = value.trim();

    if value.is_empty() {
        return Err(anyhow::anyhow!("Exclusion value cannot be empty"));
    }

    match exclusion_type {
        "host" => {
            // Must be a valid IP address
            if value.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow::anyhow!(
                    "Invalid host IP address: {}. Must be a valid IPv4 or IPv6 address",
                    value
                ));
            }
        }
        "cidr" => {
            // Must be a valid CIDR notation with explicit prefix
            if !value.contains('/') {
                return Err(anyhow::anyhow!(
                    "Invalid CIDR notation: {}. Must include subnet prefix (e.g., 192.168.1.0/24)",
                    value
                ));
            }
            if value.parse::<ipnetwork::IpNetwork>().is_err() {
                return Err(anyhow::anyhow!(
                    "Invalid CIDR notation: {}. Example: 192.168.1.0/24",
                    value
                ));
            }
        }
        "hostname" => {
            // Allow wildcards in hostname patterns
            let pattern = value.replace('*', "x"); // Replace wildcards for validation
            if !is_valid_hostname_pattern(&pattern) {
                return Err(anyhow::anyhow!(
                    "Invalid hostname pattern: {}. Examples: *.internal.com, server.local",
                    value
                ));
            }
        }
        "port" => {
            // Must be a valid port number
            match value.parse::<u16>() {
                Ok(p) if p > 0 => {}
                _ => {
                    return Err(anyhow::anyhow!(
                        "Invalid port number: {}. Must be between 1 and 65535",
                        value
                    ));
                }
            }
        }
        "port_range" => {
            // Must be in format "start-end"
            let parts: Vec<&str> = value.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!(
                    "Invalid port range format: {}. Must be in format 'start-end' (e.g., 1-1000)",
                    value
                ));
            }
            let start: u16 = parts[0].trim().parse().map_err(|_| {
                anyhow::anyhow!("Invalid start port in range: {}", parts[0])
            })?;
            let end: u16 = parts[1].trim().parse().map_err(|_| {
                anyhow::anyhow!("Invalid end port in range: {}", parts[1])
            })?;
            if start == 0 || start > end {
                return Err(anyhow::anyhow!(
                    "Invalid port range: start ({}) must be >= 1 and <= end ({})",
                    start,
                    end
                ));
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown exclusion type: {}", exclusion_type));
        }
    }

    Ok(())
}

/// Validate hostname pattern (allows wildcards)
fn is_valid_hostname_pattern(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = hostname.split('.').collect();

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Each label must start and end with alphanumeric (after wildcard replacement)
        let first_char = match label.chars().next() {
            Some(c) => c,
            None => return false,
        };
        let last_char = match label.chars().last() {
            Some(c) => c,
            None => return false,
        };

        if !first_char.is_alphanumeric() || !last_char.is_alphanumeric() {
            return false;
        }

        // Each label can only contain alphanumeric and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

// ============================================================================
// Exclusion Application Functions
// ============================================================================

/// Check if a target should be excluded
pub fn should_exclude_target(target: &str, exclusions: &[ExclusionRule]) -> bool {
    for rule in exclusions {
        match rule.exclusion_type {
            ExclusionType::Host => {
                if let Ok(target_ip) = target.parse::<std::net::IpAddr>() {
                    if let Ok(rule_ip) = rule.value.parse::<std::net::IpAddr>() {
                        if target_ip == rule_ip {
                            return true;
                        }
                    }
                }
            }
            ExclusionType::Cidr => {
                if let Ok(target_ip) = target.parse::<std::net::IpAddr>() {
                    if let Ok(network) = rule.value.parse::<ipnetwork::IpNetwork>() {
                        if network.contains(target_ip) {
                            return true;
                        }
                    }
                }
            }
            ExclusionType::Hostname => {
                if matches_hostname_pattern(target, &rule.value) {
                    return true;
                }
            }
            ExclusionType::Port | ExclusionType::PortRange => {
                // Port exclusions don't apply to target-level filtering
                continue;
            }
        }
    }
    false
}

/// Check if a port should be excluded
pub fn should_exclude_port(port: u16, exclusions: &[ExclusionRule]) -> bool {
    for rule in exclusions {
        match rule.exclusion_type {
            ExclusionType::Port => {
                if let Ok(excluded_port) = rule.value.parse::<u16>() {
                    if port == excluded_port {
                        return true;
                    }
                }
            }
            ExclusionType::PortRange => {
                let parts: Vec<&str> = rule.value.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        parts[0].trim().parse::<u16>(),
                        parts[1].trim().parse::<u16>(),
                    ) {
                        if port >= start && port <= end {
                            return true;
                        }
                    }
                }
            }
            _ => continue,
        }
    }
    false
}

/// Match hostname against a wildcard pattern
fn matches_hostname_pattern(hostname: &str, pattern: &str) -> bool {
    let hostname_lower = hostname.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    if pattern_lower.starts_with("*.") {
        // Wildcard prefix pattern (e.g., *.example.com)
        // *.example.com should match sub.example.com but NOT example.com itself
        let suffix = &pattern_lower[1..]; // Keep the leading dot (e.g., ".example.com")
        hostname_lower.ends_with(suffix)
    } else if pattern_lower.ends_with(".*") {
        // Wildcard suffix pattern (e.g., server.*)
        let prefix = &pattern_lower[..pattern_lower.len() - 2];
        hostname_lower.starts_with(prefix)
    } else if pattern_lower.contains('*') {
        // General wildcard pattern - convert to regex-like matching
        let regex_pattern = pattern_lower.replace('.', "\\.").replace('*', ".*");
        if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
            re.is_match(&hostname_lower)
        } else {
            false
        }
    } else {
        // Exact match
        hostname_lower == pattern_lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exclusion_type_conversion() {
        assert_eq!(ExclusionType::Host.as_str(), "host");
        assert_eq!(ExclusionType::from_str("cidr"), Some(ExclusionType::Cidr));
        assert_eq!(ExclusionType::from_str("invalid"), None);
    }

    #[test]
    fn test_validate_host() {
        assert!(validate_exclusion_value("host", "192.168.1.1").is_ok());
        assert!(validate_exclusion_value("host", "::1").is_ok());
        assert!(validate_exclusion_value("host", "not-an-ip").is_err());
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_exclusion_value("cidr", "192.168.1.0/24").is_ok());
        assert!(validate_exclusion_value("cidr", "10.0.0.0/8").is_ok());
        assert!(validate_exclusion_value("cidr", "192.168.1.0").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_exclusion_value("port", "22").is_ok());
        assert!(validate_exclusion_value("port", "65535").is_ok());
        assert!(validate_exclusion_value("port", "0").is_err());
        assert!(validate_exclusion_value("port", "not-a-port").is_err());
    }

    #[test]
    fn test_validate_port_range() {
        assert!(validate_exclusion_value("port_range", "1-1000").is_ok());
        assert!(validate_exclusion_value("port_range", "22-22").is_ok());
        assert!(validate_exclusion_value("port_range", "1000-1").is_err());
        assert!(validate_exclusion_value("port_range", "22").is_err());
    }

    #[test]
    fn test_should_exclude_target() {
        let exclusions = vec![
            ExclusionRule {
                exclusion_type: ExclusionType::Host,
                value: "192.168.1.1".to_string(),
            },
            ExclusionRule {
                exclusion_type: ExclusionType::Cidr,
                value: "10.0.0.0/8".to_string(),
            },
        ];

        assert!(should_exclude_target("192.168.1.1", &exclusions));
        assert!(should_exclude_target("10.0.0.1", &exclusions));
        assert!(should_exclude_target("10.255.255.255", &exclusions));
        assert!(!should_exclude_target("192.168.1.2", &exclusions));
        assert!(!should_exclude_target("8.8.8.8", &exclusions));
    }

    #[test]
    fn test_should_exclude_port() {
        let exclusions = vec![
            ExclusionRule {
                exclusion_type: ExclusionType::Port,
                value: "22".to_string(),
            },
            ExclusionRule {
                exclusion_type: ExclusionType::PortRange,
                value: "1-100".to_string(),
            },
        ];

        assert!(should_exclude_port(22, &exclusions));
        assert!(should_exclude_port(1, &exclusions));
        assert!(should_exclude_port(50, &exclusions));
        assert!(should_exclude_port(100, &exclusions));
        assert!(!should_exclude_port(101, &exclusions));
        assert!(!should_exclude_port(443, &exclusions));
    }

    #[test]
    fn test_hostname_pattern_matching() {
        assert!(matches_hostname_pattern("test.example.com", "*.example.com"));
        assert!(matches_hostname_pattern("sub.test.example.com", "*.example.com"));
        assert!(!matches_hostname_pattern("example.com", "*.example.com"));
        assert!(matches_hostname_pattern("server.local", "server.local"));
        assert!(!matches_hostname_pattern("other.local", "server.local"));
    }
}
