//! Database operations for threat intelligence data
//!
//! This module handles storage and retrieval of threat intelligence data
//! including cached lookups, alerts, and enrichment results.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use log::{debug, warn};
use sqlx::SqlitePool;

use crate::threat_intel::types::{
    AlertType, AffectedAsset, EnrichedCve, EnrichmentResult, ExploitInfo,
    IpThreatIntel, ShodanHostInfo, ShodanService, ThreatAlert, ThreatSeverity, ThreatSource,
};

/// Initialize threat intel tables
pub async fn create_threat_intel_tables(pool: &SqlitePool) -> Result<()> {
    // Threat intel cache table for IP lookups
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            ip TEXT PRIMARY KEY,
            shodan_data TEXT,
            cves_data TEXT,
            exploits_data TEXT,
            threat_score INTEGER NOT NULL,
            risk_factors TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // CVE cache table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_intel_cve_cache (
            cve_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_v3_score REAL,
            cvss_v2_score REAL,
            in_cisa_kev INTEGER NOT NULL DEFAULT 0,
            kev_due_date TEXT,
            exploits_data TEXT,
            affected_products TEXT,
            references_data TEXT,
            attack_vector TEXT,
            attack_complexity TEXT,
            published_date TEXT,
            last_modified TEXT,
            cached_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Threat alerts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id TEXT PRIMARY KEY,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            source TEXT NOT NULL,
            affected_assets TEXT NOT NULL,
            cve_ids TEXT,
            exploit_available INTEGER NOT NULL DEFAULT 0,
            in_cisa_kev INTEGER NOT NULL DEFAULT 0,
            recommendations TEXT,
            reference_urls TEXT,
            scan_id TEXT,
            created_at TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Enrichment results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_intel_enrichments (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            enriched_hosts INTEGER NOT NULL,
            total_exploits_found INTEGER NOT NULL,
            critical_findings INTEGER NOT NULL,
            kev_matches INTEGER NOT NULL,
            enriched_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_intel_cache_expires ON threat_intel_cache(expires_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_alerts_scan_id ON threat_alerts(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_alerts_severity ON threat_alerts(severity)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_alerts_created ON threat_alerts(created_at DESC)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_intel_cve_cache_expires ON threat_intel_cve_cache(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Cache IP threat intel lookup
pub async fn cache_ip_intel(pool: &SqlitePool, intel: &IpThreatIntel, ttl_hours: i64) -> Result<()> {
    let expires_at = Utc::now() + Duration::hours(ttl_hours);

    let shodan_json = intel
        .shodan_info
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_default());

    let cves_json = serde_json::to_string(&intel.associated_cves)?;
    let exploits_json = serde_json::to_string(&intel.available_exploits)?;
    let risk_factors_json = serde_json::to_string(&intel.risk_factors)?;

    sqlx::query(
        r#"
        INSERT INTO threat_intel_cache (ip, shodan_data, cves_data, exploits_data, threat_score, risk_factors, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            shodan_data = excluded.shodan_data,
            cves_data = excluded.cves_data,
            exploits_data = excluded.exploits_data,
            threat_score = excluded.threat_score,
            risk_factors = excluded.risk_factors,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at
        "#,
    )
    .bind(&intel.ip)
    .bind(&shodan_json)
    .bind(&cves_json)
    .bind(&exploits_json)
    .bind(intel.threat_score as i32)
    .bind(&risk_factors_json)
    .bind(intel.last_updated.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached threat intel for IP: {}", intel.ip);
    Ok(())
}

/// Get cached IP threat intel
pub async fn get_cached_ip_intel(pool: &SqlitePool, ip: &str) -> Result<Option<IpThreatIntel>> {
    let row = sqlx::query_as::<_, (String, Option<String>, String, String, i32, String, String, String)>(
        r#"
        SELECT ip, shodan_data, cves_data, exploits_data, threat_score, risk_factors, created_at, expires_at
        FROM threat_intel_cache
        WHERE ip = ? AND expires_at > datetime('now')
        "#,
    )
    .bind(ip)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((ip, shodan_json, cves_json, exploits_json, threat_score, risk_factors_json, created_at, _expires)) => {
            let shodan_info: Option<ShodanHostInfo> = shodan_json
                .and_then(|s| serde_json::from_str(&s).ok());

            let associated_cves: Vec<EnrichedCve> = serde_json::from_str(&cves_json).unwrap_or_default();
            let available_exploits: Vec<ExploitInfo> = serde_json::from_str(&exploits_json).unwrap_or_default();
            let risk_factors: Vec<String> = serde_json::from_str(&risk_factors_json).unwrap_or_default();

            let last_updated = DateTime::parse_from_rfc3339(&created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(Some(IpThreatIntel {
                ip,
                shodan_info,
                associated_cves,
                available_exploits,
                threat_score: threat_score as u8,
                risk_factors,
                last_updated,
            }))
        }
        None => Ok(None),
    }
}

/// Cache CVE data
pub async fn cache_cve(pool: &SqlitePool, cve: &EnrichedCve, ttl_hours: i64) -> Result<()> {
    let expires_at = Utc::now() + Duration::hours(ttl_hours);

    let exploits_json = serde_json::to_string(&cve.exploits)?;
    let products_json = serde_json::to_string(&cve.affected_products)?;
    let refs_json = serde_json::to_string(&cve.references)?;

    sqlx::query(
        r#"
        INSERT INTO threat_intel_cve_cache (
            cve_id, title, description, severity, cvss_v3_score, cvss_v2_score,
            in_cisa_kev, kev_due_date, exploits_data, affected_products, references_data,
            attack_vector, attack_complexity, published_date, last_modified, cached_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            title = excluded.title,
            description = excluded.description,
            severity = excluded.severity,
            cvss_v3_score = excluded.cvss_v3_score,
            cvss_v2_score = excluded.cvss_v2_score,
            in_cisa_kev = excluded.in_cisa_kev,
            kev_due_date = excluded.kev_due_date,
            exploits_data = excluded.exploits_data,
            affected_products = excluded.affected_products,
            references_data = excluded.references_data,
            attack_vector = excluded.attack_vector,
            attack_complexity = excluded.attack_complexity,
            published_date = excluded.published_date,
            last_modified = excluded.last_modified,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at
        "#,
    )
    .bind(&cve.cve_id)
    .bind(&cve.title)
    .bind(&cve.description)
    .bind(cve.severity.to_string())
    .bind(cve.cvss_v3_score)
    .bind(cve.cvss_v2_score)
    .bind(cve.in_cisa_kev)
    .bind(&cve.kev_due_date)
    .bind(&exploits_json)
    .bind(&products_json)
    .bind(&refs_json)
    .bind(&cve.attack_vector)
    .bind(&cve.attack_complexity)
    .bind(cve.published_date.map(|d| d.to_rfc3339()))
    .bind(cve.last_modified.map(|d| d.to_rfc3339()))
    .bind(Utc::now().to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached CVE: {}", cve.cve_id);
    Ok(())
}

/// Get cached CVE data
pub async fn get_cached_cve(pool: &SqlitePool, cve_id: &str) -> Result<Option<EnrichedCve>> {
    let row = sqlx::query_as::<_, CveCacheRow>(
        r#"
        SELECT cve_id, title, description, severity, cvss_v3_score, cvss_v2_score,
               in_cisa_kev, kev_due_date, exploits_data, affected_products, references_data,
               attack_vector, attack_complexity, published_date, last_modified
        FROM threat_intel_cve_cache
        WHERE cve_id = ? AND expires_at > datetime('now')
        "#,
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_enriched_cve())),
        None => Ok(None),
    }
}

/// Helper struct for CVE cache row
#[derive(sqlx::FromRow)]
struct CveCacheRow {
    cve_id: String,
    title: String,
    description: String,
    severity: String,
    cvss_v3_score: Option<f64>,
    cvss_v2_score: Option<f64>,
    in_cisa_kev: bool,
    kev_due_date: Option<String>,
    exploits_data: String,
    affected_products: String,
    references_data: String,
    attack_vector: Option<String>,
    attack_complexity: Option<String>,
    published_date: Option<String>,
    last_modified: Option<String>,
}

impl CveCacheRow {
    fn into_enriched_cve(self) -> EnrichedCve {
        let severity = match self.severity.as_str() {
            "critical" => ThreatSeverity::Critical,
            "high" => ThreatSeverity::High,
            "medium" => ThreatSeverity::Medium,
            "low" => ThreatSeverity::Low,
            _ => ThreatSeverity::Info,
        };

        let exploits: Vec<ExploitInfo> = serde_json::from_str(&self.exploits_data).unwrap_or_default();
        let affected_products = serde_json::from_str(&self.affected_products).unwrap_or_default();
        let references = serde_json::from_str(&self.references_data).unwrap_or_default();

        let published_date = self.published_date.and_then(|s| {
            DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))
        });

        let last_modified = self.last_modified.and_then(|s| {
            DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))
        });

        EnrichedCve {
            cve_id: self.cve_id,
            title: self.title,
            description: self.description,
            severity,
            cvss_v3_score: self.cvss_v3_score.map(|v| v as f32),
            cvss_v2_score: self.cvss_v2_score.map(|v| v as f32),
            published_date,
            last_modified,
            affected_products,
            exploits,
            in_cisa_kev: self.in_cisa_kev,
            kev_due_date: self.kev_due_date,
            references,
            attack_vector: self.attack_vector,
            attack_complexity: self.attack_complexity,
            epss_score: None,
        }
    }
}

/// Store a threat alert
pub async fn store_alert(pool: &SqlitePool, alert: &ThreatAlert) -> Result<()> {
    let affected_json = serde_json::to_string(&alert.affected_assets)?;
    let cve_ids_json = serde_json::to_string(&alert.cve_ids)?;
    let recommendations_json = serde_json::to_string(&alert.recommendations)?;
    let refs_json = serde_json::to_string(&alert.references)?;

    sqlx::query(
        r#"
        INSERT INTO threat_alerts (
            id, alert_type, severity, title, description, source, affected_assets,
            cve_ids, exploit_available, in_cisa_kev, recommendations, reference_urls,
            scan_id, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
        "#,
    )
    .bind(&alert.id)
    .bind(format!("{:?}", alert.alert_type).to_lowercase())
    .bind(alert.severity.to_string())
    .bind(&alert.title)
    .bind(&alert.description)
    .bind(alert.source.to_string())
    .bind(&affected_json)
    .bind(&cve_ids_json)
    .bind(alert.exploit_available)
    .bind(alert.in_cisa_kev)
    .bind(&recommendations_json)
    .bind(&refs_json)
    .bind(&alert.scan_id)
    .bind(alert.created_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Stored threat alert: {}", alert.id);
    Ok(())
}

/// Get recent alerts
pub async fn get_recent_alerts(pool: &SqlitePool, limit: i32) -> Result<Vec<ThreatAlert>> {
    let rows = sqlx::query_as::<_, AlertRow>(
        r#"
        SELECT id, alert_type, severity, title, description, source, affected_assets,
               cve_ids, exploit_available, in_cisa_kev, recommendations, reference_urls,
               scan_id, created_at, acknowledged, acknowledged_by, acknowledged_at
        FROM threat_alerts
        ORDER BY created_at DESC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_alert()).collect())
}

/// Get alerts for a specific scan
pub async fn get_alerts_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ThreatAlert>> {
    let rows = sqlx::query_as::<_, AlertRow>(
        r#"
        SELECT id, alert_type, severity, title, description, source, affected_assets,
               cve_ids, exploit_available, in_cisa_kev, recommendations, reference_urls,
               scan_id, created_at, acknowledged, acknowledged_by, acknowledged_at
        FROM threat_alerts
        WHERE scan_id = ?
        ORDER BY severity DESC, created_at DESC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_alert()).collect())
}

/// Store enrichment result
pub async fn store_enrichment_result(pool: &SqlitePool, result: &EnrichmentResult) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO threat_intel_enrichments (
            id, scan_id, enriched_hosts, total_exploits_found, critical_findings,
            kev_matches, enriched_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&result.scan_id)
    .bind(result.enriched_hosts as i32)
    .bind(result.total_exploits_found as i32)
    .bind(result.critical_findings as i32)
    .bind(result.kev_matches as i32)
    .bind(result.enriched_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Stored enrichment result for scan: {}", result.scan_id);
    Ok(())
}

/// Get enrichment result for a scan
pub async fn get_enrichment_result(pool: &SqlitePool, scan_id: &str) -> Result<Option<EnrichmentResult>> {
    let row = sqlx::query_as::<_, (String, i32, i32, i32, i32, String)>(
        r#"
        SELECT scan_id, enriched_hosts, total_exploits_found, critical_findings, kev_matches, enriched_at
        FROM threat_intel_enrichments
        WHERE scan_id = ?
        ORDER BY enriched_at DESC
        LIMIT 1
        "#,
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((scan_id, enriched_hosts, total_exploits, critical, kev_matches, enriched_at)) => {
            // Get alerts for this scan
            let alerts = get_alerts_for_scan(pool, &scan_id).await?;

            let enriched_at = DateTime::parse_from_rfc3339(&enriched_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(Some(EnrichmentResult {
                scan_id,
                alerts_generated: alerts,
                enriched_hosts: enriched_hosts as usize,
                total_exploits_found: total_exploits as usize,
                critical_findings: critical as usize,
                kev_matches: kev_matches as usize,
                enriched_at,
            }))
        }
        None => Ok(None),
    }
}

/// Acknowledge an alert
pub async fn acknowledge_alert(pool: &SqlitePool, alert_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE threat_alerts
        SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
        WHERE id = ?
        "#,
    )
    .bind(user_id)
    .bind(Utc::now().to_rfc3339())
    .bind(alert_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Clean up expired cache entries
pub async fn cleanup_expired_cache(pool: &SqlitePool) -> Result<(u64, u64)> {
    let ip_deleted = sqlx::query("DELETE FROM threat_intel_cache WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?
        .rows_affected();

    let cve_deleted = sqlx::query("DELETE FROM threat_intel_cve_cache WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?
        .rows_affected();

    if ip_deleted > 0 || cve_deleted > 0 {
        debug!("Cleaned up {} IP cache entries and {} CVE cache entries", ip_deleted, cve_deleted);
    }

    Ok((ip_deleted, cve_deleted))
}

/// Helper struct for alert row
#[derive(sqlx::FromRow)]
struct AlertRow {
    id: String,
    alert_type: String,
    severity: String,
    title: String,
    description: String,
    source: String,
    affected_assets: String,
    cve_ids: String,
    exploit_available: bool,
    in_cisa_kev: bool,
    recommendations: String,
    reference_urls: String,
    scan_id: Option<String>,
    created_at: String,
    #[allow(dead_code)]
    acknowledged: bool,
    #[allow(dead_code)]
    acknowledged_by: Option<String>,
    #[allow(dead_code)]
    acknowledged_at: Option<String>,
}

impl AlertRow {
    fn into_alert(self) -> ThreatAlert {
        let alert_type = match self.alert_type.as_str() {
            "exposedservice" | "exposed_service" => AlertType::ExposedService,
            "exploitavailable" | "exploit_available" => AlertType::ExploitAvailable,
            "knownexploitedvulnerability" | "known_exploited_vulnerability" => AlertType::KnownExploitedVulnerability,
            "criticalcve" | "critical_cve" => AlertType::CriticalCve,
            "newcve" | "new_cve" => AlertType::NewCve,
            "ransomwarethreat" | "ransomware_threat" => AlertType::RansomwareThreat,
            "misconfiguration" => AlertType::Misconfiguration,
            _ => AlertType::CriticalCve,
        };

        let severity = match self.severity.as_str() {
            "critical" => ThreatSeverity::Critical,
            "high" => ThreatSeverity::High,
            "medium" => ThreatSeverity::Medium,
            "low" => ThreatSeverity::Low,
            _ => ThreatSeverity::Info,
        };

        let source = match self.source.as_str() {
            "Shodan" => ThreatSource::Shodan,
            "ExploitDB" => ThreatSource::ExploitDb,
            "NVD CVE" => ThreatSource::NvdCve,
            "CISA KEV" => ThreatSource::CisaKev,
            _ => ThreatSource::Manual,
        };

        let affected_assets: Vec<AffectedAsset> = serde_json::from_str(&self.affected_assets).unwrap_or_default();
        let cve_ids: Vec<String> = serde_json::from_str(&self.cve_ids).unwrap_or_default();
        let recommendations: Vec<String> = serde_json::from_str(&self.recommendations).unwrap_or_default();
        let references: Vec<String> = serde_json::from_str(&self.reference_urls).unwrap_or_default();

        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        ThreatAlert {
            id: self.id,
            alert_type,
            severity,
            title: self.title,
            description: self.description,
            source,
            affected_assets,
            cve_ids,
            exploit_available: self.exploit_available,
            in_cisa_kev: self.in_cisa_kev,
            recommendations,
            references,
            created_at,
            scan_id: self.scan_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_type_parsing() {
        let row = AlertRow {
            id: "test".to_string(),
            alert_type: "exposed_service".to_string(),
            severity: "high".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            source: "Shodan".to_string(),
            affected_assets: "[]".to_string(),
            cve_ids: "[]".to_string(),
            exploit_available: false,
            in_cisa_kev: false,
            recommendations: "[]".to_string(),
            reference_urls: "[]".to_string(),
            scan_id: None,
            created_at: Utc::now().to_rfc3339(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
        };

        let alert = row.into_alert();
        assert_eq!(alert.alert_type, AlertType::ExposedService);
        assert_eq!(alert.severity, ThreatSeverity::High);
        assert_eq!(alert.source, ThreatSource::Shodan);
    }
}
