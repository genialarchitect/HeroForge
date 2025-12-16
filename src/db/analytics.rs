// Analytics database functions
// These functions should be added to src/db/mod.rs

use sqlx::SqlitePool;
use anyhow::Result;
use chrono::Utc;

use super::models;

/// Get overall analytics summary for a user
pub async fn get_analytics_summary(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<models::AnalyticsSummary> {
    use chrono::Duration;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);
    let week_ago = now - Duration::days(7);
    let month_ago = now - Duration::days(30);

    // Get total scans in date range
    let total_scans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_results WHERE user_id = ?1 AND created_at >= ?2"
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_one(pool)
    .await?;

    // Get scans this week
    let scans_this_week: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_results WHERE user_id = ?1 AND created_at >= ?2"
    )
    .bind(user_id)
    .bind(week_ago)
    .fetch_one(pool)
    .await?;

    // Get scans this month
    let scans_this_month: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_results WHERE user_id = ?1 AND created_at >= ?2"
    )
    .bind(user_id)
    .bind(month_ago)
    .fetch_one(pool)
    .await?;

    // Fetch completed scans with results in date range
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ?1 AND status = 'completed' AND created_at >= ?2 AND results IS NOT NULL"
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Parse scan results and aggregate stats
    let mut total_hosts = 0i64;
    let mut total_ports = 0i64;
    let mut total_vulnerabilities = 0i64;
    let mut critical_vulns = 0i64;
    let mut high_vulns = 0i64;
    let mut medium_vulns = 0i64;
    let mut low_vulns = 0i64;

    for scan in scans {
        if let Some(results_json) = &scan.results {
            if let Ok(hosts) = serde_json::from_str::<Vec<crate::types::HostInfo>>(results_json) {
                total_hosts += hosts.len() as i64;

                for host in hosts {
                    // Count open ports
                    total_ports += host.ports.iter()
                        .filter(|p| matches!(p.state, crate::types::PortState::Open))
                        .count() as i64;

                    // Count vulnerabilities by severity
                    for vuln in &host.vulnerabilities {
                        total_vulnerabilities += 1;
                        match vuln.severity {
                            crate::types::Severity::Critical => critical_vulns += 1,
                            crate::types::Severity::High => high_vulns += 1,
                            crate::types::Severity::Medium => medium_vulns += 1,
                            crate::types::Severity::Low => low_vulns += 1,
                        }
                    }
                }
            }
        }
    }

    Ok(models::AnalyticsSummary {
        total_scans,
        total_hosts,
        total_ports,
        total_vulnerabilities,
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
        scans_this_week,
        scans_this_month,
    })
}

/// Get host count over time for a user
pub async fn get_hosts_over_time(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<Vec<models::TimeSeriesPoint>> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Fetch completed scans in date range
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ?1 AND status = 'completed' AND created_at >= ?2 AND results IS NOT NULL ORDER BY created_at ASC"
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Aggregate hosts by date
    let mut hosts_by_date: HashMap<String, i64> = HashMap::new();

    for scan in scans {
        let date = scan.created_at.format("%Y-%m-%d").to_string();

        if let Some(results_json) = &scan.results {
            if let Ok(hosts) = serde_json::from_str::<Vec<crate::types::HostInfo>>(results_json) {
                *hosts_by_date.entry(date).or_insert(0) += hosts.len() as i64;
            }
        }
    }

    // Convert to sorted time series
    let mut time_series: Vec<models::TimeSeriesPoint> = hosts_by_date
        .into_iter()
        .map(|(date, value)| models::TimeSeriesPoint { date, value })
        .collect();

    time_series.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(time_series)
}

/// Get vulnerability counts over time by severity
pub async fn get_vulnerabilities_over_time(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<Vec<models::VulnerabilityTrend>> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Fetch completed scans in date range
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ?1 AND status = 'completed' AND created_at >= ?2 AND results IS NOT NULL ORDER BY created_at ASC"
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Aggregate vulnerabilities by date and severity
    let mut vulns_by_date: HashMap<String, (i64, i64, i64, i64)> = HashMap::new();

    for scan in scans {
        let date = scan.created_at.format("%Y-%m-%d").to_string();

        if let Some(results_json) = &scan.results {
            if let Ok(hosts) = serde_json::from_str::<Vec<crate::types::HostInfo>>(results_json) {
                for host in hosts {
                    for vuln in &host.vulnerabilities {
                        let entry = vulns_by_date.entry(date.clone()).or_insert((0, 0, 0, 0));
                        match vuln.severity {
                            crate::types::Severity::Critical => entry.0 += 1,
                            crate::types::Severity::High => entry.1 += 1,
                            crate::types::Severity::Medium => entry.2 += 1,
                            crate::types::Severity::Low => entry.3 += 1,
                        }
                    }
                }
            }
        }
    }

    // Convert to sorted time series
    let mut time_series: Vec<models::VulnerabilityTrend> = vulns_by_date
        .into_iter()
        .map(|(date, (critical, high, medium, low))| {
            models::VulnerabilityTrend {
                date,
                critical,
                high,
                medium,
                low,
            }
        })
        .collect();

    time_series.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(time_series)
}

/// Get top services found across all scans
pub async fn get_top_services(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<models::ServiceCount>> {
    use std::collections::HashMap;

    // Fetch all completed scans for user
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ?1 AND status = 'completed' AND results IS NOT NULL"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Aggregate service counts
    let mut service_counts: HashMap<String, i64> = HashMap::new();

    for scan in scans {
        if let Some(results_json) = &scan.results {
            if let Ok(hosts) = serde_json::from_str::<Vec<crate::types::HostInfo>>(results_json) {
                for host in hosts {
                    for port in &host.ports {
                        if let Some(service) = &port.service {
                            *service_counts.entry(service.name.clone()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    // Convert to sorted vector by count
    let mut services: Vec<models::ServiceCount> = service_counts
        .into_iter()
        .map(|(service, count)| models::ServiceCount { service, count })
        .collect();

    services.sort_by(|a, b| b.count.cmp(&a.count));
    services.truncate(limit as usize);

    Ok(services)
}

/// Get scan frequency over time (scans per day)
pub async fn get_scan_frequency(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<Vec<models::TimeSeriesPoint>> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Fetch scans in date range
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ?1 AND created_at >= ?2 ORDER BY created_at ASC"
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Count scans per day
    let mut scans_by_date: HashMap<String, i64> = HashMap::new();

    for scan in scans {
        let date = scan.created_at.format("%Y-%m-%d").to_string();
        *scans_by_date.entry(date).or_insert(0) += 1;
    }

    // Convert to sorted time series
    let mut time_series: Vec<models::TimeSeriesPoint> = scans_by_date
        .into_iter()
        .map(|(date, value)| models::TimeSeriesPoint { date, value })
        .collect();

    time_series.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(time_series)
}
