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

// ============================================================================
// Executive Analytics Functions
// ============================================================================

/// Calculate risk score from vulnerability counts
fn calculate_risk_score(critical: i64, high: i64, medium: i64, low: i64) -> f64 {
    // Weighted risk score: Critical=10, High=5, Medium=2, Low=1
    let score = (critical * 10 + high * 5 + medium * 2 + low) as f64;
    // Normalize to 0-100 scale (cap at 100)
    (score / 10.0).min(100.0)
}

/// Determine risk rating from score
fn get_risk_rating(risk_score: f64) -> String {
    if risk_score >= 75.0 {
        "Critical".to_string()
    } else if risk_score >= 50.0 {
        "High".to_string()
    } else if risk_score >= 25.0 {
        "Medium".to_string()
    } else {
        "Low".to_string()
    }
}

/// Get security trends for a customer over N months
pub async fn get_customer_security_trends(
    pool: &SqlitePool,
    customer_id: &str,
    months: i64,
) -> Result<models::CustomerSecurityTrends> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(months * 30);

    // Get customer info
    let customer = sqlx::query_as::<_, (String, String)>(
        "SELECT id, name FROM customers WHERE id = ?1"
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await?
    .unwrap_or((customer_id.to_string(), "Unknown Customer".to_string()));

    // Get all engagements for this customer
    let engagement_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM engagements WHERE customer_id = ?1"
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    // If no engagements, return empty trends
    if engagement_ids.is_empty() {
        return Ok(models::CustomerSecurityTrends {
            customer_id: customer_id.to_string(),
            customer_name: customer.1,
            months: vec![],
            improvement_percent: 0.0,
            current_risk_score: 0.0,
        });
    }

    // Get vulnerability data for these engagements grouped by month
    let mut monthly_data: HashMap<String, models::MonthlySecuritySnapshot> = HashMap::new();

    // Query vulnerabilities from vulnerability_tracking linked to engagements
    for engagement_id in &engagement_ids {
        let vulns = sqlx::query_as::<_, (String, String, Option<String>)>(
            r#"
            SELECT severity, status, created_at
            FROM vulnerability_tracking
            WHERE engagement_id = ?1 AND created_at >= ?2
            "#
        )
        .bind(engagement_id)
        .bind(cutoff_date)
        .fetch_all(pool)
        .await?;

        for (severity, status, created_at) in vulns {
            let month = created_at
                .as_deref()
                .and_then(|d| d.get(..7))
                .unwrap_or("unknown")
                .to_string();

            let entry = monthly_data.entry(month.clone()).or_insert(models::MonthlySecuritySnapshot {
                month,
                total_vulnerabilities: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                resolved: 0,
                risk_score: 0.0,
            });

            entry.total_vulnerabilities += 1;
            match severity.as_str() {
                "critical" => entry.critical += 1,
                "high" => entry.high += 1,
                "medium" => entry.medium += 1,
                "low" | "info" => entry.low += 1,
                _ => {}
            }
            if status == "resolved" || status == "false_positive" {
                entry.resolved += 1;
            }
        }
    }

    // Calculate risk scores for each month
    let mut monthly_snapshots: Vec<models::MonthlySecuritySnapshot> = monthly_data
        .into_iter()
        .map(|(_, mut snapshot)| {
            snapshot.risk_score = calculate_risk_score(
                snapshot.critical - snapshot.resolved.min(snapshot.critical),
                snapshot.high,
                snapshot.medium,
                snapshot.low,
            );
            snapshot
        })
        .collect();

    monthly_snapshots.sort_by(|a, b| a.month.cmp(&b.month));

    // Calculate improvement and current risk
    let (improvement_percent, current_risk_score) = if monthly_snapshots.len() >= 2 {
        let first = &monthly_snapshots[0];
        let last = &monthly_snapshots[monthly_snapshots.len() - 1];
        let improvement = if first.risk_score > 0.0 {
            ((first.risk_score - last.risk_score) / first.risk_score) * 100.0
        } else {
            0.0
        };
        (improvement, last.risk_score)
    } else if monthly_snapshots.len() == 1 {
        (0.0, monthly_snapshots[0].risk_score)
    } else {
        (0.0, 0.0)
    };

    Ok(models::CustomerSecurityTrends {
        customer_id: customer_id.to_string(),
        customer_name: customer.1,
        months: monthly_snapshots,
        improvement_percent,
        current_risk_score,
    })
}

/// Get executive summary for a customer
pub async fn get_customer_executive_summary(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<models::ExecutiveSummary> {
    // Get customer info
    let customer = sqlx::query_as::<_, (String, String)>(
        "SELECT id, name FROM customers WHERE id = ?1"
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await?
    .unwrap_or((customer_id.to_string(), "Unknown Customer".to_string()));

    // Count engagements
    let total_engagements: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM engagements WHERE customer_id = ?1"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let active_engagements: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM engagements WHERE customer_id = ?1 AND status IN ('in_progress', 'pending', 'active')"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    // Get engagement IDs for scan/vuln queries
    let engagement_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM engagements WHERE customer_id = ?1"
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    // Count total scans across all engagements
    let total_scans: i64 = if engagement_ids.is_empty() {
        0
    } else {
        let placeholders = engagement_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            "SELECT COUNT(*) FROM scan_results WHERE engagement_id IN ({})",
            placeholders
        );
        let mut q = sqlx::query_scalar(&query);
        for id in &engagement_ids {
            q = q.bind(id);
        }
        q.fetch_one(pool).await?
    };

    // Get vulnerability stats
    let mut total_vulnerabilities: i64 = 0;
    let mut open_vulnerabilities: i64 = 0;
    let mut critical_open: i64 = 0;
    let mut high_open: i64 = 0;

    for engagement_id in &engagement_ids {
        let stats = sqlx::query_as::<_, (i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*),
                SUM(CASE WHEN vt.status = 'open' OR vt.status = 'in_progress' THEN 1 ELSE 0 END),
                SUM(CASE WHEN vt.severity = 'critical' AND (vt.status = 'open' OR vt.status = 'in_progress') THEN 1 ELSE 0 END),
                SUM(CASE WHEN vt.severity = 'high' AND (vt.status = 'open' OR vt.status = 'in_progress') THEN 1 ELSE 0 END)
            FROM vulnerability_tracking vt
            INNER JOIN scan_results sr ON vt.scan_id = sr.id
            WHERE sr.engagement_id = ?1
            "#
        )
        .bind(engagement_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or((0, 0, 0, 0));

        total_vulnerabilities += stats.0;
        open_vulnerabilities += stats.1;
        critical_open += stats.2;
        high_open += stats.3;
    }

    // Calculate average remediation days
    let avg_remediation_days: f64 = if !engagement_ids.is_empty() {
        let mut total_days: f64 = 0.0;
        let mut count: i64 = 0;

        for engagement_id in &engagement_ids {
            let days: Option<f64> = sqlx::query_scalar(
                r#"
                SELECT AVG(JULIANDAY(vt.resolved_at) - JULIANDAY(vt.created_at))
                FROM vulnerability_tracking vt
                INNER JOIN scan_results sr ON vt.scan_id = sr.id
                WHERE sr.engagement_id = ?1 AND vt.status = 'resolved' AND vt.resolved_at IS NOT NULL
                "#
            )
            .bind(engagement_id)
            .fetch_one(pool)
            .await?;

            if let Some(d) = days {
                total_days += d;
                count += 1;
            }
        }

        if count > 0 { total_days / count as f64 } else { 0.0 }
    } else {
        0.0
    };

    // Get last scan date
    let last_scan_date: Option<String> = if engagement_ids.is_empty() {
        None
    } else {
        let placeholders = engagement_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            "SELECT MAX(created_at) FROM scan_results WHERE engagement_id IN ({})",
            placeholders
        );
        let mut q = sqlx::query_scalar(&query);
        for id in &engagement_ids {
            q = q.bind(id);
        }
        q.fetch_optional(pool).await?.flatten()
    };

    // Calculate risk score and rating
    let risk_score = calculate_risk_score(critical_open, high_open, 0, 0);
    let risk_rating = get_risk_rating(risk_score);

    // Determine trend direction (simplified)
    let trend_direction = if critical_open == 0 && high_open < 5 {
        "Improving".to_string()
    } else if critical_open > 3 || high_open > 10 {
        "Declining".to_string()
    } else {
        "Stable".to_string()
    };

    Ok(models::ExecutiveSummary {
        customer_id: customer_id.to_string(),
        customer_name: customer.1,
        total_engagements,
        active_engagements,
        total_scans,
        total_vulnerabilities,
        open_vulnerabilities,
        critical_open,
        high_open,
        avg_remediation_days,
        compliance_score: None,  // Would need compliance analysis
        last_scan_date,
        risk_rating,
        trend_direction,
    })
}

/// Get remediation velocity metrics
pub async fn get_remediation_velocity(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<models::RemediationVelocity> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Get remediation times by severity
    let severity_stats = sqlx::query_as::<_, (String, Option<f64>, i64)>(
        r#"
        SELECT
            severity,
            AVG(JULIANDAY(resolved_at) - JULIANDAY(created_at)) as avg_days,
            COUNT(*) as count
        FROM vulnerability_tracking
        WHERE user_id = ?1
          AND status = 'resolved'
          AND resolved_at IS NOT NULL
          AND resolved_at >= ?2
        GROUP BY severity
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    let mut avg_days_critical = 0.0;
    let mut avg_days_high = 0.0;
    let mut avg_days_medium = 0.0;
    let mut avg_days_low = 0.0;
    let mut total_days = 0.0;
    let mut total_count = 0i64;

    for (severity, avg_days, count) in severity_stats {
        let days = avg_days.unwrap_or(0.0);
        total_days += days * count as f64;
        total_count += count;

        match severity.as_str() {
            "critical" => avg_days_critical = days,
            "high" => avg_days_high = days,
            "medium" => avg_days_medium = days,
            "low" | "info" => avg_days_low = days,
            _ => {}
        }
    }

    let avg_days_to_remediate = if total_count > 0 {
        total_days / total_count as f64
    } else {
        0.0
    };

    // Calculate remediation rate
    let total_vulns: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking
        WHERE user_id = ?1 AND created_at >= ?2
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_one(pool)
    .await?;

    let resolved_vulns: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking
        WHERE user_id = ?1 AND status = 'resolved' AND created_at >= ?2
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_one(pool)
    .await?;

    let remediation_rate = if total_vulns > 0 {
        (resolved_vulns as f64 / total_vulns as f64) * 100.0
    } else {
        0.0
    };

    // Get weekly velocity trend
    let weekly_stats = sqlx::query_as::<_, (String, i64, Option<f64>)>(
        r#"
        SELECT
            strftime('%Y-W%W', resolved_at) as week,
            COUNT(*) as resolved_count,
            AVG(JULIANDAY(resolved_at) - JULIANDAY(created_at)) as avg_days
        FROM vulnerability_tracking
        WHERE user_id = ?1
          AND status = 'resolved'
          AND resolved_at IS NOT NULL
          AND resolved_at >= ?2
        GROUP BY week
        ORDER BY week ASC
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    let velocity_trend: Vec<models::VelocityPoint> = weekly_stats
        .into_iter()
        .map(|(week, resolved_count, avg_days)| models::VelocityPoint {
            week,
            resolved_count,
            avg_days: avg_days.unwrap_or(0.0),
        })
        .collect();

    Ok(models::RemediationVelocity {
        avg_days_to_remediate,
        avg_days_critical,
        avg_days_high,
        avg_days_medium,
        avg_days_low,
        remediation_rate,
        velocity_trend,
    })
}

/// Get risk trends over time
pub async fn get_risk_trends(
    pool: &SqlitePool,
    user_id: &str,
    months: i64,
) -> Result<Vec<models::RiskTrendPoint>> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(months * 30);

    // Get vulnerabilities grouped by date
    let vulns = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT severity, DATE(created_at) as date
        FROM vulnerability_tracking
        WHERE user_id = ?1 AND created_at >= ?2
        ORDER BY date ASC
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Aggregate by date
    let mut daily_data: HashMap<String, (i64, i64, i64, i64)> = HashMap::new();

    for (severity, date) in vulns {
        let entry = daily_data.entry(date).or_insert((0, 0, 0, 0));
        match severity.as_str() {
            "critical" => entry.0 += 1,
            "high" => entry.1 += 1,
            "medium" => entry.2 += 1,
            "low" | "info" => entry.3 += 1,
            _ => {}
        }
    }

    let mut trends: Vec<models::RiskTrendPoint> = daily_data
        .into_iter()
        .map(|(date, (critical, high, medium, low))| {
            let vuln_count = critical + high + medium + low;
            let weighted_severity = (critical * 10 + high * 5 + medium * 2 + low) as f64;
            let risk_score = calculate_risk_score(critical, high, medium, low);

            models::RiskTrendPoint {
                date,
                risk_score,
                vulnerability_count: vuln_count,
                weighted_severity,
            }
        })
        .collect();

    trends.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(trends)
}

/// Get methodology testing coverage statistics
pub async fn get_methodology_coverage(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<models::MethodologyCoverage> {
    use std::collections::HashMap;

    // Count checklists
    let total_checklists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM methodology_checklists WHERE user_id = ?1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let completed_checklists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM methodology_checklists WHERE user_id = ?1 AND status = 'completed'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get item statistics
    let item_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) as failed
        FROM checklist_items ci
        JOIN methodology_checklists mc ON ci.checklist_id = mc.id
        WHERE mc.user_id = ?1
        "#
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .unwrap_or((0, 0, 0));

    // Get coverage by framework
    let framework_stats = sqlx::query_as::<_, (String, i64, i64)>(
        r#"
        SELECT
            mt.name as framework_name,
            COUNT(*) as total_items,
            SUM(CASE WHEN ci.status IN ('pass', 'fail', 'na') THEN 1 ELSE 0 END) as tested_items
        FROM checklist_items ci
        JOIN methodology_checklists mc ON ci.checklist_id = mc.id
        JOIN methodology_templates mt ON mc.template_id = mt.id
        WHERE mc.user_id = ?1
        GROUP BY mt.name
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let coverage_by_framework: Vec<models::FrameworkCoverage> = framework_stats
        .into_iter()
        .map(|(framework_name, total_items, tested_items)| {
            let coverage_percent = if total_items > 0 {
                (tested_items as f64 / total_items as f64) * 100.0
            } else {
                0.0
            };

            models::FrameworkCoverage {
                framework_name,
                total_items,
                tested_items,
                coverage_percent,
            }
        })
        .collect();

    Ok(models::MethodologyCoverage {
        total_checklists,
        completed_checklists,
        total_items_tested: item_stats.0,
        passed_items: item_stats.1,
        failed_items: item_stats.2,
        coverage_by_framework,
    })
}

/// Get combined executive dashboard data
pub async fn get_executive_dashboard(
    pool: &SqlitePool,
    user_id: &str,
    customer_id: Option<&str>,
    months: i64,
) -> Result<models::ExecutiveDashboard> {
    // Get customer-specific data if customer_id provided
    let (summary, security_trends) = if let Some(cid) = customer_id {
        let summary = get_customer_executive_summary(pool, cid).await.ok();
        let trends = get_customer_security_trends(pool, cid, months).await.ok();
        (summary, trends)
    } else {
        (None, None)
    };

    // Get user-level analytics
    let remediation_velocity = get_remediation_velocity(pool, user_id, months * 30).await.ok();
    let risk_trends = get_risk_trends(pool, user_id, months).await.unwrap_or_default();
    let methodology_coverage = get_methodology_coverage(pool, user_id).await.ok();

    Ok(models::ExecutiveDashboard {
        summary,
        security_trends,
        remediation_velocity,
        risk_trends,
        methodology_coverage,
    })
}

// ============================================================================
// Vulnerability Trends Analytics Functions
// ============================================================================

/// Daily vulnerability count with total
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DailyVulnerabilityCount {
    pub date: String,
    pub total: i64,
    pub new: i64,
    pub resolved: i64,
    pub open: i64,
}

/// Get daily vulnerability counts over time
pub async fn get_vulnerability_trends(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<Vec<DailyVulnerabilityCount>> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Get all vulnerability tracking records in the date range
    // Join with scan_results to filter by user_id
    let vulns = sqlx::query_as::<_, (String, String, Option<String>)>(
        r#"
        SELECT
            DATE(vt.created_at) as created_date,
            vt.status,
            DATE(vt.resolved_at) as resolved_date
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1 AND vt.created_at >= ?2
        ORDER BY vt.created_at ASC
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Track cumulative state per day
    let mut daily_new: HashMap<String, i64> = HashMap::new();
    let mut daily_resolved: HashMap<String, i64> = HashMap::new();

    for (created_date, status, resolved_date) in vulns {
        *daily_new.entry(created_date).or_insert(0) += 1;

        if status == "resolved" || status == "false_positive" {
            if let Some(res_date) = resolved_date {
                *daily_resolved.entry(res_date).or_insert(0) += 1;
            }
        }
    }

    // Build date range and calculate cumulative values
    let mut result = Vec::new();
    let mut cumulative_open = 0i64;
    let mut current_date = now - Duration::days(days);

    while current_date <= now {
        let date_str = current_date.format("%Y-%m-%d").to_string();
        let new_today = *daily_new.get(&date_str).unwrap_or(&0);
        let resolved_today = *daily_resolved.get(&date_str).unwrap_or(&0);

        cumulative_open += new_today - resolved_today;

        // Only include days that had activity or every 7th day for continuity
        let day_number = (now - current_date).num_days();
        if new_today > 0 || resolved_today > 0 || day_number % 7 == 0 {
            result.push(DailyVulnerabilityCount {
                date: date_str,
                total: cumulative_open + resolved_today,
                new: new_today,
                resolved: resolved_today,
                open: cumulative_open.max(0),
            });
        }

        current_date = current_date + Duration::days(1);
    }

    Ok(result)
}

/// Get severity distribution over time
pub async fn get_severity_distribution_over_time(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<Vec<models::VulnerabilityTrend>> {
    use chrono::Duration;
    use std::collections::HashMap;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Get vulnerabilities with status to track only open ones per day
    // Join with scan_results to filter by user_id
    let vulns = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        r#"
        SELECT
            DATE(vt.created_at) as created_date,
            vt.severity,
            vt.status,
            DATE(vt.resolved_at) as resolved_date
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1 AND vt.created_at >= ?2
        ORDER BY vt.created_at ASC
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    // Track net changes per day per severity
    // Structure: date -> (critical_delta, high_delta, medium_delta, low_delta)
    let mut daily_deltas: HashMap<String, (i64, i64, i64, i64)> = HashMap::new();

    for (created_date, severity, status, resolved_date) in vulns {
        // Add vulnerability on creation date
        let entry = daily_deltas.entry(created_date).or_insert((0, 0, 0, 0));
        match severity.as_str() {
            "critical" => entry.0 += 1,
            "high" => entry.1 += 1,
            "medium" => entry.2 += 1,
            "low" | "info" => entry.3 += 1,
            _ => {}
        }

        // Subtract on resolution date
        if status == "resolved" || status == "false_positive" {
            if let Some(res_date) = resolved_date {
                let entry = daily_deltas.entry(res_date).or_insert((0, 0, 0, 0));
                match severity.as_str() {
                    "critical" => entry.0 -= 1,
                    "high" => entry.1 -= 1,
                    "medium" => entry.2 -= 1,
                    "low" | "info" => entry.3 -= 1,
                    _ => {}
                }
            }
        }
    }

    // Build cumulative time series
    let mut result = Vec::new();
    let mut cumulative = (0i64, 0i64, 0i64, 0i64);
    let mut current_date = now - Duration::days(days);

    while current_date <= now {
        let date_str = current_date.format("%Y-%m-%d").to_string();

        if let Some(delta) = daily_deltas.get(&date_str) {
            cumulative.0 += delta.0;
            cumulative.1 += delta.1;
            cumulative.2 += delta.2;
            cumulative.3 += delta.3;
        }

        // Include every 7th day for continuity, or any day with data
        let day_number = (now - current_date).num_days();
        if daily_deltas.contains_key(&date_str) || day_number % 7 == 0 {
            result.push(models::VulnerabilityTrend {
                date: date_str,
                critical: cumulative.0.max(0),
                high: cumulative.1.max(0),
                medium: cumulative.2.max(0),
                low: cumulative.3.max(0),
            });
        }

        current_date = current_date + Duration::days(1);
    }

    Ok(result)
}

/// Remediation rate over time (percentage of fixed vulnerabilities)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemediationRatePoint {
    pub date: String,
    pub total_found: i64,
    pub total_resolved: i64,
    pub remediation_rate: f64,
    pub mttr_days: f64, // Mean Time To Remediate
}

/// Get remediation rate over time
pub async fn get_remediation_rate(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<Vec<RemediationRatePoint>> {
    use chrono::Duration;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Get weekly aggregated data
    // Join with scan_results to filter by user_id
    let weekly_data = sqlx::query_as::<_, (String, i64, i64, Option<f64>)>(
        r#"
        SELECT
            strftime('%Y-W%W', vt.created_at) as week,
            COUNT(*) as total_found,
            SUM(CASE WHEN vt.status IN ('resolved', 'false_positive') THEN 1 ELSE 0 END) as total_resolved,
            AVG(CASE
                WHEN vt.status = 'resolved' AND vt.resolved_at IS NOT NULL
                THEN JULIANDAY(vt.resolved_at) - JULIANDAY(vt.created_at)
                ELSE NULL
            END) as avg_mttr
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1 AND vt.created_at >= ?2
        GROUP BY week
        ORDER BY week ASC
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_all(pool)
    .await?;

    let result: Vec<RemediationRatePoint> = weekly_data
        .into_iter()
        .map(|(week, total_found, total_resolved, avg_mttr)| {
            let remediation_rate = if total_found > 0 {
                (total_resolved as f64 / total_found as f64) * 100.0
            } else {
                0.0
            };

            RemediationRatePoint {
                date: week,
                total_found,
                total_resolved,
                remediation_rate,
                mttr_days: avg_mttr.unwrap_or(0.0),
            }
        })
        .collect();

    Ok(result)
}

/// Top recurring vulnerability type
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecurringVulnerability {
    pub vulnerability_id: String,
    pub title: String,
    pub severity: String,
    pub count: i64,
    pub affected_hosts: i64,
    pub avg_resolution_days: Option<f64>,
}

/// Get top recurring vulnerabilities
pub async fn get_top_recurring_vulns(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<RecurringVulnerability>> {
    // Join with scan_results to filter by user_id
    let vulns = sqlx::query_as::<_, (String, String, i64, i64, Option<f64>)>(
        r#"
        SELECT
            vt.vulnerability_id,
            vt.severity,
            COUNT(*) as occurrence_count,
            COUNT(DISTINCT vt.host_ip) as affected_hosts,
            AVG(CASE
                WHEN vt.status = 'resolved' AND vt.resolved_at IS NOT NULL
                THEN JULIANDAY(vt.resolved_at) - JULIANDAY(vt.created_at)
                ELSE NULL
            END) as avg_resolution_days
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1
        GROUP BY vt.vulnerability_id, vt.severity
        ORDER BY occurrence_count DESC
        LIMIT ?2
        "#
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let result: Vec<RecurringVulnerability> = vulns
        .into_iter()
        .map(|(vulnerability_id, severity, count, affected_hosts, avg_resolution_days)| {
            // Extract a readable title from vulnerability_id
            let title = vulnerability_id
                .replace("_", " ")
                .replace("-", " ")
                .split_whitespace()
                .map(|word| {
                    let mut chars = word.chars();
                    match chars.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            RecurringVulnerability {
                vulnerability_id,
                title,
                severity,
                count,
                affected_hosts,
                avg_resolution_days,
            }
        })
        .collect();

    Ok(result)
}

/// Combined vulnerability trends data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityTrendsData {
    pub daily_counts: Vec<DailyVulnerabilityCount>,
    pub severity_trends: Vec<models::VulnerabilityTrend>,
    pub remediation_rates: Vec<RemediationRatePoint>,
    pub top_recurring: Vec<RecurringVulnerability>,
    pub summary: VulnerabilityTrendsSummary,
}

/// Summary statistics for vulnerability trends
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnerabilityTrendsSummary {
    pub total_found: i64,
    pub total_resolved: i64,
    pub current_open: i64,
    pub avg_mttr_days: f64,
    pub remediation_rate: f64,
    pub trend_direction: String, // "improving", "stable", "declining"
    pub critical_open: i64,
    pub high_open: i64,
}

/// Get combined vulnerability trends dashboard data
pub async fn get_vulnerability_trends_dashboard(
    pool: &SqlitePool,
    user_id: &str,
    days: i64,
) -> Result<VulnerabilityTrendsData> {
    use chrono::Duration;

    let now = Utc::now();
    let cutoff_date = now - Duration::days(days);

    // Get summary statistics
    // Join with scan_results to filter by user_id
    let summary_stats = sqlx::query_as::<_, (i64, i64, i64, i64, i64, Option<f64>)>(
        r#"
        SELECT
            COUNT(*) as total_found,
            SUM(CASE WHEN vt.status IN ('resolved', 'false_positive') THEN 1 ELSE 0 END) as total_resolved,
            SUM(CASE WHEN vt.status NOT IN ('resolved', 'false_positive', 'accepted_risk') THEN 1 ELSE 0 END) as current_open,
            SUM(CASE WHEN vt.severity = 'critical' AND vt.status NOT IN ('resolved', 'false_positive', 'accepted_risk') THEN 1 ELSE 0 END) as critical_open,
            SUM(CASE WHEN vt.severity = 'high' AND vt.status NOT IN ('resolved', 'false_positive', 'accepted_risk') THEN 1 ELSE 0 END) as high_open,
            AVG(CASE
                WHEN vt.status = 'resolved' AND vt.resolved_at IS NOT NULL
                THEN JULIANDAY(vt.resolved_at) - JULIANDAY(vt.created_at)
                ELSE NULL
            END) as avg_mttr
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1 AND vt.created_at >= ?2
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .fetch_one(pool)
    .await?;

    let (total_found, total_resolved, current_open, critical_open, high_open, avg_mttr) = summary_stats;

    let remediation_rate = if total_found > 0 {
        (total_resolved as f64 / total_found as f64) * 100.0
    } else {
        0.0
    };

    // Determine trend direction based on recent vs earlier data
    let midpoint = now - Duration::days(days / 2);
    let recent_open: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1 AND vt.created_at >= ?2
          AND vt.status NOT IN ('resolved', 'false_positive', 'accepted_risk')
        "#
    )
    .bind(user_id)
    .bind(midpoint)
    .fetch_one(pool)
    .await?;

    let earlier_open: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?1 AND vt.created_at >= ?2 AND vt.created_at < ?3
          AND vt.status NOT IN ('resolved', 'false_positive', 'accepted_risk')
        "#
    )
    .bind(user_id)
    .bind(cutoff_date)
    .bind(midpoint)
    .fetch_one(pool)
    .await?;

    let trend_direction = if recent_open < earlier_open {
        "improving".to_string()
    } else if recent_open > earlier_open + (earlier_open / 4) {
        "declining".to_string()
    } else {
        "stable".to_string()
    };

    let summary = VulnerabilityTrendsSummary {
        total_found,
        total_resolved,
        current_open,
        avg_mttr_days: avg_mttr.unwrap_or(0.0),
        remediation_rate,
        trend_direction,
        critical_open,
        high_open,
    };

    // Get individual trend data
    let daily_counts = get_vulnerability_trends(pool, user_id, days).await?;
    let severity_trends = get_severity_distribution_over_time(pool, user_id, days).await?;
    let remediation_rates = get_remediation_rate(pool, user_id, days).await?;
    let top_recurring = get_top_recurring_vulns(pool, user_id, 10).await?;

    Ok(VulnerabilityTrendsData {
        daily_counts,
        severity_trends,
        remediation_rates,
        top_recurring,
        summary,
    })
}
