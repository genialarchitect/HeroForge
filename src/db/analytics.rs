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
