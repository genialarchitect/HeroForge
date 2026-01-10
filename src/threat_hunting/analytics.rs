use anyhow::Result;
use sqlx::SqlitePool;
use chrono::{Utc, Duration};
use std::collections::HashMap;

use super::types::{HuntAnalytics, HunterMetric};

/// Calculate hunt effectiveness metrics
pub async fn get_hunt_analytics(pool: &SqlitePool) -> Result<HuntAnalytics> {
    // Total hunts executed
    let total_hunts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_executions"
    )
    .fetch_one(pool)
    .await?;

    // Active hypotheses
    let active_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE status = 'active'"
    )
    .fetch_one(pool)
    .await?;

    // Validated hypotheses
    let validated_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE status = 'validated'"
    )
    .fetch_one(pool)
    .await?;

    // Total findings
    let total_findings: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(findings_count), 0) FROM hunt_executions"
    )
    .fetch_one(pool)
    .await?;

    // False positives
    let false_positives: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(false_positives), 0) FROM hunt_executions"
    )
    .fetch_one(pool)
    .await?;

    let total_results = total_findings + false_positives;
    let false_positive_rate = if total_results > 0 {
        false_positives as f64 / total_results as f64
    } else {
        0.0
    };

    // Calculate average hunt duration from execution results
    let average_hunt_duration_seconds = calculate_average_duration(pool).await.unwrap_or(0.0);

    // Get top hunters
    let top_hunters = get_top_hunters(pool, 10).await.unwrap_or_default();

    Ok(HuntAnalytics {
        total_hunts,
        active_hypotheses,
        validated_hypotheses,
        total_findings,
        false_positive_rate,
        average_hunt_duration_seconds,
        top_hunters,
    })
}

/// Calculate average hunt execution duration
async fn calculate_average_duration(pool: &SqlitePool) -> Result<f64> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT results FROM hunt_executions WHERE status = 'completed'"
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(0.0);
    }

    let mut total_duration_ms = 0i64;
    let mut count = 0;

    for (results_str,) in rows {
        if let Ok(results) = serde_json::from_str::<serde_json::Value>(&results_str) {
            if let Some(duration) = results.get("execution_time_ms") {
                if let Some(ms) = duration.as_i64() {
                    total_duration_ms += ms;
                    count += 1;
                }
            }
        }
    }

    if count > 0 {
        Ok((total_duration_ms as f64 / count as f64) / 1000.0) // Convert to seconds
    } else {
        Ok(0.0)
    }
}

/// Calculate ROI for a hunt campaign
pub async fn calculate_hunt_roi(
    pool: &SqlitePool,
    campaign_id: &str,
) -> Result<HuntRoiMetrics> {
    // Get findings for campaign
    let findings: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(findings_count), 0)
         FROM hunt_executions
         WHERE campaign_id = ?"
    )
    .bind(campaign_id)
    .fetch_one(pool)
    .await?;

    // Get false positives
    let false_positives: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(false_positives), 0)
         FROM hunt_executions
         WHERE campaign_id = ?"
    )
    .bind(campaign_id)
    .fetch_one(pool)
    .await?;

    // Get execution count
    let execution_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM hunt_executions
         WHERE campaign_id = ?"
    )
    .bind(campaign_id)
    .fetch_one(pool)
    .await?;

    // Get campaign duration
    let campaign_duration = get_campaign_duration(pool, campaign_id).await?;

    // Calculate precision
    let total = findings + false_positives;
    let precision = if total > 0 {
        findings as f64 / total as f64
    } else {
        0.0
    };

    // Calculate findings per hour
    let findings_per_hour = if campaign_duration > 0.0 {
        findings as f64 / campaign_duration
    } else {
        0.0
    };

    Ok(HuntRoiMetrics {
        campaign_id: campaign_id.to_string(),
        total_findings: findings,
        true_positives: findings,
        false_positives,
        precision,
        execution_count,
        campaign_duration_hours: campaign_duration,
        findings_per_hour,
        estimated_value: estimate_finding_value(findings, precision),
    })
}

/// Get campaign duration in hours
async fn get_campaign_duration(pool: &SqlitePool, campaign_id: &str) -> Result<f64> {
    let row = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT MIN(executed_at), MAX(executed_at)
         FROM hunt_executions
         WHERE campaign_id = ?"
    )
    .bind(campaign_id)
    .fetch_one(pool)
    .await?;

    match (row.0, row.1) {
        (Some(first), Some(last)) => {
            let first_dt: chrono::DateTime<Utc> = first.parse()?;
            let last_dt: chrono::DateTime<Utc> = last.parse()?;
            let duration = last_dt.signed_duration_since(first_dt);
            Ok(duration.num_hours() as f64 + (duration.num_minutes() % 60) as f64 / 60.0)
        }
        _ => Ok(0.0),
    }
}

/// Estimate the monetary value of findings
fn estimate_finding_value(findings: i64, precision: f64) -> f64 {
    // Average cost of a security incident: $4.24 million (IBM Cost of Data Breach Report 2021)
    // Assume each true positive finding prevents a potential $10,000 incident on average
    let base_value_per_finding = 10000.0;

    // Adjust value based on precision (lower precision = lower confidence in value)
    let adjusted_value = base_value_per_finding * precision;

    findings as f64 * adjusted_value
}

/// ROI metrics for a hunt campaign
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HuntRoiMetrics {
    pub campaign_id: String,
    pub total_findings: i64,
    pub true_positives: i64,
    pub false_positives: i64,
    pub precision: f64,
    pub execution_count: i64,
    pub campaign_duration_hours: f64,
    pub findings_per_hour: f64,
    pub estimated_value: f64,
}

/// Track hunter performance metrics
pub async fn get_hunter_metrics(pool: &SqlitePool, user_id: &str) -> Result<HunterMetric> {
    // Count hunts executed by this hunter
    let hunts_executed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM hunt_executions he
         JOIN hunt_hypotheses hh ON he.hypothesis_id = hh.id
         WHERE hh.created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Count findings
    let findings_count: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(he.findings_count), 0)
         FROM hunt_executions he
         JOIN hunt_hypotheses hh ON he.hypothesis_id = hh.id
         WHERE hh.created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Count validated hypotheses
    let validated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM hunt_hypotheses
         WHERE created_by = ? AND status = 'validated'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(HunterMetric {
        user_id: user_id.to_string(),
        hunts_executed,
        findings_count,
        validated_count,
    })
}

/// Get top hunters by various metrics
pub async fn get_top_hunters(pool: &SqlitePool, limit: i64) -> Result<Vec<HunterMetric>> {
    let rows = sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT
            hh.created_by as user_id,
            COUNT(DISTINCT he.id) as hunts_executed,
            COALESCE(SUM(he.findings_count), 0) as findings_count,
            COUNT(DISTINCT CASE WHEN hh.status = 'validated' THEN hh.id END) as validated_count
         FROM hunt_hypotheses hh
         LEFT JOIN hunt_executions he ON he.hypothesis_id = hh.id
         WHERE hh.created_by IS NOT NULL
         GROUP BY hh.created_by
         ORDER BY findings_count DESC
         LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(user_id, hunts_executed, findings_count, validated_count)| HunterMetric {
            user_id,
            hunts_executed,
            findings_count,
            validated_count,
        })
        .collect())
}

/// Detailed hunter statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HunterStats {
    pub user_id: String,
    pub total_hypotheses: i64,
    pub active_hypotheses: i64,
    pub validated_hypotheses: i64,
    pub invalidated_hypotheses: i64,
    pub total_hunts: i64,
    pub total_findings: i64,
    pub total_false_positives: i64,
    pub precision: f64,
    pub average_findings_per_hunt: f64,
    pub validation_rate: f64,
    pub last_hunt_date: Option<chrono::DateTime<Utc>>,
}

/// Get detailed stats for a hunter
pub async fn get_hunter_stats(pool: &SqlitePool, user_id: &str) -> Result<HunterStats> {
    // Hypothesis counts by status
    let total_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let active_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE created_by = ? AND status = 'active'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let validated_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE created_by = ? AND status = 'validated'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let invalidated_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE created_by = ? AND status = 'invalidated'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Hunt execution stats
    let hunt_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT
            COUNT(*),
            COALESCE(SUM(findings_count), 0),
            COALESCE(SUM(false_positives), 0)
         FROM hunt_executions he
         JOIN hunt_hypotheses hh ON he.hypothesis_id = hh.id
         WHERE hh.created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let (total_hunts, total_findings, total_false_positives) = hunt_stats;

    // Calculate metrics
    let total_results = total_findings + total_false_positives;
    let precision = if total_results > 0 {
        total_findings as f64 / total_results as f64
    } else {
        0.0
    };

    let average_findings_per_hunt = if total_hunts > 0 {
        total_findings as f64 / total_hunts as f64
    } else {
        0.0
    };

    let completed_hypotheses = validated_hypotheses + invalidated_hypotheses;
    let validation_rate = if completed_hypotheses > 0 {
        validated_hypotheses as f64 / completed_hypotheses as f64
    } else {
        0.0
    };

    // Last hunt date
    let last_hunt_date: Option<String> = sqlx::query_scalar(
        "SELECT MAX(he.executed_at)
         FROM hunt_executions he
         JOIN hunt_hypotheses hh ON he.hypothesis_id = hh.id
         WHERE hh.created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(HunterStats {
        user_id: user_id.to_string(),
        total_hypotheses,
        active_hypotheses,
        validated_hypotheses,
        invalidated_hypotheses,
        total_hunts,
        total_findings,
        total_false_positives,
        precision,
        average_findings_per_hunt,
        validation_rate,
        last_hunt_date: last_hunt_date.and_then(|d| d.parse().ok()),
    })
}

/// Hunt trend analytics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HuntTrends {
    pub daily_hunts: Vec<DailyHuntMetric>,
    pub top_hypothesis_categories: Vec<CategoryMetric>,
    pub findings_by_severity: HashMap<String, i64>,
    pub trend_direction: TrendDirection,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DailyHuntMetric {
    pub date: String,
    pub hunt_count: i64,
    pub findings_count: i64,
    pub false_positive_rate: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CategoryMetric {
    pub category: String,
    pub hunt_count: i64,
    pub findings_count: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Declining,
}

/// Get hunt trend analytics over time
pub async fn get_hunt_trends(pool: &SqlitePool, days: i64) -> Result<HuntTrends> {
    let start_date = Utc::now() - Duration::days(days);

    // Daily metrics
    let daily_rows = sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT
            date(executed_at) as hunt_date,
            COUNT(*) as hunt_count,
            COALESCE(SUM(findings_count), 0) as findings_count,
            COALESCE(SUM(false_positives), 0) as false_positives
         FROM hunt_executions
         WHERE executed_at >= ?
         GROUP BY date(executed_at)
         ORDER BY hunt_date"
    )
    .bind(start_date.to_rfc3339())
    .fetch_all(pool)
    .await?;

    let daily_hunts: Vec<DailyHuntMetric> = daily_rows
        .into_iter()
        .map(|(date, hunt_count, findings_count, false_positives)| {
            let total = findings_count + false_positives;
            let fp_rate = if total > 0 {
                false_positives as f64 / total as f64
            } else {
                0.0
            };
            DailyHuntMetric {
                date,
                hunt_count,
                findings_count,
                false_positive_rate: fp_rate,
            }
        })
        .collect();

    // Determine trend direction
    let trend_direction = calculate_trend_direction(&daily_hunts);

    // Top categories from hunt_queries table (which has a category column)
    let category_rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(hq.category, 'Uncategorized') as category, COUNT(*) as hunt_count
         FROM hunt_queries hq
         WHERE hq.category IS NOT NULL
         GROUP BY hq.category
         ORDER BY hunt_count DESC
         LIMIT 10"
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let top_hypothesis_categories: Vec<CategoryMetric> = if category_rows.is_empty() {
        // Fallback: derive categories from hypothesis names using common patterns
        let hypothesis_names = sqlx::query_scalar::<_, String>(
            "SELECT name FROM hunt_hypotheses ORDER BY created_at DESC LIMIT 100"
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        // Group by common security categories
        let mut category_counts: HashMap<String, i64> = HashMap::new();
        for name in hypothesis_names {
            let name_lower = name.to_lowercase();
            let category = if name_lower.contains("auth") || name_lower.contains("login") || name_lower.contains("credential") {
                "Authentication"
            } else if name_lower.contains("lateral") || name_lower.contains("pivot") {
                "Lateral Movement"
            } else if name_lower.contains("exfil") || name_lower.contains("data") {
                "Data Exfiltration"
            } else if name_lower.contains("persist") || name_lower.contains("backdoor") {
                "Persistence"
            } else if name_lower.contains("priv") || name_lower.contains("escalat") {
                "Privilege Escalation"
            } else if name_lower.contains("c2") || name_lower.contains("command") || name_lower.contains("beacon") {
                "Command & Control"
            } else if name_lower.contains("recon") || name_lower.contains("scan") || name_lower.contains("discovery") {
                "Reconnaissance"
            } else {
                "Other"
            };
            *category_counts.entry(category.to_string()).or_insert(0) += 1;
        }

        category_counts.into_iter()
            .map(|(category, hunt_count)| CategoryMetric { category, hunt_count, findings_count: 0 })
            .collect()
    } else {
        category_rows.into_iter()
            .map(|(category, hunt_count)| CategoryMetric { category, hunt_count, findings_count: 0 })
            .collect()
    };

    // Findings by severity - parse from executions results JSON
    let results_json: Vec<String> = sqlx::query_scalar(
        "SELECT results FROM hunt_executions WHERE executed_at >= ? AND results IS NOT NULL"
    )
    .bind(start_date.to_rfc3339())
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut findings_by_severity: HashMap<String, i64> = HashMap::new();
    for result in results_json {
        // Try to parse the results JSON and extract severity counts
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&result) {
            // Check for severity field in different locations
            if let Some(findings) = parsed.get("findings").and_then(|f| f.as_array()) {
                for finding in findings {
                    let severity = finding.get("severity")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    *findings_by_severity.entry(severity).or_insert(0) += 1;
                }
            } else if let Some(severity) = parsed.get("severity").and_then(|s| s.as_str()) {
                *findings_by_severity.entry(severity.to_string()).or_insert(0) += 1;
            }
        }
    }

    Ok(HuntTrends {
        daily_hunts,
        top_hypothesis_categories,
        findings_by_severity,
        trend_direction,
    })
}

fn calculate_trend_direction(daily_hunts: &[DailyHuntMetric]) -> TrendDirection {
    if daily_hunts.len() < 7 {
        return TrendDirection::Stable;
    }

    let recent_half = &daily_hunts[daily_hunts.len() / 2..];
    let older_half = &daily_hunts[..daily_hunts.len() / 2];

    let recent_fp_rate: f64 = recent_half.iter().map(|d| d.false_positive_rate).sum::<f64>()
        / recent_half.len() as f64;
    let older_fp_rate: f64 = older_half.iter().map(|d| d.false_positive_rate).sum::<f64>()
        / older_half.len() as f64;

    // If FP rate is decreasing, we're improving
    if recent_fp_rate < older_fp_rate * 0.9 {
        TrendDirection::Improving
    } else if recent_fp_rate > older_fp_rate * 1.1 {
        TrendDirection::Declining
    } else {
        TrendDirection::Stable
    }
}

/// Hypothesis effectiveness metrics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HypothesisEffectiveness {
    pub hypothesis_id: String,
    pub hypothesis_name: String,
    pub execution_count: i64,
    pub total_findings: i64,
    pub false_positives: i64,
    pub precision: f64,
    pub average_execution_time_ms: f64,
    pub last_executed: Option<chrono::DateTime<Utc>>,
}

/// Get effectiveness metrics for all hypotheses
pub async fn get_hypothesis_effectiveness(pool: &SqlitePool) -> Result<Vec<HypothesisEffectiveness>> {
    let rows = sqlx::query_as::<_, (String, String, i64, i64, i64, Option<String>)>(
        "SELECT
            hh.id,
            hh.name,
            COUNT(he.id) as execution_count,
            COALESCE(SUM(he.findings_count), 0) as total_findings,
            COALESCE(SUM(he.false_positives), 0) as false_positives,
            MAX(he.executed_at) as last_executed
         FROM hunt_hypotheses hh
         LEFT JOIN hunt_executions he ON he.hypothesis_id = hh.id
         GROUP BY hh.id, hh.name
         ORDER BY total_findings DESC"
    )
    .fetch_all(pool)
    .await?;

    let mut results = Vec::new();
    for (id, name, execution_count, total_findings, false_positives, last_executed) in rows {
        let total = total_findings + false_positives;
        let precision = if total > 0 {
            total_findings as f64 / total as f64
        } else {
            0.0
        };

        // Get average execution time
        let avg_time: Option<f64> = sqlx::query_scalar(
            "SELECT AVG(CAST(json_extract(results, '$.execution_time_ms') AS REAL))
             FROM hunt_executions
             WHERE hypothesis_id = ?"
        )
        .bind(&id)
        .fetch_optional(pool)
        .await?
        .flatten();

        results.push(HypothesisEffectiveness {
            hypothesis_id: id,
            hypothesis_name: name,
            execution_count,
            total_findings,
            false_positives,
            precision,
            average_execution_time_ms: avg_time.unwrap_or(0.0),
            last_executed: last_executed.and_then(|d| d.parse().ok()),
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roi_calculation() {
        let findings = 80;
        let false_positives = 20;
        let total = findings + false_positives;
        let roi = findings as f64 / total as f64;
        assert_eq!(roi, 0.8);
    }

    #[test]
    fn test_estimate_finding_value() {
        let value_high_precision = estimate_finding_value(10, 0.9);
        let value_low_precision = estimate_finding_value(10, 0.5);

        assert!(value_high_precision > value_low_precision);
        assert_eq!(value_high_precision, 90000.0); // 10 * 10000 * 0.9
        assert_eq!(value_low_precision, 50000.0);  // 10 * 10000 * 0.5
    }

    #[test]
    fn test_trend_direction() {
        let improving_data: Vec<DailyHuntMetric> = (0..14)
            .map(|i| DailyHuntMetric {
                date: format!("2024-01-{:02}", i + 1),
                hunt_count: 10,
                findings_count: 50,
                false_positive_rate: 0.5 - (i as f64 * 0.02), // Decreasing FP rate
            })
            .collect();

        assert!(matches!(
            calculate_trend_direction(&improving_data),
            TrendDirection::Improving
        ));
    }
}
