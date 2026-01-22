//! Log storage module with date-based partitioning.
//!
//! This module provides efficient storage and retrieval of log entries
//! using SQLite with date-based partitioning for optimal query performance.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::{
    LogEntry, LogQuery, LogQueryResult, LogSource, SiemAlert, SiemRule,
    SiemSeverity,
};

/// Statistics for storage operations
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    pub total_entries: u64,
    pub entries_today: u64,
    pub storage_size_bytes: u64,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
    pub partitions_count: u32,
}

/// Log storage manager with date-based partitioning
pub struct LogStorage {
    pool: SqlitePool,
    /// Default retention period in days
    retention_days: i64,
    /// Cache for partition existence checks
    partition_cache: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl LogStorage {
    /// Create a new log storage manager
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            retention_days: 90,
            partition_cache: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Create with custom retention period
    pub fn with_retention(pool: SqlitePool, retention_days: i64) -> Self {
        Self {
            pool,
            retention_days,
            partition_cache: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Store a single log entry
    pub async fn store_entry(&self, entry: &LogEntry) -> Result<()> {
        // Ensure partition table exists
        self.ensure_partition(&entry.partition_date).await?;

        let structured_data = serde_json::to_string(&entry.structured_data)?;
        let tags = serde_json::to_string(&entry.tags)?;
        let alert_ids = serde_json::to_string(&entry.alert_ids)?;

        sqlx::query(
            r#"
            INSERT INTO siem_log_entries (
                id, source_id, timestamp, received_at, severity, facility, format,
                source_ip, destination_ip, source_port, destination_port, protocol,
                hostname, application, pid, message_id, structured_data, message,
                raw, category, action, outcome, user, tags, alerted, alert_ids,
                partition_date
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?
            )
            "#,
        )
        .bind(&entry.id)
        .bind(&entry.source_id)
        .bind(entry.timestamp.to_rfc3339())
        .bind(entry.received_at.to_rfc3339())
        .bind(entry.severity.as_str())
        .bind(entry.facility.map(|f| f.to_code() as i32))
        .bind(entry.format.as_str())
        .bind(entry.source_ip.map(|ip| ip.to_string()))
        .bind(entry.destination_ip.map(|ip| ip.to_string()))
        .bind(entry.source_port.map(|p| p as i32))
        .bind(entry.destination_port.map(|p| p as i32))
        .bind(&entry.protocol)
        .bind(&entry.hostname)
        .bind(&entry.application)
        .bind(entry.pid.map(|p| p as i64))
        .bind(&entry.message_id)
        .bind(&structured_data)
        .bind(&entry.message)
        .bind(&entry.raw)
        .bind(&entry.category)
        .bind(&entry.action)
        .bind(&entry.outcome)
        .bind(&entry.user)
        .bind(&tags)
        .bind(entry.alerted)
        .bind(&alert_ids)
        .bind(&entry.partition_date)
        .execute(&self.pool)
        .await?;

        // Update source statistics
        self.update_source_stats(&entry.source_id).await?;

        Ok(())
    }

    /// Store multiple log entries in a batch
    pub async fn store_entries(&self, entries: &[LogEntry]) -> Result<usize> {
        if entries.is_empty() {
            return Ok(0);
        }

        let mut stored = 0;

        // Group entries by partition date for efficiency
        let mut by_partition: std::collections::HashMap<String, Vec<&LogEntry>> =
            std::collections::HashMap::new();
        for entry in entries {
            by_partition
                .entry(entry.partition_date.clone())
                .or_default()
                .push(entry);
        }

        // Ensure all partitions exist
        for partition_date in by_partition.keys() {
            self.ensure_partition(partition_date).await?;
        }

        // Insert in batches
        for entry in entries {
            if self.store_entry(entry).await.is_ok() {
                stored += 1;
            }
        }

        Ok(stored)
    }

    /// Query log entries with proper parameter binding
    pub async fn query(&self, query: &LogQuery) -> Result<LogQueryResult> {
        let start = std::time::Instant::now();

        // Validate sort field (whitelist to prevent SQL injection)
        let allowed_sort_fields = [
            "id", "source_id", "timestamp", "received_at", "severity", "facility",
            "format", "source_ip", "destination_ip", "source_port", "destination_port",
            "protocol", "hostname", "application", "pid", "message_id", "message",
            "category", "action", "outcome", "user", "alerted", "partition_date"
        ];
        let sort_field = query.sort_by.as_deref().unwrap_or("timestamp");
        let validated_sort_field = if allowed_sort_fields.contains(&sort_field) {
            sort_field
        } else {
            log::warn!("Invalid sort field '{}' requested, defaulting to 'timestamp'", sort_field);
            "timestamp"
        };
        let sort_order = if query.sort_asc { "ASC" } else { "DESC" };

        // Build query with proper parameter binding
        let entries = self.execute_log_query(query, validated_sort_field, sort_order).await?;
        let total_count = self.execute_count_query(query).await?;

        let query_time_ms = start.elapsed().as_millis() as u64;

        Ok(LogQueryResult {
            entries: entries.into_iter().map(|r| r.into()).collect(),
            total_count: total_count.0 as u64,
            query_time_ms,
            offset: query.offset,
            limit: query.limit,
        })
    }

    /// Execute the main log query with proper parameter binding
    async fn execute_log_query(
        &self,
        query: &LogQuery,
        sort_field: &str,
        sort_order: &str,
    ) -> Result<Vec<LogEntryRow>> {
        // Build base query
        let base_sql = format!(
            "SELECT id, source_id, timestamp, received_at, severity, facility, format,
                    source_ip, destination_ip, source_port, destination_port, protocol,
                    hostname, application, pid, message_id, structured_data, message,
                    raw, category, action, outcome, user, tags, alerted, alert_ids,
                    partition_date
             FROM siem_log_entries WHERE 1=1 {} ORDER BY {} {} LIMIT {} OFFSET {}",
            self.build_where_clause(query),
            sort_field,
            sort_order,
            query.limit,
            query.offset
        );

        // Execute with bound parameters
        let mut sqlx_query = sqlx::query_as::<_, LogEntryRow>(&base_sql);
        sqlx_query = self.bind_query_params(sqlx_query, query);

        Ok(sqlx_query.fetch_all(&self.pool).await?)
    }

    /// Execute count query with proper parameter binding
    async fn execute_count_query(&self, query: &LogQuery) -> Result<(i64,)> {
        let count_sql = format!(
            "SELECT COUNT(*) FROM siem_log_entries WHERE 1=1 {}",
            self.build_where_clause(query)
        );

        let mut sqlx_query = sqlx::query_as::<_, (i64,)>(&count_sql);
        sqlx_query = self.bind_count_params(sqlx_query, query);

        Ok(sqlx_query.fetch_one(&self.pool).await?)
    }

    /// Build WHERE clause conditions (returns SQL fragment without values)
    fn build_where_clause(&self, query: &LogQuery) -> String {
        let mut conditions = Vec::new();

        if !query.source_ids.is_empty() {
            let placeholders: Vec<&str> = query.source_ids.iter().map(|_| "?").collect();
            conditions.push(format!("source_id IN ({})", placeholders.join(",")));
        }

        if let Some(min_sev) = query.min_severity {
            // Severity uses enum values, not user input - safe to inline
            conditions.push(format!("severity IN ({})", get_severity_levels_above(min_sev)));
        }

        if !query.categories.is_empty() {
            let placeholders: Vec<&str> = query.categories.iter().map(|_| "?").collect();
            conditions.push(format!("category IN ({})", placeholders.join(",")));
        }

        if query.source_ip.is_some() {
            conditions.push("source_ip = ?".to_string());
        }

        if query.destination_ip.is_some() {
            conditions.push("destination_ip = ?".to_string());
        }

        if query.hostname.is_some() {
            conditions.push("hostname LIKE ?".to_string());
        }

        if query.application.is_some() {
            conditions.push("application LIKE ?".to_string());
        }

        if query.user.is_some() {
            conditions.push("user = ?".to_string());
        }

        if query.start_time.is_some() {
            conditions.push("timestamp >= ?".to_string());
        }

        if query.end_time.is_some() {
            conditions.push("timestamp < ?".to_string());
        }

        if query.alerted.is_some() {
            conditions.push("alerted = ?".to_string());
        }

        if query.query.is_some() {
            conditions.push("(message LIKE ? OR raw LIKE ?)".to_string());
        }

        if conditions.is_empty() {
            String::new()
        } else {
            format!(" AND {}", conditions.join(" AND "))
        }
    }

    /// Bind parameters to the log entry query
    fn bind_query_params<'q>(
        &self,
        mut sqlx_query: sqlx::query::QueryAs<'q, sqlx::Sqlite, LogEntryRow, sqlx::sqlite::SqliteArguments<'q>>,
        query: &'q LogQuery,
    ) -> sqlx::query::QueryAs<'q, sqlx::Sqlite, LogEntryRow, sqlx::sqlite::SqliteArguments<'q>> {
        // Bind source_ids
        for source_id in &query.source_ids {
            sqlx_query = sqlx_query.bind(source_id);
        }

        // Bind categories
        for category in &query.categories {
            sqlx_query = sqlx_query.bind(category);
        }

        // Bind optional filters in order
        if let Some(ref ip) = query.source_ip {
            sqlx_query = sqlx_query.bind(ip.to_string());
        }

        if let Some(ref ip) = query.destination_ip {
            sqlx_query = sqlx_query.bind(ip.to_string());
        }

        if let Some(ref hostname) = query.hostname {
            sqlx_query = sqlx_query.bind(format!("%{}%", hostname));
        }

        if let Some(ref app) = query.application {
            sqlx_query = sqlx_query.bind(format!("%{}%", app));
        }

        if let Some(ref user) = query.user {
            sqlx_query = sqlx_query.bind(user);
        }

        if let Some(ref start_time) = query.start_time {
            sqlx_query = sqlx_query.bind(start_time.to_rfc3339());
        }

        if let Some(ref end_time) = query.end_time {
            sqlx_query = sqlx_query.bind(end_time.to_rfc3339());
        }

        if let Some(alerted) = query.alerted {
            sqlx_query = sqlx_query.bind(alerted);
        }

        if let Some(ref search) = query.query {
            let search_pattern = format!("%{}%", search);
            sqlx_query = sqlx_query.bind(search_pattern.clone());
            sqlx_query = sqlx_query.bind(search_pattern);
        }

        sqlx_query
    }

    /// Bind parameters to the count query
    fn bind_count_params<'q>(
        &self,
        mut sqlx_query: sqlx::query::QueryAs<'q, sqlx::Sqlite, (i64,), sqlx::sqlite::SqliteArguments<'q>>,
        query: &'q LogQuery,
    ) -> sqlx::query::QueryAs<'q, sqlx::Sqlite, (i64,), sqlx::sqlite::SqliteArguments<'q>> {
        // Bind source_ids
        for source_id in &query.source_ids {
            sqlx_query = sqlx_query.bind(source_id);
        }

        // Bind categories
        for category in &query.categories {
            sqlx_query = sqlx_query.bind(category);
        }

        // Bind optional filters in order
        if let Some(ref ip) = query.source_ip {
            sqlx_query = sqlx_query.bind(ip.to_string());
        }

        if let Some(ref ip) = query.destination_ip {
            sqlx_query = sqlx_query.bind(ip.to_string());
        }

        if let Some(ref hostname) = query.hostname {
            sqlx_query = sqlx_query.bind(format!("%{}%", hostname));
        }

        if let Some(ref app) = query.application {
            sqlx_query = sqlx_query.bind(format!("%{}%", app));
        }

        if let Some(ref user) = query.user {
            sqlx_query = sqlx_query.bind(user);
        }

        if let Some(ref start_time) = query.start_time {
            sqlx_query = sqlx_query.bind(start_time.to_rfc3339());
        }

        if let Some(ref end_time) = query.end_time {
            sqlx_query = sqlx_query.bind(end_time.to_rfc3339());
        }

        if let Some(alerted) = query.alerted {
            sqlx_query = sqlx_query.bind(alerted);
        }

        if let Some(ref search) = query.query {
            let search_pattern = format!("%{}%", search);
            sqlx_query = sqlx_query.bind(search_pattern.clone());
            sqlx_query = sqlx_query.bind(search_pattern);
        }

        sqlx_query
    }

    /// Get a single log entry by ID
    pub async fn get_entry(&self, id: &str) -> Result<Option<LogEntry>> {
        let row: Option<LogEntryRow> = sqlx::query_as(
            "SELECT * FROM siem_log_entries WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Delete log entries older than retention period
    pub async fn cleanup_old_entries(&self) -> Result<u64> {
        let cutoff = Utc::now() - Duration::days(self.retention_days);
        let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

        let result = sqlx::query("DELETE FROM siem_log_entries WHERE partition_date < ?")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<StorageStats> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_log_entries")
            .fetch_one(&self.pool)
            .await?;

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let today_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM siem_log_entries WHERE partition_date = ?")
                .bind(&today)
                .fetch_one(&self.pool)
                .await?;

        let oldest: Option<(String,)> =
            sqlx::query_as("SELECT MIN(timestamp) FROM siem_log_entries")
                .fetch_optional(&self.pool)
                .await?;

        let newest: Option<(String,)> =
            sqlx::query_as("SELECT MAX(timestamp) FROM siem_log_entries")
                .fetch_optional(&self.pool)
                .await?;

        let partitions: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT partition_date) FROM siem_log_entries",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(StorageStats {
            total_entries: total.0 as u64,
            entries_today: today_count.0 as u64,
            storage_size_bytes: 0, // Would need PRAGMA page_count * page_size
            oldest_entry: oldest.and_then(|o| DateTime::parse_from_rfc3339(&o.0).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            newest_entry: newest.and_then(|n| DateTime::parse_from_rfc3339(&n.0).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            partitions_count: partitions.0 as u32,
        })
    }

    /// Ensure partition index exists for efficient date-based queries
    async fn ensure_partition(&self, partition_date: &str) -> Result<()> {
        // Check cache first
        {
            let cache = self.partition_cache.read().await;
            if cache.contains(partition_date) {
                return Ok(());
            }
        }

        // Add to cache (the actual partitioning is handled by the partition_date column index)
        let mut cache = self.partition_cache.write().await;
        cache.insert(partition_date.to_string());

        Ok(())
    }

    /// Update source statistics after storing an entry
    async fn update_source_stats(&self, source_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE siem_log_sources SET
                log_count = log_count + 1,
                last_seen = datetime('now'),
                updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(source_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ==================== Log Sources ====================

    /// Create a new log source
    pub async fn create_source(&self, source: &LogSource) -> Result<()> {
        let field_mappings = source
            .field_mappings
            .as_ref()
            .map(|m| serde_json::to_string(m))
            .transpose()?;
        let custom_patterns = source
            .custom_patterns
            .as_ref()
            .map(|p| serde_json::to_string(p))
            .transpose()?;
        let tags = serde_json::to_string(&source.tags)?;

        sqlx::query(
            r#"
            INSERT INTO siem_log_sources (
                id, name, description, source_type, host, format, protocol, port,
                status, last_seen, log_count, logs_per_hour, custom_patterns,
                field_mappings, tags, auto_enrich, retention_days, created_at,
                updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&source.id)
        .bind(&source.name)
        .bind(&source.description)
        .bind(&source.source_type)
        .bind(&source.host)
        .bind(source.format.as_str())
        .bind(source.protocol.as_str())
        .bind(source.port.map(|p| p as i32))
        .bind(source.status.as_str())
        .bind(source.last_seen.map(|t| t.to_rfc3339()))
        .bind(source.log_count)
        .bind(source.logs_per_hour)
        .bind(&custom_patterns)
        .bind(&field_mappings)
        .bind(&tags)
        .bind(source.auto_enrich)
        .bind(source.retention_days)
        .bind(source.created_at.to_rfc3339())
        .bind(source.updated_at.to_rfc3339())
        .bind(&source.created_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a log source by ID
    pub async fn get_source(&self, id: &str) -> Result<Option<LogSource>> {
        let row: Option<LogSourceRow> = sqlx::query_as(
            "SELECT * FROM siem_log_sources WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into()).transpose()
    }

    /// List all log sources
    pub async fn list_sources(&self) -> Result<Vec<LogSource>> {
        let rows: Vec<LogSourceRow> = sqlx::query_as(
            "SELECT * FROM siem_log_sources ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Update a log source
    pub async fn update_source(&self, source: &LogSource) -> Result<()> {
        let field_mappings = source
            .field_mappings
            .as_ref()
            .map(|m| serde_json::to_string(m))
            .transpose()?;
        let custom_patterns = source
            .custom_patterns
            .as_ref()
            .map(|p| serde_json::to_string(p))
            .transpose()?;
        let tags = serde_json::to_string(&source.tags)?;

        sqlx::query(
            r#"
            UPDATE siem_log_sources SET
                name = ?, description = ?, source_type = ?, host = ?, format = ?,
                protocol = ?, port = ?, status = ?, custom_patterns = ?,
                field_mappings = ?, tags = ?, auto_enrich = ?, retention_days = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&source.name)
        .bind(&source.description)
        .bind(&source.source_type)
        .bind(&source.host)
        .bind(source.format.as_str())
        .bind(source.protocol.as_str())
        .bind(source.port.map(|p| p as i32))
        .bind(source.status.as_str())
        .bind(&custom_patterns)
        .bind(&field_mappings)
        .bind(&tags)
        .bind(source.auto_enrich)
        .bind(source.retention_days)
        .bind(Utc::now().to_rfc3339())
        .bind(&source.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a log source
    pub async fn delete_source(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM siem_log_sources WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ==================== Rules ====================

    /// Create a new detection rule
    pub async fn create_rule(&self, rule: &SiemRule) -> Result<()> {
        let definition = serde_json::to_string(&rule.definition)?;
        let source_ids = serde_json::to_string(&rule.source_ids)?;
        let categories = serde_json::to_string(&rule.categories)?;
        let mitre_tactics = serde_json::to_string(&rule.mitre_tactics)?;
        let mitre_techniques = serde_json::to_string(&rule.mitre_techniques)?;
        let tags = serde_json::to_string(&rule.tags)?;
        let response_actions = serde_json::to_string(&rule.response_actions)?;
        let group_by_fields = serde_json::to_string(&rule.group_by_fields)?;

        sqlx::query(
            r#"
            INSERT INTO siem_rules (
                id, name, description, rule_type, severity, status, definition,
                source_ids, categories, mitre_tactics, mitre_techniques,
                false_positive_rate, trigger_count, last_triggered, tags,
                response_actions, time_window_seconds, threshold_count,
                group_by_fields, created_at, updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.rule_type.as_str())
        .bind(rule.severity.as_str())
        .bind(rule.status.as_str())
        .bind(&definition)
        .bind(&source_ids)
        .bind(&categories)
        .bind(&mitre_tactics)
        .bind(&mitre_techniques)
        .bind(rule.false_positive_rate)
        .bind(rule.trigger_count)
        .bind(rule.last_triggered.map(|t| t.to_rfc3339()))
        .bind(&tags)
        .bind(&response_actions)
        .bind(rule.time_window_seconds)
        .bind(rule.threshold_count)
        .bind(&group_by_fields)
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .bind(&rule.created_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a rule by ID
    pub async fn get_rule(&self, id: &str) -> Result<Option<SiemRule>> {
        let row: Option<SiemRuleRow> = sqlx::query_as(
            "SELECT * FROM siem_rules WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into()).transpose()
    }

    /// List all enabled rules
    pub async fn list_enabled_rules(&self) -> Result<Vec<SiemRule>> {
        let rows: Vec<SiemRuleRow> = sqlx::query_as(
            "SELECT * FROM siem_rules WHERE status = 'enabled' ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// List all rules
    pub async fn list_rules(&self) -> Result<Vec<SiemRule>> {
        let rows: Vec<SiemRuleRow> = sqlx::query_as(
            "SELECT * FROM siem_rules ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Update a rule
    pub async fn update_rule(&self, rule: &SiemRule) -> Result<()> {
        let definition = serde_json::to_string(&rule.definition)?;
        let source_ids = serde_json::to_string(&rule.source_ids)?;
        let categories = serde_json::to_string(&rule.categories)?;
        let mitre_tactics = serde_json::to_string(&rule.mitre_tactics)?;
        let mitre_techniques = serde_json::to_string(&rule.mitre_techniques)?;
        let tags = serde_json::to_string(&rule.tags)?;
        let response_actions = serde_json::to_string(&rule.response_actions)?;
        let group_by_fields = serde_json::to_string(&rule.group_by_fields)?;

        sqlx::query(
            r#"
            UPDATE siem_rules SET
                name = ?, description = ?, rule_type = ?, severity = ?, status = ?,
                definition = ?, source_ids = ?, categories = ?, mitre_tactics = ?,
                mitre_techniques = ?, false_positive_rate = ?, tags = ?,
                response_actions = ?, time_window_seconds = ?, threshold_count = ?,
                group_by_fields = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.rule_type.as_str())
        .bind(rule.severity.as_str())
        .bind(rule.status.as_str())
        .bind(&definition)
        .bind(&source_ids)
        .bind(&categories)
        .bind(&mitre_tactics)
        .bind(&mitre_techniques)
        .bind(rule.false_positive_rate)
        .bind(&tags)
        .bind(&response_actions)
        .bind(rule.time_window_seconds)
        .bind(rule.threshold_count)
        .bind(&group_by_fields)
        .bind(Utc::now().to_rfc3339())
        .bind(&rule.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a rule
    pub async fn delete_rule(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM siem_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Increment rule trigger count
    pub async fn record_rule_trigger(&self, rule_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE siem_rules SET
                trigger_count = trigger_count + 1,
                last_triggered = datetime('now'),
                updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(rule_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ==================== Alerts ====================

    /// Create a new alert
    pub async fn create_alert(&self, alert: &SiemAlert) -> Result<()> {
        let log_entry_ids = serde_json::to_string(&alert.log_entry_ids)?;
        let source_ips = serde_json::to_string(&alert.source_ips)?;
        let destination_ips = serde_json::to_string(&alert.destination_ips)?;
        let users = serde_json::to_string(&alert.users)?;
        let hosts = serde_json::to_string(&alert.hosts)?;
        let mitre_tactics = serde_json::to_string(&alert.mitre_tactics)?;
        let mitre_techniques = serde_json::to_string(&alert.mitre_techniques)?;
        let tags = serde_json::to_string(&alert.tags)?;
        let context = serde_json::to_string(&alert.context)?;
        let related_alert_ids = serde_json::to_string(&alert.related_alert_ids)?;

        sqlx::query(
            r#"
            INSERT INTO siem_alerts (
                id, rule_id, rule_name, severity, status, title, description,
                log_entry_ids, event_count, source_ips, destination_ips, users,
                hosts, first_seen, last_seen, created_at, updated_at, assigned_to,
                resolved_by, resolved_at, resolution_notes, mitre_tactics,
                mitre_techniques, tags, context, related_alert_ids, external_ticket_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&alert.id)
        .bind(&alert.rule_id)
        .bind(&alert.rule_name)
        .bind(alert.severity.as_str())
        .bind(alert.status.as_str())
        .bind(&alert.title)
        .bind(&alert.description)
        .bind(&log_entry_ids)
        .bind(alert.event_count)
        .bind(&source_ips)
        .bind(&destination_ips)
        .bind(&users)
        .bind(&hosts)
        .bind(alert.first_seen.to_rfc3339())
        .bind(alert.last_seen.to_rfc3339())
        .bind(alert.created_at.to_rfc3339())
        .bind(alert.updated_at.to_rfc3339())
        .bind(&alert.assigned_to)
        .bind(&alert.resolved_by)
        .bind(alert.resolved_at.map(|t| t.to_rfc3339()))
        .bind(&alert.resolution_notes)
        .bind(&mitre_tactics)
        .bind(&mitre_techniques)
        .bind(&tags)
        .bind(&context)
        .bind(&related_alert_ids)
        .bind(&alert.external_ticket_id)
        .execute(&self.pool)
        .await?;

        // Mark log entries as alerted
        for entry_id in &alert.log_entry_ids {
            self.mark_entry_alerted(entry_id, &alert.id).await?;
        }

        Ok(())
    }

    /// Mark a log entry as having triggered an alert
    async fn mark_entry_alerted(&self, entry_id: &str, alert_id: &str) -> Result<()> {
        // Get current alert_ids
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT alert_ids FROM siem_log_entries WHERE id = ?",
        )
        .bind(entry_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((current,)) = row {
            let mut alert_ids: Vec<String> = serde_json::from_str(&current).unwrap_or_default();
            if !alert_ids.contains(&alert_id.to_string()) {
                alert_ids.push(alert_id.to_string());
                let new_ids = serde_json::to_string(&alert_ids)?;
                sqlx::query(
                    "UPDATE siem_log_entries SET alerted = 1, alert_ids = ? WHERE id = ?",
                )
                .bind(&new_ids)
                .bind(entry_id)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    /// Get an alert by ID
    pub async fn get_alert(&self, id: &str) -> Result<Option<SiemAlert>> {
        let row: Option<SiemAlertRow> = sqlx::query_as(
            "SELECT * FROM siem_alerts WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into()).transpose()
    }

    /// List recent alerts
    pub async fn list_recent_alerts(&self, limit: u32) -> Result<Vec<SiemAlert>> {
        let rows: Vec<SiemAlertRow> = sqlx::query_as(
            "SELECT * FROM siem_alerts ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// List alerts by status
    pub async fn list_alerts_by_status(&self, status: &str) -> Result<Vec<SiemAlert>> {
        let rows: Vec<SiemAlertRow> = sqlx::query_as(
            "SELECT * FROM siem_alerts WHERE status = ? ORDER BY created_at DESC",
        )
        .bind(status)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    /// Update alert status
    pub async fn update_alert_status(
        &self,
        id: &str,
        status: &str,
        assigned_to: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE siem_alerts SET status = ?, assigned_to = ?, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(status)
        .bind(assigned_to)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Resolve an alert
    pub async fn resolve_alert(
        &self,
        id: &str,
        resolved_by: &str,
        resolution_notes: Option<&str>,
        is_false_positive: bool,
    ) -> Result<()> {
        let status = if is_false_positive {
            "false_positive"
        } else {
            "resolved"
        };

        sqlx::query(
            r#"
            UPDATE siem_alerts SET
                status = ?,
                resolved_by = ?,
                resolved_at = datetime('now'),
                resolution_notes = ?,
                updated_at = datetime('now')
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(resolved_by)
        .bind(resolution_notes)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Helper function to get severity levels at or above a minimum
fn get_severity_levels_above(min: SiemSeverity) -> String {
    let levels: Vec<&str> = match min {
        SiemSeverity::Debug => vec!["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"],
        SiemSeverity::Info => vec!["info", "notice", "warning", "error", "critical", "alert", "emergency"],
        SiemSeverity::Notice => vec!["notice", "warning", "error", "critical", "alert", "emergency"],
        SiemSeverity::Warning => vec!["warning", "error", "critical", "alert", "emergency"],
        SiemSeverity::Error => vec!["error", "critical", "alert", "emergency"],
        SiemSeverity::Critical => vec!["critical", "alert", "emergency"],
        SiemSeverity::Alert => vec!["alert", "emergency"],
        SiemSeverity::Emergency => vec!["emergency"],
    };
    levels.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(",")
}

// Database row types for sqlx

#[derive(sqlx::FromRow)]
struct LogEntryRow {
    id: String,
    source_id: String,
    timestamp: String,
    received_at: String,
    severity: String,
    facility: Option<i32>,
    format: String,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    source_port: Option<i32>,
    destination_port: Option<i32>,
    protocol: Option<String>,
    hostname: Option<String>,
    application: Option<String>,
    pid: Option<i64>,
    message_id: Option<String>,
    structured_data: String,
    message: String,
    raw: String,
    category: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    user: Option<String>,
    tags: String,
    alerted: bool,
    alert_ids: String,
    partition_date: String,
}

impl From<LogEntryRow> for LogEntry {
    fn from(row: LogEntryRow) -> Self {
        use super::types::{LogFormat, SyslogFacility};

        LogEntry {
            id: row.id,
            source_id: row.source_id,
            timestamp: DateTime::parse_from_rfc3339(&row.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            received_at: DateTime::parse_from_rfc3339(&row.received_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            severity: SiemSeverity::from_syslog_priority(
                match row.severity.as_str() {
                    "emergency" => 0,
                    "alert" => 1,
                    "critical" => 2,
                    "error" => 3,
                    "warning" => 4,
                    "notice" => 5,
                    "info" => 6,
                    "debug" => 7,
                    _ => 6,
                }
            ),
            facility: row.facility.and_then(|f| SyslogFacility::from_code(f as u8)),
            format: LogFormat::from_str(&row.format).unwrap_or(LogFormat::Raw),
            source_ip: row.source_ip.and_then(|s| s.parse().ok()),
            destination_ip: row.destination_ip.and_then(|s| s.parse().ok()),
            source_port: row.source_port.map(|p| p as u16),
            destination_port: row.destination_port.map(|p| p as u16),
            protocol: row.protocol,
            hostname: row.hostname,
            application: row.application,
            pid: row.pid.map(|p| p as u32),
            message_id: row.message_id,
            structured_data: serde_json::from_str(&row.structured_data).unwrap_or_default(),
            message: row.message,
            raw: row.raw,
            category: row.category,
            action: row.action,
            outcome: row.outcome,
            user: row.user,
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            alerted: row.alerted,
            alert_ids: serde_json::from_str(&row.alert_ids).unwrap_or_default(),
            partition_date: row.partition_date,
        }
    }
}

#[derive(sqlx::FromRow)]
struct LogSourceRow {
    id: String,
    name: String,
    description: Option<String>,
    source_type: String,
    host: Option<String>,
    format: String,
    protocol: String,
    port: Option<i32>,
    status: String,
    last_seen: Option<String>,
    log_count: i64,
    logs_per_hour: i64,
    custom_patterns: Option<String>,
    field_mappings: Option<String>,
    tags: String,
    auto_enrich: bool,
    retention_days: Option<i32>,
    created_at: String,
    updated_at: String,
    created_by: Option<String>,
}

impl TryFrom<LogSourceRow> for LogSource {
    type Error = anyhow::Error;

    fn try_from(row: LogSourceRow) -> Result<Self> {
        use super::types::{LogFormat, LogSourceStatus, TransportProtocol};

        Ok(LogSource {
            id: row.id,
            name: row.name,
            description: row.description,
            source_type: row.source_type,
            host: row.host,
            format: LogFormat::from_str(&row.format).unwrap_or(LogFormat::Raw),
            protocol: match row.protocol.as_str() {
                "udp" => TransportProtocol::Udp,
                "tcp" => TransportProtocol::Tcp,
                "tcp+tls" => TransportProtocol::TcpTls,
                "http" => TransportProtocol::Http,
                "https" => TransportProtocol::Https,
                _ => TransportProtocol::Udp,
            },
            port: row.port.map(|p| p as u16),
            status: match row.status.as_str() {
                "active" => LogSourceStatus::Active,
                "inactive" => LogSourceStatus::Inactive,
                "error" => LogSourceStatus::Error,
                _ => LogSourceStatus::Pending,
            },
            last_seen: row.last_seen.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            log_count: row.log_count,
            logs_per_hour: row.logs_per_hour,
            custom_patterns: row.custom_patterns.and_then(|s| serde_json::from_str(&s).ok()),
            field_mappings: row.field_mappings.and_then(|s| serde_json::from_str(&s).ok()),
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            auto_enrich: row.auto_enrich,
            retention_days: row.retention_days,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            created_by: row.created_by,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SiemRuleRow {
    id: String,
    name: String,
    description: Option<String>,
    rule_type: String,
    severity: String,
    status: String,
    definition: String,
    source_ids: String,
    categories: String,
    mitre_tactics: String,
    mitre_techniques: String,
    false_positive_rate: Option<f32>,
    trigger_count: i64,
    last_triggered: Option<String>,
    tags: String,
    response_actions: String,
    time_window_seconds: Option<i64>,
    threshold_count: Option<i64>,
    group_by_fields: String,
    created_at: String,
    updated_at: String,
    created_by: Option<String>,
}

impl TryFrom<SiemRuleRow> for SiemRule {
    type Error = anyhow::Error;

    fn try_from(row: SiemRuleRow) -> Result<Self> {
        use super::types::{RuleStatus, RuleType};

        Ok(SiemRule {
            id: row.id,
            name: row.name,
            description: row.description,
            rule_type: match row.rule_type.as_str() {
                "pattern" => RuleType::Pattern,
                "regex" => RuleType::Regex,
                "threshold" => RuleType::Threshold,
                "correlation" => RuleType::Correlation,
                "anomaly" => RuleType::Anomaly,
                "machine_learning" => RuleType::MachineLearning,
                "sigma" => RuleType::Sigma,
                "yara" => RuleType::Yara,
                _ => RuleType::Pattern,
            },
            severity: SiemSeverity::from_syslog_priority(
                match row.severity.as_str() {
                    "emergency" => 0,
                    "alert" => 1,
                    "critical" => 2,
                    "error" => 3,
                    "warning" => 4,
                    "notice" => 5,
                    "info" => 6,
                    "debug" => 7,
                    _ => 6,
                }
            ),
            status: match row.status.as_str() {
                "enabled" => RuleStatus::Enabled,
                "disabled" => RuleStatus::Disabled,
                "testing" => RuleStatus::Testing,
                _ => RuleStatus::Disabled,
            },
            definition: serde_json::from_str(&row.definition)?,
            source_ids: serde_json::from_str(&row.source_ids).unwrap_or_default(),
            categories: serde_json::from_str(&row.categories).unwrap_or_default(),
            mitre_tactics: serde_json::from_str(&row.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&row.mitre_techniques).unwrap_or_default(),
            false_positive_rate: row.false_positive_rate,
            trigger_count: row.trigger_count,
            last_triggered: row.last_triggered.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            response_actions: serde_json::from_str(&row.response_actions).unwrap_or_default(),
            time_window_seconds: row.time_window_seconds,
            threshold_count: row.threshold_count,
            group_by_fields: serde_json::from_str(&row.group_by_fields).unwrap_or_default(),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            created_by: row.created_by,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SiemAlertRow {
    id: String,
    rule_id: String,
    rule_name: String,
    severity: String,
    status: String,
    title: String,
    description: Option<String>,
    log_entry_ids: String,
    event_count: i64,
    source_ips: String,
    destination_ips: String,
    users: String,
    hosts: String,
    first_seen: String,
    last_seen: String,
    created_at: String,
    updated_at: String,
    assigned_to: Option<String>,
    resolved_by: Option<String>,
    resolved_at: Option<String>,
    resolution_notes: Option<String>,
    mitre_tactics: String,
    mitre_techniques: String,
    tags: String,
    context: String,
    related_alert_ids: String,
    external_ticket_id: Option<String>,
}

impl TryFrom<SiemAlertRow> for SiemAlert {
    type Error = anyhow::Error;

    fn try_from(row: SiemAlertRow) -> Result<Self> {
        use super::types::AlertStatus;

        Ok(SiemAlert {
            id: row.id,
            rule_id: row.rule_id,
            rule_name: row.rule_name,
            severity: SiemSeverity::from_syslog_priority(
                match row.severity.as_str() {
                    "emergency" => 0,
                    "alert" => 1,
                    "critical" => 2,
                    "error" => 3,
                    "warning" => 4,
                    "notice" => 5,
                    "info" => 6,
                    "debug" => 7,
                    _ => 6,
                }
            ),
            status: match row.status.as_str() {
                "new" => AlertStatus::New,
                "in_progress" => AlertStatus::InProgress,
                "escalated" => AlertStatus::Escalated,
                "resolved" => AlertStatus::Resolved,
                "false_positive" => AlertStatus::FalsePositive,
                "ignored" => AlertStatus::Ignored,
                _ => AlertStatus::New,
            },
            title: row.title,
            description: row.description,
            log_entry_ids: serde_json::from_str(&row.log_entry_ids).unwrap_or_default(),
            event_count: row.event_count,
            source_ips: serde_json::from_str(&row.source_ips).unwrap_or_default(),
            destination_ips: serde_json::from_str(&row.destination_ips).unwrap_or_default(),
            users: serde_json::from_str(&row.users).unwrap_or_default(),
            hosts: serde_json::from_str(&row.hosts).unwrap_or_default(),
            first_seen: DateTime::parse_from_rfc3339(&row.first_seen)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: DateTime::parse_from_rfc3339(&row.last_seen)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            assigned_to: row.assigned_to,
            resolved_by: row.resolved_by,
            resolved_at: row.resolved_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            resolution_notes: row.resolution_notes,
            mitre_tactics: serde_json::from_str(&row.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&row.mitre_techniques).unwrap_or_default(),
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            context: serde_json::from_str(&row.context).unwrap_or(serde_json::json!({})),
            related_alert_ids: serde_json::from_str(&row.related_alert_ids).unwrap_or_default(),
            external_ticket_id: row.external_ticket_id,
        })
    }
}
