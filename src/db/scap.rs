//! Database operations for SCAP 1.3 content and scan results
//!
//! This module provides CRUD operations for SCAP content bundles, XCCDF benchmarks,
//! OVAL definitions, CPE dictionaries, and scan execution results.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// SCAP content bundle database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapContentBundle {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub source: String, // "disa", "nist", "cis", "custom"
    pub content_type: String, // "stig", "benchmark", "oval"
    pub file_hash: String,
    pub file_path: String,
    pub imported_by: String,
    pub imported_at: String,
    pub metadata: Option<String>, // JSON
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// XCCDF Benchmark database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapXccdfBenchmark {
    pub id: String,
    pub bundle_id: String,
    pub benchmark_id: String,
    pub title: String,
    pub description: Option<String>,
    pub version: String,
    pub status: String,
    pub style: Option<String>,
    pub platform_specification: Option<String>,
    pub metadata: Option<String>, // JSON
    pub created_at: String,
}

/// XCCDF Profile database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapXccdfProfile {
    pub id: String,
    pub benchmark_id: String,
    pub profile_id: String,
    pub title: String,
    pub description: Option<String>,
    pub extends: Option<String>,
    pub selected_rules: String, // JSON array
    pub refined_values: Option<String>, // JSON
    pub created_at: String,
}

/// XCCDF Rule database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapXccdfRule {
    pub id: String,
    pub benchmark_id: String,
    pub rule_id: String,
    pub title: String,
    pub description: Option<String>,
    pub rationale: Option<String>,
    pub severity: String,
    pub weight: f64,
    pub selected: bool,
    pub check_content_ref: Option<String>,
    pub fix_text: Option<String>,
    pub cci_refs: Option<String>, // JSON array
    pub stig_id: Option<String>,
    pub created_at: String,
}

/// OVAL Definition database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapOvalDefinition {
    pub id: String,
    pub bundle_id: String,
    pub definition_id: String,
    pub class: String, // "vulnerability", "compliance", "inventory", "patch"
    pub title: String,
    pub description: Option<String>,
    pub version: i32,
    pub platform: Option<String>,
    pub criteria_xml: String, // Serialized criteria
    pub affected_family: Option<String>,
    pub affected_platforms: Option<String>, // JSON array
    pub created_at: String,
}

/// OVAL Test database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapOvalTest {
    pub id: String,
    pub definition_id: String,
    pub test_id: String,
    pub test_type: String,
    pub comment: Option<String>,
    pub check_existence: String,
    pub check: String,
    pub state_operator: String,
    pub object_ref: String,
    pub state_ref: Option<String>,
    pub created_at: String,
}

/// OVAL Object database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapOvalObject {
    pub id: String,
    pub definition_id: String,
    pub object_id: String,
    pub object_type: String,
    pub comment: Option<String>,
    pub object_xml: String, // Serialized object definition
    pub created_at: String,
}

/// OVAL State database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapOvalState {
    pub id: String,
    pub definition_id: String,
    pub state_id: String,
    pub state_type: String,
    pub comment: Option<String>,
    pub state_xml: String, // Serialized state definition
    pub created_at: String,
}

/// CPE Dictionary entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapCpeEntry {
    pub id: String,
    pub bundle_id: Option<String>,
    pub cpe_uri: String, // CPE 2.2 URI format
    pub cpe_formatted: String, // CPE 2.3 formatted string
    pub title: Option<String>,
    pub part: String, // "a", "o", "h"
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub update_version: Option<String>,
    pub edition: Option<String>,
    pub language: Option<String>,
    pub check_id: Option<String>,
    pub created_at: String,
}

/// SCAP Scan Execution record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapScanExecution {
    pub id: String,
    pub scan_id: String,
    pub benchmark_id: String,
    pub profile_id: String,
    pub target_id: String,
    pub target_type: String, // "host", "container", "cloud_resource"
    pub status: String, // "pending", "running", "completed", "failed"
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub score: Option<f64>,
    pub pass_count: i32,
    pub fail_count: i32,
    pub error_count: i32,
    pub not_applicable_count: i32,
    pub not_checked_count: i32,
    pub executed_by: String,
    pub error_message: Option<String>,
    pub created_at: String,
}

/// SCAP Rule Result record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapRuleResult {
    pub id: String,
    pub execution_id: String,
    pub rule_id: String,
    pub result: String, // "pass", "fail", "error", "notapplicable", "notchecked"
    pub severity_override: Option<String>,
    pub message: Option<String>,
    pub finding_details: Option<String>,
    pub collected_items: Option<String>, // JSON - items collected during evaluation
    pub evaluated_at: String,
}

/// ARF Report record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapArfReport {
    pub id: String,
    pub execution_id: String,
    pub report_content: String, // Full ARF XML
    pub content_hash: String,
    pub file_path: Option<String>,
    pub generated_at: String,
    pub generated_by: String,
}

/// SCAP Control Mapping record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapControlMapping {
    pub id: String,
    pub rule_id: String,
    pub framework_id: String,
    pub control_id: String,
    pub cci_id: Option<String>,
    pub mapping_source: String,
    pub created_at: String,
}

/// Tailoring File record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScapTailoringFile {
    pub id: String,
    pub benchmark_id: String,
    pub name: String,
    pub description: Option<String>,
    pub base_profile_id: String,
    pub tailoring_xml: String,
    pub file_hash: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize SCAP database tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    log::info!("Starting SCAP init_tables...");
    log::debug!("Creating scap_content_bundles table...");
    // SCAP Content Bundles
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_content_bundles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT,
            source TEXT NOT NULL,
            content_type TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_path TEXT NOT NULL,
            imported_by TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            metadata TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // XCCDF Benchmarks
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_xccdf_benchmarks (
            id TEXT PRIMARY KEY,
            bundle_id TEXT NOT NULL,
            benchmark_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            version TEXT NOT NULL,
            status TEXT NOT NULL,
            style TEXT,
            platform_specification TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (bundle_id) REFERENCES scap_content_bundles(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // XCCDF Profiles
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_xccdf_profiles (
            id TEXT PRIMARY KEY,
            benchmark_id TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            extends TEXT,
            selected_rules TEXT NOT NULL,
            refined_values TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (benchmark_id) REFERENCES scap_xccdf_benchmarks(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // XCCDF Rules
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_xccdf_rules (
            id TEXT PRIMARY KEY,
            benchmark_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            rationale TEXT,
            severity TEXT NOT NULL,
            weight REAL NOT NULL,
            selected INTEGER NOT NULL DEFAULT 1,
            check_content_ref TEXT,
            fix_text TEXT,
            cci_refs TEXT,
            stig_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (benchmark_id) REFERENCES scap_xccdf_benchmarks(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // OVAL Definitions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_oval_definitions (
            id TEXT PRIMARY KEY,
            bundle_id TEXT NOT NULL,
            definition_id TEXT NOT NULL,
            class TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            version INTEGER NOT NULL,
            platform TEXT,
            criteria_xml TEXT NOT NULL,
            affected_family TEXT,
            affected_platforms TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (bundle_id) REFERENCES scap_content_bundles(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // OVAL Tests
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_oval_tests (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            test_id TEXT NOT NULL,
            test_type TEXT NOT NULL,
            comment TEXT,
            check_existence TEXT NOT NULL,
            check_attr TEXT NOT NULL,
            state_operator TEXT NOT NULL,
            object_ref TEXT NOT NULL,
            state_ref TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (definition_id) REFERENCES scap_oval_definitions(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // OVAL Objects
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_oval_objects (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            comment TEXT,
            object_xml TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (definition_id) REFERENCES scap_oval_definitions(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // OVAL States
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_oval_states (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            state_id TEXT NOT NULL,
            state_type TEXT NOT NULL,
            comment TEXT,
            state_xml TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (definition_id) REFERENCES scap_oval_definitions(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // CPE Dictionary
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_cpe_dictionary (
            id TEXT PRIMARY KEY,
            bundle_id TEXT,
            cpe_uri TEXT NOT NULL,
            cpe_formatted TEXT NOT NULL,
            title TEXT,
            part TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT,
            update_version TEXT,
            edition TEXT,
            language TEXT,
            check_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (bundle_id) REFERENCES scap_content_bundles(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Scan Executions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_scan_executions (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            benchmark_id TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            target_type TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            score REAL,
            pass_count INTEGER NOT NULL DEFAULT 0,
            fail_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0,
            not_applicable_count INTEGER NOT NULL DEFAULT 0,
            not_checked_count INTEGER NOT NULL DEFAULT 0,
            executed_by TEXT NOT NULL,
            error_message TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (benchmark_id) REFERENCES scap_xccdf_benchmarks(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Rule Results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_rule_results (
            id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            result TEXT NOT NULL,
            severity_override TEXT,
            message TEXT,
            finding_details TEXT,
            collected_items TEXT,
            evaluated_at TEXT NOT NULL,
            FOREIGN KEY (execution_id) REFERENCES scap_scan_executions(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // ARF Reports
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_arf_reports (
            id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            report_content TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            file_path TEXT,
            generated_at TEXT NOT NULL,
            generated_by TEXT NOT NULL,
            FOREIGN KEY (execution_id) REFERENCES scap_scan_executions(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Control Mappings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_control_mappings (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            cci_id TEXT,
            mapping_source TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Tailoring Files
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scap_tailoring_files (
            id TEXT PRIMARY KEY,
            benchmark_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            base_profile_id TEXT NOT NULL,
            tailoring_xml TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (benchmark_id) REFERENCES scap_xccdf_benchmarks(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    log::debug!("Creating SCAP indexes...");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_benchmarks_bundle ON scap_xccdf_benchmarks(bundle_id)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_benchmarks_bundle");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_profiles_benchmark ON scap_xccdf_profiles(benchmark_id)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_profiles_benchmark");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_rules_benchmark ON scap_xccdf_rules(benchmark_id)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_rules_benchmark");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_oval_defs_bundle ON scap_oval_definitions(bundle_id)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_oval_defs_bundle");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_executions_scan ON scap_scan_executions(scan_id)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_executions_scan");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_results_execution ON scap_rule_results(execution_id)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_results_execution");
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scap_cpe_vendor ON scap_cpe_dictionary(vendor)")
        .execute(pool)
        .await?;
    log::debug!("Created idx_scap_cpe_vendor");
    log::info!("SCAP init_tables completed successfully");

    Ok(())
}

// ============================================================================
// Content Bundle Operations
// ============================================================================

/// Create a new SCAP content bundle
pub async fn create_content_bundle(pool: &SqlitePool, bundle: &ScapContentBundle) -> Result<String> {
    let id = if bundle.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        bundle.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO scap_content_bundles (
            id, name, version, description, source, content_type,
            file_hash, file_path, imported_by, imported_at,
            metadata, is_active, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(&bundle.name)
    .bind(&bundle.version)
    .bind(&bundle.description)
    .bind(&bundle.source)
    .bind(&bundle.content_type)
    .bind(&bundle.file_hash)
    .bind(&bundle.file_path)
    .bind(&bundle.imported_by)
    .bind(&bundle.imported_at)
    .bind(&bundle.metadata)
    .bind(bundle.is_active)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get content bundle by ID
pub async fn get_content_bundle(pool: &SqlitePool, id: &str) -> Result<Option<ScapContentBundle>> {
    let bundle = sqlx::query_as::<_, ScapContentBundle>(
        "SELECT * FROM scap_content_bundles WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(bundle)
}

/// List all content bundles
pub async fn list_content_bundles(
    pool: &SqlitePool,
    source: Option<&str>,
    content_type: Option<&str>,
    active_only: bool,
) -> Result<Vec<ScapContentBundle>> {
    let mut query = String::from("SELECT * FROM scap_content_bundles WHERE 1=1");

    if let Some(s) = source {
        query.push_str(&format!(" AND source = '{}'", s));
    }
    if let Some(ct) = content_type {
        query.push_str(&format!(" AND content_type = '{}'", ct));
    }
    if active_only {
        query.push_str(" AND is_active = 1");
    }

    query.push_str(" ORDER BY imported_at DESC");

    let bundles = sqlx::query_as::<_, ScapContentBundle>(&query)
        .fetch_all(pool)
        .await?;

    Ok(bundles)
}

/// Delete content bundle and all related data
pub async fn delete_content_bundle(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete in order of dependencies
    sqlx::query("DELETE FROM scap_arf_reports WHERE execution_id IN (SELECT id FROM scap_scan_executions WHERE benchmark_id IN (SELECT id FROM scap_xccdf_benchmarks WHERE bundle_id = ?1))")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_rule_results WHERE execution_id IN (SELECT id FROM scap_scan_executions WHERE benchmark_id IN (SELECT id FROM scap_xccdf_benchmarks WHERE bundle_id = ?1))")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_scan_executions WHERE benchmark_id IN (SELECT id FROM scap_xccdf_benchmarks WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_tailoring_files WHERE benchmark_id IN (SELECT id FROM scap_xccdf_benchmarks WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_xccdf_rules WHERE benchmark_id IN (SELECT id FROM scap_xccdf_benchmarks WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_xccdf_profiles WHERE benchmark_id IN (SELECT id FROM scap_xccdf_benchmarks WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_xccdf_benchmarks WHERE bundle_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_oval_states WHERE definition_id IN (SELECT id FROM scap_oval_definitions WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_oval_objects WHERE definition_id IN (SELECT id FROM scap_oval_definitions WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_oval_tests WHERE definition_id IN (SELECT id FROM scap_oval_definitions WHERE bundle_id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_oval_definitions WHERE bundle_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_cpe_dictionary WHERE bundle_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM scap_content_bundles WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Benchmark Operations
// ============================================================================

/// Create XCCDF benchmark
pub async fn create_benchmark(pool: &SqlitePool, benchmark: &ScapXccdfBenchmark) -> Result<String> {
    let id = if benchmark.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        benchmark.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_xccdf_benchmarks (
            id, bundle_id, benchmark_id, title, description,
            version, status, style, platform_specification, metadata, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&id)
    .bind(&benchmark.bundle_id)
    .bind(&benchmark.benchmark_id)
    .bind(&benchmark.title)
    .bind(&benchmark.description)
    .bind(&benchmark.version)
    .bind(&benchmark.status)
    .bind(&benchmark.style)
    .bind(&benchmark.platform_specification)
    .bind(&benchmark.metadata)
    .bind(&benchmark.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get benchmarks for a content bundle
pub async fn get_benchmarks_for_bundle(
    pool: &SqlitePool,
    bundle_id: &str,
) -> Result<Vec<ScapXccdfBenchmark>> {
    let benchmarks = sqlx::query_as::<_, ScapXccdfBenchmark>(
        "SELECT * FROM scap_xccdf_benchmarks WHERE bundle_id = ?1 ORDER BY title",
    )
    .bind(bundle_id)
    .fetch_all(pool)
    .await?;

    Ok(benchmarks)
}

/// Get benchmark by ID
pub async fn get_benchmark(pool: &SqlitePool, id: &str) -> Result<Option<ScapXccdfBenchmark>> {
    let benchmark = sqlx::query_as::<_, ScapXccdfBenchmark>(
        "SELECT * FROM scap_xccdf_benchmarks WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(benchmark)
}

// ============================================================================
// Profile Operations
// ============================================================================

/// Create XCCDF profile
pub async fn create_profile(pool: &SqlitePool, profile: &ScapXccdfProfile) -> Result<String> {
    let id = if profile.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        profile.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_xccdf_profiles (
            id, benchmark_id, profile_id, title, description,
            extends, selected_rules, refined_values, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&profile.benchmark_id)
    .bind(&profile.profile_id)
    .bind(&profile.title)
    .bind(&profile.description)
    .bind(&profile.extends)
    .bind(&profile.selected_rules)
    .bind(&profile.refined_values)
    .bind(&profile.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get profiles for a benchmark
pub async fn get_profiles_for_benchmark(
    pool: &SqlitePool,
    benchmark_id: &str,
) -> Result<Vec<ScapXccdfProfile>> {
    let profiles = sqlx::query_as::<_, ScapXccdfProfile>(
        "SELECT * FROM scap_xccdf_profiles WHERE benchmark_id = ?1 ORDER BY title",
    )
    .bind(benchmark_id)
    .fetch_all(pool)
    .await?;

    Ok(profiles)
}

// ============================================================================
// Rule Operations
// ============================================================================

/// Create XCCDF rule
pub async fn create_rule(pool: &SqlitePool, rule: &ScapXccdfRule) -> Result<String> {
    let id = if rule.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        rule.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_xccdf_rules (
            id, benchmark_id, rule_id, title, description, rationale,
            severity, weight, selected, check_content_ref, fix_text,
            cci_refs, stig_id, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(&rule.benchmark_id)
    .bind(&rule.rule_id)
    .bind(&rule.title)
    .bind(&rule.description)
    .bind(&rule.rationale)
    .bind(&rule.severity)
    .bind(rule.weight)
    .bind(rule.selected)
    .bind(&rule.check_content_ref)
    .bind(&rule.fix_text)
    .bind(&rule.cci_refs)
    .bind(&rule.stig_id)
    .bind(&rule.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get rules for a benchmark
pub async fn get_rules_for_benchmark(
    pool: &SqlitePool,
    benchmark_id: &str,
    severity: Option<&str>,
) -> Result<Vec<ScapXccdfRule>> {
    let mut query = String::from("SELECT * FROM scap_xccdf_rules WHERE benchmark_id = ?1");

    if let Some(sev) = severity {
        query.push_str(&format!(" AND severity = '{}'", sev));
    }

    query.push_str(" ORDER BY rule_id");

    let rules = sqlx::query_as::<_, ScapXccdfRule>(&query)
        .bind(benchmark_id)
        .fetch_all(pool)
        .await?;

    Ok(rules)
}

// ============================================================================
// Scan Execution Operations
// ============================================================================

/// Create scan execution record
pub async fn create_scan_execution(
    pool: &SqlitePool,
    execution: &ScapScanExecution,
) -> Result<String> {
    let id = if execution.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        execution.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_scan_executions (
            id, scan_id, benchmark_id, profile_id, target_id, target_type,
            status, started_at, completed_at, score, pass_count, fail_count,
            error_count, not_applicable_count, not_checked_count,
            executed_by, error_message, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        "#,
    )
    .bind(&id)
    .bind(&execution.scan_id)
    .bind(&execution.benchmark_id)
    .bind(&execution.profile_id)
    .bind(&execution.target_id)
    .bind(&execution.target_type)
    .bind(&execution.status)
    .bind(&execution.started_at)
    .bind(&execution.completed_at)
    .bind(execution.score)
    .bind(execution.pass_count)
    .bind(execution.fail_count)
    .bind(execution.error_count)
    .bind(execution.not_applicable_count)
    .bind(execution.not_checked_count)
    .bind(&execution.executed_by)
    .bind(&execution.error_message)
    .bind(&execution.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update scan execution status
pub async fn update_execution_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    score: Option<f64>,
    pass_count: i32,
    fail_count: i32,
    error_count: i32,
    not_applicable: i32,
    not_checked: i32,
    error_message: Option<&str>,
) -> Result<()> {
    let completed_at = if status == "completed" || status == "failed" {
        Some(Utc::now().to_rfc3339())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE scap_scan_executions
        SET status = ?1, completed_at = ?2, score = ?3,
            pass_count = ?4, fail_count = ?5, error_count = ?6,
            not_applicable_count = ?7, not_checked_count = ?8, error_message = ?9
        WHERE id = ?10
        "#,
    )
    .bind(status)
    .bind(&completed_at)
    .bind(score)
    .bind(pass_count)
    .bind(fail_count)
    .bind(error_count)
    .bind(not_applicable)
    .bind(not_checked)
    .bind(error_message)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get scan execution by ID
pub async fn get_scan_execution(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<ScapScanExecution>> {
    let execution = sqlx::query_as::<_, ScapScanExecution>(
        "SELECT * FROM scap_scan_executions WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(execution)
}

/// Get executions for a scan
pub async fn get_executions_for_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<ScapScanExecution>> {
    let executions = sqlx::query_as::<_, ScapScanExecution>(
        "SELECT * FROM scap_scan_executions WHERE scan_id = ?1 ORDER BY created_at DESC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(executions)
}

// ============================================================================
// Rule Result Operations
// ============================================================================

/// Create rule result
pub async fn create_rule_result(pool: &SqlitePool, result: &ScapRuleResult) -> Result<String> {
    let id = if result.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        result.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_rule_results (
            id, execution_id, rule_id, result, severity_override,
            message, finding_details, collected_items, evaluated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&result.execution_id)
    .bind(&result.rule_id)
    .bind(&result.result)
    .bind(&result.severity_override)
    .bind(&result.message)
    .bind(&result.finding_details)
    .bind(&result.collected_items)
    .bind(&result.evaluated_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get results for an execution
pub async fn get_results_for_execution(
    pool: &SqlitePool,
    execution_id: &str,
    result_filter: Option<&str>,
) -> Result<Vec<ScapRuleResult>> {
    let mut query = String::from("SELECT * FROM scap_rule_results WHERE execution_id = ?1");

    if let Some(r) = result_filter {
        query.push_str(&format!(" AND result = '{}'", r));
    }

    query.push_str(" ORDER BY rule_id");

    let results = sqlx::query_as::<_, ScapRuleResult>(&query)
        .bind(execution_id)
        .fetch_all(pool)
        .await?;

    Ok(results)
}

// ============================================================================
// ARF Report Operations
// ============================================================================

/// Create ARF report
pub async fn create_arf_report(pool: &SqlitePool, report: &ScapArfReport) -> Result<String> {
    let id = if report.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        report.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_arf_reports (
            id, execution_id, report_content, content_hash,
            file_path, generated_at, generated_by
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(&report.execution_id)
    .bind(&report.report_content)
    .bind(&report.content_hash)
    .bind(&report.file_path)
    .bind(&report.generated_at)
    .bind(&report.generated_by)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get ARF report for execution
pub async fn get_arf_report_for_execution(
    pool: &SqlitePool,
    execution_id: &str,
) -> Result<Option<ScapArfReport>> {
    let report = sqlx::query_as::<_, ScapArfReport>(
        "SELECT * FROM scap_arf_reports WHERE execution_id = ?1",
    )
    .bind(execution_id)
    .fetch_optional(pool)
    .await?;

    Ok(report)
}

// ============================================================================
// CPE Operations
// ============================================================================

/// Create CPE entry
pub async fn create_cpe_entry(pool: &SqlitePool, entry: &ScapCpeEntry) -> Result<String> {
    let id = if entry.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        entry.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_cpe_dictionary (
            id, bundle_id, cpe_uri, cpe_formatted, title,
            part, vendor, product, version, update_version,
            edition, language, check_id, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(&entry.bundle_id)
    .bind(&entry.cpe_uri)
    .bind(&entry.cpe_formatted)
    .bind(&entry.title)
    .bind(&entry.part)
    .bind(&entry.vendor)
    .bind(&entry.product)
    .bind(&entry.version)
    .bind(&entry.update_version)
    .bind(&entry.edition)
    .bind(&entry.language)
    .bind(&entry.check_id)
    .bind(&entry.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Search CPE dictionary
pub async fn search_cpe(
    pool: &SqlitePool,
    vendor: Option<&str>,
    product: Option<&str>,
    part: Option<&str>,
    limit: i32,
) -> Result<Vec<ScapCpeEntry>> {
    let mut query = String::from("SELECT * FROM scap_cpe_dictionary WHERE 1=1");

    if let Some(v) = vendor {
        query.push_str(&format!(" AND vendor LIKE '%{}%'", v));
    }
    if let Some(p) = product {
        query.push_str(&format!(" AND product LIKE '%{}%'", p));
    }
    if let Some(pt) = part {
        query.push_str(&format!(" AND part = '{}'", pt));
    }

    query.push_str(&format!(" LIMIT {}", limit));

    let entries = sqlx::query_as::<_, ScapCpeEntry>(&query)
        .fetch_all(pool)
        .await?;

    Ok(entries)
}

// ============================================================================
// Control Mapping Operations
// ============================================================================

/// Create control mapping
pub async fn create_control_mapping(
    pool: &SqlitePool,
    mapping: &ScapControlMapping,
) -> Result<String> {
    let id = if mapping.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        mapping.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_control_mappings (
            id, rule_id, framework_id, control_id, cci_id, mapping_source, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(&mapping.rule_id)
    .bind(&mapping.framework_id)
    .bind(&mapping.control_id)
    .bind(&mapping.cci_id)
    .bind(&mapping.mapping_source)
    .bind(&mapping.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get control mappings for a rule
pub async fn get_mappings_for_rule(
    pool: &SqlitePool,
    rule_id: &str,
) -> Result<Vec<ScapControlMapping>> {
    let mappings = sqlx::query_as::<_, ScapControlMapping>(
        "SELECT * FROM scap_control_mappings WHERE rule_id = ?1",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await?;

    Ok(mappings)
}

/// Get rules mapped to a control
pub async fn get_rules_for_control(
    pool: &SqlitePool,
    framework_id: &str,
    control_id: &str,
) -> Result<Vec<ScapControlMapping>> {
    let mappings = sqlx::query_as::<_, ScapControlMapping>(
        "SELECT * FROM scap_control_mappings WHERE framework_id = ?1 AND control_id = ?2",
    )
    .bind(framework_id)
    .bind(control_id)
    .fetch_all(pool)
    .await?;

    Ok(mappings)
}

// ============================================================================
// Tailoring File Operations
// ============================================================================

/// Create tailoring file
pub async fn create_tailoring_file(
    pool: &SqlitePool,
    tailoring: &ScapTailoringFile,
) -> Result<String> {
    let id = if tailoring.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        tailoring.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO scap_tailoring_files (
            id, benchmark_id, name, description, base_profile_id,
            tailoring_xml, file_hash, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
    )
    .bind(&id)
    .bind(&tailoring.benchmark_id)
    .bind(&tailoring.name)
    .bind(&tailoring.description)
    .bind(&tailoring.base_profile_id)
    .bind(&tailoring.tailoring_xml)
    .bind(&tailoring.file_hash)
    .bind(&tailoring.created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get tailoring files for benchmark
pub async fn get_tailoring_files(
    pool: &SqlitePool,
    benchmark_id: &str,
) -> Result<Vec<ScapTailoringFile>> {
    let files = sqlx::query_as::<_, ScapTailoringFile>(
        "SELECT * FROM scap_tailoring_files WHERE benchmark_id = ?1 ORDER BY name",
    )
    .bind(benchmark_id)
    .fetch_all(pool)
    .await?;

    Ok(files)
}

/// Delete tailoring file
pub async fn delete_tailoring_file(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scap_tailoring_files WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// OVAL Definition Operations
// ============================================================================

/// Create OVAL definition
pub async fn create_oval_definition(
    pool: &SqlitePool,
    definition: &ScapOvalDefinition,
) -> Result<String> {
    let id = if definition.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        definition.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_oval_definitions (
            id, bundle_id, definition_id, class, title, description,
            version, platform, criteria_xml, affected_family, affected_platforms, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&id)
    .bind(&definition.bundle_id)
    .bind(&definition.definition_id)
    .bind(&definition.class)
    .bind(&definition.title)
    .bind(&definition.description)
    .bind(definition.version)
    .bind(&definition.platform)
    .bind(&definition.criteria_xml)
    .bind(&definition.affected_family)
    .bind(&definition.affected_platforms)
    .bind(&definition.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get OVAL definitions for a content bundle
pub async fn get_oval_definitions_for_bundle(
    pool: &SqlitePool,
    bundle_id: &str,
) -> Result<Vec<ScapOvalDefinition>> {
    let definitions = sqlx::query_as::<_, ScapOvalDefinition>(
        "SELECT * FROM scap_oval_definitions WHERE bundle_id = ?1 ORDER BY definition_id",
    )
    .bind(bundle_id)
    .fetch_all(pool)
    .await?;

    Ok(definitions)
}

/// Get OVAL definition by definition_id
pub async fn get_oval_definition(
    pool: &SqlitePool,
    definition_id: &str,
) -> Result<Option<ScapOvalDefinition>> {
    let definition = sqlx::query_as::<_, ScapOvalDefinition>(
        "SELECT * FROM scap_oval_definitions WHERE definition_id = ?1",
    )
    .bind(definition_id)
    .fetch_optional(pool)
    .await?;

    Ok(definition)
}

/// Create OVAL test
pub async fn create_oval_test(pool: &SqlitePool, test: &ScapOvalTest) -> Result<String> {
    let id = if test.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        test.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_oval_tests (
            id, definition_id, test_id, test_type, comment,
            check_existence, check_attr, state_operator, object_ref, state_ref, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&id)
    .bind(&test.definition_id)
    .bind(&test.test_id)
    .bind(&test.test_type)
    .bind(&test.comment)
    .bind(&test.check_existence)
    .bind(&test.check)
    .bind(&test.state_operator)
    .bind(&test.object_ref)
    .bind(&test.state_ref)
    .bind(&test.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get OVAL tests for a definition
pub async fn get_oval_tests_for_definition(
    pool: &SqlitePool,
    definition_id: &str,
) -> Result<Vec<ScapOvalTest>> {
    let tests = sqlx::query_as::<_, ScapOvalTest>(
        "SELECT * FROM scap_oval_tests WHERE definition_id = ?1 ORDER BY test_id",
    )
    .bind(definition_id)
    .fetch_all(pool)
    .await?;

    Ok(tests)
}

/// Create OVAL object
pub async fn create_oval_object(pool: &SqlitePool, object: &ScapOvalObject) -> Result<String> {
    let id = if object.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        object.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_oval_objects (
            id, definition_id, object_id, object_type, comment, object_xml, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(&object.definition_id)
    .bind(&object.object_id)
    .bind(&object.object_type)
    .bind(&object.comment)
    .bind(&object.object_xml)
    .bind(&object.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get OVAL objects for a definition
pub async fn get_oval_objects_for_definition(
    pool: &SqlitePool,
    definition_id: &str,
) -> Result<Vec<ScapOvalObject>> {
    let objects = sqlx::query_as::<_, ScapOvalObject>(
        "SELECT * FROM scap_oval_objects WHERE definition_id = ?1 ORDER BY object_id",
    )
    .bind(definition_id)
    .fetch_all(pool)
    .await?;

    Ok(objects)
}

/// Create OVAL state
pub async fn create_oval_state(pool: &SqlitePool, state: &ScapOvalState) -> Result<String> {
    let id = if state.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        state.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO scap_oval_states (
            id, definition_id, state_id, state_type, comment, state_xml, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(&state.definition_id)
    .bind(&state.state_id)
    .bind(&state.state_type)
    .bind(&state.comment)
    .bind(&state.state_xml)
    .bind(&state.created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get OVAL states for a definition
pub async fn get_oval_states_for_definition(
    pool: &SqlitePool,
    definition_id: &str,
) -> Result<Vec<ScapOvalState>> {
    let states = sqlx::query_as::<_, ScapOvalState>(
        "SELECT * FROM scap_oval_states WHERE definition_id = ?1 ORDER BY state_id",
    )
    .bind(definition_id)
    .fetch_all(pool)
    .await?;

    Ok(states)
}

/// List all benchmarks (across all bundles)
pub async fn list_all_benchmarks(pool: &SqlitePool) -> Result<Vec<ScapXccdfBenchmark>> {
    let benchmarks = sqlx::query_as::<_, ScapXccdfBenchmark>(
        r#"
        SELECT b.* FROM scap_xccdf_benchmarks b
        INNER JOIN scap_content_bundles c ON b.bundle_id = c.id
        WHERE c.is_active = 1
        ORDER BY b.title
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(benchmarks)
}

/// Get benchmark by benchmark_id (not primary key id)
pub async fn get_benchmark_by_benchmark_id(
    pool: &SqlitePool,
    benchmark_id: &str,
) -> Result<Option<ScapXccdfBenchmark>> {
    let benchmark = sqlx::query_as::<_, ScapXccdfBenchmark>(
        "SELECT * FROM scap_xccdf_benchmarks WHERE benchmark_id = ?1",
    )
    .bind(benchmark_id)
    .fetch_optional(pool)
    .await?;

    Ok(benchmark)
}

// ============================================================================
// STIG Repository Sync Operations
// ============================================================================

use crate::scap::stig_sync::types::{TrackedStig, StigSyncHistoryEntry};

/// List all tracked STIGs
pub async fn list_tracked_stigs(pool: &SqlitePool) -> Result<Vec<TrackedStig>> {
    let rows = sqlx::query_as::<_, TrackedStigRow>(
        r#"
        SELECT id, stig_id, stig_name, current_version, current_release,
               available_version, available_release, release_date, bundle_id,
               local_path, download_url, last_checked_at, last_updated_at,
               auto_update, created_at
        FROM stig_repository
        ORDER BY stig_name
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into()).collect())
}

/// Get a tracked STIG by ID
pub async fn get_tracked_stig(pool: &SqlitePool, id: &str) -> Result<Option<TrackedStig>> {
    let row = sqlx::query_as::<_, TrackedStigRow>(
        r#"
        SELECT id, stig_id, stig_name, current_version, current_release,
               available_version, available_release, release_date, bundle_id,
               local_path, download_url, last_checked_at, last_updated_at,
               auto_update, created_at
        FROM stig_repository
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into()))
}

/// Get a tracked STIG by STIG ID
pub async fn get_tracked_stig_by_stig_id(pool: &SqlitePool, stig_id: &str) -> Result<Option<TrackedStig>> {
    let row = sqlx::query_as::<_, TrackedStigRow>(
        r#"
        SELECT id, stig_id, stig_name, current_version, current_release,
               available_version, available_release, release_date, bundle_id,
               local_path, download_url, last_checked_at, last_updated_at,
               auto_update, created_at
        FROM stig_repository
        WHERE stig_id = ?1
        "#,
    )
    .bind(stig_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into()))
}

/// Create a tracked STIG entry
pub async fn create_tracked_stig(pool: &SqlitePool, tracked: &TrackedStig) -> Result<String> {
    let id = if tracked.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        tracked.id.clone()
    };

    let release_date = tracked.release_date.map(|d| d.to_string());
    let last_checked_at = tracked.last_checked_at.map(|dt| dt.to_rfc3339());
    let last_updated_at = tracked.last_updated_at.map(|dt| dt.to_rfc3339());
    let created_at = tracked.created_at.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO stig_repository (
            id, stig_id, stig_name, current_version, current_release,
            available_version, available_release, release_date, bundle_id,
            local_path, download_url, last_checked_at, last_updated_at,
            auto_update, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&id)
    .bind(&tracked.stig_id)
    .bind(&tracked.stig_name)
    .bind(tracked.current_version)
    .bind(tracked.current_release)
    .bind(tracked.available_version)
    .bind(tracked.available_release)
    .bind(&release_date)
    .bind(&tracked.bundle_id)
    .bind(&tracked.local_path)
    .bind(&tracked.download_url)
    .bind(&last_checked_at)
    .bind(&last_updated_at)
    .bind(tracked.auto_update)
    .bind(&created_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update available version for a tracked STIG
pub async fn update_tracked_stig_available_version(
    pool: &SqlitePool,
    id: &str,
    version: i32,
    release: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE stig_repository
        SET available_version = ?1, available_release = ?2
        WHERE id = ?3
        "#,
    )
    .bind(version)
    .bind(release)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update last_checked_at timestamp for a tracked STIG
pub async fn update_tracked_stig_last_checked(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE stig_repository
        SET last_checked_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update last_updated_at timestamp and version for a tracked STIG
pub async fn update_tracked_stig_version(
    pool: &SqlitePool,
    id: &str,
    version: i32,
    release: i32,
    bundle_id: Option<&str>,
    local_path: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE stig_repository
        SET current_version = ?1, current_release = ?2,
            available_version = NULL, available_release = NULL,
            bundle_id = ?3, local_path = ?4, last_updated_at = ?5
        WHERE id = ?6
        "#,
    )
    .bind(version)
    .bind(release)
    .bind(bundle_id)
    .bind(local_path)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update auto_update setting for a tracked STIG
pub async fn update_tracked_stig_auto_update(
    pool: &SqlitePool,
    id: &str,
    auto_update: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE stig_repository
        SET auto_update = ?1
        WHERE id = ?2
        "#,
    )
    .bind(auto_update)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a tracked STIG
pub async fn delete_tracked_stig(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete sync history first
    sqlx::query("DELETE FROM stig_sync_history WHERE stig_id = (SELECT stig_id FROM stig_repository WHERE id = ?1)")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM stig_repository WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Create a STIG sync history entry
pub async fn create_stig_sync_history(
    pool: &SqlitePool,
    history: &StigSyncHistoryEntry,
) -> Result<String> {
    let id = if history.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        history.id.clone()
    };

    let synced_at = history.synced_at.to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO stig_sync_history (
            id, stig_id, old_version, new_version, old_release, new_release,
            sync_type, status, error_message, synced_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
    )
    .bind(&id)
    .bind(&history.stig_id)
    .bind(history.old_version)
    .bind(history.new_version)
    .bind(history.old_release)
    .bind(history.new_release)
    .bind(history.sync_type.to_string())
    .bind(history.status.to_string())
    .bind(&history.error_message)
    .bind(&synced_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get sync history for a STIG
pub async fn get_stig_sync_history(
    pool: &SqlitePool,
    stig_id: &str,
    limit: i32,
) -> Result<Vec<StigSyncHistoryRow>> {
    let rows = sqlx::query_as::<_, StigSyncHistoryRow>(
        r#"
        SELECT id, stig_id, old_version, new_version, old_release, new_release,
               sync_type, status, error_message, synced_at
        FROM stig_sync_history
        WHERE stig_id = ?1
        ORDER BY synced_at DESC
        LIMIT ?2
        "#,
    )
    .bind(stig_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get recent sync history across all STIGs
pub async fn get_recent_sync_history(pool: &SqlitePool, limit: i32) -> Result<Vec<StigSyncHistoryRow>> {
    let rows = sqlx::query_as::<_, StigSyncHistoryRow>(
        r#"
        SELECT id, stig_id, old_version, new_version, old_release, new_release,
               sync_type, status, error_message, synced_at
        FROM stig_sync_history
        ORDER BY synced_at DESC
        LIMIT ?1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Count tracked STIGs with updates available
pub async fn count_stigs_with_updates(pool: &SqlitePool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM stig_repository
        WHERE available_version IS NOT NULL
          AND (available_version > current_version
               OR (available_version = current_version AND available_release > current_release))
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

// Helper types for database row mapping
#[derive(Debug, sqlx::FromRow)]
struct TrackedStigRow {
    id: String,
    stig_id: String,
    stig_name: String,
    current_version: i32,
    current_release: i32,
    available_version: Option<i32>,
    available_release: Option<i32>,
    release_date: Option<String>,
    bundle_id: Option<String>,
    local_path: Option<String>,
    download_url: Option<String>,
    last_checked_at: Option<String>,
    last_updated_at: Option<String>,
    auto_update: bool,
    created_at: String,
}

impl From<TrackedStigRow> for TrackedStig {
    fn from(row: TrackedStigRow) -> Self {
        use chrono::NaiveDate;

        TrackedStig {
            id: row.id,
            stig_id: row.stig_id,
            stig_name: row.stig_name,
            current_version: row.current_version,
            current_release: row.current_release,
            available_version: row.available_version,
            available_release: row.available_release,
            release_date: row.release_date.and_then(|s| NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok()),
            bundle_id: row.bundle_id,
            local_path: row.local_path,
            download_url: row.download_url,
            last_checked_at: row.last_checked_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
            last_updated_at: row.last_updated_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
            auto_update: row.auto_update,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, sqlx::FromRow, Serialize, Deserialize)]
pub struct StigSyncHistoryRow {
    pub id: String,
    pub stig_id: String,
    pub old_version: Option<i32>,
    pub new_version: i32,
    pub old_release: Option<i32>,
    pub new_release: i32,
    pub sync_type: String,
    pub status: String,
    pub error_message: Option<String>,
    pub synced_at: String,
}
