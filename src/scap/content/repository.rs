//! SCAP Content Repository
//!
//! Manages storage and retrieval of SCAP content, bridging between in-memory
//! types and database storage.

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::db::scap as db;
use crate::scap::{ScapContentBundle, ScapContentSource, ContentStatus, xccdf, oval};

/// Repository for SCAP content with database persistence
pub struct ContentRepository {
    /// In-memory cache of loaded bundles (bundle_id -> bundle)
    bundle_cache: HashMap<String, ScapContentBundle>,
    /// In-memory cache of benchmarks (benchmark_id -> benchmark)
    benchmark_cache: HashMap<String, xccdf::XccdfBenchmark>,
}

impl ContentRepository {
    pub fn new() -> Self {
        Self {
            bundle_cache: HashMap::new(),
            benchmark_cache: HashMap::new(),
        }
    }

    /// Add a content bundle to the repository (persists to database)
    pub async fn add_bundle(
        &mut self,
        bundle: ScapContentBundle,
        pool: &SqlitePool,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Convert to database type
        let db_bundle = db::ScapContentBundle {
            id: bundle.id.clone(),
            name: bundle.name.clone(),
            version: bundle.version.clone(),
            description: bundle.metadata.get("description").cloned(),
            source: bundle.source.to_string().to_lowercase(),
            content_type: "stig".to_string(), // Default to STIG, can be overridden
            file_hash: bundle.file_hash.clone(),
            file_path: bundle.source_url.clone().unwrap_or_default(),
            imported_by: bundle.imported_by.clone().unwrap_or_else(|| "system".to_string()),
            imported_at: bundle.imported_at.to_rfc3339(),
            metadata: Some(serde_json::to_string(&bundle.metadata)?),
            is_active: bundle.status == ContentStatus::Active,
            created_at: now.clone(),
            updated_at: now,
        };

        // Store in database
        db::create_content_bundle(pool, &db_bundle).await?;

        // Add to cache
        self.bundle_cache.insert(bundle.id.clone(), bundle);

        Ok(())
    }

    /// Store a parsed XCCDF benchmark and its components
    pub async fn add_benchmark(
        &mut self,
        bundle_id: &str,
        benchmark: &xccdf::XccdfBenchmark,
        pool: &SqlitePool,
    ) -> Result<String> {
        let now = Utc::now().to_rfc3339();

        // Convert to database type
        let db_benchmark = db::ScapXccdfBenchmark {
            id: String::new(), // Will be generated
            bundle_id: bundle_id.to_string(),
            benchmark_id: benchmark.id.clone(),
            title: benchmark.title.text.clone(),
            description: benchmark.description.as_ref().map(|d| d.text.clone()),
            version: benchmark.version.clone(),
            status: benchmark.status.first()
                .map(|s| format!("{:?}", s.status))
                .unwrap_or_else(|| "draft".to_string()),
            style: None,
            platform_specification: if benchmark.platform.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&benchmark.platform)?)
            },
            metadata: Some(serde_json::to_string(&benchmark.metadata)?),
            created_at: now.clone(),
        };

        let benchmark_db_id = db::create_benchmark(pool, &db_benchmark).await?;

        // Store profiles
        for profile in &benchmark.profiles {
            let selected_rules: Vec<String> = profile.selects.iter()
                .filter(|s| s.selected)
                .map(|s| s.id_ref.clone())
                .collect();

            let db_profile = db::ScapXccdfProfile {
                id: String::new(),
                benchmark_id: benchmark_db_id.clone(),
                profile_id: profile.id.clone(),
                title: profile.title.text.clone(),
                description: profile.description.as_ref().map(|d| d.text.clone()),
                extends: profile.extends.clone(),
                selected_rules: serde_json::to_string(&selected_rules)?,
                refined_values: if profile.refine_values.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&profile.refine_values)?)
                },
                created_at: now.clone(),
            };

            db::create_profile(pool, &db_profile).await?;
        }

        // Store rules
        for rule in &benchmark.rules {
            let cci_refs: Vec<String> = rule.idents.iter()
                .filter(|i| i.system.contains("cci"))
                .map(|i| i.value.clone())
                .collect();

            let stig_id = rule.idents.iter()
                .find(|i| i.system.contains("stig") || i.value.starts_with("V-"))
                .map(|i| i.value.clone());

            let db_rule = db::ScapXccdfRule {
                id: String::new(),
                benchmark_id: benchmark_db_id.clone(),
                rule_id: rule.id.clone(),
                title: rule.title.text.clone(),
                description: rule.description.as_ref().map(|d| d.text.clone()),
                rationale: rule.rationale.as_ref().map(|r| r.text.clone()),
                severity: format!("{:?}", rule.severity).to_lowercase(),
                weight: rule.weight,
                selected: true, // Default to selected
                check_content_ref: rule.checks.first()
                    .and_then(|c| c.check_content_ref.clone()),
                fix_text: rule.fixtext.as_ref().map(|f| f.text.clone()),
                cci_refs: if cci_refs.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&cci_refs)?)
                },
                stig_id,
                created_at: now.clone(),
            };

            db::create_rule(pool, &db_rule).await?;
        }

        // Cache the benchmark
        self.benchmark_cache.insert(benchmark.id.clone(), benchmark.clone());

        Ok(benchmark_db_id)
    }

    /// Store OVAL definitions from a parsed bundle
    pub async fn add_oval_definitions(
        &self,
        bundle_id: &str,
        oval_defs: &oval::OvalDefinitions,
        pool: &SqlitePool,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        for (def_id, definition) in &oval_defs.definitions {
            // Serialize criteria to XML-like structure
            let criteria_xml = definition.criteria.as_ref()
                .map(|c| serde_json::to_string(c))
                .transpose()?
                .unwrap_or_default();

            let db_definition = db::ScapOvalDefinition {
                id: String::new(),
                bundle_id: bundle_id.to_string(),
                definition_id: def_id.clone(),
                class: format!("{:?}", definition.class).to_lowercase(),
                title: definition.metadata.title.clone().unwrap_or_default(),
                description: definition.metadata.description.clone(),
                version: definition.version as i32,
                platform: definition.metadata.affected.first()
                    .map(|a| a.platform.join(", ")),
                criteria_xml,
                affected_family: definition.metadata.affected.first()
                    .map(|a| a.family.clone()),
                affected_platforms: if definition.metadata.affected.is_empty() {
                    None
                } else {
                    let platforms: Vec<String> = definition.metadata.affected.iter()
                        .flat_map(|a| a.platform.clone())
                        .collect();
                    Some(serde_json::to_string(&platforms)?)
                },
                created_at: now.clone(),
            };

            let def_db_id = db::create_oval_definition(pool, &db_definition).await?;

            // Store tests associated with this definition
            // Note: Tests in OVAL are referenced by criteria, not directly owned by definitions
            // For now, we store tests with a reference to the first definition that uses them
            for (test_id, test) in &oval_defs.tests {
                let db_test = db::ScapOvalTest {
                    id: String::new(),
                    definition_id: def_db_id.clone(),
                    test_id: test_id.clone(),
                    test_type: "generic".to_string(),
                    comment: test.comment.clone(),
                    check_existence: format!("{:?}", test.check_existence),
                    check: format!("{:?}", test.check),
                    state_operator: test.state_operator
                        .map(|op| format!("{:?}", op))
                        .unwrap_or_else(|| "And".to_string()),
                    object_ref: test.object_ref.clone(),
                    state_ref: test.state_ref.clone(),
                    created_at: now.clone(),
                };

                // Try to create, ignore duplicates
                let _ = db::create_oval_test(pool, &db_test).await;
            }
        }

        // Store objects
        for (obj_id, object) in &oval_defs.objects {
            let db_object = db::ScapOvalObject {
                id: String::new(),
                definition_id: bundle_id.to_string(), // Use bundle_id as parent for global objects
                object_id: obj_id.clone(),
                object_type: format!("{:?}", object.object_type),
                comment: object.comment.clone(),
                object_xml: serde_json::to_string(&object.data)?,
                created_at: now.clone(),
            };

            let _ = db::create_oval_object(pool, &db_object).await;
        }

        // Store states
        for (state_id, state) in &oval_defs.states {
            let db_state = db::ScapOvalState {
                id: String::new(),
                definition_id: bundle_id.to_string(),
                state_id: state_id.clone(),
                state_type: format!("{:?}", state.state_type),
                comment: state.comment.clone(),
                state_xml: serde_json::to_string(&state.data)?,
                created_at: now.clone(),
            };

            let _ = db::create_oval_state(pool, &db_state).await;
        }

        Ok(())
    }

    /// List all benchmarks from active bundles
    pub async fn list_benchmarks(
        &self,
        pool: &SqlitePool,
    ) -> Result<Vec<xccdf::XccdfBenchmarkSummary>> {
        let db_benchmarks = db::list_all_benchmarks(pool).await?;

        let summaries = db_benchmarks.iter().map(|b| {
            xccdf::XccdfBenchmarkSummary {
                id: b.benchmark_id.clone(),
                title: b.title.clone(),
                version: b.version.clone(),
                profile_count: 0, // Would need additional query
                rule_count: 0,    // Would need additional query
                platform: b.platform_specification.as_ref()
                    .and_then(|p| serde_json::from_str::<Vec<String>>(p).ok())
                    .unwrap_or_default(),
            }
        }).collect();

        Ok(summaries)
    }

    /// Get a specific benchmark with full details
    pub async fn get_benchmark(
        &self,
        benchmark_id: &str,
        pool: &SqlitePool,
    ) -> Result<xccdf::XccdfBenchmark> {
        // Check cache first
        if let Some(cached) = self.benchmark_cache.get(benchmark_id) {
            return Ok(cached.clone());
        }

        // Query database
        let db_benchmark = db::get_benchmark_by_benchmark_id(pool, benchmark_id).await?
            .ok_or_else(|| anyhow::anyhow!("Benchmark not found: {}", benchmark_id))?;

        // Load profiles
        let db_profiles = db::get_profiles_for_benchmark(pool, &db_benchmark.id).await?;

        // Load rules
        let db_rules = db::get_rules_for_benchmark(pool, &db_benchmark.id, None).await?;

        // Convert to in-memory types
        let profiles: Vec<xccdf::XccdfProfile> = db_profiles.iter().map(|p| {
            let selected_rules: Vec<String> = serde_json::from_str(&p.selected_rules)
                .unwrap_or_default();

            xccdf::XccdfProfile {
                id: p.profile_id.clone(),
                title: crate::scap::LocalizedText::new(&p.title),
                description: p.description.as_ref().map(|d| crate::scap::LocalizedText::new(d)),
                extends: p.extends.clone(),
                selects: selected_rules.iter().map(|r| xccdf::ProfileSelect {
                    id_ref: r.clone(),
                    selected: true,
                }).collect(),
                set_values: Vec::new(),
                refine_values: Vec::new(),
                refine_rules: Vec::new(),
            }
        }).collect();

        let rules: Vec<xccdf::XccdfRule> = db_rules.iter().map(|r| {
            let mut rule = xccdf::XccdfRule::default();
            rule.id = r.rule_id.clone();
            rule.title = crate::scap::LocalizedText::new(&r.title);
            rule.description = r.description.as_ref().map(|d| crate::scap::LocalizedText::new(d));
            rule.rationale = r.rationale.as_ref().map(|d| crate::scap::LocalizedText::new(d));
            rule.severity = crate::scap::ScapSeverity::from_str_loose(&r.severity);
            rule.weight = r.weight;

            if let Some(ref check_ref) = r.check_content_ref {
                rule.checks.push(xccdf::XccdfCheck {
                    system: xccdf::CheckSystem::Oval,
                    content_ref: None,
                    check_content_ref: Some(check_ref.clone()),
                    check_exports: Vec::new(),
                    check_imports: Vec::new(),
                    multi_check: false,
                });
            }

            if let Some(ref fix_text) = r.fix_text {
                rule.fixtext = Some(xccdf::Fixtext {
                    text: fix_text.clone(),
                    fixref: None,
                    reboot: false,
                    strategy: None,
                    disruption: None,
                    complexity: None,
                });
            }

            // Parse CCI refs
            if let Some(ref cci_json) = r.cci_refs {
                if let Ok(ccis) = serde_json::from_str::<Vec<String>>(cci_json) {
                    for cci in ccis {
                        rule.idents.push(crate::scap::Ident {
                            system: "http://iase.disa.mil/cci".to_string(),
                            value: cci,
                        });
                    }
                }
            }

            rule
        }).collect();

        let benchmark = xccdf::XccdfBenchmark {
            id: db_benchmark.benchmark_id.clone(),
            version: db_benchmark.version.clone(),
            status: Vec::new(), // Would need to parse from db_benchmark.status
            title: crate::scap::LocalizedText::new(&db_benchmark.title),
            description: db_benchmark.description.as_ref().map(|d| crate::scap::LocalizedText::new(d)),
            platform: Vec::new(), // Would need to parse from platform_specification
            profiles,
            groups: Vec::new(),
            rules,
            values: Vec::new(),
            metadata: xccdf::BenchmarkMetadata::default(),
            scoring: xccdf::ScoringModel::Default,
        };

        Ok(benchmark)
    }

    /// Get OVAL definitions for a benchmark
    pub async fn get_oval_definitions(
        &self,
        benchmark_id: &str,
        pool: &SqlitePool,
    ) -> Result<oval::OvalDefinitions> {
        // Get the benchmark to find its bundle
        let db_benchmark = db::get_benchmark_by_benchmark_id(pool, benchmark_id).await?
            .ok_or_else(|| anyhow::anyhow!("Benchmark not found: {}", benchmark_id))?;

        // Get OVAL definitions for the bundle
        let db_definitions = db::get_oval_definitions_for_bundle(pool, &db_benchmark.bundle_id).await?;

        let mut oval_defs = oval::OvalDefinitions::new();

        for db_def in db_definitions {
            let definition = oval::OvalDefinition {
                id: db_def.definition_id.clone(),
                version: db_def.version as u32,
                class: match db_def.class.as_str() {
                    "compliance" => oval::DefinitionClass::Compliance,
                    "vulnerability" => oval::DefinitionClass::Vulnerability,
                    "inventory" => oval::DefinitionClass::Inventory,
                    "patch" => oval::DefinitionClass::Patch,
                    _ => oval::DefinitionClass::Miscellaneous,
                },
                status: oval::DefinitionStatus::Accepted,
                metadata: oval::OvalMetadata {
                    title: Some(db_def.title),
                    description: db_def.description,
                    affected: Vec::new(),
                    references: Vec::new(),
                },
                criteria: if db_def.criteria_xml.is_empty() {
                    None
                } else {
                    serde_json::from_str(&db_def.criteria_xml).ok()
                },
                deprecated: false,
            };

            oval_defs.definitions.insert(db_def.definition_id, definition);
        }

        Ok(oval_defs)
    }

    /// Get content bundle by ID
    pub async fn get_bundle(
        &self,
        bundle_id: &str,
        pool: &SqlitePool,
    ) -> Result<Option<ScapContentBundle>> {
        // Check cache first
        if let Some(cached) = self.bundle_cache.get(bundle_id) {
            return Ok(Some(cached.clone()));
        }

        // Query database
        let db_bundle = db::get_content_bundle(pool, bundle_id).await?;

        if let Some(db) = db_bundle {
            let bundle = ScapContentBundle {
                id: db.id,
                name: db.name,
                version: db.version,
                source: match db.source.as_str() {
                    "disa" => ScapContentSource::Disa,
                    "cis" => ScapContentSource::Cis,
                    "nist" => ScapContentSource::Nist,
                    _ => ScapContentSource::Custom,
                },
                source_url: Some(db.file_path),
                file_hash: db.file_hash,
                imported_at: chrono::DateTime::parse_from_rfc3339(&db.imported_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                imported_by: Some(db.imported_by),
                status: if db.is_active { ContentStatus::Active } else { ContentStatus::Disabled },
                metadata: db.metadata
                    .and_then(|m| serde_json::from_str(&m).ok())
                    .unwrap_or_default(),
                benchmark_count: 0, // Would need additional query
                oval_definition_count: 0,
            };

            return Ok(Some(bundle));
        }

        Ok(None)
    }

    /// List all content bundles
    pub async fn list_bundles(
        &self,
        pool: &SqlitePool,
        active_only: bool,
    ) -> Result<Vec<ScapContentBundle>> {
        let db_bundles = db::list_content_bundles(pool, None, None, active_only).await?;

        let bundles = db_bundles.into_iter().map(|db| {
            ScapContentBundle {
                id: db.id,
                name: db.name,
                version: db.version,
                source: match db.source.as_str() {
                    "disa" => ScapContentSource::Disa,
                    "cis" => ScapContentSource::Cis,
                    "nist" => ScapContentSource::Nist,
                    _ => ScapContentSource::Custom,
                },
                source_url: Some(db.file_path),
                file_hash: db.file_hash,
                imported_at: chrono::DateTime::parse_from_rfc3339(&db.imported_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                imported_by: Some(db.imported_by),
                status: if db.is_active { ContentStatus::Active } else { ContentStatus::Disabled },
                metadata: db.metadata
                    .and_then(|m| serde_json::from_str(&m).ok())
                    .unwrap_or_default(),
                benchmark_count: 0,
                oval_definition_count: 0,
            }
        }).collect();

        Ok(bundles)
    }

    /// Delete a content bundle and all associated data
    pub async fn delete_bundle(
        &mut self,
        bundle_id: &str,
        pool: &SqlitePool,
    ) -> Result<()> {
        db::delete_content_bundle(pool, bundle_id).await?;

        // Remove from cache
        self.bundle_cache.remove(bundle_id);

        // Remove associated benchmarks from cache
        self.benchmark_cache.retain(|_, b| {
            // This is a simplification - in reality we'd need to track bundle->benchmark mapping
            true
        });

        Ok(())
    }

    /// Clear all caches
    pub fn clear_cache(&mut self) {
        self.bundle_cache.clear();
        self.benchmark_cache.clear();
    }
}

impl Default for ContentRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repository_creation() {
        let repo = ContentRepository::new();
        assert!(repo.bundle_cache.is_empty());
        assert!(repo.benchmark_cache.is_empty());
    }
}
