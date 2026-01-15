//! OVAL Collector Integration for Windows Audit Scanner
//!
//! Bridges the Windows Audit Scanner with SCAP OVAL collectors for
//! comprehensive compliance assessment.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::client::WinRmClient;
use super::types::*;
use crate::scap::oval::types::{
    OvalItem, OvalObject, OvalValue, ItemStatus, ObjectType,
};
use crate::scap::oval::collectors::windows::{
    CollectionContext, WindowsCollectorRegistry, CloneCollector,
};

/// OVAL-aware Windows audit scanner
pub struct OvalWindowsAuditScanner {
    client: Arc<RwLock<WinRmClient>>,
    config: WindowsAuditConfig,
    collector_registry: WindowsCollectorRegistry,
}

impl OvalWindowsAuditScanner {
    /// Create a new OVAL-aware Windows audit scanner
    pub fn new(config: WindowsAuditConfig) -> Self {
        let client = WinRmClient::new(&config.target, config.credentials.clone());

        Self {
            client: Arc::new(RwLock::new(client)),
            config,
            collector_registry: WindowsCollectorRegistry::new(),
        }
    }

    /// Build collection context from current config
    fn build_collection_context(&self) -> CollectionContext {
        CollectionContext {
            target: self.config.target.clone(),
            winrm_endpoint: Some(format!(
                "http{}://{}:{}/wsman",
                if self.config.credentials.auth_type == WindowsAuthType::Basic { "s" } else { "" },
                self.config.target,
                5985
            )),
            username: Some(self.config.credentials.username.clone()),
            password: Some(self.config.credentials.password.clone()),
            domain: self.config.credentials.domain.clone(),
            use_ssl: false,
            timeout_seconds: self.config.timeout_seconds,
            skip_cert_verify: false,
        }
    }

    /// Collect OVAL items for an object specification
    pub async fn collect_oval_object(&self, object: &OvalObject) -> Result<Vec<OvalItem>> {
        let context = self.build_collection_context();
        self.collector_registry.collect(object, &context).await
    }

    /// Collect registry items using OVAL object spec
    pub async fn collect_registry_oval(
        &self,
        hive: &str,
        key: &str,
        name: Option<&str>,
    ) -> Result<Vec<OvalItem>> {
        let mut data = HashMap::new();
        data.insert("hive".to_string(), serde_json::json!(hive));
        data.insert("key".to_string(), serde_json::json!(key));
        if let Some(n) = name {
            data.insert("name".to_string(), serde_json::json!(n));
        }

        let object = OvalObject {
            id: format!("oval:heroforge:obj:registry:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinRegistry,
            data,
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Collect file items using OVAL object spec
    pub async fn collect_file_oval(
        &self,
        path: &str,
        filename: Option<&str>,
    ) -> Result<Vec<OvalItem>> {
        let mut data = HashMap::new();
        data.insert("path".to_string(), serde_json::json!(path));
        if let Some(f) = filename {
            data.insert("filename".to_string(), serde_json::json!(f));
        }

        let object = OvalObject {
            id: format!("oval:heroforge:obj:file:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinFile,
            data,
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Collect service items using OVAL object spec
    pub async fn collect_service_oval(&self, service_name: &str) -> Result<Vec<OvalItem>> {
        let mut data = HashMap::new();
        data.insert("service_name".to_string(), serde_json::json!(service_name));

        let object = OvalObject {
            id: format!("oval:heroforge:obj:service:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinService,
            data,
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Collect WMI query results using OVAL object spec
    pub async fn collect_wmi_oval(&self, namespace: &str, wql: &str) -> Result<Vec<OvalItem>> {
        let mut data = HashMap::new();
        data.insert("namespace".to_string(), serde_json::json!(namespace));
        data.insert("wql".to_string(), serde_json::json!(wql));

        let object = OvalObject {
            id: format!("oval:heroforge:obj:wmi:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinWmi,
            data,
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Collect audit policy using OVAL
    pub async fn collect_audit_policy_oval(&self) -> Result<Vec<OvalItem>> {
        let object = OvalObject {
            id: format!("oval:heroforge:obj:auditpolicy:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinAuditEventPolicy,
            data: HashMap::new(),
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Collect password policy using OVAL
    pub async fn collect_password_policy_oval(&self) -> Result<Vec<OvalItem>> {
        let object = OvalObject {
            id: format!("oval:heroforge:obj:passwordpolicy:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinPasswordPolicy,
            data: HashMap::new(),
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Collect lockout policy using OVAL
    pub async fn collect_lockout_policy_oval(&self) -> Result<Vec<OvalItem>> {
        let object = OvalObject {
            id: format!("oval:heroforge:obj:lockoutpolicy:{}", uuid::Uuid::new_v4()),
            version: 1,
            object_type: ObjectType::WinLockoutPolicy,
            data: HashMap::new(),
            comment: None,
        };

        self.collect_oval_object(&object).await
    }

    /// Convert WindowsAuditResult to OVAL items for result caching
    pub fn audit_result_to_oval_items(result: &WindowsAuditResult) -> Vec<OvalItem> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1000000);

        let mut items = Vec::new();

        // Convert services
        for service in &result.services {
            let mut data = HashMap::new();
            data.insert("service_name".to_string(), OvalValue::String(service.name.clone()));
            data.insert("display_name".to_string(), OvalValue::String(service.display_name.clone()));
            data.insert("status".to_string(), OvalValue::String(format!("{:?}", service.status)));
            data.insert("start_type".to_string(), OvalValue::String(format!("{:?}", service.start_type)));
            if let Some(account) = &service.account {
                data.insert("service_account".to_string(), OvalValue::String(account.clone()));
            }

            items.push(OvalItem {
                id: COUNTER.fetch_add(1, Ordering::SeqCst),
                status: ItemStatus::Exists,
                item_type: ObjectType::WinService,
                data,
            });
        }

        // Convert users
        for user in &result.local_users {
            let mut data = HashMap::new();
            data.insert("username".to_string(), OvalValue::String(user.name.clone()));
            data.insert("enabled".to_string(), OvalValue::Boolean(user.enabled));
            data.insert("password_required".to_string(), OvalValue::Boolean(user.password_required));
            data.insert("password_changeable".to_string(), OvalValue::Boolean(user.password_changeable));
            data.insert("password_expires".to_string(), OvalValue::Boolean(user.password_expires));

            items.push(OvalItem {
                id: COUNTER.fetch_add(1, Ordering::SeqCst),
                status: ItemStatus::Exists,
                item_type: ObjectType::WinUser,
                data,
            });
        }

        // Convert groups
        for group in &result.local_groups {
            let mut data = HashMap::new();
            data.insert("group".to_string(), OvalValue::String(group.name.clone()));
            data.insert("members".to_string(), OvalValue::String(group.members.join(",")));

            items.push(OvalItem {
                id: COUNTER.fetch_add(1, Ordering::SeqCst),
                status: ItemStatus::Exists,
                item_type: ObjectType::WinGroup,
                data,
            });
        }

        // Convert registry state
        for reg_key in &result.registry_state {
            for value in &reg_key.values {
                let mut data = HashMap::new();
                // Parse hive from path
                let (hive, key) = if reg_key.path.starts_with("HKEY_LOCAL_MACHINE") {
                    ("HKEY_LOCAL_MACHINE", reg_key.path.trim_start_matches("HKEY_LOCAL_MACHINE\\"))
                } else if reg_key.path.starts_with("HKEY_CURRENT_USER") {
                    ("HKEY_CURRENT_USER", reg_key.path.trim_start_matches("HKEY_CURRENT_USER\\"))
                } else {
                    ("", reg_key.path.as_str())
                };

                data.insert("hive".to_string(), OvalValue::String(hive.to_string()));
                data.insert("key".to_string(), OvalValue::String(key.to_string()));
                data.insert("name".to_string(), OvalValue::String(value.name.clone()));
                data.insert("value".to_string(), OvalValue::String(value.data.clone()));
                data.insert("type".to_string(), OvalValue::String(format!("{:?}", value.value_type)));

                items.push(OvalItem {
                    id: COUNTER.fetch_add(1, Ordering::SeqCst),
                    status: ItemStatus::Exists,
                    item_type: ObjectType::WinRegistry,
                    data,
                });
            }
        }

        // Convert password policy
        let pp = &result.security_policies.password_policy;
        let mut pp_data = HashMap::new();
        pp_data.insert("min_passwd_len".to_string(), OvalValue::Int(pp.minimum_length as i64));
        pp_data.insert("password_complexity".to_string(), OvalValue::Boolean(pp.complexity_enabled));
        pp_data.insert("max_passwd_age".to_string(), OvalValue::Int(pp.maximum_age_days as i64));
        pp_data.insert("min_passwd_age".to_string(), OvalValue::Int(pp.minimum_age_days as i64));
        pp_data.insert("password_hist_len".to_string(), OvalValue::Int(pp.history_count as i64));
        pp_data.insert("reversible_encryption".to_string(), OvalValue::Boolean(pp.reversible_encryption));

        items.push(OvalItem {
            id: COUNTER.fetch_add(1, Ordering::SeqCst),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinPasswordPolicy,
            data: pp_data,
        });

        // Convert lockout policy
        let lp = &result.security_policies.account_lockout_policy;
        let mut lp_data = HashMap::new();
        lp_data.insert("lockout_threshold".to_string(), OvalValue::Int(lp.threshold as i64));
        lp_data.insert("lockout_duration".to_string(), OvalValue::Int(lp.duration_minutes as i64));
        lp_data.insert("lockout_observation_window".to_string(), OvalValue::Int(lp.reset_after_minutes as i64));

        items.push(OvalItem {
            id: COUNTER.fetch_add(1, Ordering::SeqCst),
            status: ItemStatus::Exists,
            item_type: ObjectType::WinLockoutPolicy,
            data: lp_data,
        });

        items
    }

    /// Run OVAL definitions against the current audit state
    pub async fn evaluate_oval_definitions(
        &self,
        definitions: &crate::scap::oval::OvalDefinitions,
    ) -> Result<Vec<crate::scap::oval::types::DefinitionResult>> {
        let context = self.build_collection_context();

        // Create engine and set remote context
        let mut engine = crate::scap::oval::interpreter::OvalEngine::new(definitions.clone());

        // Create remote execution context
        let remote_ctx = crate::scap::oval::remote::RemoteExecutionContext {
            host: self.config.target.clone(),
            executor: crate::scap::oval::remote::ExecutorType::WinRm {
                username: self.config.credentials.username.clone(),
                password: self.config.credentials.password.clone(),
                port: 5985,
                use_ssl: false,
                domain: self.config.credentials.domain.clone(),
            },
        };
        engine.set_remote_context(remote_ctx);

        // Evaluate all vulnerability class definitions
        engine.evaluate_all(Some("vulnerability")).await
    }
}

/// Convert STIG results to OVAL definition results
pub fn stig_results_to_oval(
    stig_results: &[StigCheckResult],
) -> Vec<crate::scap::oval::types::DefinitionResult> {
    use crate::scap::oval::types::{DefinitionResult, OvalResultType};

    stig_results.iter().map(|stig| {
        let result = match stig.status {
            StigCheckStatus::NotAFinding => OvalResultType::True,
            StigCheckStatus::Open => OvalResultType::False,
            StigCheckStatus::NotApplicable => OvalResultType::NotApplicable,
            StigCheckStatus::NotReviewed => OvalResultType::NotEvaluated,
        };

        DefinitionResult {
            definition_id: format!("oval:heroforge.stig:def:{}", stig.stig_id),
            result,
            criteria_results: None,
            message: stig.finding_details.clone(),
            evaluated_at: chrono::Utc::now(),
        }
    }).collect()
}

/// Convert OVAL results to STIG results for reporting
pub fn oval_to_stig_results(
    oval_results: &[crate::scap::oval::types::DefinitionResult],
    stig_mapping: &HashMap<String, StigMapping>,
) -> Vec<StigCheckResult> {
    use crate::scap::oval::types::OvalResultType;

    oval_results.iter().filter_map(|oval| {
        // Find STIG mapping for this OVAL definition
        stig_mapping.get(&oval.definition_id).map(|mapping| {
            let status = match oval.result {
                OvalResultType::True => StigCheckStatus::NotAFinding,
                OvalResultType::False => StigCheckStatus::Open,
                OvalResultType::NotApplicable => StigCheckStatus::NotApplicable,
                _ => StigCheckStatus::NotReviewed,
            };

            StigCheckResult {
                stig_id: mapping.stig_id.clone(),
                rule_id: mapping.rule_id.clone(),
                title: mapping.title.clone(),
                category: mapping.category,
                status,
                finding_details: oval.message.clone(),
                expected: mapping.expected.clone(),
                actual: String::new(), // Would be filled from OVAL item data
                remediation: mapping.remediation.clone(),
            }
        })
    }).collect()
}

/// Mapping from OVAL definition to STIG check
#[derive(Debug, Clone)]
pub struct StigMapping {
    pub stig_id: String,
    pub rule_id: String,
    pub title: String,
    pub category: StigCategory,
    pub expected: String,
    pub remediation: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stig_to_oval_conversion() {
        let stig_results = vec![
            StigCheckResult {
                stig_id: "V-1234".to_string(),
                rule_id: "SV-1234r1".to_string(),
                title: "Test check".to_string(),
                category: StigCategory::CatI,
                status: StigCheckStatus::NotAFinding,
                finding_details: Some("Passed".to_string()),
                expected: "Value should be 1".to_string(),
                actual: "1".to_string(),
                remediation: None,
            },
        ];

        let oval_results = stig_results_to_oval(&stig_results);
        assert_eq!(oval_results.len(), 1);
        assert_eq!(
            oval_results[0].result,
            crate::scap::oval::types::OvalResultType::True
        );
    }
}
