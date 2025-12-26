//! Data Flow Diagram Analysis

use serde::{Deserialize, Serialize};

/// Data flow diagram
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowDiagram {
    /// Diagram ID
    pub id: String,
    /// Diagram name
    pub name: String,
    /// External entities
    pub external_entities: Vec<ExternalEntity>,
    /// Processes
    pub processes: Vec<Process>,
    /// Data stores
    pub data_stores: Vec<DataStore>,
    /// Data flows
    pub flows: Vec<DfdFlow>,
}

/// External entity in DFD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalEntity {
    pub id: String,
    pub name: String,
    pub entity_type: String,
    pub trusted: bool,
}

/// Process in DFD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub id: String,
    pub name: String,
    pub trust_level: u8,
    pub handles_sensitive_data: bool,
}

/// Data store in DFD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStore {
    pub id: String,
    pub name: String,
    pub data_classification: DataClassification,
    pub encrypted: bool,
}

/// Data classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Flow in DFD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfdFlow {
    pub id: String,
    pub from_id: String,
    pub to_id: String,
    pub data_elements: Vec<String>,
    pub encrypted: bool,
    pub protocol: String,
}

impl DataFlowDiagram {
    /// Analyze the diagram for security issues
    pub fn analyze(&self) -> Vec<DfdIssue> {
        let mut issues = Vec::new();

        // Check for unencrypted sensitive data flows
        for flow in &self.flows {
            // Check if source or target handles sensitive data
            let sensitive = self.processes.iter()
                .any(|p| (p.id == flow.from_id || p.id == flow.to_id) && p.handles_sensitive_data);
            
            let restricted = self.data_stores.iter()
                .any(|d| (d.id == flow.from_id || d.id == flow.to_id) 
                    && matches!(d.data_classification, DataClassification::Restricted | DataClassification::Confidential));

            if (sensitive || restricted) && !flow.encrypted {
                issues.push(DfdIssue {
                    flow_id: flow.id.clone(),
                    issue_type: DfdIssueType::UnencryptedSensitiveData,
                    description: format!("Sensitive data flow '{}' is not encrypted", flow.id),
                });
            }
        }

        // Check for untrusted external entity accessing sensitive data
        for entity in &self.external_entities {
            if !entity.trusted {
                for flow in &self.flows {
                    if flow.from_id == entity.id || flow.to_id == entity.id {
                        // Check if flow involves sensitive data
                        let sensitive_store = self.data_stores.iter()
                            .any(|d| (d.id == flow.from_id || d.id == flow.to_id)
                                && matches!(d.data_classification, DataClassification::Restricted));
                        
                        if sensitive_store {
                            issues.push(DfdIssue {
                                flow_id: flow.id.clone(),
                                issue_type: DfdIssueType::UntrustedAccess,
                                description: format!("Untrusted entity '{}' accesses restricted data", entity.name),
                            });
                        }
                    }
                }
            }
        }

        issues
    }
}

/// DFD Issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DfdIssue {
    pub flow_id: String,
    pub issue_type: DfdIssueType,
    pub description: String,
}

/// DFD Issue Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DfdIssueType {
    UnencryptedSensitiveData,
    UntrustedAccess,
    MissingAuthentication,
    CrossBoundaryFlow,
}
