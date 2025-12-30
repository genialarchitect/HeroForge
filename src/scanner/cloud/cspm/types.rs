//! CSPM type definitions

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    pub id: String,
    pub resource_type: String,
    pub region: String,
    pub tags: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceBenchmark {
    CisAwsFoundations,
    CisAzureFoundations,
    CisGcpFoundations,
    PciDss,
    Hipaa,
    FedRamp,
}
