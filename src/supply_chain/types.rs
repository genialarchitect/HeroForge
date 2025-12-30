//! Supply chain security types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub purl: String, // Package URL
    pub license: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
    Swid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlsaLevel {
    Level0,
    Level1,
    Level2,
    Level3,
    Level4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceAttestation {
    pub build_type: String,
    pub builder: String,
    pub invocation: serde_json::Value,
    pub materials: Vec<Material>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Material {
    pub uri: String,
    pub digest: std::collections::HashMap<String, String>,
}
