use crate::investigation::types::InjectionDetection;
use anyhow::Result;

pub fn detect_injections(processes: &[serde_json::Value]) -> Result<Vec<InjectionDetection>> {
    let detections = Vec::new();

    // Detect DLL injection
    // Detect process hollowing
    // Detect reflective DLL injection

    Ok(detections)
}
