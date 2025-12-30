use anyhow::Result;

pub fn dissect_http(payload: &[u8]) -> Result<serde_json::Value> {
    Ok(serde_json::json!({}))
}

pub fn dissect_dns(payload: &[u8]) -> Result<serde_json::Value> {
    Ok(serde_json::json!({}))
}

pub fn dissect_tls(payload: &[u8]) -> Result<serde_json::Value> {
    Ok(serde_json::json!({}))
}
