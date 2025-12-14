use anyhow::Result;
use crate::types::{HostInfo, PortInfo};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

pub fn output_json(
    results: &[HostInfo],
    output_file: Option<&str>,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;

    if let Some(file_path) = output_file {
        let mut file = File::create(file_path)?;
        file.write_all(json.as_bytes())?;
        println!("Results saved to: {}", file_path);
    } else {
        println!("{}", json);
    }

    Ok(())
}

pub fn output_port_scan_json(
    results: &HashMap<IpAddr, Vec<PortInfo>>,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    println!("{}", json);
    Ok(())
}
