use anyhow::Result;
mod csv_output;
mod json_output;
mod terminal_output;

use crate::types::{HostInfo, OutputFormat, PortInfo};
use std::collections::HashMap;
use std::net::IpAddr;

pub fn display_results(
    results: &[HostInfo],
    format: &OutputFormat,
    output_file: Option<&str>,
) -> Result<()> {
    match format {
        OutputFormat::Json => json_output::output_json(results, output_file)?,
        OutputFormat::Csv => csv_output::output_csv(results, output_file)?,
        OutputFormat::Terminal => terminal_output::output_terminal(results)?,
        OutputFormat::All => {
            terminal_output::output_terminal(results)?;
            if let Some(file_base) = output_file {
                json_output::output_json(results, Some(&format!("{}.json", file_base)))?;
                csv_output::output_csv(results, Some(&format!("{}.csv", file_base)))?;
            }
        }
    }
    Ok(())
}

pub fn display_port_results(
    results: &HashMap<IpAddr, Vec<PortInfo>>,
    format: &OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Terminal | OutputFormat::All => {
            terminal_output::output_port_scan_terminal(results)?;
        }
        OutputFormat::Json => {
            json_output::output_port_scan_json(results)?;
        }
        OutputFormat::Csv => {
            csv_output::output_port_scan_csv(results)?;
        }
    }
    Ok(())
}
