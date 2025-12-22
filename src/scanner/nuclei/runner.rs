// Nuclei Runner
// Execute Nuclei binary and capture results

use super::parser::parse_nuclei_output;
use super::types::*;
use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;

/// Check if nuclei is installed and available
pub fn check_nuclei_available() -> bool {
    std::process::Command::new("nuclei")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get nuclei version
pub async fn get_nuclei_version() -> Result<String> {
    let output = Command::new("nuclei")
        .arg("-version")
        .output()
        .await?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Nuclei outputs version to stderr
    if let Some(version_line) = stderr.lines().next() {
        Ok(version_line.to_string())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().next().unwrap_or("unknown").to_string())
    }
}

/// Get templates directory path
pub fn get_templates_path() -> PathBuf {
    // Default nuclei templates location
    if let Some(home) = dirs::home_dir() {
        home.join("nuclei-templates")
    } else {
        PathBuf::from("/root/nuclei-templates")
    }
}

/// Update nuclei templates
pub async fn update_templates() -> Result<String> {
    info!("Updating Nuclei templates...");

    let output = Command::new("nuclei")
        .arg("-ut")
        .arg("-silent")
        .output()
        .await?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(format!("{}\n{}", stdout, stderr).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!("Failed to update templates: {}", stderr))
    }
}

/// Cancellation token for running scans
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a Nuclei scan with the given configuration
pub async fn run_nuclei_scan(
    config: &NucleiConfig,
    progress_tx: Option<broadcast::Sender<NucleiProgress>>,
    cancel_token: Option<CancellationToken>,
) -> Result<Vec<NucleiResult>> {
    if !check_nuclei_available() {
        return Err(anyhow!(
            "Nuclei is not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ));
    }

    // Build command arguments
    let mut args = build_nuclei_args(config)?;

    // Always use JSON output for parsing
    args.push("-jsonl".to_string());

    // Create targets file
    let targets_file = create_targets_file(&config.targets)?;
    args.push("-l".to_string());
    args.push(targets_file.path().to_string_lossy().to_string());

    debug!("Nuclei command: nuclei {}", args.join(" "));

    // Spawn nuclei process
    let mut child = Command::new("nuclei")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().ok_or_else(|| anyhow!("Failed to capture stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| anyhow!("Failed to capture stderr"))?;

    let mut results = Vec::new();
    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    // Track severity counts for progress
    let mut severity_counts: HashMap<String, usize> = HashMap::new();

    // Send start progress
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(NucleiProgress::Started {
            scan_id: "current".to_string(),
            total_targets: config.targets.len(),
            total_templates: 0, // Unknown until nuclei reports it
        });
    }

    // Read output lines
    loop {
        // Check for cancellation
        if let Some(ref token) = cancel_token {
            if token.is_cancelled() {
                warn!("Nuclei scan cancelled");
                let _ = child.kill().await;
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(NucleiProgress::Cancelled {
                        scan_id: "current".to_string(),
                    });
                }
                break;
            }
        }

        tokio::select! {
            line = stdout_reader.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        // Parse JSON result
                        if let Some(result) = parse_nuclei_output(&line) {
                            // Update counts
                            *severity_counts
                                .entry(result.severity.to_string())
                                .or_insert(0) += 1;

                            // Send progress update
                            if let Some(ref tx) = progress_tx {
                                let _ = tx.send(NucleiProgress::ResultFound {
                                    template_id: result.template_id.clone(),
                                    host: result.host.clone(),
                                    severity: result.severity.clone(),
                                });
                            }

                            results.push(result);
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(e) => {
                        error!("Error reading nuclei stdout: {}", e);
                        break;
                    }
                }
            }
            line = stderr_reader.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        // Log stderr but don't treat as error (nuclei logs progress to stderr)
                        if line.contains("[ERR]") || line.contains("error") {
                            warn!("Nuclei stderr: {}", line);
                        } else {
                            debug!("Nuclei: {}", line);
                        }

                        // Parse template count from stderr
                        if line.contains("Templates loaded") || line.contains("templates loaded") {
                            if let Some(count) = extract_template_count(&line) {
                                if let Some(ref tx) = progress_tx {
                                    let _ = tx.send(NucleiProgress::TemplatesLoaded { count });
                                }
                            }
                        }
                    }
                    Ok(None) => {} // EOF on stderr is fine
                    Err(e) => {
                        debug!("Error reading nuclei stderr: {}", e);
                    }
                }
            }
        }
    }

    // Wait for process to complete
    let status = child.wait().await?;

    // Clean up targets file (tempfile will auto-delete on drop)
    drop(targets_file);

    if !status.success() && results.is_empty() {
        return Err(anyhow!("Nuclei scan failed with exit code: {:?}", status.code()));
    }

    // Send completion progress
    if let Some(ref tx) = progress_tx {
        let _ = tx.send(NucleiProgress::Completed {
            scan_id: "current".to_string(),
            total_results: results.len(),
            duration_ms: 0, // Caller should track this
        });
    }

    info!(
        "Nuclei scan completed: {} results (critical: {}, high: {}, medium: {}, low: {}, info: {})",
        results.len(),
        severity_counts.get("critical").unwrap_or(&0),
        severity_counts.get("high").unwrap_or(&0),
        severity_counts.get("medium").unwrap_or(&0),
        severity_counts.get("low").unwrap_or(&0),
        severity_counts.get("info").unwrap_or(&0)
    );

    Ok(results)
}

/// Build nuclei command arguments from config
fn build_nuclei_args(config: &NucleiConfig) -> Result<Vec<String>> {
    let mut args = Vec::new();

    // Templates
    for template in &config.templates {
        args.push("-t".to_string());
        args.push(template.clone());
    }

    // Template tags
    if !config.template_tags.is_empty() {
        args.push("-tags".to_string());
        args.push(config.template_tags.join(","));
    }

    // Exclude tags
    if !config.exclude_tags.is_empty() {
        args.push("-etags".to_string());
        args.push(config.exclude_tags.join(","));
    }

    // Severity filter
    if !config.severity.is_empty() {
        args.push("-severity".to_string());
        args.push(
            config
                .severity
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
    }

    // Rate limiting
    args.push("-rate-limit".to_string());
    args.push(config.rate_limit.to_string());

    // Concurrency
    args.push("-concurrency".to_string());
    args.push(config.concurrency.to_string());

    // Timeout
    args.push("-timeout".to_string());
    args.push(config.timeout.as_secs().to_string());

    // Headless
    if config.headless {
        args.push("-headless".to_string());
    }

    // Follow redirects
    if config.follow_redirects {
        args.push("-follow-redirects".to_string());
        args.push("-max-redirects".to_string());
        args.push(config.max_redirects.to_string());
    } else {
        args.push("-no-redirect".to_string());
    }

    // Custom headers
    for (key, value) in &config.headers {
        args.push("-H".to_string());
        args.push(format!("{}: {}", key, value));
    }

    // Proxy
    if let Some(ref proxy) = config.proxy {
        args.push("-proxy".to_string());
        args.push(proxy.clone());
    }

    // Custom templates path
    if let Some(ref path) = config.custom_templates_path {
        args.push("-t".to_string());
        args.push(path.clone());
    }

    // Silent mode
    if config.silent {
        args.push("-silent".to_string());
    }

    // Always include these for better output
    args.push("-nc".to_string()); // No color (cleaner logs)
    args.push("-stats".to_string()); // Show stats

    Ok(args)
}

/// Create a temporary file with targets
fn create_targets_file(targets: &[String]) -> Result<tempfile::NamedTempFile> {
    use std::io::Write;

    let mut file = tempfile::NamedTempFile::new()?;
    for target in targets {
        writeln!(file, "{}", target)?;
    }
    file.flush()?;
    Ok(file)
}

/// Extract template count from nuclei output
fn extract_template_count(line: &str) -> Option<usize> {
    // Look for patterns like "Templates loaded: 1234" or "[INF] Templates: 1234"
    let patterns = [
        "Templates loaded: ",
        "templates loaded: ",
        "Templates: ",
    ];

    for pattern in patterns {
        if let Some(idx) = line.find(pattern) {
            let after = &line[idx + pattern.len()..];
            if let Some(num_str) = after.split_whitespace().next() {
                if let Ok(count) = num_str.parse::<usize>() {
                    return Some(count);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_args_basic() {
        let config = NucleiConfig::default();
        let args = build_nuclei_args(&config).unwrap();

        assert!(args.contains(&"-rate-limit".to_string()));
        assert!(args.contains(&"-concurrency".to_string()));
    }

    #[test]
    fn test_build_args_with_tags() {
        let mut config = NucleiConfig::default();
        config.template_tags = vec!["cve".to_string(), "rce".to_string()];

        let args = build_nuclei_args(&config).unwrap();

        assert!(args.contains(&"-tags".to_string()));
        assert!(args.contains(&"cve,rce".to_string()));
    }

    #[test]
    fn test_extract_template_count() {
        assert_eq!(
            extract_template_count("[INF] Templates loaded: 1234 (New: 0)"),
            Some(1234)
        );
        assert_eq!(
            extract_template_count("Templates: 567"),
            Some(567)
        );
        assert_eq!(
            extract_template_count("Some other message"),
            None
        );
    }

    #[test]
    fn test_cancellation_token() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());

        token.cancel();
        assert!(token.is_cancelled());
    }
}
