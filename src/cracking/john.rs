//! John the Ripper integration for password cracking
//!
//! This module provides integration with John the Ripper (JtR), supporting:
//! - Multiple hash formats (md5crypt, sha512crypt, NT, etc.)
//! - Dictionary attacks with wordlists
//! - Rule-based attacks
//! - Incremental (brute force) mode
//! - Session management (pause/resume)
//! - Pot file management for recovered passwords

use anyhow::{Result, Context};
use log::{info, warn, debug, error};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

use crate::cracking::types::{
    HashEntry, CrackingJobConfig, CrackingProgress, HashType,
};

/// John the Ripper format names mapping from hashcat modes
fn hash_type_to_john_format(hash_type: i32) -> &'static str {
    match hash_type {
        0 => "raw-md5",            // MD5
        100 => "raw-sha1",         // SHA-1
        1400 => "raw-sha256",      // SHA-256
        1700 => "raw-sha512",      // SHA-512
        1000 => "nt",              // NTLM
        3000 => "lm",              // LM
        5500 => "netntlm",         // NetNTLMv1
        5600 => "netntlmv2",       // NetNTLMv2
        13100 => "krb5tgs",        // Kerberos TGS (Kerberoasting)
        18200 => "krb5asrep",      // Kerberos AS-REP
        3200 => "bcrypt",          // bcrypt
        200 => "mysql",            // MySQL323
        300 => "mysql-sha1",       // MySQL 4.1+
        131 => "mssql",            // MSSQL 2000
        132 => "mssql05",          // MSSQL 2005
        112 => "oracle11",         // Oracle 11g
        12 => "postgres",          // PostgreSQL
        22000 => "wpapsk-pmkid",   // WPA-PMKID
        2410 => "cisco4",          // Cisco-ASA
        7400 => "sha256crypt",     // SHA-256 crypt
        1800 => "sha512crypt",     // SHA-512 crypt
        1500 => "descrypt",        // descrypt
        111 => "ldap-sha",         // LDAP SSHA
        9600 => "office",          // Office 2013
        10500 => "pdf",            // PDF
        11600 => "7z",             // 7-Zip
        13000 => "rar5",           // RAR5
        _ => "auto",               // Let John detect
    }
}

/// John the Ripper runner configuration
#[derive(Debug, Clone)]
pub struct JohnConfig {
    /// Path to john binary
    pub john_path: String,
    /// Session name for pause/resume
    pub session_name: Option<String>,
    /// Working directory for temp files
    pub work_dir: PathBuf,
    /// Path to potfile
    pub pot_file: Option<PathBuf>,
    /// Maximum runtime in seconds (0 = unlimited)
    pub max_runtime: u64,
    /// Fork count for parallelization
    pub fork_count: Option<u32>,
    /// OpenCL device to use (None = CPU)
    pub opencl_device: Option<u32>,
}

impl Default for JohnConfig {
    fn default() -> Self {
        Self {
            john_path: "john".to_string(),
            session_name: None,
            work_dir: std::env::temp_dir(),
            pot_file: None,
            max_runtime: 0,
            fork_count: None,
            opencl_device: None,
        }
    }
}

/// John the Ripper runner
pub struct JohnRunner {
    /// Hash format for John
    format: String,
    /// Hashes to crack
    hashes: Vec<HashEntry>,
    /// Job configuration
    config: CrackingJobConfig,
    /// John configuration
    john_config: JohnConfig,
}

impl JohnRunner {
    /// Create a new John runner
    pub fn new(
        hash_type: i32,
        hashes: &[HashEntry],
        config: &CrackingJobConfig,
    ) -> Result<Self> {
        let john_config = JohnConfig::default();
        Self::with_john_config(hash_type, hashes, config, john_config)
    }

    /// Create with custom John configuration
    pub fn with_john_config(
        hash_type: i32,
        hashes: &[HashEntry],
        config: &CrackingJobConfig,
        john_config: JohnConfig,
    ) -> Result<Self> {
        let format = hash_type_to_john_format(hash_type).to_string();

        Ok(Self {
            format,
            hashes: hashes.to_vec(),
            config: config.clone(),
            john_config,
        })
    }

    /// Check if John the Ripper is installed
    pub fn is_available() -> bool {
        Command::new("john")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get John version
    pub fn get_version() -> Result<String> {
        let output = Command::new("john")
            .arg("--version")
            .output()
            .context("Failed to run john --version")?;

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.lines().next().unwrap_or("unknown").to_string())
    }

    /// Write hashes to a temporary file in John format
    pub fn write_hash_file(&self) -> Result<NamedTempFile> {
        let mut file = NamedTempFile::new()
            .context("Failed to create temporary hash file")?;

        for hash in &self.hashes {
            // John format: user:hash or just hash
            if let Some(ref username) = hash.username {
                writeln!(file, "{}:{}", username, hash.hash)?;
            } else {
                writeln!(file, "{}", hash.hash)?;
            }
        }

        file.flush()?;
        Ok(file)
    }

    /// Build John command arguments
    pub fn build_args(
        &self,
        hash_file: &Path,
        wordlist_paths: &[String],
        rule_paths: &[String],
    ) -> Result<Vec<String>> {
        let mut args = Vec::new();

        // Hash format (if not auto-detect)
        if self.format != "auto" {
            args.push(format!("--format={}", self.format));
        }

        // Session name for pause/resume
        if let Some(ref session) = self.john_config.session_name {
            args.push(format!("--session={}", session));
        }

        // Potfile location
        if let Some(ref pot_file) = self.john_config.pot_file {
            args.push(format!("--pot={}", pot_file.display()));
        }

        // Attack mode based on config
        match self.config.attack_mode {
            crate::cracking::types::AttackMode::Dictionary => {
                // Dictionary attack (default)
                if let Some(first_wordlist) = wordlist_paths.first() {
                    args.push(format!("--wordlist={}", first_wordlist));
                } else {
                    // Use John's default wordlist
                    args.push("--wordlist".to_string());
                }

                // Add rules
                for rule_path in rule_paths {
                    args.push(format!("--rules={}", rule_path));
                }

                // Use built-in rules if no custom rules and rule_ids are empty
                if rule_paths.is_empty() && !self.config.rule_ids.is_empty() {
                    args.push("--rules=All".to_string());
                }
            }
            crate::cracking::types::AttackMode::BruteForce => {
                // Incremental (brute force) mode
                args.push("--incremental".to_string());

                // Character set if specified
                if let Some(ref charset) = self.config.custom_charsets.first() {
                    args.push(format!("--incremental:{}", charset));
                }
            }
            crate::cracking::types::AttackMode::Combinator => {
                // Combinator attack - combine words from multiple wordlists
                for (i, wordlist) in wordlist_paths.iter().take(2).enumerate() {
                    if i == 0 {
                        args.push(format!("--wordlist={}", wordlist));
                    } else {
                        // John uses prince mode for combination
                        args.push("--prince".to_string());
                    }
                }
            }
            crate::cracking::types::AttackMode::HybridWordlistMask => {
                // Hybrid mode - wordlist + mask
                if let Some(first_wordlist) = wordlist_paths.first() {
                    args.push(format!("--wordlist={}", first_wordlist));
                }
                if let Some(ref mask) = self.config.mask {
                    args.push(format!("--mask={}", mask));
                }
            }
            crate::cracking::types::AttackMode::HybridMaskWordlist => {
                // Hybrid mode - mask + wordlist (reversed)
                if let Some(ref mask) = self.config.mask {
                    args.push(format!("--mask={}", mask));
                }
                if let Some(first_wordlist) = wordlist_paths.first() {
                    args.push(format!("--wordlist={}", first_wordlist));
                }
            }
            crate::cracking::types::AttackMode::Association => {
                // Association attack - uses contextual data
                if let Some(first_wordlist) = wordlist_paths.first() {
                    args.push(format!("--wordlist={}", first_wordlist));
                }
                args.push("--rules=All".to_string());
            }
        }

        // Parallelization
        if let Some(fork_count) = self.john_config.fork_count {
            args.push(format!("--fork={}", fork_count));
        }

        // OpenCL support
        if let Some(device) = self.john_config.opencl_device {
            args.push(format!("--devices={}", device));
        }

        // Max runtime
        if self.john_config.max_runtime > 0 {
            args.push(format!("--max-run-time={}", self.john_config.max_runtime));
        }

        // Password length limits
        if let Some(min_len) = self.config.min_length {
            args.push(format!("--min-length={}", min_len));
        }
        if let Some(max_len) = self.config.max_length {
            args.push(format!("--max-length={}", max_len));
        }

        // Hash file path (must be last)
        args.push(hash_file.to_string_lossy().to_string());

        Ok(args)
    }

    /// Run John the Ripper and return cracked passwords
    pub async fn run(
        &self,
        hash_file: &Path,
        wordlist_paths: &[String],
        rule_paths: &[String],
        progress_callback: impl Fn(CrackingProgress) + Send + 'static,
    ) -> Result<Vec<CrackedPassword>> {
        let args = self.build_args(hash_file, wordlist_paths, rule_paths)?;

        info!("Running John the Ripper with args: {:?}", args);

        // Create pot file path
        let pot_file = self.john_config.pot_file.clone()
            .unwrap_or_else(|| self.john_config.work_dir.join("john.pot"));

        // Spawn John process
        let mut child = Command::new(&self.john_config.john_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn John the Ripper process")?;

        // Read output in background
        let stdout = child.stdout.take();
        let total_hashes = self.hashes.len();

        // Progress monitoring task
        let pot_file_clone = pot_file.clone();
        let progress_handle = tokio::spawn(async move {
            let mut last_cracked = 0;

            loop {
                // Check pot file for cracked passwords
                let cracked_count = count_pot_entries(&pot_file_clone).unwrap_or(0);

                if cracked_count > last_cracked {
                    last_cracked = cracked_count;

                    let progress = CrackingProgress {
                        total_hashes,
                        cracked: cracked_count,
                        speed: "Calculating...".to_string(),
                        estimated_time: "N/A".to_string(),
                        progress_percent: (cracked_count as f32 / total_hashes as f32) * 100.0,
                        candidates_tested: 0,
                        candidates_total: None,
                        status_message: format!("Cracked {} of {} hashes", cracked_count, total_hashes),
                        temperatures: vec![],
                        utilization: vec![],
                    };

                    progress_callback(progress);
                }

                // Sleep before next check
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        });

        // Wait for John to complete
        let status = child.wait()
            .context("Failed to wait for John process")?;

        // Stop progress monitoring
        progress_handle.abort();

        if !status.success() {
            // John returns non-zero even on partial success, so just log it
            debug!("John exited with status: {}", status);
        }

        // Parse cracked passwords from pot file and show output
        let cracked = self.show_cracked(hash_file).await?;

        Ok(cracked)
    }

    /// Show cracked passwords using john --show
    pub async fn show_cracked(&self, hash_file: &Path) -> Result<Vec<CrackedPassword>> {
        let mut args = vec!["--show".to_string()];

        if self.format != "auto" {
            args.push(format!("--format={}", self.format));
        }

        if let Some(ref pot_file) = self.john_config.pot_file {
            args.push(format!("--pot={}", pot_file.display()));
        }

        args.push(hash_file.to_string_lossy().to_string());

        let output = Command::new(&self.john_config.john_path)
            .args(&args)
            .output()
            .context("Failed to run john --show")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut cracked = Vec::new();

        for line in stdout.lines() {
            // Format: user:password or hash:password
            if let Some((user_or_hash, password)) = line.split_once(':') {
                // Skip summary lines
                if user_or_hash.contains("password hash") || user_or_hash.contains("left") {
                    continue;
                }

                cracked.push(CrackedPassword {
                    username: Some(user_or_hash.to_string()),
                    hash: String::new(), // Would need to look up
                    password: password.to_string(),
                });
            }
        }

        Ok(cracked)
    }

    /// Resume a paused session
    pub async fn resume(&self) -> Result<()> {
        let session = self.john_config.session_name.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session name set"))?;

        let output = Command::new(&self.john_config.john_path)
            .arg(format!("--restore={}", session))
            .output()
            .context("Failed to resume John session")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to resume session: {}", stderr));
        }

        Ok(())
    }

    /// Get status of current session
    pub async fn get_status(&self) -> Result<JohnStatus> {
        let session = self.john_config.session_name.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session name set"))?;

        let output = Command::new(&self.john_config.john_path)
            .arg(format!("--status={}", session))
            .output()
            .context("Failed to get John status")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse status output
        Ok(JohnStatus {
            running: output.status.success(),
            message: stdout.to_string(),
        })
    }

    /// Clean up temporary files
    pub fn cleanup(&self, hash_file: &Path) -> Result<()> {
        // Remove hash file if it exists
        if hash_file.exists() {
            fs::remove_file(hash_file).ok();
        }

        // Remove session files
        if let Some(ref session) = self.john_config.session_name {
            let session_file = self.john_config.work_dir.join(format!("{}.rec", session));
            if session_file.exists() {
                fs::remove_file(session_file).ok();
            }
        }

        Ok(())
    }
}

/// Count entries in pot file
fn count_pot_entries(pot_file: &Path) -> Result<usize> {
    if !pot_file.exists() {
        return Ok(0);
    }

    let file = File::open(pot_file)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count())
}

/// Cracked password result
#[derive(Debug, Clone)]
pub struct CrackedPassword {
    pub username: Option<String>,
    pub hash: String,
    pub password: String,
}

/// John session status
#[derive(Debug, Clone)]
pub struct JohnStatus {
    pub running: bool,
    pub message: String,
}

/// Run a John the Ripper cracking job
pub async fn run_john_job(
    pool: &sqlx::SqlitePool,
    job_id: &str,
    hash_type: i32,
    hashes: &[HashEntry],
    config: &CrackingJobConfig,
    progress_tx: tokio::sync::broadcast::Sender<crate::cracking::types::CrackingProgressMessage>,
) -> Result<usize> {
    // Check if John is available
    if !JohnRunner::is_available() {
        return Err(anyhow::anyhow!(
            "John the Ripper is not installed or not in PATH. \
             Install with: apt install john (Debian/Ubuntu) or brew install john (macOS)"
        ));
    }

    // Get version for logging
    if let Ok(version) = JohnRunner::get_version() {
        info!("Using John the Ripper version: {}", version);
    }

    // Get wordlist and rule paths
    let wordlist_paths = get_wordlist_paths(pool, &config.wordlist_ids).await?;
    let rule_paths = get_rule_paths(pool, &config.rule_ids).await?;

    // Create John runner with session
    let john_config = JohnConfig {
        session_name: Some(format!("heroforge_{}", job_id)),
        ..Default::default()
    };

    let runner = JohnRunner::with_john_config(hash_type, hashes, config, john_config)?;

    // Write hash file
    let hash_file = runner.write_hash_file()?;
    let hash_path = hash_file.path().to_path_buf();

    // Keep the temp file alive
    let _temp_guard = hash_file;

    // Progress callback
    let job_id_clone = job_id.to_string();
    let pool_clone = pool.clone();
    let progress_tx_clone = progress_tx.clone();
    let total = hashes.len();

    let progress_callback = move |progress: CrackingProgress| {
        // Update database
        if let Ok(progress_json) = serde_json::to_string(&progress) {
            let pool = pool_clone.clone();
            let job_id = job_id_clone.clone();
            tokio::spawn(async move {
                let _ = crate::db::cracking::update_job_progress(&pool, &job_id, &progress_json).await;
            });
        }

        // Broadcast progress
        let _ = progress_tx_clone.send(crate::cracking::types::CrackingProgressMessage::ProgressUpdate {
            job_id: job_id_clone.clone(),
            cracked: progress.cracked,
            total,
            speed: progress.speed.clone(),
            eta: progress.estimated_time.clone(),
            progress_percent: progress.progress_percent,
        });
    };

    // Run John
    let cracked = runner.run(&hash_path, &wordlist_paths, &rule_paths, progress_callback).await?;

    // Store cracked credentials in database
    for credential in &cracked {
        // Find the original hash entry
        let hash_entry = hashes.iter().find(|h| {
            h.username.as_deref() == credential.username.as_deref()
        });

        if let Some(entry) = hash_entry {
            let cred_id = uuid::Uuid::new_v4().to_string();
            crate::db::cracking::store_cracked_credential(
                pool,
                &cred_id,
                job_id,
                &entry.hash,
                &credential.password,
                hash_type,
                credential.username.as_deref(),
                None,  // domain
                None,  // asset_id
            ).await?;
        }
    }

    // Cleanup
    runner.cleanup(&hash_path)?;

    Ok(cracked.len())
}

/// Get wordlist file paths from database
async fn get_wordlist_paths(pool: &sqlx::SqlitePool, wordlist_ids: &[String]) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for id in wordlist_ids {
        if let Ok(wordlist) = crate::db::cracking::get_wordlist(pool, id).await {
            paths.push(wordlist.file_path);
        }
    }
    Ok(paths)
}

/// Get rule file paths from database
async fn get_rule_paths(pool: &sqlx::SqlitePool, rule_ids: &[String]) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for id in rule_ids {
        if let Ok(rule) = crate::db::cracking::get_rule_file(pool, id).await {
            paths.push(rule.file_path);
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_mapping() {
        assert_eq!(hash_type_to_john_format(1000), "nt");
        assert_eq!(hash_type_to_john_format(3200), "bcrypt");
        assert_eq!(hash_type_to_john_format(0), "raw-md5");
        assert_eq!(hash_type_to_john_format(99999), "auto");
    }

    #[test]
    fn test_john_config_default() {
        let config = JohnConfig::default();
        assert_eq!(config.john_path, "john");
        assert_eq!(config.max_runtime, 0);
        assert!(config.session_name.is_none());
    }

    #[tokio::test]
    async fn test_john_availability() {
        // This test will pass if John is installed, skip otherwise
        let available = JohnRunner::is_available();
        println!("John the Ripper available: {}", available);
    }
}
