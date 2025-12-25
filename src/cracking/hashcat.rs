//! Hashcat integration module
//!
//! Handles running hashcat as a subprocess and parsing its output.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use anyhow::Result;
use tempfile::TempDir;

use crate::cracking::types::{
    HashEntry, CrackingJobConfig, AttackMode, CrackingProgress, CrackedCredential,
};

/// Hashcat runner for executing password cracking jobs
pub struct HashcatRunner {
    /// Hash type mode (e.g., 1000 for NTLM)
    hash_type: i32,
    /// Hashes to crack
    hashes: Vec<HashEntry>,
    /// Job configuration
    config: CrackingJobConfig,
    /// Temporary directory for hash files
    temp_dir: TempDir,
}

impl HashcatRunner {
    /// Create a new hashcat runner
    pub fn new(hash_type: i32, hashes: &[HashEntry], config: &CrackingJobConfig) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        Ok(Self {
            hash_type,
            hashes: hashes.to_vec(),
            config: config.clone(),
            temp_dir,
        })
    }

    /// Write hashes to a temporary file
    pub fn write_hash_file(&self) -> Result<PathBuf> {
        let hash_file = self.temp_dir.path().join("hashes.txt");
        let mut file = File::create(&hash_file)?;

        for entry in &self.hashes {
            // Format depends on hash type, but typically:
            // For user:hash format: "username:hash"
            // For hash only: "hash"
            if let Some(ref username) = entry.username {
                if let Some(ref domain) = entry.domain {
                    writeln!(file, "{}\\{}:{}", domain, username, entry.hash)?;
                } else {
                    writeln!(file, "{}:{}", username, entry.hash)?;
                }
            } else {
                writeln!(file, "{}", entry.hash)?;
            }
        }

        Ok(hash_file)
    }

    /// Build hashcat command arguments
    pub fn build_args(
        &self,
        hash_file: &Path,
        wordlist_paths: &[String],
        rule_paths: &[String],
    ) -> Result<Vec<String>> {
        let mut args = Vec::new();

        // Hash type
        args.push("-m".to_string());
        args.push(self.hash_type.to_string());

        // Attack mode
        args.push("-a".to_string());
        args.push((self.config.attack_mode as i32).to_string());

        // Output file for cracked hashes
        let potfile = self.temp_dir.path().join("cracked.pot");
        args.push("--potfile-path".to_string());
        args.push(potfile.to_string_lossy().to_string());

        // Output format: hash:password
        args.push("--outfile-format".to_string());
        args.push("2".to_string());

        // Status output
        args.push("--status".to_string());
        args.push("--status-timer".to_string());
        args.push("5".to_string());

        // Machine-readable status
        args.push("--machine-readable".to_string());

        // Workload profile
        if let Some(wp) = self.config.workload_profile {
            args.push("-w".to_string());
            args.push(wp.to_string());
        }

        // Optimized kernels
        if self.config.optimized_kernels {
            args.push("-O".to_string());
        }

        // Device types
        if let Some(ref device_types) = self.config.device_types {
            args.push("-D".to_string());
            args.push(device_types.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(","));
        }

        // Specific devices
        if let Some(ref devices) = self.config.devices {
            args.push("-d".to_string());
            args.push(devices.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(","));
        }

        // Custom charsets
        for (i, charset) in self.config.custom_charsets.iter().enumerate() {
            args.push(format!("-{}", i + 1));
            args.push(charset.clone());
        }

        // Increment mode for brute-force
        if self.config.attack_mode == AttackMode::BruteForce {
            if let Some(min_len) = self.config.min_length {
                args.push("--increment".to_string());
                args.push("--increment-min".to_string());
                args.push(min_len.to_string());
            }
            if let Some(max_len) = self.config.max_length {
                args.push("--increment-max".to_string());
                args.push(max_len.to_string());
            }
        }

        // Extra arguments
        args.extend(self.config.extra_args.clone());

        // Hash file
        args.push(hash_file.to_string_lossy().to_string());

        // Wordlists (for dictionary/hybrid attacks)
        match self.config.attack_mode {
            AttackMode::Dictionary | AttackMode::HybridWordlistMask | AttackMode::HybridMaskWordlist => {
                for wordlist in wordlist_paths {
                    args.push(wordlist.clone());
                }
            }
            AttackMode::BruteForce => {
                // Add mask
                if let Some(ref mask) = self.config.mask {
                    args.push(mask.clone());
                } else {
                    // Default mask for brute-force
                    args.push("?a?a?a?a?a?a?a?a".to_string());
                }
            }
            _ => {}
        }

        // Rule files
        for rule in rule_paths {
            args.push("-r".to_string());
            args.push(rule.clone());
        }

        Ok(args)
    }

    /// Spawn hashcat process
    pub fn spawn(&self, args: &[String]) -> Result<Child> {
        let child = Command::new("hashcat")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(child)
    }

    /// Parse hashcat status output
    pub fn parse_status(line: &str) -> Option<CrackingProgress> {
        // Hashcat machine-readable format:
        // STATUS\t<status>\tSPEED\t<speed>\tCURPOSITION\t<pos>\tPROGRESS\t<done>\t<total>\t...

        if !line.starts_with("STATUS") {
            return None;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 10 {
            return None;
        }

        let mut progress = CrackingProgress::default();

        // Parse key-value pairs
        let mut i = 0;
        while i < parts.len() - 1 {
            match parts[i] {
                "SPEED" => {
                    if let Ok(speed) = parts[i + 1].parse::<u64>() {
                        progress.speed = format_speed(speed);
                    }
                }
                "RECOVERED" => {
                    // Format: cracked/total
                    let recovered: Vec<&str> = parts[i + 1].split('/').collect();
                    if recovered.len() >= 2 {
                        progress.cracked = recovered[0].parse().unwrap_or(0);
                        progress.total_hashes = recovered[1].parse().unwrap_or(0);
                    }
                }
                "PROGRESS" => {
                    // Format: done/total
                    let prog: Vec<&str> = parts[i + 1].split('/').collect();
                    if prog.len() >= 2 {
                        if let (Ok(done), Ok(total)) = (prog[0].parse::<u64>(), prog[1].parse::<u64>()) {
                            progress.candidates_tested = done;
                            progress.candidates_total = Some(total);
                            if total > 0 {
                                progress.progress_percent = (done as f32 / total as f32) * 100.0;
                            }
                        }
                    }
                }
                "TIMEREMAIN" => {
                    progress.estimated_time = parts[i + 1].to_string();
                }
                "TEMP" => {
                    // Parse GPU temperatures
                    let temps: Vec<u32> = parts[i + 1]
                        .split(',')
                        .filter_map(|t| t.parse().ok())
                        .collect();
                    progress.temperatures = temps;
                }
                _ => {}
            }
            i += 2;
        }

        Some(progress)
    }

    /// Parse cracked hash from potfile line
    pub fn parse_cracked(line: &str) -> Option<CrackedCredential> {
        // Format: hash:password or user:hash:password
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() < 2 {
            return None;
        }

        let (hash, plaintext) = (parts[0].to_string(), parts[1].to_string());

        Some(CrackedCredential {
            id: uuid::Uuid::new_v4().to_string(),
            hash,
            plaintext,
            hash_type: 0, // Will be set by caller
            username: None,
            domain: None,
            asset_id: None,
            cracked_at: chrono::Utc::now(),
        })
    }

    /// Clean up temporary files
    pub fn cleanup(&self, hash_file: &Path) -> Result<()> {
        if hash_file.exists() {
            fs::remove_file(hash_file)?;
        }
        Ok(())
    }

    /// Check if hashcat is installed
    pub fn is_available() -> bool {
        Command::new("hashcat")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Get hashcat version
    pub fn version() -> Option<String> {
        Command::new("hashcat")
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok()
                } else {
                    None
                }
            })
            .map(|v| v.trim().to_string())
    }

    /// List available hash modes
    pub fn list_hash_modes() -> Result<Vec<(i32, String)>> {
        let output = Command::new("hashcat")
            .args(["--example-hashes"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to get hash modes"));
        }

        let mut modes = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output to extract mode numbers and names
        // Format: "Hash mode #1000\n  Name: NTLM"
        let mut current_mode: Option<i32> = None;
        for line in stdout.lines() {
            if line.starts_with("Hash mode #") {
                if let Some(mode_str) = line.strip_prefix("Hash mode #") {
                    current_mode = mode_str.parse().ok();
                }
            } else if line.trim_start().starts_with("Name:") {
                if let Some(mode) = current_mode {
                    let name = line.trim_start().strip_prefix("Name:").unwrap_or("").trim();
                    modes.push((mode, name.to_string()));
                    current_mode = None;
                }
            }
        }

        Ok(modes)
    }
}

/// Format speed in human-readable format
fn format_speed(hashes_per_sec: u64) -> String {
    if hashes_per_sec >= 1_000_000_000_000 {
        format!("{:.2} TH/s", hashes_per_sec as f64 / 1_000_000_000_000.0)
    } else if hashes_per_sec >= 1_000_000_000 {
        format!("{:.2} GH/s", hashes_per_sec as f64 / 1_000_000_000.0)
    } else if hashes_per_sec >= 1_000_000 {
        format!("{:.2} MH/s", hashes_per_sec as f64 / 1_000_000.0)
    } else if hashes_per_sec >= 1_000 {
        format!("{:.2} KH/s", hashes_per_sec as f64 / 1_000.0)
    } else {
        format!("{} H/s", hashes_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(500), "500 H/s");
        assert_eq!(format_speed(1_500), "1.50 KH/s");
        assert_eq!(format_speed(1_500_000), "1.50 MH/s");
        assert_eq!(format_speed(1_500_000_000), "1.50 GH/s");
        assert_eq!(format_speed(1_500_000_000_000), "1.50 TH/s");
    }

    #[test]
    fn test_parse_cracked() {
        let line = "31d6cfe0d16ae931b73c59d7e0c089c0:password123";
        let result = HashcatRunner::parse_cracked(line);
        assert!(result.is_some());
        let cred = result.unwrap();
        assert_eq!(cred.hash, "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(cred.plaintext, "password123");
    }
}
