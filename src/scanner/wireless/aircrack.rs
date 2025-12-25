//! Aircrack-ng Integration
//!
//! Password cracking using aircrack-ng for WPA/WPA2 handshakes.

#![allow(dead_code)]

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use anyhow::{Result, Context};
use regex::Regex;

use super::types::*;

/// Default wordlists to try
pub const DEFAULT_WORDLISTS: &[&str] = &[
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
    "/usr/share/wordlists/common.txt",
];

/// Aircrack-ng password cracker
pub struct AircrackCracker {
    wordlist: String,
}

impl AircrackCracker {
    pub fn new() -> Self {
        Self {
            wordlist: Self::find_default_wordlist(),
        }
    }

    pub fn with_wordlist(wordlist: &str) -> Self {
        Self {
            wordlist: wordlist.to_string(),
        }
    }

    /// Find first available default wordlist
    fn find_default_wordlist() -> String {
        for wl in DEFAULT_WORDLISTS {
            if std::path::Path::new(wl).exists() {
                return wl.to_string();
            }
        }
        "/usr/share/wordlists/rockyou.txt".to_string()
    }

    /// Crack WPA handshake using aircrack-ng
    pub async fn crack_handshake(
        &self,
        capture_file: &str,
        bssid: Option<&str>,
        progress_tx: Option<mpsc::Sender<CrackProgress>>,
    ) -> Result<CrackResult> {
        let mut args = vec![
            "-w".to_string(),
            self.wordlist.clone(),
            "-q".to_string(), // Quiet mode for easier parsing
        ];

        if let Some(b) = bssid {
            args.push("-b".to_string());
            args.push(b.to_string());
        }

        args.push(capture_file.to_string());

        let mut child = Command::new("aircrack-ng")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start aircrack-ng")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();

        let mut keys_tested: u64 = 0;
        let mut keys_per_second: f64 = 0.0;
        let mut password: Option<String> = None;

        while let Some(line) = reader.next_line().await? {
            // Parse progress
            if let Some(progress) = Self::parse_progress_line(&line) {
                keys_tested = progress.keys_tested;
                keys_per_second = progress.keys_per_second;

                if let Some(tx) = &progress_tx {
                    let _ = tx.send(progress).await;
                }
            }

            // Check for found key
            if line.contains("KEY FOUND!") {
                if let Some(key) = Self::extract_key(&line) {
                    password = Some(key);
                    break;
                }
            }
        }

        // Wait for process to complete
        let status = child.wait().await?;

        let crack_status = if password.is_some() {
            CrackStatus::Success
        } else if status.success() || status.code() == Some(1) {
            CrackStatus::Exhausted
        } else {
            CrackStatus::Failed
        };

        Ok(CrackResult {
            status: crack_status,
            password,
            keys_tested,
            keys_per_second,
        })
    }

    /// Parse aircrack-ng progress line
    fn parse_progress_line(line: &str) -> Option<CrackProgress> {
        // Pattern: "[00:00:01] 1234 keys tested (567.89 k/s)"
        let re = Regex::new(r"\[[\d:]+\]\s+(\d+)\s+keys?\s+tested\s+\(([0-9.]+)\s*[km]?/s\)").ok()?;

        if let Some(caps) = re.captures(line) {
            let keys: u64 = caps.get(1)?.as_str().parse().ok()?;
            let mut rate: f64 = caps.get(2)?.as_str().parse().ok()?;

            // Convert k/s to raw rate
            if line.contains("k/s") {
                rate *= 1000.0;
            }

            return Some(CrackProgress {
                keys_tested: keys,
                keys_per_second: rate,
                estimated_remaining: None,
            });
        }

        None
    }

    /// Extract key from "KEY FOUND!" line
    fn extract_key(line: &str) -> Option<String> {
        // Pattern: "KEY FOUND! [ password123 ]"
        let re = Regex::new(r"KEY FOUND!\s*\[\s*(.+?)\s*\]").ok()?;
        re.captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Crack PMKID hash using hashcat (if available) or aircrack-ng
    pub async fn crack_pmkid(
        &self,
        pmkid_file: &str,
        progress_tx: Option<mpsc::Sender<CrackProgress>>,
    ) -> Result<CrackResult> {
        // Try hashcat first (faster)
        if Self::check_hashcat_available().await {
            return self.crack_pmkid_hashcat(pmkid_file, progress_tx).await;
        }

        // Fall back to aircrack-ng with converted file
        self.crack_pmkid_aircrack(pmkid_file, progress_tx).await
    }

    /// Check if hashcat is available
    async fn check_hashcat_available() -> bool {
        Command::new("hashcat")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Crack PMKID using hashcat
    async fn crack_pmkid_hashcat(
        &self,
        pmkid_file: &str,
        progress_tx: Option<mpsc::Sender<CrackProgress>>,
    ) -> Result<CrackResult> {
        let output_file = format!("{}.cracked", pmkid_file);

        let mut child = Command::new("hashcat")
            .args([
                "-m", "22000",  // WPA-PMKID-PBKDF2 hash mode
                "-a", "0",     // Dictionary attack
                pmkid_file,
                &self.wordlist,
                "-o", &output_file,
                "--status",
                "--status-timer", "5",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start hashcat")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();

        let mut keys_tested: u64 = 0;
        let mut keys_per_second: f64 = 0.0;

        while let Some(line) = reader.next_line().await? {
            // Parse hashcat status output
            if line.starts_with("Progress") {
                if let Some(progress) = Self::parse_hashcat_progress(&line) {
                    keys_tested = progress.keys_tested;
                    keys_per_second = progress.keys_per_second;

                    if let Some(tx) = &progress_tx {
                        let _ = tx.send(progress).await;
                    }
                }
            }
        }

        let status = child.wait().await?;

        // Check for cracked password
        let password = if let Ok(content) = tokio::fs::read_to_string(&output_file).await {
            // hashcat output: hash:password
            content.lines()
                .next()
                .and_then(|l| l.split(':').last())
                .map(|s| s.to_string())
        } else {
            None
        };

        // Cleanup
        let _ = tokio::fs::remove_file(&output_file).await;

        let crack_status = if password.is_some() {
            CrackStatus::Success
        } else if status.success() || status.code() == Some(1) {
            CrackStatus::Exhausted
        } else {
            CrackStatus::Failed
        };

        Ok(CrackResult {
            status: crack_status,
            password,
            keys_tested,
            keys_per_second,
        })
    }

    /// Parse hashcat progress line
    fn parse_hashcat_progress(line: &str) -> Option<CrackProgress> {
        // Pattern varies by hashcat version
        let re = Regex::new(r"Progress[.:]\s*(\d+)/\d+.*Speed[.:]\s*([0-9.]+)\s*([kMG]?)H/s").ok()?;

        if let Some(caps) = re.captures(line) {
            let keys: u64 = caps.get(1)?.as_str().parse().ok()?;
            let mut rate: f64 = caps.get(2)?.as_str().parse().ok()?;

            // Convert to raw rate
            match caps.get(3).map(|m| m.as_str()) {
                Some("k") => rate *= 1000.0,
                Some("M") => rate *= 1_000_000.0,
                Some("G") => rate *= 1_000_000_000.0,
                _ => {}
            }

            return Some(CrackProgress {
                keys_tested: keys,
                keys_per_second: rate,
                estimated_remaining: None,
            });
        }

        None
    }

    /// Crack PMKID using aircrack-ng (requires conversion)
    async fn crack_pmkid_aircrack(
        &self,
        pmkid_file: &str,
        progress_tx: Option<mpsc::Sender<CrackProgress>>,
    ) -> Result<CrackResult> {
        // Convert PMKID to cap format using hcxpcapngtool
        let cap_file = format!("{}.cap", pmkid_file);

        let convert = Command::new("hcxhash2cap")
            .args(["-c", &cap_file, "-m", pmkid_file])
            .output()
            .await;

        if convert.is_err() || !convert.unwrap().status.success() {
            anyhow::bail!("Failed to convert PMKID to cap format");
        }

        // Use aircrack-ng on converted file
        let result = self.crack_handshake(&cap_file, None, progress_tx).await?;

        // Cleanup
        let _ = tokio::fs::remove_file(&cap_file).await;

        Ok(result)
    }

    /// List available wordlists
    pub async fn list_wordlists() -> Vec<WordlistInfo> {
        let mut wordlists = Vec::new();
        let search_paths = [
            "/usr/share/wordlists",
            "/usr/share/seclists/Passwords",
            "/opt/wordlists",
        ];

        for base_path in search_paths {
            if let Ok(mut entries) = tokio::fs::read_dir(base_path).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_file() {
                        let name = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let size = entry.metadata().await
                            .map(|m| m.len())
                            .unwrap_or(0);

                        wordlists.push(WordlistInfo {
                            name,
                            path: path.to_string_lossy().to_string(),
                            size,
                            lines: None, // Would need to count
                        });
                    }
                }
            }
        }

        wordlists
    }
}

impl Default for AircrackCracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Crack progress information
#[derive(Debug, Clone)]
pub struct CrackProgress {
    pub keys_tested: u64,
    pub keys_per_second: f64,
    pub estimated_remaining: Option<u64>,
}

/// Crack result
#[derive(Debug, Clone)]
pub struct CrackResult {
    pub status: CrackStatus,
    pub password: Option<String>,
    pub keys_tested: u64,
    pub keys_per_second: f64,
}

/// Wordlist information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WordlistInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub lines: Option<u64>,
}

/// WPS attack handler
pub struct WpsAttack {
    interface: String,
}

impl WpsAttack {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    /// Perform Pixie Dust WPS attack
    pub async fn pixie_dust(&self, bssid: &str, timeout_secs: u32) -> Result<WpsResult> {
        let mut child = Command::new("reaver")
            .args([
                "-i", &self.interface,
                "-b", bssid,
                "-K", "1",  // Pixie Dust attack
                "-vv",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start reaver")?;

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout).lines();

        let mut pin: Option<String> = None;
        let mut psk: Option<String> = None;

        let timeout = tokio::time::Duration::from_secs(timeout_secs as u64);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() >= timeout {
                child.kill().await.ok();
                break;
            }

            tokio::select! {
                line = reader.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            // Parse for PIN
                            if l.contains("WPS PIN:") {
                                pin = Self::extract_wps_pin(&l);
                            }
                            // Parse for PSK
                            if l.contains("WPA PSK:") || l.contains("WPS PSK:") {
                                psk = Self::extract_wps_psk(&l);
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
            }
        }

        child.kill().await.ok();

        Ok(WpsResult {
            success: psk.is_some(),
            pin,
            psk,
            error: None,
        })
    }

    /// Extract WPS PIN from reaver output
    fn extract_wps_pin(line: &str) -> Option<String> {
        let re = Regex::new(r"WPS PIN:\s*'?(\d{8})'?").ok()?;
        re.captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Extract WPS PSK from reaver output
    fn extract_wps_psk(line: &str) -> Option<String> {
        let re = Regex::new(r"(?:WPA|WPS) PSK:\s*'([^']+)'").ok()?;
        re.captures(line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }
}

/// WPS attack result
#[derive(Debug, Clone)]
pub struct WpsResult {
    pub success: bool,
    pub pin: Option<String>,
    pub psk: Option<String>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_progress_line() {
        let line = "[00:01:23] 12345 keys tested (987.65 k/s)";
        let progress = AircrackCracker::parse_progress_line(line).unwrap();
        assert_eq!(progress.keys_tested, 12345);
        assert!((progress.keys_per_second - 987650.0).abs() < 1.0);
    }

    #[test]
    fn test_extract_key() {
        let line = "KEY FOUND! [ mysecretpassword ]";
        let key = AircrackCracker::extract_key(line).unwrap();
        assert_eq!(key, "mysecretpassword");
    }
}
