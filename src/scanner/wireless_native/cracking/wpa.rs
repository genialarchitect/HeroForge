//! WPA/WPA2 PSK cracking
//!
//! Native implementation of WPA/WPA2 password cracking.

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::scanner::wireless_native::handshake::capture::{
    calculate_pmk, calculate_ptk, verify_handshake_mic,
};
use crate::scanner::wireless_native::handshake::pmkid::verify_pmkid;
use crate::scanner::wireless_native::types::{CapturedHandshake, HandshakeCrackData, PmkidData};

/// WPA cracker configuration
#[derive(Debug, Clone)]
pub struct WpaCrackerConfig {
    /// Number of threads to use
    pub threads: usize,
    /// Report progress every N passwords
    pub progress_interval: u64,
    /// Minimum password length
    pub min_length: usize,
    /// Maximum password length
    pub max_length: usize,
}

impl Default for WpaCrackerConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            progress_interval: 10000,
            min_length: 8, // WPA minimum
            max_length: 63, // WPA maximum
        }
    }
}

/// WPA cracker
pub struct WpaCracker {
    config: WpaCrackerConfig,
    /// Passwords tried
    passwords_tried: Arc<AtomicU64>,
    /// Is cracking
    is_cracking: Arc<AtomicBool>,
    /// Found password
    found_password: Arc<std::sync::Mutex<Option<String>>>,
}

impl WpaCracker {
    /// Create new WPA cracker
    pub fn new(config: WpaCrackerConfig) -> Self {
        Self {
            config,
            passwords_tried: Arc::new(AtomicU64::new(0)),
            is_cracking: Arc::new(AtomicBool::new(false)),
            found_password: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Crack handshake using wordlist
    pub fn crack_handshake(&self, handshake: &CapturedHandshake,
                           wordlist: &[String]) -> Result<WpaCrackResult> {
        let crack_data = handshake.get_crack_data()
            .ok_or_else(|| anyhow!("Handshake not crackable"))?;

        self.crack_with_data(&crack_data, wordlist)
    }

    /// Crack using prepared crack data
    pub fn crack_with_data(&self, crack_data: &HandshakeCrackData,
                           wordlist: &[String]) -> Result<WpaCrackResult> {
        // Filter wordlist by length constraints
        let valid_passwords: Vec<&String> = wordlist.iter()
            .filter(|p| p.len() >= self.config.min_length && p.len() <= self.config.max_length)
            .collect();

        if valid_passwords.is_empty() {
            return Err(anyhow!("No valid passwords in wordlist"));
        }

        self.passwords_tried.store(0, Ordering::Relaxed);
        self.is_cracking.store(true, Ordering::Relaxed);
        *self.found_password.lock().unwrap() = None;

        let start_time = Instant::now();

        // Split work across threads
        let chunk_size = (valid_passwords.len() + self.config.threads - 1) / self.config.threads;

        std::thread::scope(|s| {
            for chunk in valid_passwords.chunks(chunk_size) {
                let is_cracking = self.is_cracking.clone();
                let passwords_tried = self.passwords_tried.clone();
                let found_password = self.found_password.clone();
                let crack_data = crack_data.clone();
                let progress_interval = self.config.progress_interval;

                s.spawn(move || {
                    for (i, password) in chunk.iter().enumerate() {
                        if !is_cracking.load(Ordering::Relaxed) {
                            break;
                        }

                        if verify_handshake_mic(&crack_data, password) {
                            is_cracking.store(false, Ordering::Relaxed);
                            *found_password.lock().unwrap() = Some(password.to_string());
                            break;
                        }

                        let tried = passwords_tried.fetch_add(1, Ordering::Relaxed) + 1;

                        // Progress reporting would go here
                        if tried % progress_interval == 0 {
                            // Report progress
                        }
                    }
                });
            }
        });

        let elapsed = start_time.elapsed();
        let tried = self.passwords_tried.load(Ordering::Relaxed);
        let found = self.found_password.lock().unwrap().clone();

        Ok(WpaCrackResult {
            success: found.is_some(),
            password: found,
            passwords_tried: tried,
            elapsed,
            rate: tried as f64 / elapsed.as_secs_f64(),
            ssid: crack_data.ssid.clone(),
            bssid: crack_data.bssid.clone(),
        })
    }

    /// Crack PMKID using wordlist
    pub fn crack_pmkid(&self, pmkid: &PmkidData,
                       wordlist: &[String]) -> Result<WpaCrackResult> {
        let valid_passwords: Vec<&String> = wordlist.iter()
            .filter(|p| p.len() >= self.config.min_length && p.len() <= self.config.max_length)
            .collect();

        if valid_passwords.is_empty() {
            return Err(anyhow!("No valid passwords in wordlist"));
        }

        self.passwords_tried.store(0, Ordering::Relaxed);
        self.is_cracking.store(true, Ordering::Relaxed);
        *self.found_password.lock().unwrap() = None;

        let start_time = Instant::now();

        let chunk_size = (valid_passwords.len() + self.config.threads - 1) / self.config.threads;

        std::thread::scope(|s| {
            for chunk in valid_passwords.chunks(chunk_size) {
                let is_cracking = self.is_cracking.clone();
                let passwords_tried = self.passwords_tried.clone();
                let found_password = self.found_password.clone();
                let pmkid = pmkid.clone();

                s.spawn(move || {
                    for password in chunk.iter() {
                        if !is_cracking.load(Ordering::Relaxed) {
                            break;
                        }

                        if verify_pmkid(&pmkid, password) {
                            is_cracking.store(false, Ordering::Relaxed);
                            *found_password.lock().unwrap() = Some(password.to_string());
                            break;
                        }

                        passwords_tried.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });

        let elapsed = start_time.elapsed();
        let tried = self.passwords_tried.load(Ordering::Relaxed);
        let found = self.found_password.lock().unwrap().clone();

        Ok(WpaCrackResult {
            success: found.is_some(),
            password: found,
            passwords_tried: tried,
            elapsed,
            rate: tried as f64 / elapsed.as_secs_f64(),
            ssid: pmkid.ssid.clone(),
            bssid: pmkid.bssid.clone(),
        })
    }

    /// Stop cracking
    pub fn stop(&self) {
        self.is_cracking.store(false, Ordering::Relaxed);
    }

    /// Get current progress
    pub fn get_progress(&self) -> CrackProgress {
        CrackProgress {
            passwords_tried: self.passwords_tried.load(Ordering::Relaxed),
            is_cracking: self.is_cracking.load(Ordering::Relaxed),
            found: self.found_password.lock().unwrap().is_some(),
        }
    }
}

/// Crack result
#[derive(Debug, Clone)]
pub struct WpaCrackResult {
    /// Was password found
    pub success: bool,
    /// Found password
    pub password: Option<String>,
    /// Passwords tried
    pub passwords_tried: u64,
    /// Time elapsed
    pub elapsed: Duration,
    /// Crack rate (passwords/second)
    pub rate: f64,
    /// Target SSID
    pub ssid: String,
    /// Target BSSID
    pub bssid: String,
}

impl WpaCrackResult {
    /// Format result as string
    pub fn format(&self) -> String {
        if self.success {
            format!(
                "SUCCESS! Password: '{}'\n\
                 SSID: {}\n\
                 BSSID: {}\n\
                 Tried: {} passwords in {:.2}s ({:.0} p/s)",
                self.password.as_ref().unwrap(),
                self.ssid,
                self.bssid,
                self.passwords_tried,
                self.elapsed.as_secs_f64(),
                self.rate
            )
        } else {
            format!(
                "Password not found\n\
                 SSID: {}\n\
                 BSSID: {}\n\
                 Tried: {} passwords in {:.2}s ({:.0} p/s)",
                self.ssid,
                self.bssid,
                self.passwords_tried,
                self.elapsed.as_secs_f64(),
                self.rate
            )
        }
    }
}

/// Cracking progress
#[derive(Debug, Clone)]
pub struct CrackProgress {
    pub passwords_tried: u64,
    pub is_cracking: bool,
    pub found: bool,
}

/// Load wordlist from file
pub fn load_wordlist(path: &str) -> Result<Vec<String>> {
    use std::io::{BufRead, BufReader};
    use std::fs::File;

    let file = File::open(path)
        .map_err(|e| anyhow!("Failed to open wordlist: {}", e))?;

    let reader = BufReader::new(file);
    let passwords: Vec<String> = reader.lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    Ok(passwords)
}

/// Generate common password mutations
pub fn generate_mutations(base_password: &str) -> Vec<String> {
    let mut mutations = Vec::new();

    // Original
    mutations.push(base_password.to_string());

    // Capitalize first letter
    if !base_password.is_empty() {
        let mut chars: Vec<char> = base_password.chars().collect();
        chars[0] = chars[0].to_uppercase().next().unwrap_or(chars[0]);
        mutations.push(chars.into_iter().collect());
    }

    // All uppercase
    mutations.push(base_password.to_uppercase());

    // Add common suffixes
    let suffixes = ["1", "123", "!", "1!", "12", "2023", "2024", "2025", "2026"];
    for suffix in &suffixes {
        mutations.push(format!("{}{}", base_password, suffix));
        mutations.push(format!("{}{}", base_password.to_uppercase(), suffix));
    }

    // Leet speak substitutions
    let leet = base_password
        .replace('a', "4")
        .replace('A', "4")
        .replace('e', "3")
        .replace('E', "3")
        .replace('i', "1")
        .replace('I', "1")
        .replace('o', "0")
        .replace('O', "0")
        .replace('s', "$")
        .replace('S', "$");

    if leet != base_password {
        mutations.push(leet);
    }

    mutations
}

/// Common WPA passwords to try first
pub fn get_common_passwords() -> Vec<String> {
    vec![
        // Top common passwords
        "password".to_string(),
        "password1".to_string(),
        "password123".to_string(),
        "12345678".to_string(),
        "123456789".to_string(),
        "1234567890".to_string(),
        "qwertyuiop".to_string(),
        "qwerty123".to_string(),
        "letmein123".to_string(),
        "welcome123".to_string(),
        "admin123".to_string(),
        "changeme".to_string(),
        "default123".to_string(),
        "wireless".to_string(),
        "password!".to_string(),
        // Default router passwords
        "adminadmin".to_string(),
        "administrator".to_string(),
        "netgear1".to_string(),
        "linksys1".to_string(),
        "dlink1234".to_string(),
        "tplink1234".to_string(),
    ]
}

/// Benchmark crack rate on current system
pub fn benchmark_crack_rate(threads: usize, duration_secs: u64) -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    let count = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let test_ssid = "benchmark";
    let test_password = "testpassword12345678";

    let start = Instant::now();

    std::thread::scope(|s| {
        for _ in 0..threads {
            let count = count.clone();
            let running = running.clone();

            s.spawn(move || {
                while running.load(Ordering::Relaxed) {
                    // Calculate PMK (the expensive operation)
                    let _pmk = calculate_pmk(test_password, test_ssid);
                    count.fetch_add(1, Ordering::Relaxed);
                }
            });
        }

        // Let it run for specified duration
        std::thread::sleep(Duration::from_secs(duration_secs));
        running.store(false, Ordering::Relaxed);
    });

    let elapsed = start.elapsed();
    let total = count.load(Ordering::Relaxed);

    total as f64 / elapsed.as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutations() {
        let mutations = generate_mutations("password");

        assert!(mutations.contains(&"password".to_string()));
        assert!(mutations.contains(&"Password".to_string()));
        assert!(mutations.contains(&"PASSWORD".to_string()));
        assert!(mutations.contains(&"password123".to_string()));
    }

    #[test]
    fn test_common_passwords() {
        let passwords = get_common_passwords();
        assert!(!passwords.is_empty());
        assert!(passwords.iter().all(|p| p.len() >= 8));
    }
}
