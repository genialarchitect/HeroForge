//! Fuzzing Engine
//!
//! Core fuzzing orchestration engine that manages campaign execution.

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock, Semaphore};
use tokio::time::{Duration, Instant};
use chrono::Utc;

use crate::fuzzing::types::*;
use crate::fuzzing::mutators::Mutator;
use crate::fuzzing::generators::InputGenerator;
use crate::fuzzing::crash_triage::CrashTriager;
use crate::fuzzing::coverage::CoverageTracker;

/// Progress update message
#[derive(Debug, Clone)]
pub struct FuzzProgress {
    pub campaign_id: String,
    pub iterations: u64,
    pub crashes: u32,
    pub unique_crashes: u32,
    pub execs_per_sec: f64,
    pub coverage_percent: f64,
    pub status: CampaignStatus,
}

/// Fuzzing engine
pub struct FuzzingEngine {
    mutator: Arc<Mutator>,
    generator: Arc<InputGenerator>,
    triager: Arc<CrashTriager>,
    coverage: Arc<RwLock<CoverageTracker>>,
    progress_tx: broadcast::Sender<FuzzProgress>,
    cancel_signal: Arc<RwLock<bool>>,
    max_workers: u32,
}

impl FuzzingEngine {
    /// Create a new fuzzing engine
    pub fn new(max_workers: u32) -> Self {
        let (progress_tx, _) = broadcast::channel(100);
        Self {
            mutator: Arc::new(Mutator::new()),
            generator: Arc::new(InputGenerator::new()),
            triager: Arc::new(CrashTriager::new()),
            coverage: Arc::new(RwLock::new(CoverageTracker::new())),
            progress_tx,
            cancel_signal: Arc::new(RwLock::new(false)),
            max_workers,
        }
    }

    /// Subscribe to progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<FuzzProgress> {
        self.progress_tx.subscribe()
    }

    /// Signal to stop fuzzing
    pub async fn stop(&self) {
        let mut cancel = self.cancel_signal.write().await;
        *cancel = true;
    }

    /// Run a fuzzing campaign
    pub async fn run_campaign(
        &self,
        campaign: &FuzzingCampaign,
        input_queue: Vec<Vec<u8>>,
    ) -> Result<CampaignStats, FuzzError> {
        // Reset cancel signal
        {
            let mut cancel = self.cancel_signal.write().await;
            *cancel = false;
        }

        let start_time = Instant::now();
        let max_iterations = campaign.fuzzer_config.max_iterations.unwrap_or(0);
        let max_runtime = campaign.fuzzer_config.max_runtime_secs.unwrap_or(0);
        let workers = campaign.fuzzer_config.workers.unwrap_or(1).min(self.max_workers);

        let stats = Arc::new(RwLock::new(CampaignStats {
            campaign_id: campaign.id.clone(),
            total_execs: 0,
            execs_per_sec: 0.0,
            total_crashes: 0,
            unique_crashes: 0,
            hangs: 0,
            coverage_percent: 0.0,
            new_edges: 0,
            pending_inputs: input_queue.len() as u32,
            stability: 100.0,
            runtime_secs: 0,
            last_crash_at: None,
            last_new_edge_at: None,
        }));

        let crash_hashes = Arc::new(RwLock::new(std::collections::HashSet::<String>::new()));
        let input_corpus = Arc::new(RwLock::new(input_queue));
        let semaphore = Arc::new(Semaphore::new(workers as usize));

        // Main fuzzing loop
        loop {
            // Check cancellation
            if *self.cancel_signal.read().await {
                break;
            }

            // Check max iterations
            let current_stats = stats.read().await;
            if max_iterations > 0 && current_stats.total_execs >= max_iterations {
                break;
            }

            // Check max runtime
            let elapsed = start_time.elapsed().as_secs();
            if max_runtime > 0 && elapsed >= max_runtime {
                break;
            }
            drop(current_stats);

            // Get next input
            let input = {
                let mut corpus = input_corpus.write().await;
                if corpus.is_empty() {
                    // Generate new input using mutation
                    self.generator.generate(&campaign.fuzzer_config)
                } else {
                    let base = corpus.pop().unwrap();
                    // Mutate existing input
                    self.mutator.mutate(&base, &campaign.fuzzer_config)
                }
            };

            // Acquire worker slot
            let _permit = semaphore.acquire().await.unwrap();

            // Execute the input
            let result = self.execute_input(campaign, &input).await;

            // Update stats
            {
                let mut s = stats.write().await;
                s.total_execs += 1;
                s.runtime_secs = start_time.elapsed().as_secs();
                s.execs_per_sec = s.total_execs as f64 / s.runtime_secs.max(1) as f64;

                // Check for crash
                if let Some(crash) = result {
                    s.total_crashes += 1;

                    // Check if unique
                    let mut hashes = crash_hashes.write().await;
                    if hashes.insert(crash.crash_hash.clone()) {
                        s.unique_crashes += 1;
                        s.last_crash_at = Some(Utc::now());
                    }

                    // Add to corpus for crash exploration
                    if crash.crash_type == CrashType::Hang || crash.crash_type == CrashType::Timeout {
                        s.hangs += 1;
                    }
                }

                // Update coverage
                let cov = self.coverage.read().await;
                s.coverage_percent = cov.get_coverage_percent();
                s.new_edges = cov.get_new_edges();
                s.pending_inputs = input_corpus.read().await.len() as u32;
            }

            // Send progress update periodically
            if stats.read().await.total_execs % 100 == 0 {
                let s = stats.read().await;
                let _ = self.progress_tx.send(FuzzProgress {
                    campaign_id: campaign.id.clone(),
                    iterations: s.total_execs,
                    crashes: s.total_crashes,
                    unique_crashes: s.unique_crashes,
                    execs_per_sec: s.execs_per_sec,
                    coverage_percent: s.coverage_percent,
                    status: CampaignStatus::Running,
                });
            }
        }

        // Return final stats
        let final_stats = stats.read().await.clone();

        // Send final progress
        let _ = self.progress_tx.send(FuzzProgress {
            campaign_id: campaign.id.clone(),
            iterations: final_stats.total_execs,
            crashes: final_stats.total_crashes,
            unique_crashes: final_stats.unique_crashes,
            execs_per_sec: final_stats.execs_per_sec,
            coverage_percent: final_stats.coverage_percent,
            status: CampaignStatus::Completed,
        });

        Ok(final_stats)
    }

    /// Execute a single input and check for crashes
    async fn execute_input(
        &self,
        campaign: &FuzzingCampaign,
        input: &[u8],
    ) -> Option<FuzzingCrash> {
        let timeout = Duration::from_millis(
            campaign.target_config.timeout_ms.unwrap_or(5000)
        );

        match &campaign.target_type {
            FuzzTargetType::Protocol => {
                self.execute_protocol(campaign, input, timeout).await
            }
            FuzzTargetType::Http => {
                self.execute_http(campaign, input, timeout).await
            }
            FuzzTargetType::File => {
                self.execute_file(campaign, input, timeout).await
            }
            FuzzTargetType::Api => {
                self.execute_api(campaign, input, timeout).await
            }
            FuzzTargetType::Custom => {
                self.execute_custom(campaign, input, timeout).await
            }
        }
    }

    /// Execute protocol fuzzing
    async fn execute_protocol(
        &self,
        campaign: &FuzzingCampaign,
        input: &[u8],
        timeout: Duration,
    ) -> Option<FuzzingCrash> {
        let target = &campaign.target_config.target;
        let port = campaign.target_config.port.unwrap_or(80);
        let protocol = campaign.target_config.protocol.as_deref().unwrap_or("tcp");

        let addr = format!("{}:{}", target, port);

        let result = tokio::time::timeout(timeout, async {
            match protocol {
                "tcp" => {
                    match tokio::net::TcpStream::connect(&addr).await {
                        Ok(mut stream) => {
                            use tokio::io::AsyncWriteExt;
                            if let Err(e) = stream.write_all(input).await {
                                // Connection error might indicate crash
                                return Some(self.analyze_error(&e.to_string(), input));
                            }
                            None
                        }
                        Err(e) => {
                            Some(self.analyze_error(&e.to_string(), input))
                        }
                    }
                }
                "udp" => {
                    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        Ok(socket) => {
                            if let Err(e) = socket.send_to(input, &addr).await {
                                return Some(self.analyze_error(&e.to_string(), input));
                            }
                            None
                        }
                        Err(e) => {
                            Some(self.analyze_error(&e.to_string(), input))
                        }
                    }
                }
                _ => None,
            }
        }).await;

        match result {
            Ok(crash) => crash,
            Err(_) => {
                // Timeout
                Some(FuzzingCrash {
                    id: uuid::Uuid::new_v4().to_string(),
                    campaign_id: campaign.id.clone(),
                    crash_type: CrashType::Timeout,
                    crash_hash: self.hash_input(input),
                    exploitability: Exploitability::Unknown,
                    input_data: input.to_vec(),
                    input_size: input.len(),
                    stack_trace: None,
                    registers: None,
                    signal: None,
                    exit_code: None,
                    stderr_output: Some("Timeout".to_string()),
                    reproduced: false,
                    reproduction_count: 1,
                    minimized_input: None,
                    notes: None,
                    created_at: Utc::now(),
                })
            }
        }
    }

    /// Execute HTTP fuzzing
    async fn execute_http(
        &self,
        campaign: &FuzzingCampaign,
        input: &[u8],
        timeout: Duration,
    ) -> Option<FuzzingCrash> {
        let target = &campaign.target_config.target;
        let method = campaign.target_config.method.as_deref().unwrap_or("GET");
        let headers = campaign.target_config.headers.clone().unwrap_or_default();

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .ok()?;

        let mut request = match method.to_uppercase().as_str() {
            "GET" => client.get(target),
            "POST" => client.post(target).body(input.to_vec()),
            "PUT" => client.put(target).body(input.to_vec()),
            "DELETE" => client.delete(target),
            "PATCH" => client.patch(target).body(input.to_vec()),
            _ => client.get(target),
        };

        for (key, value) in headers {
            request = request.header(&key, &value);
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                // Check for server errors that might indicate crashes
                if status >= 500 {
                    return Some(FuzzingCrash {
                        id: uuid::Uuid::new_v4().to_string(),
                        campaign_id: campaign.id.clone(),
                        crash_type: CrashType::Unknown,
                        crash_hash: self.hash_input(input),
                        exploitability: Exploitability::Unknown,
                        input_data: input.to_vec(),
                        input_size: input.len(),
                        stack_trace: None,
                        registers: None,
                        signal: None,
                        exit_code: Some(status as i32),
                        stderr_output: Some(format!("HTTP {} error", status)),
                        reproduced: false,
                        reproduction_count: 1,
                        minimized_input: None,
                        notes: None,
                        created_at: Utc::now(),
                    });
                }
                None
            }
            Err(e) => {
                if e.is_timeout() {
                    return Some(FuzzingCrash {
                        id: uuid::Uuid::new_v4().to_string(),
                        campaign_id: campaign.id.clone(),
                        crash_type: CrashType::Timeout,
                        crash_hash: self.hash_input(input),
                        exploitability: Exploitability::Unknown,
                        input_data: input.to_vec(),
                        input_size: input.len(),
                        stack_trace: None,
                        registers: None,
                        signal: None,
                        exit_code: None,
                        stderr_output: Some("HTTP timeout".to_string()),
                        reproduced: false,
                        reproduction_count: 1,
                        minimized_input: None,
                        notes: None,
                        created_at: Utc::now(),
                    });
                }
                None
            }
        }
    }

    /// Execute file format fuzzing
    async fn execute_file(
        &self,
        campaign: &FuzzingCampaign,
        input: &[u8],
        timeout: Duration,
    ) -> Option<FuzzingCrash> {
        let command = campaign.target_config.command.as_ref()?;
        let arguments = campaign.target_config.arguments.clone().unwrap_or_default();

        // Write input to temp file
        let temp_path = format!("/tmp/fuzz_input_{}", uuid::Uuid::new_v4());
        if let Err(_) = tokio::fs::write(&temp_path, input).await {
            return None;
        }

        // Replace @@ with temp file path in arguments
        let args: Vec<String> = arguments.iter()
            .map(|arg| arg.replace("@@", &temp_path))
            .collect();

        // Execute command
        let result = tokio::time::timeout(timeout, async {
            let output = tokio::process::Command::new(command)
                .args(&args)
                .output()
                .await;

            output
        }).await;

        // Cleanup temp file
        let _ = tokio::fs::remove_file(&temp_path).await;

        match result {
            Ok(Ok(output)) => {
                // Check for crash signals
                let crash = self.triager.analyze_output(&output, input);
                if let Some(mut c) = crash {
                    c.campaign_id = campaign.id.clone();
                    return Some(c);
                }
                None
            }
            Ok(Err(e)) => {
                Some(self.analyze_error(&e.to_string(), input))
            }
            Err(_) => {
                // Timeout/hang
                Some(FuzzingCrash {
                    id: uuid::Uuid::new_v4().to_string(),
                    campaign_id: campaign.id.clone(),
                    crash_type: CrashType::Hang,
                    crash_hash: self.hash_input(input),
                    exploitability: Exploitability::Unknown,
                    input_data: input.to_vec(),
                    input_size: input.len(),
                    stack_trace: None,
                    registers: None,
                    signal: None,
                    exit_code: None,
                    stderr_output: Some("Process hang/timeout".to_string()),
                    reproduced: false,
                    reproduction_count: 1,
                    minimized_input: None,
                    notes: None,
                    created_at: Utc::now(),
                })
            }
        }
    }

    /// Execute API fuzzing (similar to HTTP but with structured payloads)
    async fn execute_api(
        &self,
        campaign: &FuzzingCampaign,
        input: &[u8],
        timeout: Duration,
    ) -> Option<FuzzingCrash> {
        // API fuzzing is similar to HTTP but with JSON payloads
        self.execute_http(campaign, input, timeout).await
    }

    /// Execute custom fuzzing
    async fn execute_custom(
        &self,
        _campaign: &FuzzingCampaign,
        _input: &[u8],
        _timeout: Duration,
    ) -> Option<FuzzingCrash> {
        // Custom fuzzing would be implemented by user scripts
        None
    }

    /// Analyze an error string for crash information
    fn analyze_error(&self, error: &str, input: &[u8]) -> FuzzingCrash {
        let crash_type = if error.contains("connection refused") {
            CrashType::Unknown
        } else if error.contains("broken pipe") {
            CrashType::Segfault
        } else if error.contains("reset by peer") {
            CrashType::Segfault
        } else {
            CrashType::Unknown
        };

        FuzzingCrash {
            id: uuid::Uuid::new_v4().to_string(),
            campaign_id: String::new(),
            crash_type,
            crash_hash: self.hash_input(input),
            exploitability: Exploitability::Unknown,
            input_data: input.to_vec(),
            input_size: input.len(),
            stack_trace: None,
            registers: None,
            signal: None,
            exit_code: None,
            stderr_output: Some(error.to_string()),
            reproduced: false,
            reproduction_count: 1,
            minimized_input: None,
            notes: None,
            created_at: Utc::now(),
        }
    }

    /// Hash input for deduplication
    fn hash_input(&self, input: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
}

/// Fuzzing error type
#[derive(Debug)]
pub struct FuzzError {
    pub message: String,
}

impl std::fmt::Display for FuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for FuzzError {}

impl From<String> for FuzzError {
    fn from(s: String) -> Self {
        Self { message: s }
    }
}

impl From<&str> for FuzzError {
    fn from(s: &str) -> Self {
        Self { message: s.to_string() }
    }
}
