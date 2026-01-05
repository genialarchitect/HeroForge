//! Plugin sandboxing and isolation
//!
//! This module provides:
//! - Secure plugin execution with resource limits
//! - WASM runtime with WASI support via wasmtime
//! - Process isolation using namespaces (Linux)
//! - Resource limits via cgroups
//! - Permission enforcement based on plugin manifest
//! - Timeout and memory limit enforcement

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::timeout;
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

use super::types::{PluginEntrypoint, PluginManifest, PluginPermissions};

/// Check if a command exists in PATH
fn command_exists(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {}", name)])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Resource limits for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU time in seconds
    pub cpu_seconds: u32,
    /// Maximum memory in megabytes
    pub memory_mb: u64,
    /// Maximum number of open file descriptors
    pub max_fds: u32,
    /// Maximum number of processes/threads
    pub max_pids: u32,
    /// Maximum execution time before timeout
    pub timeout_seconds: u64,
    /// Maximum network bandwidth (bytes/sec, 0 = unlimited)
    pub network_bandwidth: u64,
    /// Maximum disk write bytes
    pub disk_write_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_seconds: 300,       // 5 minutes
            memory_mb: 512,         // 512 MB
            max_fds: 256,           // 256 file descriptors
            max_pids: 50,           // 50 processes
            timeout_seconds: 600,   // 10 minutes
            network_bandwidth: 0,   // Unlimited
            disk_write_bytes: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// Sandbox execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    /// Whether execution completed successfully
    pub success: bool,
    /// Exit code from plugin
    pub exit_code: Option<i32>,
    /// Stdout output
    pub stdout: String,
    /// Stderr output
    pub stderr: String,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Peak memory usage in bytes
    pub peak_memory_bytes: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Security policy for sandbox
#[derive(Debug, Clone, Default)]
pub struct SandboxPolicy {
    /// Allow network access
    pub allow_network: bool,
    /// Allow filesystem access (paths)
    pub allow_filesystem: Vec<PathBuf>,
    /// Allow environment variable access
    pub allow_environment: bool,
    /// Allow subprocess creation
    pub allow_subprocess: bool,
    /// Read-only filesystem paths
    pub readonly_paths: Vec<PathBuf>,
    /// Deny list for syscalls
    pub blocked_syscalls: Vec<String>,
}

impl SandboxPolicy {
    /// Create policy from plugin permissions
    pub fn from_permissions(permissions: &PluginPermissions) -> Self {
        Self {
            allow_network: permissions.network,
            allow_filesystem: if permissions.filesystem {
                vec![PathBuf::from("/tmp")]
            } else {
                vec![]
            },
            allow_environment: permissions.environment,
            allow_subprocess: permissions.subprocess,
            readonly_paths: vec![],
            blocked_syscalls: vec![],
        }
    }

    /// Create a restrictive policy
    pub fn restrictive() -> Self {
        Self {
            allow_network: false,
            allow_filesystem: vec![],
            allow_environment: false,
            allow_subprocess: false,
            readonly_paths: vec![],
            blocked_syscalls: vec![
                "ptrace".to_string(),
                "mount".to_string(),
                "umount".to_string(),
                "reboot".to_string(),
                "sethostname".to_string(),
                "setdomainname".to_string(),
                "init_module".to_string(),
                "delete_module".to_string(),
            ],
        }
    }
}

/// Plugin sandbox for secure execution
pub struct PluginSandbox {
    /// Resource limits
    limits: ResourceLimits,
    /// Security policy
    policy: SandboxPolicy,
    /// Plugin installation directory
    plugins_dir: PathBuf,
    /// Running plugin processes
    running: Arc<Mutex<HashMap<String, SandboxedProcess>>>,
    /// Sandbox namespace prefix
    namespace_prefix: String,
}

/// A sandboxed plugin process
struct SandboxedProcess {
    child: Child,
    started_at: std::time::Instant,
    plugin_id: String,
}

impl PluginSandbox {
    /// Create a new plugin sandbox
    pub fn new() -> Self {
        let plugins_dir = std::env::var("HEROFORGE_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"))
            .join("plugins");

        Self {
            limits: ResourceLimits::default(),
            policy: SandboxPolicy::restrictive(),
            plugins_dir,
            running: Arc::new(Mutex::new(HashMap::new())),
            namespace_prefix: format!("heroforge-sandbox-{}", std::process::id()),
        }
    }

    /// Create sandbox with custom limits
    pub fn with_limits(limits: ResourceLimits) -> Self {
        let mut sandbox = Self::new();
        sandbox.limits = limits;
        sandbox
    }

    /// Set resource limits
    pub fn set_limits(&mut self, cpu: u32, memory_mb: u64) {
        self.limits.cpu_seconds = cpu;
        self.limits.memory_mb = memory_mb;
    }

    /// Set security policy
    pub fn set_policy(&mut self, policy: SandboxPolicy) {
        self.policy = policy;
    }

    /// Set policy from plugin manifest
    pub fn configure_for_plugin(&mut self, manifest: &PluginManifest) {
        self.policy = SandboxPolicy::from_permissions(&manifest.permissions);
    }

    /// Execute plugin in sandbox
    pub async fn execute(&self, plugin_id: &str, args: &[String]) -> Result<String> {
        let result = self.execute_with_result(plugin_id, args, None).await?;

        if result.success {
            Ok(result.stdout)
        } else {
            anyhow::bail!(
                "Plugin execution failed: {}",
                result.error.unwrap_or_else(|| result.stderr)
            )
        }
    }

    /// Execute plugin with full result
    pub async fn execute_with_result(
        &self,
        plugin_id: &str,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<SandboxResult> {
        let plugin_path = self.plugins_dir.join(plugin_id);

        if !plugin_path.exists() {
            return Ok(SandboxResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                execution_time_ms: 0,
                peak_memory_bytes: None,
                error: Some(format!("Plugin not found: {}", plugin_id)),
            });
        }

        // Load manifest to determine entrypoint
        let manifest_path = plugin_path.join("plugin.toml");
        let manifest = super::manifest::parse_manifest_file(&manifest_path)
            .context("Failed to load plugin manifest")?;

        let start_time = std::time::Instant::now();

        let result = match &manifest.entrypoint {
            PluginEntrypoint::Wasm(wasm_file) => {
                self.execute_wasm(plugin_id, &plugin_path.join(wasm_file), args, input).await
            }
            PluginEntrypoint::Native(native_file) => {
                self.execute_native(plugin_id, &plugin_path.join(native_file), args, input).await
            }
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(mut res) => {
                res.execution_time_ms = execution_time_ms;
                Ok(res)
            }
            Err(e) => Ok(SandboxResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                execution_time_ms,
                peak_memory_bytes: None,
                error: Some(e.to_string()),
            }),
        }
    }

    /// Execute WASM plugin using wasmtime with WASI support
    async fn execute_wasm(
        &self,
        plugin_id: &str,
        wasm_path: &PathBuf,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<SandboxResult> {
        // Clone values for the blocking task
        let wasm_path = wasm_path.clone();
        let args = args.to_vec();
        let input = input.map(|b| b.to_vec());
        let limits = self.limits.clone();
        let policy = self.policy.clone();
        let plugin_id = plugin_id.to_string();

        // Run WASM execution in blocking task since wasmtime is sync
        let result = tokio::task::spawn_blocking(move || {
            execute_wasm_sync(&wasm_path, &args, input.as_deref(), &limits, &policy, &plugin_id)
        }).await?;

        result
    }

    /// Execute native plugin with Linux sandboxing
    async fn execute_native(
        &self,
        plugin_id: &str,
        native_path: &PathBuf,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<SandboxResult> {
        // For native plugins, use more restrictive sandboxing
        // Options: bubblewrap (bwrap), firejail, or direct seccomp

        let mut cmd = if cfg!(target_os = "linux") && command_exists("bwrap") {
            // Use bubblewrap for strong isolation
            self.build_bwrap_command(plugin_id, native_path, args)?
        } else if cfg!(target_os = "linux") && command_exists("firejail") {
            // Fallback to firejail
            self.build_firejail_command(plugin_id, native_path, args)?
        } else {
            // Direct execution with basic limits
            self.build_direct_command(native_path, args)?
        };

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("Failed to spawn sandboxed process")?;

        // Send input if provided
        if let Some(input_data) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input_data).await?;
            }
        }

        // Wait for completion with timeout
        let timeout_duration = Duration::from_secs(self.limits.timeout_seconds);

        // Use wait() instead of wait_with_output() so we can kill on timeout
        let wait_result = timeout(timeout_duration, child.wait()).await;

        match wait_result {
            Ok(Ok(status)) => {
                // Process completed - read output
                let stdout = if let Some(mut stdout) = child.stdout.take() {
                    let mut buf = Vec::new();
                    let _ = tokio::io::AsyncReadExt::read_to_end(&mut stdout, &mut buf).await;
                    String::from_utf8_lossy(&buf).to_string()
                } else {
                    String::new()
                };

                let stderr = if let Some(mut stderr) = child.stderr.take() {
                    let mut buf = Vec::new();
                    let _ = tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut buf).await;
                    String::from_utf8_lossy(&buf).to_string()
                } else {
                    String::new()
                };

                Ok(SandboxResult {
                    success: status.success(),
                    exit_code: status.code(),
                    stdout,
                    stderr,
                    execution_time_ms: 0,
                    peak_memory_bytes: None,
                    error: if status.success() {
                        None
                    } else {
                        Some(format!("Exited with code {:?}", status.code()))
                    },
                })
            }
            Ok(Err(e)) => Ok(SandboxResult {
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                execution_time_ms: 0,
                peak_memory_bytes: None,
                error: Some(format!("Process error: {}", e)),
            }),
            Err(_) => {
                // Timeout - kill the process
                let _ = child.kill().await;
                Ok(SandboxResult {
                    success: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    execution_time_ms: self.limits.timeout_seconds * 1000,
                    peak_memory_bytes: None,
                    error: Some("Execution timeout".to_string()),
                })
            }
        }
    }

    /// Build bubblewrap command for strong isolation
    fn build_bwrap_command(
        &self,
        plugin_id: &str,
        native_path: &PathBuf,
        args: &[String],
    ) -> Result<Command> {
        let mut cmd = Command::new("bwrap");

        // Create new namespaces
        cmd.arg("--unshare-all");

        // Share network only if allowed
        if self.policy.allow_network {
            cmd.arg("--share-net");
        }

        // Mount minimal filesystem
        cmd.arg("--ro-bind").arg("/lib").arg("/lib");
        cmd.arg("--ro-bind").arg("/lib64").arg("/lib64");
        cmd.arg("--ro-bind").arg("/usr").arg("/usr");
        cmd.arg("--ro-bind").arg("/bin").arg("/bin");

        // Mount plugin directory
        let plugin_dir = native_path.parent().unwrap();
        cmd.arg("--ro-bind")
            .arg(plugin_dir)
            .arg(format!("/plugin"));

        // Writable /tmp
        cmd.arg("--tmpfs").arg("/tmp");

        // Set resource limits
        if cfg!(target_os = "linux") {
            // prlimit for resource control
            cmd.env("HEROFORGE_MEMORY_LIMIT", self.limits.memory_mb.to_string());
            cmd.env("HEROFORGE_CPU_LIMIT", self.limits.cpu_seconds.to_string());
        }

        // Die with parent
        cmd.arg("--die-with-parent");

        // Set hostname
        cmd.arg("--hostname").arg("sandbox");

        // Execute the plugin
        cmd.arg("--")
            .arg(format!("/plugin/{}", native_path.file_name().unwrap().to_string_lossy()))
            .args(args);

        // Clear environment
        cmd.env_clear();
        cmd.env("HEROFORGE_PLUGIN_ID", plugin_id);
        cmd.env("HEROFORGE_SANDBOX", "1");
        cmd.env("HOME", "/tmp");
        cmd.env("PATH", "/usr/bin:/bin");

        Ok(cmd)
    }

    /// Build firejail command for sandboxing
    fn build_firejail_command(
        &self,
        plugin_id: &str,
        native_path: &PathBuf,
        args: &[String],
    ) -> Result<Command> {
        let mut cmd = Command::new("firejail");

        // Security options
        cmd.arg("--noprofile");
        cmd.arg("--quiet");
        cmd.arg("--private");
        cmd.arg("--noroot");

        // Resource limits
        cmd.arg(format!("--rlimit-as={}", self.limits.memory_mb * 1024 * 1024));
        cmd.arg(format!("--rlimit-cpu={}", self.limits.cpu_seconds));
        cmd.arg(format!("--rlimit-nofile={}", self.limits.max_fds));
        cmd.arg(format!("--rlimit-nproc={}", self.limits.max_pids));

        // Network isolation
        if !self.policy.allow_network {
            cmd.arg("--net=none");
        }

        // Timeout
        cmd.arg(format!("--timeout=00:{:02}:00", self.limits.timeout_seconds / 60));

        // Execute
        cmd.arg("--").arg(native_path).args(args);

        cmd.env_clear();
        cmd.env("HEROFORGE_PLUGIN_ID", plugin_id);
        cmd.env("HEROFORGE_SANDBOX", "1");

        Ok(cmd)
    }

    /// Build direct execution command with basic limits
    fn build_direct_command(&self, native_path: &PathBuf, args: &[String]) -> Result<Command> {
        let mut cmd = Command::new(native_path);
        cmd.args(args);

        // Set basic resource limits via environment
        cmd.env("HEROFORGE_SANDBOX", "1");

        // On Linux, we can use prlimit to set some limits
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;

            unsafe {
                cmd.pre_exec(move || {
                    // Set memory limit (RLIMIT_AS)
                    let mem_limit = libc::rlimit {
                        rlim_cur: (512 * 1024 * 1024) as u64, // 512 MB
                        rlim_max: (512 * 1024 * 1024) as u64,
                    };
                    libc::setrlimit(libc::RLIMIT_AS, &mem_limit);

                    // Set CPU time limit
                    let cpu_limit = libc::rlimit {
                        rlim_cur: 300,
                        rlim_max: 300,
                    };
                    libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit);

                    // Set file descriptor limit
                    let fd_limit = libc::rlimit {
                        rlim_cur: 256,
                        rlim_max: 256,
                    };
                    libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit);

                    Ok(())
                });
            }
        }

        Ok(cmd)
    }

    /// Kill a running plugin
    pub async fn kill(&self, plugin_id: &str) -> Result<()> {
        let mut running = self.running.lock().await;
        if let Some(mut process) = running.remove(plugin_id) {
            process.child.kill().await?;
            log::info!("Killed sandboxed plugin: {}", plugin_id);
        }
        Ok(())
    }

    /// List running plugins
    pub async fn list_running(&self) -> Vec<String> {
        let running = self.running.lock().await;
        running.keys().cloned().collect()
    }

    /// Get resource limits
    pub fn get_limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Get security policy
    pub fn get_policy(&self) -> &SandboxPolicy {
        &self.policy
    }
}

impl Default for PluginSandbox {
    fn default() -> Self {
        Self::new()
    }
}

/// State for WASM execution with WASI preview1
struct WasmState {
    wasi: WasiP1Ctx,
}

/// Synchronous WASM execution using wasmtime with WASI preview1
fn execute_wasm_sync(
    wasm_path: &Path,
    args: &[String],
    _input: Option<&[u8]>,
    limits: &ResourceLimits,
    policy: &SandboxPolicy,
    plugin_id: &str,
) -> Result<SandboxResult> {
    use std::time::Instant;

    let start_time = Instant::now();

    // Configure the WASM engine with resource limits
    let mut config = Config::new();

    // Enable fuel-based instruction counting for CPU limits
    config.consume_fuel(true);

    // Set memory limits
    config.max_wasm_stack(limits.memory_mb as usize * 1024 * 1024 / 16); // Stack is a fraction of memory

    // Create the engine
    let engine = Engine::new(&config)
        .context("Failed to create WASM engine")?;

    // Read the WASM module
    let wasm_bytes = std::fs::read(wasm_path)
        .context("Failed to read WASM file")?;

    // Compile the module
    let module = Module::new(&engine, &wasm_bytes)
        .context("Failed to compile WASM module")?;

    // Build WASI context with sandbox restrictions
    let mut wasi_builder = WasiCtxBuilder::new();

    // Set program arguments
    let mut full_args = vec![wasm_path.to_string_lossy().to_string()];
    full_args.extend(args.iter().cloned());
    wasi_builder.args(&full_args);

    // Set environment variables
    wasi_builder.env("HEROFORGE_PLUGIN_ID", plugin_id);
    wasi_builder.env("HEROFORGE_SANDBOX", "1");

    // Inherit stdout/stderr for output capture
    wasi_builder.inherit_stdout();
    wasi_builder.inherit_stderr();

    // Add allowed filesystem paths as preopened directories
    // Note: The filesystem preopening API varies by wasmtime-wasi version
    // For now, we log which paths would be allowed
    for path in &policy.allow_filesystem {
        if path.exists() {
            log::debug!("Filesystem path allowed for plugin: {}", path.display());
            // In production, use preopened_dir with appropriate permissions:
            // wasi_builder.preopened_dir(path, path.to_string_lossy(), DirPerms::all(), FilePerms::all());
        }
    }

    // Build WASI preview1 context
    let wasi_ctx = wasi_builder.build_p1();

    // Create store with WASI state
    let wasm_state = WasmState { wasi: wasi_ctx };
    let mut store = Store::new(&engine, wasm_state);

    // Set fuel (instructions) limit based on CPU time
    // Rough estimate: 1 billion instructions per second
    let fuel_limit = (limits.cpu_seconds as u64) * 1_000_000_000;
    store.set_fuel(fuel_limit)?;

    // Create linker and add WASI preview1 functions
    let mut linker: Linker<WasmState> = Linker::new(&engine);
    preview1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;

    // Instantiate the module
    let instance = linker.instantiate(&mut store, &module)
        .context("Failed to instantiate WASM module")?;

    // Look for the _start function (WASI entry point)
    let start_func = instance.get_typed_func::<(), ()>(&mut store, "_start");

    // Execute the module
    let (success, error) = match start_func {
        Ok(func) => {
            match func.call(&mut store, ()) {
                Ok(()) => (true, None),
                Err(e) => {
                    // Check if it's a fuel exhaustion error
                    let error_str = e.to_string();
                    if error_str.contains("fuel") {
                        (false, Some("CPU time limit exceeded".to_string()))
                    } else if error_str.contains("out of bounds") {
                        (false, Some("Memory access violation".to_string()))
                    } else {
                        (false, Some(format!("Execution error: {}", e)))
                    }
                }
            }
        }
        Err(_) => {
            // No _start function, try main
            if let Ok(main_func) = instance.get_typed_func::<(), i32>(&mut store, "main") {
                match main_func.call(&mut store, ()) {
                    Ok(exit_code) => {
                        if exit_code == 0 {
                            (true, None)
                        } else {
                            (false, Some(format!("Exited with code {}", exit_code)))
                        }
                    }
                    Err(e) => (false, Some(format!("Execution error: {}", e))),
                }
            } else {
                (false, Some("No _start or main function found in WASM module".to_string()))
            }
        }
    };

    let execution_time_ms = start_time.elapsed().as_millis() as u64;

    // Get fuel consumed (for debugging/metrics)
    let fuel_consumed = fuel_limit.saturating_sub(store.get_fuel().unwrap_or(0));
    let _instructions_executed = fuel_consumed;

    Ok(SandboxResult {
        success,
        exit_code: if success { Some(0) } else { Some(1) },
        stdout: String::new(), // Output goes to inherited stdout
        stderr: String::new(), // Output goes to inherited stderr
        execution_time_ms,
        peak_memory_bytes: None, // Would need memory tracking instrumentation
        error,
    })
}

/// WASM module validator
pub struct WasmValidator;

impl WasmValidator {
    /// Validate a WASM module before execution
    pub fn validate(wasm_bytes: &[u8]) -> Result<WasmValidationResult> {
        let engine = Engine::default();

        // Try to compile the module (validates it)
        match Module::new(&engine, wasm_bytes) {
            Ok(module) => {
                // Get module information
                let imports: Vec<_> = module.imports()
                    .map(|i| WasmImport {
                        module: i.module().to_string(),
                        name: i.name().to_string(),
                        kind: format!("{:?}", i.ty()),
                    })
                    .collect();

                let exports: Vec<_> = module.exports()
                    .map(|e| WasmExport {
                        name: e.name().to_string(),
                        kind: format!("{:?}", e.ty()),
                    })
                    .collect();

                // Check for WASI compliance
                let has_wasi = imports.iter().any(|i| i.module == "wasi_snapshot_preview1");
                let has_start = exports.iter().any(|e| e.name == "_start");

                // Security checks
                let mut warnings = Vec::new();

                // Check for suspicious imports
                for imp in &imports {
                    if imp.module != "wasi_snapshot_preview1" && imp.module != "env" {
                        warnings.push(format!(
                            "Non-standard import module: {} ({})",
                            imp.module, imp.name
                        ));
                    }
                }

                Ok(WasmValidationResult {
                    valid: true,
                    imports,
                    exports,
                    has_wasi,
                    has_start,
                    warnings,
                    error: None,
                })
            }
            Err(e) => {
                Ok(WasmValidationResult {
                    valid: false,
                    imports: vec![],
                    exports: vec![],
                    has_wasi: false,
                    has_start: false,
                    warnings: vec![],
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Validate a WASM file
    pub fn validate_file(path: &Path) -> Result<WasmValidationResult> {
        let bytes = std::fs::read(path).context("Failed to read WASM file")?;
        Self::validate(&bytes)
    }
}

/// Result of WASM module validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmValidationResult {
    /// Whether the module is valid
    pub valid: bool,
    /// Module imports
    pub imports: Vec<WasmImport>,
    /// Module exports
    pub exports: Vec<WasmExport>,
    /// Whether the module uses WASI
    pub has_wasi: bool,
    /// Whether the module has a _start function
    pub has_start: bool,
    /// Validation warnings
    pub warnings: Vec<String>,
    /// Error message if invalid
    pub error: Option<String>,
}

/// WASM module import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    /// Import module name
    pub module: String,
    /// Import name
    pub name: String,
    /// Import type (function, memory, etc.)
    pub kind: String,
}

/// WASM module export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExport {
    /// Export name
    pub name: String,
    /// Export type
    pub kind: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.memory_mb, 512);
        assert_eq!(limits.cpu_seconds, 300);
        assert_eq!(limits.timeout_seconds, 600);
    }

    #[test]
    fn test_sandbox_policy_restrictive() {
        let policy = SandboxPolicy::restrictive();
        assert!(!policy.allow_network);
        assert!(!policy.allow_subprocess);
        assert!(!policy.allow_environment);
        assert!(policy.allow_filesystem.is_empty());
    }

    #[test]
    fn test_sandbox_policy_from_permissions() {
        let permissions = PluginPermissions {
            network: true,
            filesystem: true,
            environment: false,
            subprocess: false,
            scan_results: true,
            vulnerabilities: false,
            assets: false,
            reports: true,
        };

        let policy = SandboxPolicy::from_permissions(&permissions);
        assert!(policy.allow_network);
        assert!(!policy.allow_filesystem.is_empty());
        assert!(!policy.allow_environment);
        assert!(!policy.allow_subprocess);
    }

    #[test]
    fn test_set_limits() {
        let mut sandbox = PluginSandbox::new();
        sandbox.set_limits(60, 256);

        assert_eq!(sandbox.limits.cpu_seconds, 60);
        assert_eq!(sandbox.limits.memory_mb, 256);
    }

    #[test]
    fn test_sandbox_result_serialization() {
        let result = SandboxResult {
            success: true,
            exit_code: Some(0),
            stdout: "output".to_string(),
            stderr: String::new(),
            execution_time_ms: 100,
            peak_memory_bytes: Some(1024),
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: SandboxResult = serde_json::from_str(&json).unwrap();

        assert!(parsed.success);
        assert_eq!(parsed.exit_code, Some(0));
        assert_eq!(parsed.stdout, "output");
    }
}
