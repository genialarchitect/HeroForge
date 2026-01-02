//! Artifact extraction from memory dumps
//!
//! Extract credentials, browser data, command history, and other forensic artifacts.

pub mod credentials;
pub mod browser;

pub use credentials::*;
pub use browser::*;

use super::dump_parser::ParsedDump;
use super::types::ProcessInfo;
use anyhow::Result;

/// Extract all artifacts from memory
pub fn extract_all_artifacts(
    dump: &ParsedDump,
    processes: &[ProcessInfo],
) -> Result<ExtractionResult> {
    let mut result = ExtractionResult::default();

    // Extract credentials
    result.credentials = credentials::extract_all_credentials(dump, processes)?;

    // Extract browser data
    result.browser_data = browser::extract_browser_data(dump, processes)?;

    // Extract command history
    result.command_history = extract_command_history(dump, processes)?;

    // Extract clipboard contents
    result.clipboard = extract_clipboard(dump)?;

    // Extract environment variables
    result.environment = extract_environment_vars(dump, processes)?;

    Ok(result)
}

/// Extraction result containing all artifacts
#[derive(Debug, Clone, Default)]
pub struct ExtractionResult {
    /// Extracted credentials
    pub credentials: Vec<CredentialArtifact>,
    /// Browser data
    pub browser_data: Vec<BrowserArtifact>,
    /// Command history
    pub command_history: Vec<CommandHistoryEntry>,
    /// Clipboard contents
    pub clipboard: Vec<ClipboardEntry>,
    /// Environment variables
    pub environment: Vec<EnvironmentVariable>,
}

/// A credential artifact found in memory
#[derive(Debug, Clone)]
pub struct CredentialArtifact {
    /// Source of the credential
    pub source: String,
    /// Credential type
    pub cred_type: String,
    /// Username if available
    pub username: Option<String>,
    /// Domain if available
    pub domain: Option<String>,
    /// The credential value (password, hash, ticket)
    pub value: String,
    /// Is this a hash or plaintext
    pub is_hash: bool,
    /// Process that held this credential
    pub process: Option<String>,
    /// Additional context
    pub context: Option<String>,
}

/// Command history entry
#[derive(Debug, Clone)]
pub struct CommandHistoryEntry {
    /// Shell/application
    pub shell: String,
    /// The command
    pub command: String,
    /// Process ID
    pub pid: Option<u32>,
    /// Offset in dump
    pub offset: u64,
}

/// Clipboard entry
#[derive(Debug, Clone)]
pub struct ClipboardEntry {
    /// Clipboard format
    pub format: String,
    /// Content (text or hex for binary)
    pub content: String,
    /// Size in bytes
    pub size: usize,
}

/// Environment variable
#[derive(Debug, Clone)]
pub struct EnvironmentVariable {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
}

/// Extract command history from shell processes
fn extract_command_history(dump: &ParsedDump, processes: &[ProcessInfo]) -> Result<Vec<CommandHistoryEntry>> {
    let mut history = Vec::new();

    // Find shell processes
    let shell_names = ["cmd.exe", "powershell.exe", "bash", "sh", "zsh"];

    for process in processes {
        let name_lower = process.name.to_lowercase();
        if shell_names.iter().any(|&s| name_lower.contains(s)) {
            // Search for command patterns in process memory
            let commands = extract_shell_commands(dump, process)?;
            history.extend(commands);
        }
    }

    // Also search for PowerShell command history patterns
    let ps_patterns: &[&[u8]] = &[
        b"Invoke-Expression",
        b"IEX(",
        b"DownloadString",
        b"Invoke-WebRequest",
        b"New-Object System.Net.WebClient",
    ];

    for pattern in ps_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(100) {
            if let Some(context) = dump.read_bytes(offset.saturating_sub(32), 256) {
                // Extract the full command
                let start = context.iter().position(|&b| b == b'\n' || b == b'\r')
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let end = context[start..].iter().position(|&b| b == b'\n' || b == b'\r' || b == 0)
                    .unwrap_or(context.len() - start);

                let command = String::from_utf8_lossy(&context[start..start + end]);

                history.push(CommandHistoryEntry {
                    shell: "PowerShell".to_string(),
                    command: command.to_string(),
                    pid: None,
                    offset,
                });
            }
        }
    }

    // Deduplicate
    history.sort_by(|a, b| a.command.cmp(&b.command));
    history.dedup_by(|a, b| a.command == b.command);

    Ok(history)
}

/// Extract commands from a shell process
fn extract_shell_commands(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<CommandHistoryEntry>> {
    let mut commands = Vec::new();

    // For cmd.exe, look for command buffer patterns
    // For PowerShell, look for PSReadLine history
    // For bash/zsh, look for history file patterns

    // Search for common command patterns
    let cmd_patterns: &[&[u8]] = &[
        b"net user",
        b"net localgroup",
        b"whoami",
        b"systeminfo",
        b"ipconfig",
        b"netstat",
        b"tasklist",
        b"reg query",
        b"wmic",
        b"certutil",
    ];

    for pattern in cmd_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(50) {
            if let Some(context) = dump.read_bytes(offset, 128) {
                let end = context.iter().position(|&b| b == 0 || b == b'\n' || b == b'\r')
                    .unwrap_or(128);

                let command = String::from_utf8_lossy(&context[..end]);

                commands.push(CommandHistoryEntry {
                    shell: process.name.clone(),
                    command: command.to_string(),
                    pid: Some(process.pid),
                    offset,
                });
            }
        }
    }

    Ok(commands)
}

/// Extract clipboard contents
fn extract_clipboard(dump: &ParsedDump) -> Result<Vec<ClipboardEntry>> {
    let mut entries = Vec::new();

    // Windows clipboard is managed by win32k.sys
    // The clipboard chain is stored in kernel memory

    // Search for clipboard format markers
    // CF_TEXT, CF_UNICODETEXT, etc.

    // Search for clipboard data patterns
    // This is simplified - real extraction would parse clipboard structures

    // Look for text that might be clipboard content
    let clipboard_markers: &[&[u8]] = &[
        b"CF_TEXT",
        b"CF_UNICODETEXT",
        b"DataObject",
        b"ClipboardData",
    ];

    for marker in clipboard_markers {
        let matches = dump.search_pattern(marker);

        for &offset in matches.iter().take(10) {
            // Note the location but actual content extraction requires more parsing
            entries.push(ClipboardEntry {
                format: String::from_utf8_lossy(*marker).to_string(),
                content: format!("Clipboard data reference at offset {:#x}", offset),
                size: 0,
            });
        }
    }

    Ok(entries)
}

/// Extract environment variables from processes
fn extract_environment_vars(dump: &ParsedDump, processes: &[ProcessInfo]) -> Result<Vec<EnvironmentVariable>> {
    let mut vars = Vec::new();

    // Interesting environment variables
    let interesting_vars = [
        "PATH",
        "USERNAME",
        "USERDOMAIN",
        "COMPUTERNAME",
        "TEMP",
        "TMP",
        "APPDATA",
        "LOCALAPPDATA",
        "USERPROFILE",
        "HOME",
        "SSH_AUTH_SOCK",
        "AWS_ACCESS_KEY",
        "AWS_SECRET",
        "AZURE_",
        "GCP_",
        "API_KEY",
        "TOKEN",
        "PASSWORD",
        "SECRET",
    ];

    for var_name in &interesting_vars {
        let pattern = format!("{}=", var_name);
        let matches = dump.search_pattern(pattern.as_bytes());

        for &offset in matches.iter().take(100) {
            if let Some(data) = dump.read_bytes(offset, 512) {
                // Find the value
                let eq_pos = data.iter().position(|&b| b == b'=').unwrap_or(0);
                let end = data[eq_pos..].iter()
                    .position(|&b| b == 0 || b == b'\n' || b == b'\r')
                    .unwrap_or(data.len() - eq_pos);

                let value = String::from_utf8_lossy(&data[eq_pos + 1..eq_pos + end]);

                // Skip if value looks like garbage
                if value.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    vars.push(EnvironmentVariable {
                        pid: 0, // Would need process context
                        process_name: String::new(),
                        name: var_name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
        }
    }

    // Deduplicate
    vars.sort_by(|a, b| (&a.name, &a.value).cmp(&(&b.name, &b.value)));
    vars.dedup_by(|a, b| a.name == b.name && a.value == b.value);

    Ok(vars)
}

/// Browser artifact
#[derive(Debug, Clone)]
pub struct BrowserArtifact {
    /// Browser name
    pub browser: String,
    /// Artifact type
    pub artifact_type: BrowserArtifactType,
    /// URL if applicable
    pub url: Option<String>,
    /// Title if applicable
    pub title: Option<String>,
    /// Username if applicable
    pub username: Option<String>,
    /// Password if applicable
    pub password: Option<String>,
    /// Additional data
    pub data: Option<String>,
}

/// Type of browser artifact
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserArtifactType {
    History,
    Cookie,
    Credential,
    Download,
    Bookmark,
    Session,
}
