//! Screenshot capture module using Playwright
//!
//! This module provides screenshot capture functionality for web pages,
//! useful for security assessment reports and evidence collection.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// Screenshot capture options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotOptions {
    /// Target URL to capture
    pub url: String,
    /// Output file path
    pub output_path: PathBuf,
    /// Capture full scrollable page
    #[serde(default)]
    pub full_page: bool,
    /// Viewport width (default: 1920)
    #[serde(default = "default_width")]
    pub width: u32,
    /// Viewport height (default: 1080)
    #[serde(default = "default_height")]
    pub height: u32,
    /// Navigation timeout in ms (default: 30000)
    #[serde(default = "default_timeout")]
    pub timeout: u32,
    /// Wait time after load in ms (default: 1000)
    #[serde(default = "default_wait")]
    pub wait: u32,
    /// CSS selector to screenshot specific element
    #[serde(default)]
    pub selector: Option<String>,
    /// Output format: png or jpeg (default: png)
    #[serde(default = "default_format")]
    pub format: String,
    /// JPEG quality 0-100 (default: 80)
    #[serde(default = "default_quality")]
    pub quality: u32,
    /// Enable dark color scheme
    #[serde(default)]
    pub dark_mode: bool,
    /// Use mobile viewport
    #[serde(default)]
    pub mobile: bool,
    /// Bearer token for authorization
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Cookies to set (as JSON)
    #[serde(default)]
    pub cookies: Option<String>,
    /// Custom user agent
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Ignore SSL certificate errors
    #[serde(default)]
    pub ignore_ssl: bool,
}

fn default_width() -> u32 {
    1920
}
fn default_height() -> u32 {
    1080
}
fn default_timeout() -> u32 {
    30000
}
fn default_wait() -> u32 {
    1000
}
fn default_format() -> String {
    "png".to_string()
}
fn default_quality() -> u32 {
    80
}

impl Default for ScreenshotOptions {
    fn default() -> Self {
        Self {
            url: String::new(),
            output_path: PathBuf::new(),
            full_page: false,
            width: default_width(),
            height: default_height(),
            timeout: default_timeout(),
            wait: default_wait(),
            selector: None,
            format: default_format(),
            quality: default_quality(),
            dark_mode: false,
            mobile: false,
            auth_token: None,
            cookies: None,
            user_agent: None,
            ignore_ssl: false,
        }
    }
}

/// Screenshot capture result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotResult {
    pub success: bool,
    pub path: Option<String>,
    pub url: String,
    pub title: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub file_size: Option<u64>,
    pub format: Option<String>,
    pub duration: Option<u64>,
    pub error: Option<String>,
    pub timestamp: String,
}

/// Screenshot service for capturing web page screenshots
pub struct ScreenshotService {
    script_path: PathBuf,
}

impl ScreenshotService {
    /// Create a new screenshot service
    pub fn new() -> Result<Self> {
        // Look for the screenshot service script in multiple locations
        let possible_paths = vec![
            PathBuf::from("./scripts/screenshot-service.js"),
            PathBuf::from("/root/Development/HeroForge/scripts/screenshot-service.js"),
            PathBuf::from("../scripts/screenshot-service.js"),
        ];

        for path in possible_paths {
            if path.exists() {
                return Ok(Self { script_path: path });
            }
        }

        Err(anyhow!(
            "Screenshot service script not found. Please ensure scripts/screenshot-service.js exists."
        ))
    }

    /// Create with explicit script path
    pub fn with_script_path(script_path: PathBuf) -> Result<Self> {
        if !script_path.exists() {
            return Err(anyhow!(
                "Screenshot service script not found at: {:?}",
                script_path
            ));
        }
        Ok(Self { script_path })
    }

    /// Capture a screenshot of a URL
    pub async fn capture(&self, options: &ScreenshotOptions) -> Result<ScreenshotResult> {
        // Build command arguments
        let mut args = vec![
            self.script_path.to_string_lossy().to_string(),
            options.url.clone(),
            options.output_path.to_string_lossy().to_string(),
            "--json".to_string(),
        ];

        if options.full_page {
            args.push("--full-page".to_string());
        }

        args.push(format!("--width={}", options.width));
        args.push(format!("--height={}", options.height));
        args.push(format!("--timeout={}", options.timeout));
        args.push(format!("--wait={}", options.wait));
        args.push(format!("--format={}", options.format));
        args.push(format!("--quality={}", options.quality));

        if let Some(selector) = &options.selector {
            args.push(format!("--selector={}", selector));
        }

        if options.dark_mode {
            args.push("--dark-mode".to_string());
        }

        if options.mobile {
            args.push("--mobile".to_string());
        }

        if let Some(token) = &options.auth_token {
            args.push(format!("--auth={}", token));
        }

        if let Some(cookies) = &options.cookies {
            args.push(format!("--cookie={}", cookies));
        }

        if let Some(ua) = &options.user_agent {
            args.push(format!("--user-agent={}", ua));
        }

        if options.ignore_ssl {
            args.push("--ignore-ssl".to_string());
        }

        // Execute the screenshot service
        let output = Command::new("node")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            // Try to parse error from JSON output
            if let Ok(result) = serde_json::from_str::<ScreenshotResult>(&stdout) {
                return Ok(result);
            }
            return Err(anyhow!(
                "Screenshot capture failed: {}",
                if stderr.is_empty() {
                    stdout.to_string()
                } else {
                    stderr.to_string()
                }
            ));
        }

        // Parse JSON result
        let result: ScreenshotResult = serde_json::from_str(&stdout).map_err(|e| {
            anyhow!(
                "Failed to parse screenshot result: {}. Output: {}",
                e,
                stdout
            )
        })?;

        Ok(result)
    }

    /// Capture multiple screenshots in batch
    pub async fn capture_batch(
        &self,
        jobs: Vec<ScreenshotOptions>,
    ) -> Result<Vec<ScreenshotResult>> {
        let mut results = Vec::new();

        for options in jobs {
            let result = self.capture(&options).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Capture screenshot with automatic filename generation
    pub async fn capture_auto(
        &self,
        url: &str,
        output_dir: &PathBuf,
        prefix: &str,
    ) -> Result<ScreenshotResult> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("{}_{}.png", prefix, timestamp);
        let output_path = output_dir.join(filename);

        let options = ScreenshotOptions {
            url: url.to_string(),
            output_path,
            ..Default::default()
        };

        self.capture(&options).await
    }
}

impl Default for ScreenshotService {
    fn default() -> Self {
        Self::new().expect("Failed to initialize screenshot service")
    }
}

/// Convenience function to capture a single screenshot
pub async fn capture_screenshot(url: &str, output_path: &str) -> Result<ScreenshotResult> {
    let service = ScreenshotService::new()?;
    let options = ScreenshotOptions {
        url: url.to_string(),
        output_path: PathBuf::from(output_path),
        ..Default::default()
    };
    service.capture(&options).await
}

/// Convenience function to capture full page screenshot
pub async fn capture_full_page(url: &str, output_path: &str) -> Result<ScreenshotResult> {
    let service = ScreenshotService::new()?;
    let options = ScreenshotOptions {
        url: url.to_string(),
        output_path: PathBuf::from(output_path),
        full_page: true,
        ..Default::default()
    };
    service.capture(&options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_screenshot_options_default() {
        let options = ScreenshotOptions::default();
        assert_eq!(options.width, 1920);
        assert_eq!(options.height, 1080);
        assert_eq!(options.format, "png");
        assert!(!options.full_page);
    }

    #[test]
    fn test_screenshot_options_serialization() {
        let options = ScreenshotOptions {
            url: "https://example.com".to_string(),
            output_path: PathBuf::from("/tmp/test.png"),
            full_page: true,
            ..Default::default()
        };

        let json = serde_json::to_string(&options).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("full_page"));
    }
}
