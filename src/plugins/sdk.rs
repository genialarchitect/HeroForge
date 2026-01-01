//! Plugin SDK for development
//!
//! This module provides:
//! - Plugin template generation for different plugin types
//! - Manifest validation with detailed error messages
//! - Development utilities for plugin authors
//! - Project scaffolding with best practices

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use super::manifest::{parse_manifest, parse_manifest_file, validate_manifest};
use super::types::{PluginManifest, PluginType, PluginValidationResult};

/// Plugin SDK for creating custom plugins
pub struct PluginSdk {
    /// Template customization options
    options: SdkOptions,
}

/// SDK configuration options
#[derive(Debug, Clone, Default)]
pub struct SdkOptions {
    /// Author name for generated manifests
    pub author: Option<String>,
    /// Author email for generated manifests
    pub author_email: Option<String>,
    /// Default license for generated plugins
    pub default_license: Option<String>,
    /// Organization name
    pub organization: Option<String>,
}

/// Plugin template configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTemplateConfig {
    /// Plugin ID (must be unique)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Short description
    pub description: String,
    /// Plugin type
    pub plugin_type: PluginType,
    /// Whether to use WASM (true) or native (false) entrypoint
    pub use_wasm: bool,
    /// Programming language for native plugins
    pub language: Option<PluginLanguage>,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Tags for marketplace
    pub tags: Vec<String>,
}

/// Supported plugin languages
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
}

impl std::fmt::Display for PluginLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginLanguage::Rust => write!(f, "rust"),
            PluginLanguage::Python => write!(f, "python"),
            PluginLanguage::JavaScript => write!(f, "javascript"),
            PluginLanguage::TypeScript => write!(f, "typescript"),
            PluginLanguage::Go => write!(f, "go"),
        }
    }
}

/// Generated plugin files
#[derive(Debug, Clone)]
pub struct GeneratedPlugin {
    /// Map of relative file paths to their contents
    pub files: HashMap<String, String>,
    /// Main manifest content
    pub manifest: String,
    /// Instructions for the developer
    pub instructions: String,
}

impl PluginSdk {
    /// Create a new plugin SDK
    pub fn new() -> Self {
        Self {
            options: SdkOptions::default(),
        }
    }

    /// Create SDK with custom options
    pub fn with_options(options: SdkOptions) -> Self {
        Self { options }
    }

    /// Generate plugin boilerplate from a template configuration
    pub fn generate_template(&self, plugin_type: &str) -> Result<String> {
        let pt: PluginType = plugin_type
            .parse()
            .context("Invalid plugin type")?;

        let config = PluginTemplateConfig {
            id: format!("my-{}-plugin", plugin_type),
            name: format!("My {} Plugin", capitalize(plugin_type)),
            description: format!("A custom {} plugin for HeroForge", plugin_type),
            plugin_type: pt,
            use_wasm: true,
            language: Some(PluginLanguage::Rust),
            permissions: default_permissions_for_type(pt),
            tags: default_tags_for_type(pt),
        };

        self.generate_from_config(&config)
    }

    /// Generate plugin from detailed configuration
    pub fn generate_from_config(&self, config: &PluginTemplateConfig) -> Result<String> {
        let generated = self.generate_full_plugin(config)?;
        Ok(generated.manifest)
    }

    /// Generate a complete plugin project
    pub fn generate_full_plugin(&self, config: &PluginTemplateConfig) -> Result<GeneratedPlugin> {
        let mut files = HashMap::new();

        // Generate manifest
        let manifest = self.generate_manifest(config);
        files.insert("plugin.toml".to_string(), manifest.clone());

        // Generate entrypoint based on language/type
        if config.use_wasm {
            let (entrypoint_files, instructions) = match config.language.unwrap_or(PluginLanguage::Rust) {
                PluginLanguage::Rust => self.generate_rust_wasm_plugin(config),
                PluginLanguage::TypeScript => self.generate_ts_wasm_plugin(config),
                _ => self.generate_rust_wasm_plugin(config), // Default to Rust for WASM
            };

            for (path, content) in entrypoint_files {
                files.insert(path, content);
            }

            return Ok(GeneratedPlugin {
                files,
                manifest,
                instructions,
            });
        } else {
            // Native plugin
            let (entrypoint_files, instructions) = match config.language {
                Some(PluginLanguage::Rust) => self.generate_rust_native_plugin(config),
                Some(PluginLanguage::Python) => self.generate_python_plugin(config),
                Some(PluginLanguage::Go) => self.generate_go_plugin(config),
                _ => self.generate_rust_native_plugin(config),
            };

            for (path, content) in entrypoint_files {
                files.insert(path, content);
            }

            return Ok(GeneratedPlugin {
                files,
                manifest,
                instructions,
            });
        }
    }

    /// Generate plugin manifest
    fn generate_manifest(&self, config: &PluginTemplateConfig) -> String {
        let author = self.options.author.as_deref().unwrap_or("Your Name");
        let license = self.options.default_license.as_deref().unwrap_or("MIT");

        let entrypoint = if config.use_wasm {
            "wasm = \"plugin.wasm\""
        } else {
            match config.language {
                Some(PluginLanguage::Rust) => "native = \"libplugin.so\"",
                Some(PluginLanguage::Go) => "native = \"plugin.so\"",
                Some(PluginLanguage::Python) => "native = \"plugin.py\"",
                _ => "native = \"libplugin.so\"",
            }
        };

        let permissions = config
            .permissions
            .iter()
            .map(|p| format!("{} = true", p))
            .collect::<Vec<_>>()
            .join("\n");

        let tags = config
            .tags
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<_>>()
            .join(", ");

        format!(
            r#"# HeroForge Plugin Manifest
# Documentation: https://docs.heroforge.io/plugins

[plugin]
id = "{id}"
name = "{name}"
version = "0.1.0"
type = "{plugin_type}"
author = "{author}"
description = "{description}"
license = "{license}"
min_heroforge_version = "1.0.0"
tags = [{tags}]

[entrypoint]
{entrypoint}

[permissions]
{permissions}

# Optional: Define configuration schema for your plugin
# [config_schema]
# type = "object"
# properties.option1 = {{ type = "string", description = "Example option" }}
"#,
            id = config.id,
            name = config.name,
            plugin_type = config.plugin_type,
            author = author,
            description = config.description,
            license = license,
            tags = tags,
            entrypoint = entrypoint,
            permissions = if permissions.is_empty() {
                "# No special permissions required".to_string()
            } else {
                permissions
            },
        )
    }

    /// Generate Rust WASM plugin template
    fn generate_rust_wasm_plugin(&self, config: &PluginTemplateConfig) -> (HashMap<String, String>, String) {
        let mut files = HashMap::new();

        // Cargo.toml
        let cargo_toml = format!(
            r#"[package]
name = "{id}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
heroforge-plugin-sdk = "0.1"
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
wasm-bindgen = "0.2"

[profile.release]
opt-level = "s"
lto = true
"#,
            id = config.id
        );
        files.insert("Cargo.toml".to_string(), cargo_toml);

        // src/lib.rs
        let lib_rs = match config.plugin_type {
            PluginType::Scanner => generate_scanner_rust_code(&config.id),
            PluginType::Detector => generate_detector_rust_code(&config.id),
            PluginType::Reporter => generate_reporter_rust_code(&config.id),
            PluginType::Integration => generate_integration_rust_code(&config.id),
        };
        files.insert("src/lib.rs".to_string(), lib_rs);

        // README.md
        let readme = format!(
            r#"# {name}

{description}

## Building

```bash
# Install wasm-pack if needed
cargo install wasm-pack

# Build the plugin
wasm-pack build --target web --out-name plugin

# The plugin.wasm file will be in pkg/
cp pkg/plugin_bg.wasm plugin.wasm
```

## Installation

1. Package the plugin: `heroforge plugin package .`
2. Install: `heroforge plugin install ./plugin.zip`
"#,
            name = config.name,
            description = config.description
        );
        files.insert("README.md".to_string(), readme);

        let instructions = format!(
            r#"
Plugin "{}" generated successfully!

Next steps:
1. cd into your plugin directory
2. Edit src/lib.rs to implement your plugin logic
3. Build with: wasm-pack build --target web
4. Package with: heroforge plugin package .
5. Test with: heroforge plugin install ./plugin.zip
"#,
            config.name
        );

        (files, instructions)
    }

    /// Generate TypeScript WASM plugin template
    fn generate_ts_wasm_plugin(&self, config: &PluginTemplateConfig) -> (HashMap<String, String>, String) {
        let mut files = HashMap::new();

        // package.json
        let package_json = format!(
            r#"{{
  "name": "{id}",
  "version": "0.1.0",
  "description": "{description}",
  "main": "dist/plugin.js",
  "scripts": {{
    "build": "asc src/index.ts -o plugin.wasm --optimize",
    "test": "jest"
  }},
  "devDependencies": {{
    "assemblyscript": "^0.27.0",
    "@heroforge/plugin-sdk": "^0.1.0"
  }}
}}
"#,
            id = config.id,
            description = config.description
        );
        files.insert("package.json".to_string(), package_json);

        // src/index.ts
        let index_ts = format!(
            r#"import {{ Plugin, PluginContext, ScanResult }} from "@heroforge/plugin-sdk";

export class {class_name} implements Plugin {{
    name = "{name}";
    version = "0.1.0";

    async initialize(ctx: PluginContext): Promise<void> {{
        console.log("Initializing {name}");
    }}

    async execute(ctx: PluginContext, input: any): Promise<ScanResult> {{
        // Implement your plugin logic here
        return {{
            success: true,
            data: {{}},
        }};
    }}

    async cleanup(): Promise<void> {{
        // Cleanup resources
    }}
}}

export const plugin = new {class_name}();
"#,
            class_name = to_pascal_case(&config.id),
            name = config.name
        );
        files.insert("src/index.ts".to_string(), index_ts);

        let readme = format!(
            r#"# {name}

{description}

## Building

```bash
npm install
npm run build
```

## Installation

```bash
heroforge plugin package .
heroforge plugin install ./plugin.zip
```
"#,
            name = config.name,
            description = config.description
        );
        files.insert("README.md".to_string(), readme);

        let instructions = format!(
            "Plugin \"{}\" generated! Run 'npm install && npm run build' to compile.",
            config.name
        );

        (files, instructions)
    }

    /// Generate Rust native plugin template
    fn generate_rust_native_plugin(&self, config: &PluginTemplateConfig) -> (HashMap<String, String>, String) {
        let mut files = HashMap::new();

        let cargo_toml = format!(
            r#"[package]
name = "{id}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
heroforge-plugin-sdk = "0.1"
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
tokio = {{ version = "1.0", features = ["full"] }}
anyhow = "1.0"
"#,
            id = config.id
        );
        files.insert("Cargo.toml".to_string(), cargo_toml);

        let lib_rs = match config.plugin_type {
            PluginType::Scanner => generate_scanner_rust_code(&config.id),
            PluginType::Detector => generate_detector_rust_code(&config.id),
            PluginType::Reporter => generate_reporter_rust_code(&config.id),
            PluginType::Integration => generate_integration_rust_code(&config.id),
        };
        files.insert("src/lib.rs".to_string(), lib_rs);

        let instructions = format!(
            "Plugin \"{}\" generated! Build with 'cargo build --release'.",
            config.name
        );

        (files, instructions)
    }

    /// Generate Python plugin template
    fn generate_python_plugin(&self, config: &PluginTemplateConfig) -> (HashMap<String, String>, String) {
        let mut files = HashMap::new();

        let plugin_py = format!(
            r#"#!/usr/bin/env python3
\"\"\"
{name} - {description}
\"\"\"

from heroforge_sdk import Plugin, PluginContext, ScanResult

class {class_name}(Plugin):
    \"\"\"HeroForge {plugin_type} plugin.\"\"\"

    name = "{name}"
    version = "0.1.0"

    def initialize(self, ctx: PluginContext) -> None:
        \"\"\"Initialize the plugin.\"\"\"
        self.ctx = ctx
        self.logger = ctx.get_logger()
        self.logger.info(f"Initializing {{self.name}}")

    def execute(self, ctx: PluginContext, input_data: dict) -> ScanResult:
        \"\"\"Execute the plugin logic.\"\"\"
        # Implement your plugin logic here
        return ScanResult(
            success=True,
            data={{}},
        )

    def cleanup(self) -> None:
        \"\"\"Cleanup resources.\"\"\"
        pass

# Export the plugin instance
plugin = {class_name}()
"#,
            name = config.name,
            description = config.description,
            class_name = to_pascal_case(&config.id),
            plugin_type = config.plugin_type
        );
        files.insert("plugin.py".to_string(), plugin_py);

        let requirements = r#"heroforge-sdk>=0.1.0
"#;
        files.insert("requirements.txt".to_string(), requirements.to_string());

        let instructions = format!(
            "Plugin \"{}\" generated! Install deps with 'pip install -r requirements.txt'.",
            config.name
        );

        (files, instructions)
    }

    /// Generate Go plugin template
    fn generate_go_plugin(&self, config: &PluginTemplateConfig) -> (HashMap<String, String>, String) {
        let mut files = HashMap::new();

        let go_mod = format!(
            r#"module {id}

go 1.21

require github.com/heroforge/plugin-sdk v0.1.0
"#,
            id = config.id
        );
        files.insert("go.mod".to_string(), go_mod);

        let main_go = format!(
            r#"package main

import (
    "github.com/heroforge/plugin-sdk/plugin"
)

// {class_name} implements the HeroForge plugin interface
type {class_name} struct {{
    ctx *plugin.Context
}}

// Initialize sets up the plugin
func (p *{class_name}) Initialize(ctx *plugin.Context) error {{
    p.ctx = ctx
    ctx.Logger.Info("Initializing {name}")
    return nil
}}

// Execute runs the plugin logic
func (p *{class_name}) Execute(ctx *plugin.Context, input interface{{}}) (*plugin.Result, error) {{
    // Implement your plugin logic here
    return &plugin.Result{{
        Success: true,
        Data:    map[string]interface{{}}{{}},
    }}, nil
}}

// Cleanup releases resources
func (p *{class_name}) Cleanup() error {{
    return nil
}}

// Export the plugin
var Plugin = &{class_name}{{}}

func main() {{}}
"#,
            class_name = to_pascal_case(&config.id),
            name = config.name
        );
        files.insert("main.go".to_string(), main_go);

        let instructions = format!(
            "Plugin \"{}\" generated! Build with 'go build -buildmode=plugin -o plugin.so'.",
            config.name
        );

        (files, instructions)
    }

    /// Validate plugin manifest from a file path
    pub fn validate_manifest(&self, manifest_path: &str) -> Result<()> {
        let path = Path::new(manifest_path);

        if !path.exists() {
            anyhow::bail!("Manifest file not found: {}", manifest_path);
        }

        let manifest = parse_manifest_file(path)
            .context("Failed to parse manifest")?;

        let validation = validate_manifest(&manifest);

        if !validation.valid {
            let errors = validation.errors.join("\n  - ");
            anyhow::bail!("Manifest validation failed:\n  - {}", errors);
        }

        if !validation.warnings.is_empty() {
            for warning in &validation.warnings {
                log::warn!("Manifest warning: {}", warning);
            }
        }

        log::info!(
            "Manifest valid: {} v{} ({})",
            manifest.plugin.id,
            manifest.plugin.version,
            manifest.plugin.plugin_type
        );

        Ok(())
    }

    /// Validate manifest content directly
    pub fn validate_manifest_content(&self, content: &str) -> Result<PluginValidationResult> {
        let manifest = parse_manifest(content)
            .context("Failed to parse manifest")?;

        Ok(validate_manifest(&manifest))
    }

    /// Write generated plugin to disk
    pub fn write_plugin(&self, config: &PluginTemplateConfig, output_dir: &Path) -> Result<()> {
        let generated = self.generate_full_plugin(config)?;

        // Create output directory
        std::fs::create_dir_all(output_dir)
            .context("Failed to create output directory")?;

        // Write all files
        for (path, content) in &generated.files {
            let file_path = output_dir.join(path);

            // Create parent directories if needed
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(&file_path, content)
                .with_context(|| format!("Failed to write {}", path))?;

            log::info!("Created: {}", path);
        }

        println!("{}", generated.instructions);
        Ok(())
    }
}

impl Default for PluginSdk {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate default permissions for a plugin type
fn default_permissions_for_type(pt: PluginType) -> Vec<String> {
    match pt {
        PluginType::Scanner => vec!["network".to_string(), "scan_results".to_string()],
        PluginType::Detector => vec!["scan_results".to_string(), "vulnerabilities".to_string()],
        PluginType::Reporter => vec!["scan_results".to_string(), "reports".to_string()],
        PluginType::Integration => vec!["network".to_string()],
    }
}

/// Generate default tags for a plugin type
fn default_tags_for_type(pt: PluginType) -> Vec<String> {
    match pt {
        PluginType::Scanner => vec!["scanner".to_string(), "discovery".to_string()],
        PluginType::Detector => vec!["detector".to_string(), "vulnerability".to_string()],
        PluginType::Reporter => vec!["reporter".to_string(), "output".to_string()],
        PluginType::Integration => vec!["integration".to_string(), "external".to_string()],
    }
}

/// Capitalize first letter
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Convert to PascalCase
fn to_pascal_case(s: &str) -> String {
    s.split(|c: char| c == '-' || c == '_')
        .map(capitalize)
        .collect()
}

/// Generate scanner Rust code
fn generate_scanner_rust_code(id: &str) -> String {
    format!(
        r#"//! {} - HeroForge Scanner Plugin

use heroforge_plugin_sdk::{{Plugin, PluginContext, ScanResult, ScanTarget}};
use serde::{{Deserialize, Serialize}};

#[derive(Debug, Default)]
pub struct {class_name} {{
    config: Config,
}}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {{
    pub timeout_ms: u64,
    pub max_depth: u32,
}}

impl Plugin for {class_name} {{
    fn name(&self) -> &str {{
        "{id}"
    }}

    fn version(&self) -> &str {{
        "0.1.0"
    }}

    fn initialize(&mut self, ctx: &PluginContext) -> Result<(), String> {{
        if let Some(config) = ctx.get_config() {{
            self.config = serde_json::from_value(config).map_err(|e| e.to_string())?;
        }}
        Ok(())
    }}

    fn scan(&self, ctx: &PluginContext, target: &ScanTarget) -> Result<ScanResult, String> {{
        // Implement your scanning logic here
        // Example: network discovery, port scanning, etc.

        Ok(ScanResult {{
            success: true,
            findings: vec![],
            metadata: Default::default(),
        }})
    }}

    fn cleanup(&mut self) -> Result<(), String> {{
        Ok(())
    }}
}}

#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {{
    Box::into_raw(Box::new({class_name}::default()))
}}
"#,
        id,
        class_name = to_pascal_case(id),
        id = id
    )
}

/// Generate detector Rust code
fn generate_detector_rust_code(id: &str) -> String {
    format!(
        r#"//! {} - HeroForge Detector Plugin

use heroforge_plugin_sdk::{{Plugin, PluginContext, DetectionResult, Finding}};
use serde::{{Deserialize, Serialize}};

#[derive(Debug, Default)]
pub struct {class_name} {{
    config: Config,
}}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {{
    pub severity_threshold: String,
    pub include_info: bool,
}}

impl Plugin for {class_name} {{
    fn name(&self) -> &str {{
        "{id}"
    }}

    fn version(&self) -> &str {{
        "0.1.0"
    }}

    fn initialize(&mut self, ctx: &PluginContext) -> Result<(), String> {{
        if let Some(config) = ctx.get_config() {{
            self.config = serde_json::from_value(config).map_err(|e| e.to_string())?;
        }}
        Ok(())
    }}

    fn detect(&self, ctx: &PluginContext, scan_data: &[u8]) -> Result<DetectionResult, String> {{
        // Implement your detection logic here
        // Example: vulnerability detection, misconfiguration detection, etc.

        Ok(DetectionResult {{
            findings: vec![],
            summary: "No issues detected".to_string(),
        }})
    }}

    fn cleanup(&mut self) -> Result<(), String> {{
        Ok(())
    }}
}}

#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {{
    Box::into_raw(Box::new({class_name}::default()))
}}
"#,
        id,
        class_name = to_pascal_case(id),
        id = id
    )
}

/// Generate reporter Rust code
fn generate_reporter_rust_code(id: &str) -> String {
    format!(
        r#"//! {} - HeroForge Reporter Plugin

use heroforge_plugin_sdk::{{Plugin, PluginContext, ReportData, ReportOutput}};
use serde::{{Deserialize, Serialize}};

#[derive(Debug, Default)]
pub struct {class_name} {{
    config: Config,
}}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {{
    pub format: String,
    pub include_summary: bool,
}}

impl Plugin for {class_name} {{
    fn name(&self) -> &str {{
        "{id}"
    }}

    fn version(&self) -> &str {{
        "0.1.0"
    }}

    fn initialize(&mut self, ctx: &PluginContext) -> Result<(), String> {{
        if let Some(config) = ctx.get_config() {{
            self.config = serde_json::from_value(config).map_err(|e| e.to_string())?;
        }}
        Ok(())
    }}

    fn generate_report(&self, ctx: &PluginContext, data: &ReportData) -> Result<ReportOutput, String> {{
        // Implement your report generation logic here

        Ok(ReportOutput {{
            format: self.config.format.clone(),
            content: vec![],
            filename: format!("report.{{}}", self.config.format),
        }})
    }}

    fn cleanup(&mut self) -> Result<(), String> {{
        Ok(())
    }}
}}

#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {{
    Box::into_raw(Box::new({class_name}::default()))
}}
"#,
        id,
        class_name = to_pascal_case(id),
        id = id
    )
}

/// Generate integration Rust code
fn generate_integration_rust_code(id: &str) -> String {
    format!(
        r#"//! {} - HeroForge Integration Plugin

use heroforge_plugin_sdk::{{Plugin, PluginContext, IntegrationResult}};
use serde::{{Deserialize, Serialize}};

#[derive(Debug, Default)]
pub struct {class_name} {{
    config: Config,
}}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {{
    pub api_url: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
}}

impl Plugin for {class_name} {{
    fn name(&self) -> &str {{
        "{id}"
    }}

    fn version(&self) -> &str {{
        "0.1.0"
    }}

    fn initialize(&mut self, ctx: &PluginContext) -> Result<(), String> {{
        if let Some(config) = ctx.get_config() {{
            self.config = serde_json::from_value(config).map_err(|e| e.to_string())?;
        }}
        Ok(())
    }}

    fn connect(&self, ctx: &PluginContext) -> Result<(), String> {{
        // Implement connection logic to external service
        Ok(())
    }}

    fn send(&self, ctx: &PluginContext, data: &[u8]) -> Result<IntegrationResult, String> {{
        // Implement data sending logic
        Ok(IntegrationResult {{
            success: true,
            message: "Data sent successfully".to_string(),
            external_id: None,
        }})
    }}

    fn cleanup(&mut self) -> Result<(), String> {{
        Ok(())
    }}
}}

#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {{
    Box::into_raw(Box::new({class_name}::default()))
}}
"#,
        id,
        class_name = to_pascal_case(id),
        id = id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_scanner_template() {
        let sdk = PluginSdk::new();
        let template = sdk.generate_template("scanner").unwrap();

        assert!(template.contains("[plugin]"));
        assert!(template.contains("type = \"scanner\""));
        assert!(template.contains("wasm = \"plugin.wasm\""));
    }

    #[test]
    fn test_generate_full_plugin() {
        let sdk = PluginSdk::new();
        let config = PluginTemplateConfig {
            id: "test-scanner".to_string(),
            name: "Test Scanner".to_string(),
            description: "A test scanner plugin".to_string(),
            plugin_type: PluginType::Scanner,
            use_wasm: true,
            language: Some(PluginLanguage::Rust),
            permissions: vec!["network".to_string()],
            tags: vec!["test".to_string()],
        };

        let generated = sdk.generate_full_plugin(&config).unwrap();

        assert!(generated.files.contains_key("plugin.toml"));
        assert!(generated.files.contains_key("Cargo.toml"));
        assert!(generated.files.contains_key("src/lib.rs"));
        assert!(generated.files.contains_key("README.md"));
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("test-plugin"), "TestPlugin");
        assert_eq!(to_pascal_case("my_scanner"), "MyScanner");
        assert_eq!(to_pascal_case("simple"), "Simple");
    }

    #[test]
    fn test_validate_manifest_content() {
        let sdk = PluginSdk::new();

        let valid_manifest = r#"
[plugin]
id = "test-plugin"
name = "Test Plugin"
version = "1.0.0"
type = "scanner"
author = "Test"
description = "A test plugin"

[entrypoint]
wasm = "plugin.wasm"
"#;

        let result = sdk.validate_manifest_content(valid_manifest).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_validate_invalid_manifest() {
        let sdk = PluginSdk::new();

        let invalid_manifest = r#"
[plugin]
id = ""
name = ""
version = "invalid"
type = "scanner"
author = ""
description = ""

[entrypoint]
wasm = "plugin.wasm"
"#;

        let result = sdk.validate_manifest_content(invalid_manifest).unwrap();
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }
}
