//! Plugin manifest parsing and validation
//!
//! This module handles parsing plugin.toml manifests and validating their contents.

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::Path;

use super::types::{
    PluginEntrypoint, PluginInfo, PluginManifest, PluginPermissions, PluginType,
    PluginValidationResult,
};

/// TOML structure for parsing the [plugin] section
#[derive(Debug, serde::Deserialize)]
struct TomlPluginSection {
    id: String,
    name: String,
    version: String,
    #[serde(rename = "type")]
    plugin_type: String,
    author: String,
    description: String,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    min_heroforge_version: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// TOML structure for parsing the [permissions] section
#[derive(Debug, Default, serde::Deserialize)]
struct TomlPermissionsSection {
    #[serde(default)]
    network: bool,
    #[serde(default)]
    filesystem: bool,
    #[serde(default)]
    environment: bool,
    #[serde(default)]
    subprocess: bool,
    #[serde(default)]
    scan_results: bool,
    #[serde(default)]
    vulnerabilities: bool,
    #[serde(default)]
    assets: bool,
    #[serde(default)]
    reports: bool,
}

/// TOML structure for parsing the [entrypoint] section
#[derive(Debug, serde::Deserialize)]
struct TomlEntrypointSection {
    #[serde(default)]
    wasm: Option<String>,
    #[serde(default)]
    native: Option<String>,
}

/// TOML structure for parsing the [dependencies] section
#[derive(Debug, Default, serde::Deserialize)]
struct TomlDependenciesSection {
    #[serde(default)]
    plugins: Vec<String>,
}

/// Root TOML structure
#[derive(Debug, serde::Deserialize)]
struct TomlManifest {
    plugin: TomlPluginSection,
    #[serde(default)]
    permissions: TomlPermissionsSection,
    entrypoint: TomlEntrypointSection,
    #[serde(default)]
    dependencies: TomlDependenciesSection,
    #[serde(default)]
    config_schema: Option<toml::Value>,
}

/// Parse a plugin manifest from a TOML string
pub fn parse_manifest(content: &str) -> Result<PluginManifest> {
    let toml_manifest: TomlManifest =
        toml::from_str(content).context("Failed to parse plugin manifest TOML")?;

    // Parse plugin type
    let plugin_type: PluginType = toml_manifest
        .plugin
        .plugin_type
        .parse()
        .context("Invalid plugin type")?;

    // Create plugin info
    let plugin_info = PluginInfo {
        id: toml_manifest.plugin.id,
        name: toml_manifest.plugin.name,
        version: toml_manifest.plugin.version,
        plugin_type,
        author: toml_manifest.plugin.author,
        description: toml_manifest.plugin.description,
        homepage: toml_manifest.plugin.homepage,
        repository: toml_manifest.plugin.repository,
        license: toml_manifest.plugin.license,
        min_heroforge_version: toml_manifest.plugin.min_heroforge_version,
        tags: toml_manifest.plugin.tags,
    };

    // Create permissions
    let permissions = PluginPermissions {
        network: toml_manifest.permissions.network,
        filesystem: toml_manifest.permissions.filesystem,
        environment: toml_manifest.permissions.environment,
        subprocess: toml_manifest.permissions.subprocess,
        scan_results: toml_manifest.permissions.scan_results,
        vulnerabilities: toml_manifest.permissions.vulnerabilities,
        assets: toml_manifest.permissions.assets,
        reports: toml_manifest.permissions.reports,
    };

    // Parse entrypoint
    let entrypoint = if let Some(wasm_path) = toml_manifest.entrypoint.wasm {
        PluginEntrypoint::Wasm(wasm_path)
    } else if let Some(native_path) = toml_manifest.entrypoint.native {
        PluginEntrypoint::Native(native_path)
    } else {
        anyhow::bail!("Plugin manifest must specify either wasm or native entrypoint");
    };

    // Convert config_schema from TOML to JSON if present
    let config_schema = toml_manifest
        .config_schema
        .map(|v| toml_to_json(v))
        .transpose()?;

    Ok(PluginManifest {
        plugin: plugin_info,
        permissions,
        entrypoint,
        dependencies: toml_manifest.dependencies.plugins,
        config_schema,
    })
}

/// Parse a plugin manifest from a file
pub fn parse_manifest_file(path: &Path) -> Result<PluginManifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;
    parse_manifest(&content)
}

/// Convert TOML value to JSON value
fn toml_to_json(value: toml::Value) -> Result<serde_json::Value> {
    match value {
        toml::Value::String(s) => Ok(serde_json::Value::String(s)),
        toml::Value::Integer(i) => Ok(serde_json::Value::Number(i.into())),
        toml::Value::Float(f) => {
            let n = serde_json::Number::from_f64(f)
                .ok_or_else(|| anyhow::anyhow!("Invalid float value"))?;
            Ok(serde_json::Value::Number(n))
        }
        toml::Value::Boolean(b) => Ok(serde_json::Value::Bool(b)),
        toml::Value::Datetime(dt) => Ok(serde_json::Value::String(dt.to_string())),
        toml::Value::Array(arr) => {
            let json_arr: Result<Vec<_>> = arr.into_iter().map(toml_to_json).collect();
            Ok(serde_json::Value::Array(json_arr?))
        }
        toml::Value::Table(table) => {
            let mut map = serde_json::Map::new();
            for (k, v) in table {
                map.insert(k, toml_to_json(v)?);
            }
            Ok(serde_json::Value::Object(map))
        }
    }
}

/// Validate a plugin manifest
pub fn validate_manifest(manifest: &PluginManifest) -> PluginValidationResult {
    let mut result = PluginValidationResult::ok();

    // Validate plugin ID (alphanumeric + hyphens, starts with letter)
    if manifest.plugin.id.is_empty() {
        result.add_error("Plugin ID cannot be empty");
    } else if !manifest.plugin.id.chars().next().unwrap().is_alphabetic() {
        result.add_error("Plugin ID must start with a letter");
    } else if !manifest
        .plugin
        .id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-')
    {
        result.add_error("Plugin ID can only contain alphanumeric characters and hyphens");
    }

    // Validate plugin name
    if manifest.plugin.name.is_empty() {
        result.add_error("Plugin name cannot be empty");
    }

    // Validate version (semver format)
    if !is_valid_semver(&manifest.plugin.version) {
        result.add_error("Plugin version must be valid semver (e.g., 1.0.0)");
    }

    // Validate author
    if manifest.plugin.author.is_empty() {
        result.add_error("Plugin author cannot be empty");
    }

    // Validate description
    if manifest.plugin.description.is_empty() {
        result.add_error("Plugin description cannot be empty");
    }

    // Validate entrypoint filename
    match &manifest.entrypoint {
        PluginEntrypoint::Wasm(path) => {
            if !path.ends_with(".wasm") {
                result.add_error("WASM entrypoint must have .wasm extension");
            }
        }
        PluginEntrypoint::Native(path) => {
            // Native plugins require elevated trust
            result.add_warning("Native plugins require elevated trust and manual review");
            if !(path.ends_with(".so") || path.ends_with(".dll") || path.ends_with(".dylib")) {
                result.add_error("Native entrypoint must have .so, .dll, or .dylib extension");
            }
        }
    }

    // Validate permissions for native plugins
    if manifest.entrypoint.is_native() {
        if manifest.permissions.subprocess {
            result.add_warning("Native plugin requests subprocess permission - security review required");
        }
        if manifest.permissions.filesystem {
            result.add_warning("Native plugin requests filesystem permission - security review required");
        }
    }

    // Validate min_heroforge_version if present
    if let Some(ref min_version) = manifest.plugin.min_heroforge_version {
        if !is_valid_semver(min_version) {
            result.add_error("min_heroforge_version must be valid semver");
        }
    }

    result
}

/// Check if a version string is valid semver (simplified check)
fn is_valid_semver(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return false;
    }

    // Allow optional pre-release/build metadata after the patch version
    let last_part = parts.last().unwrap();
    let patch_part = last_part
        .split(|c| c == '-' || c == '+')
        .next()
        .unwrap_or(last_part);

    // Check that major.minor are numeric
    for (i, part) in parts.iter().enumerate() {
        let check_part = if i == parts.len() - 1 {
            patch_part
        } else {
            part
        };
        if check_part.parse::<u32>().is_err() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_MANIFEST: &str = r#"
[plugin]
id = "example-scanner"
name = "Example Scanner Plugin"
version = "1.0.0"
type = "scanner"
author = "HeroForge"
description = "An example scanner plugin"

[permissions]
network = true
filesystem = false

[entrypoint]
wasm = "plugin.wasm"
"#;

    const NATIVE_MANIFEST: &str = r#"
[plugin]
id = "native-detector"
name = "Native Detector Plugin"
version = "2.1.0"
type = "detector"
author = "Security Team"
description = "A native detector plugin"

[permissions]
network = true
scan_results = true

[entrypoint]
native = "libplugin.so"
"#;

    #[test]
    fn test_parse_wasm_manifest() {
        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        assert_eq!(manifest.plugin.id, "example-scanner");
        assert_eq!(manifest.plugin.name, "Example Scanner Plugin");
        assert_eq!(manifest.plugin.version, "1.0.0");
        assert_eq!(manifest.plugin.plugin_type, PluginType::Scanner);
        assert!(manifest.permissions.network);
        assert!(!manifest.permissions.filesystem);
        assert!(manifest.entrypoint.is_wasm());
        assert_eq!(manifest.entrypoint.path(), "plugin.wasm");
    }

    #[test]
    fn test_parse_native_manifest() {
        let manifest = parse_manifest(NATIVE_MANIFEST).unwrap();
        assert_eq!(manifest.plugin.id, "native-detector");
        assert_eq!(manifest.plugin.plugin_type, PluginType::Detector);
        assert!(manifest.entrypoint.is_native());
        assert_eq!(manifest.entrypoint.path(), "libplugin.so");
    }

    #[test]
    fn test_validate_valid_manifest() {
        let manifest = parse_manifest(VALID_MANIFEST).unwrap();
        let result = validate_manifest(&manifest);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_native_manifest_warnings() {
        let manifest = parse_manifest(NATIVE_MANIFEST).unwrap();
        let result = validate_manifest(&manifest);
        assert!(result.valid);
        // Native plugins should generate warnings
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_is_valid_semver() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("1.0"));
        assert!(is_valid_semver("2.1.3"));
        assert!(is_valid_semver("0.1.0-alpha"));
        assert!(is_valid_semver("1.0.0+build123"));

        assert!(!is_valid_semver("1"));
        assert!(!is_valid_semver("abc"));
        assert!(!is_valid_semver("1.2.3.4"));
    }

    #[test]
    fn test_invalid_manifest_missing_entrypoint() {
        let invalid = r#"
[plugin]
id = "test"
name = "Test"
version = "1.0.0"
type = "scanner"
author = "Test"
description = "Test"

[entrypoint]
"#;
        let result = parse_manifest(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_with_dependencies() {
        let manifest_with_deps = r#"
[plugin]
id = "dependent-plugin"
name = "Dependent Plugin"
version = "1.0.0"
type = "integration"
author = "HeroForge"
description = "A plugin with dependencies"

[entrypoint]
wasm = "plugin.wasm"

[dependencies]
plugins = ["other-plugin", "another-plugin"]
"#;
        let manifest = parse_manifest(manifest_with_deps).unwrap();
        assert_eq!(manifest.dependencies.len(), 2);
        assert!(manifest.dependencies.contains(&"other-plugin".to_string()));
    }
}
