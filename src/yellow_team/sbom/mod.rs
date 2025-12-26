//! Software Bill of Materials (SBOM) Generation
//!
//! Generates SBOMs in CycloneDX and SPDX formats by parsing
//! dependency manifests from various package managers.

pub mod cyclonedx;
pub mod spdx;
pub mod dependency_graph;
pub mod license_checker;

use crate::yellow_team::types::*;
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// SBOM Generator for multiple package ecosystems
pub struct SbomGenerator {
    /// Project being analyzed
    pub project: SbomProject,
    /// Discovered components
    pub components: Vec<SbomComponent>,
    /// Dependency relationships
    pub dependencies: HashMap<String, Vec<String>>,
}

impl SbomGenerator {
    /// Create a new SBOM generator
    pub fn new(name: &str, version: Option<&str>, source_path: &str) -> Self {
        Self {
            project: SbomProject {
                id: Uuid::new_v4().to_string(),
                user_id: String::new(),
                name: name.to_string(),
                version: version.map(|s| s.to_string()),
                source_type: SastSourceType::Directory,
                source_path: source_path.to_string(),
                last_scan_at: None,
                component_count: 0,
                vulnerability_count: 0,
                license_risk: LicenseRisk::Unknown,
                created_at: Utc::now(),
            },
            components: Vec::new(),
            dependencies: HashMap::new(),
        }
    }

    /// Parse Cargo.toml content (string) for Rust dependencies
    pub fn parse_cargo_toml(&mut self, content: &str) -> Result<(), String> {
        let parsed: toml::Value = toml::from_str(content).map_err(|e| e.to_string())?;

        if let Some(package) = parsed.get("package") {
            if let Some(name) = package.get("name").and_then(|v| v.as_str()) {
                self.project.name = name.to_string();
            }
            if let Some(version) = package.get("version").and_then(|v| v.as_str()) {
                self.project.version = Some(version.to_string());
            }
        }

        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_table()) {
            for (name, version_info) in deps {
                let version = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => t.get("version")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| "*".to_string()),
                    _ => "*".to_string(),
                };
                self.add_component(name, &version, "cargo", true, None);
            }
        }

        if let Some(dev_deps) = parsed.get("dev-dependencies").and_then(|v| v.as_table()) {
            for (name, version_info) in dev_deps {
                let version = match version_info {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => t.get("version")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| "*".to_string()),
                    _ => "*".to_string(),
                };
                self.add_component(name, &version, "cargo", false, None);
            }
        }

        self.project.component_count = self.components.len() as i32;
        Ok(())
    }

    /// Parse package.json content (string) for Node.js dependencies
    pub fn parse_package_json(&mut self, content: &str) -> Result<(), String> {
        let parsed: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;

        if let Some(name) = parsed.get("name").and_then(|v| v.as_str()) {
            self.project.name = name.to_string();
        }
        if let Some(version) = parsed.get("version").and_then(|v| v.as_str()) {
            self.project.version = Some(version.to_string());
        }

        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                if let Some(ver) = version.as_str() {
                    self.add_component(name, ver, "npm", true, None);
                }
            }
        }

        if let Some(dev_deps) = parsed.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, version) in dev_deps {
                if let Some(ver) = version.as_str() {
                    self.add_component(name, ver, "npm", false, None);
                }
            }
        }

        self.project.component_count = self.components.len() as i32;
        Ok(())
    }

    /// Parse requirements.txt content (string) for Python dependencies
    pub fn parse_requirements_txt(&mut self, content: &str) -> Result<(), String> {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }

            let (name, version) = if let Some(pos) = line.find("==") {
                (&line[..pos], &line[pos+2..])
            } else if let Some(pos) = line.find(">=") {
                (&line[..pos], &line[pos+2..])
            } else if let Some(pos) = line.find("<=") {
                (&line[..pos], &line[pos+2..])
            } else if let Some(pos) = line.find("~=") {
                (&line[..pos], &line[pos+2..])
            } else {
                (line, "*")
            };

            self.add_component(name.trim(), version.trim(), "pypi", true, None);
        }

        self.project.component_count = self.components.len() as i32;
        Ok(())
    }

    /// Parse go.mod content (string) for Go dependencies
    pub fn parse_go_mod(&mut self, content: &str) -> Result<(), String> {
        let mut in_require = false;

        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("module ") {
                self.project.name = line[7..].trim().to_string();
            } else if line.starts_with("go ") {
                continue;
            } else if line == "require (" {
                in_require = true;
            } else if line == ")" {
                in_require = false;
            } else if line.starts_with("require ") && !line.contains("(") {
                let parts: Vec<&str> = line[8..].split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    let version = parts[1].trim_start_matches('v');
                    self.add_component(name, version, "go", true, None);
                }
            } else if in_require && !line.is_empty() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    let version = parts[1].trim_start_matches('v');
                    let is_indirect = line.contains("// indirect");
                    self.add_component(name, version, "go", !is_indirect, None);
                }
            }
        }

        self.project.component_count = self.components.len() as i32;
        Ok(())
    }

    /// Generate SBOM from a directory
    pub async fn generate_from_directory(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check for various manifest files
        let cargo_toml = path.join("Cargo.toml");
        let package_json = path.join("package.json");
        let requirements_txt = path.join("requirements.txt");
        let go_mod = path.join("go.mod");
        let pom_xml = path.join("pom.xml");
        let gemfile = path.join("Gemfile");
        let composer_json = path.join("composer.json");

        if cargo_toml.exists() {
            self.parse_cargo_toml_file(&cargo_toml).await?;
        }
        if package_json.exists() {
            self.parse_package_json_file(&package_json).await?;
        }
        if requirements_txt.exists() {
            self.parse_requirements_txt_file(&requirements_txt).await?;
        }
        if go_mod.exists() {
            self.parse_go_mod_file(&go_mod).await?;
        }
        if pom_xml.exists() {
            self.parse_pom_xml(&pom_xml).await?;
        }
        if gemfile.exists() {
            self.parse_gemfile(&gemfile).await?;
        }
        if composer_json.exists() {
            self.parse_composer_json(&composer_json).await?;
        }

        // Also check for lock files for more accurate versions
        let cargo_lock = path.join("Cargo.lock");
        let package_lock = path.join("package-lock.json");
        let yarn_lock = path.join("yarn.lock");
        let go_sum = path.join("go.sum");

        if cargo_lock.exists() {
            self.parse_cargo_lock(&cargo_lock).await?;
        }
        if package_lock.exists() {
            self.parse_package_lock(&package_lock).await?;
        }
        if yarn_lock.exists() {
            self.parse_yarn_lock(&yarn_lock).await?;
        }
        if go_sum.exists() {
            self.parse_go_sum(&go_sum).await?;
        }

        // Update project stats
        self.project.component_count = self.components.len() as i32;
        self.project.last_scan_at = Some(Utc::now());
        self.project.license_risk = self.calculate_overall_license_risk();

        Ok(())
    }

    /// Parse Cargo.toml file for Rust dependencies (async)
    async fn parse_cargo_toml_file(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        // Parse as TOML
        let parsed: toml::Value = toml::from_str(&content)?;
        
        // Get package info
        if let Some(package) = parsed.get("package") {
            if let Some(name) = package.get("name").and_then(|v| v.as_str()) {
                self.project.name = name.to_string();
            }
            if let Some(version) = package.get("version").and_then(|v| v.as_str()) {
                self.project.version = Some(version.to_string());
            }
        }

        // Parse dependencies
        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_table()) {
            for (name, value) in deps {
                let version = extract_version_from_toml(value);
                self.add_component(name, &version, "cargo", true, None);
            }
        }

        // Parse dev-dependencies
        if let Some(deps) = parsed.get("dev-dependencies").and_then(|v| v.as_table()) {
            for (name, value) in deps {
                let version = extract_version_from_toml(value);
                self.add_component(name, &version, "cargo", true, None);
            }
        }

        // Parse build-dependencies
        if let Some(deps) = parsed.get("build-dependencies").and_then(|v| v.as_table()) {
            for (name, value) in deps {
                let version = extract_version_from_toml(value);
                self.add_component(name, &version, "cargo", true, None);
            }
        }

        Ok(())
    }

    /// Parse Cargo.lock for exact versions
    async fn parse_cargo_lock(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        let parsed: toml::Value = toml::from_str(&content)?;

        if let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) {
            for pkg in packages {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|v| v.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    // Update existing component or add new one
                    if let Some(comp) = self.components.iter_mut().find(|c| &c.name == name) {
                        comp.version = version.to_string();
                    } else {
                        self.add_component(name, version, "cargo", false, None);
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse package.json file for Node.js dependencies (async)
    async fn parse_package_json_file(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        let parsed: serde_json::Value = serde_json::from_str(&content)?;

        // Get package info
        if let Some(name) = parsed.get("name").and_then(|v| v.as_str()) {
            self.project.name = name.to_string();
        }
        if let Some(version) = parsed.get("version").and_then(|v| v.as_str()) {
            self.project.version = Some(version.to_string());
        }

        // Parse dependencies
        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
            for (name, value) in deps {
                let version = value.as_str().unwrap_or("*");
                self.add_component(name, version, "npm", true, None);
            }
        }

        // Parse devDependencies
        if let Some(deps) = parsed.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, value) in deps {
                let version = value.as_str().unwrap_or("*");
                self.add_component(name, version, "npm", true, None);
            }
        }

        Ok(())
    }

    /// Parse package-lock.json for exact versions
    async fn parse_package_lock(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        let parsed: serde_json::Value = serde_json::from_str(&content)?;

        // V2/V3 format
        if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
            for (pkg_path, pkg_info) in packages {
                // Skip the root package
                if pkg_path.is_empty() {
                    continue;
                }
                
                let name = pkg_path.strip_prefix("node_modules/").unwrap_or(pkg_path);
                if let Some(version) = pkg_info.get("version").and_then(|v| v.as_str()) {
                    // Update existing or add new
                    if let Some(comp) = self.components.iter_mut().find(|c| &c.name == name) {
                        comp.version = version.to_string();
                    } else {
                        self.add_component(name, version, "npm", false, None);
                    }
                }
            }
        }

        // V1 format fallback
        if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
            for (name, info) in deps {
                if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                    if let Some(comp) = self.components.iter_mut().find(|c| &c.name == name) {
                        comp.version = version.to_string();
                    } else {
                        self.add_component(name, version, "npm", false, None);
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse yarn.lock
    async fn parse_yarn_lock(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        // Simple yarn.lock parser
        let mut current_package: Option<String> = None;
        
        for line in content.lines() {
            let trimmed = line.trim();
            
            // Package declaration line
            if !trimmed.starts_with('#') && trimmed.ends_with(':') && !trimmed.starts_with("version") {
                // Extract package name from declaration
                let decl = trimmed.trim_end_matches(':');
                if let Some(name) = extract_yarn_package_name(decl) {
                    current_package = Some(name);
                }
            }
            
            // Version line
            if trimmed.starts_with("version") {
                if let Some(ref pkg) = current_package {
                    if let Some(version) = trimmed.split('"').nth(1) {
                        if let Some(comp) = self.components.iter_mut().find(|c| c.name == *pkg) {
                            comp.version = version.to_string();
                        } else {
                            self.add_component(pkg, version, "npm", false, None);
                        }
                    }
                }
                current_package = None;
            }
        }

        Ok(())
    }

    /// Parse requirements.txt file for Python dependencies (async)
    async fn parse_requirements_txt_file(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Skip options
            if line.starts_with('-') {
                continue;
            }

            // Parse package specification
            let (name, version) = parse_python_requirement(line);
            self.add_component(&name, &version, "pypi", true, None);
        }

        Ok(())
    }

    /// Parse go.mod file for Go dependencies (async)
    async fn parse_go_mod_file(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        let mut in_require = false;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Module declaration
            if line.starts_with("module ") {
                self.project.name = line.strip_prefix("module ").unwrap_or("").trim().to_string();
            }
            
            // Require block
            if line == "require (" {
                in_require = true;
                continue;
            }
            if line == ")" {
                in_require = false;
                continue;
            }
            
            // Single require
            if line.starts_with("require ") {
                let parts: Vec<&str> = line.strip_prefix("require ").unwrap_or("").split_whitespace().collect();
                if parts.len() >= 2 {
                    self.add_component(parts[0], parts[1], "go", true, None);
                }
            }
            
            // Inside require block
            if in_require && !line.is_empty() && !line.starts_with("//") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let version = parts[1].trim_start_matches('v');
                    self.add_component(parts[0], version, "go", true, None);
                }
            }
        }

        Ok(())
    }

    /// Parse go.sum for checksums and additional dependencies
    async fn parse_go_sum(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0];
                let version = parts[1].split('/').next().unwrap_or("").trim_start_matches('v');
                
                // Skip /go.mod entries
                if parts[1].contains("/go.mod") {
                    continue;
                }
                
                // Update or add component
                if !self.components.iter().any(|c| c.name == name) {
                    self.add_component(name, version, "go", false, None);
                }
            }
        }

        Ok(())
    }

    /// Parse pom.xml for Maven dependencies
    async fn parse_pom_xml(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        // Simple XML parsing for dependencies
        // In production, use a proper XML parser
        let mut in_dependency = false;
        let mut group_id = String::new();
        let mut artifact_id = String::new();
        let mut version = String::new();
        
        for line in content.lines() {
            let line = line.trim();
            
            if line.contains("<dependency>") {
                in_dependency = true;
                group_id.clear();
                artifact_id.clear();
                version.clear();
            }
            
            if in_dependency {
                if let Some(val) = extract_xml_value(line, "groupId") {
                    group_id = val;
                }
                if let Some(val) = extract_xml_value(line, "artifactId") {
                    artifact_id = val;
                }
                if let Some(val) = extract_xml_value(line, "version") {
                    version = val;
                }
            }
            
            if line.contains("</dependency>") && in_dependency {
                if !artifact_id.is_empty() {
                    let name = format!("{}:{}", group_id, artifact_id);
                    let ver = if version.is_empty() { "*" } else { &version };
                    self.add_component(&name, ver, "maven", true, None);
                }
                in_dependency = false;
            }
        }

        Ok(())
    }

    /// Parse Gemfile for Ruby dependencies
    async fn parse_gemfile(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse gem declarations
            if line.starts_with("gem ") {
                let parts: Vec<&str> = line[4..].split(',').map(|s| s.trim()).collect();
                if let Some(name) = parts.first() {
                    let name = name.trim_matches(|c| c == '\'' || c == '"');
                    let version = parts.get(1)
                        .map(|v| v.trim_matches(|c| c == '\'' || c == '"'))
                        .unwrap_or("*");
                    self.add_component(name, version, "rubygems", true, None);
                }
            }
        }

        Ok(())
    }

    /// Parse composer.json for PHP dependencies
    async fn parse_composer_json(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = tokio::fs::read_to_string(path).await?;
        let parsed: serde_json::Value = serde_json::from_str(&content)?;

        // Get package info
        if let Some(name) = parsed.get("name").and_then(|v| v.as_str()) {
            self.project.name = name.to_string();
        }

        // Parse require
        if let Some(deps) = parsed.get("require").and_then(|v| v.as_object()) {
            for (name, value) in deps {
                // Skip PHP version constraint
                if name == "php" {
                    continue;
                }
                let version = value.as_str().unwrap_or("*");
                self.add_component(name, version, "composer", true, None);
            }
        }

        // Parse require-dev
        if let Some(deps) = parsed.get("require-dev").and_then(|v| v.as_object()) {
            for (name, value) in deps {
                let version = value.as_str().unwrap_or("*");
                self.add_component(name, version, "composer", true, None);
            }
        }

        Ok(())
    }

    /// Add a component to the SBOM
    fn add_component(&mut self, name: &str, version: &str, ecosystem: &str, is_direct: bool, _parent_id: Option<String>) {
        let purl = generate_purl(name, version, ecosystem);
        let _license_risk = license_checker::assess_license_risk(None); // Reserved for future use

        let dependency_type = if is_direct {
            DependencyType::Direct
        } else {
            DependencyType::Transitive
        };

        let component = SbomComponent {
            id: Uuid::new_v4().to_string(),
            project_id: self.project.id.clone(),
            name: name.to_string(),
            version: version.to_string(),
            purl,
            cpe: None,
            component_type: ComponentType::Library,
            supplier: None,
            licenses: Vec::new(),
            hashes: std::collections::HashMap::new(),
            description: None,
            dependency_type,
            external_refs: Vec::new(),
            vulnerabilities: Vec::new(),
            created_at: Utc::now(),
        };

        // Avoid duplicates
        if !self.components.iter().any(|c| c.name == name && c.version == version) {
            self.components.push(component);
        }
    }

    /// Calculate overall license risk for the project
    fn calculate_overall_license_risk(&self) -> LicenseRisk {
        let mut highest_risk = LicenseRisk::Low;

        for component in &self.components {
            // Check license risk from the component's licenses
            for license in &component.licenses {
                match license.risk_level {
                    LicenseRisk::Critical => return LicenseRisk::Critical,
                    LicenseRisk::High => highest_risk = LicenseRisk::High,
                    LicenseRisk::Medium if highest_risk != LicenseRisk::High => {
                        highest_risk = LicenseRisk::Medium;
                    }
                    _ => {}
                }
            }
        }

        highest_risk
    }

    /// Export to CycloneDX format
    pub fn to_cyclonedx(&self) -> cyclonedx::CycloneDxBom {
        cyclonedx::CycloneDxBom::from_sbom(self)
    }

    /// Export to SPDX format
    pub fn to_spdx(&self) -> spdx::SpdxDocument {
        spdx::SpdxDocument::from_sbom(self)
    }

    /// Get the dependency graph
    pub fn get_dependency_graph(&self) -> dependency_graph::DependencyGraph {
        dependency_graph::DependencyGraph::from_components(&self.components, &self.dependencies)
    }
}

/// Extract version from TOML dependency value
fn extract_version_from_toml(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => {
            t.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string()
        }
        _ => "*".to_string(),
    }
}

/// Extract package name from yarn.lock declaration
fn extract_yarn_package_name(decl: &str) -> Option<String> {
    // Handle formats like: "package@^1.0.0", "@scope/package@^1.0.0"
    let decl = decl.trim_matches('"');
    
    if decl.starts_with('@') {
        // Scoped package
        let parts: Vec<&str> = decl.splitn(3, '@').collect();
        if parts.len() >= 2 {
            return Some(format!("@{}", parts[1]));
        }
    } else {
        // Regular package
        let parts: Vec<&str> = decl.splitn(2, '@').collect();
        if !parts.is_empty() {
            return Some(parts[0].to_string());
        }
    }
    
    None
}

/// Parse Python requirement line
fn parse_python_requirement(line: &str) -> (String, String) {
    // Handle various formats: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg[extra]==1.0
    let line = line.split('#').next().unwrap_or(line).trim();
    let line = line.split(';').next().unwrap_or(line).trim(); // Remove environment markers
    
    // Extract package name and version
    for sep in &["===", "==", "~=", ">=", "<=", "!=", ">", "<"] {
        if let Some(idx) = line.find(sep) {
            let name = line[..idx].trim();
            let version = line[idx + sep.len()..].trim();
            // Remove extras
            let name = name.split('[').next().unwrap_or(name);
            return (name.to_string(), version.to_string());
        }
    }
    
    // No version specified
    let name = line.split('[').next().unwrap_or(line);
    (name.to_string(), "*".to_string())
}

/// Extract XML tag value
fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);
    
    if let Some(start) = line.find(&open_tag) {
        if let Some(end) = line.find(&close_tag) {
            let value_start = start + open_tag.len();
            if value_start < end {
                return Some(line[value_start..end].to_string());
            }
        }
    }
    None
}

/// Generate Package URL (PURL)
fn generate_purl(name: &str, version: &str, ecosystem: &str) -> String {
    let purl_type = match ecosystem {
        "cargo" => "cargo",
        "npm" => "npm",
        "pypi" => "pypi",
        "go" => "golang",
        "maven" => "maven",
        "rubygems" => "gem",
        "composer" => "composer",
        _ => ecosystem,
    };
    
    format!("pkg:{}/{}@{}", purl_type, name, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_python_requirement() {
        assert_eq!(parse_python_requirement("requests==2.28.0"), ("requests".to_string(), "2.28.0".to_string()));
        assert_eq!(parse_python_requirement("django>=4.0"), ("django".to_string(), "4.0".to_string()));
        assert_eq!(parse_python_requirement("flask"), ("flask".to_string(), "*".to_string()));
        assert_eq!(parse_python_requirement("pytest[extra]==7.0"), ("pytest".to_string(), "7.0".to_string()));
    }

    #[test]
    fn test_generate_purl() {
        assert_eq!(generate_purl("serde", "1.0.0", "cargo"), "pkg:cargo/serde@1.0.0");
        assert_eq!(generate_purl("express", "4.18.0", "npm"), "pkg:npm/express@4.18.0");
        assert_eq!(generate_purl("requests", "2.28.0", "pypi"), "pkg:pypi/requests@2.28.0");
    }

    #[test]
    fn test_extract_yarn_package_name() {
        assert_eq!(extract_yarn_package_name("lodash@^4.17.0"), Some("lodash".to_string()));
        assert_eq!(extract_yarn_package_name("@babel/core@^7.0.0"), Some("@babel".to_string()));
    }
}
