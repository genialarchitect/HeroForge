//! Subdomain Mutation and Permutation Generator
//!
//! Generates subdomain variations using various mutation techniques:
//! - Prefix/suffix additions (dev-, -api, -cdn)
//! - Number increments (app1 → app2, app3...)
//! - Environment variants (dev, staging, prod)
//! - Region variants (us-east, eu-west)
//! - Cloud provider patterns
//! - Common naming conventions

use std::collections::HashSet;

/// Common environment prefixes for subdomain generation
pub const ENVIRONMENT_PREFIXES: &[&str] = &[
    "dev", "development",
    "stg", "stage", "staging",
    "qa", "test", "testing",
    "uat", "sandbox",
    "prod", "production",
    "pre", "preprod", "pre-prod",
    "demo", "poc", "beta", "alpha",
    "int", "internal",
    "ext", "external",
    "local", "localhost",
];

/// Common environment suffixes
pub const ENVIRONMENT_SUFFIXES: &[&str] = &[
    "-dev", "-development",
    "-stg", "-stage", "-staging",
    "-qa", "-test", "-testing",
    "-uat", "-sandbox",
    "-prod", "-production",
    "-pre", "-preprod",
    "-demo", "-poc", "-beta", "-alpha",
    "-int", "-internal",
    "-ext", "-external",
];

/// Common service prefixes
pub const SERVICE_PREFIXES: &[&str] = &[
    "api", "api-",
    "app", "app-",
    "web", "web-",
    "www", "www-",
    "cdn", "cdn-",
    "static", "static-",
    "assets", "assets-",
    "images", "img", "img-",
    "media", "media-",
    "admin", "admin-",
    "portal", "portal-",
    "dashboard", "dash",
    "backend", "backend-",
    "frontend", "frontend-",
    "service", "svc", "svc-",
    "auth", "auth-",
    "login", "login-",
    "oauth", "oauth-",
    "sso", "sso-",
    "mail", "mail-", "email",
    "smtp", "imap", "pop",
    "ftp", "sftp",
    "vpn", "vpn-",
    "rdp", "remote",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "cache", "memcache",
    "queue", "mq", "rabbitmq", "kafka",
    "search", "elastic", "es",
    "logs", "logging", "log",
    "metrics", "grafana", "prometheus",
    "status", "health", "monitor",
    "git", "gitlab", "github", "bitbucket",
    "ci", "jenkins", "travis", "drone",
    "docker", "k8s", "kubernetes", "registry",
    "vault", "secrets",
];

/// Common service suffixes
pub const SERVICE_SUFFIXES: &[&str] = &[
    "-api", "-app", "-web", "-www",
    "-cdn", "-static", "-assets",
    "-admin", "-portal", "-dashboard",
    "-backend", "-frontend",
    "-service", "-svc",
    "-auth", "-login", "-sso",
    "-mail", "-db", "-cache",
    "-logs", "-metrics", "-status",
    "-internal", "-external",
    "-public", "-private",
    "-v1", "-v2", "-v3",
];

/// Region prefixes (cloud providers)
pub const REGION_PREFIXES: &[&str] = &[
    // AWS
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
    "sa-east-1", "ca-central-1",
    // Short versions
    "us-east", "us-west", "eu-west", "eu-central",
    "ap-south", "ap-northeast", "ap-southeast",
    // Azure
    "eastus", "eastus2", "westus", "westus2",
    "northeurope", "westeurope", "centralus",
    "southeastasia", "eastasia",
    // GCP
    "us-central1", "us-east1", "us-west1",
    "europe-west1", "europe-west2", "europe-north1",
    "asia-east1", "asia-southeast1",
    // Generic
    "us", "eu", "ap", "sa", "ca", "au",
    "north", "south", "east", "west", "central",
];

/// Cloud provider specific patterns
pub const CLOUD_PATTERNS: &[&str] = &[
    // AWS
    "s3", "ec2", "elb", "alb", "nlb",
    "lambda", "rds", "dynamodb", "cloudfront",
    "sqs", "sns", "ecs", "eks", "fargate",
    // Azure
    "azure", "blob", "cosmos", "aks",
    // GCP
    "gcp", "gcs", "gke", "cloudsql",
    // Generic cloud
    "cloud", "saas", "paas", "iaas",
];

/// Number ranges for permutation
pub const NUMBER_RANGES: &[(i32, i32)] = &[
    (0, 10),    // 0-9
    (1, 10),    // 1-9
    (01, 100),  // 01-99 with padding
];

/// Configuration for subdomain generation
#[derive(Debug, Clone)]
pub struct SubdomainGeneratorConfig {
    /// Maximum number of subdomains to generate per technique
    pub max_per_technique: usize,
    /// Enable number permutations
    pub enable_numbers: bool,
    /// Enable environment variations
    pub enable_environments: bool,
    /// Enable region variations
    pub enable_regions: bool,
    /// Enable service variations
    pub enable_services: bool,
    /// Enable cloud patterns
    pub enable_cloud: bool,
    /// Custom prefixes to try
    pub custom_prefixes: Vec<String>,
    /// Custom suffixes to try
    pub custom_suffixes: Vec<String>,
}

impl Default for SubdomainGeneratorConfig {
    fn default() -> Self {
        Self {
            max_per_technique: 1000,
            enable_numbers: true,
            enable_environments: true,
            enable_regions: true,
            enable_services: true,
            enable_cloud: true,
            custom_prefixes: Vec::new(),
            custom_suffixes: Vec::new(),
        }
    }
}

/// Subdomain generator
pub struct SubdomainGenerator {
    config: SubdomainGeneratorConfig,
}

impl SubdomainGenerator {
    /// Create a new subdomain generator with default configuration
    pub fn new() -> Self {
        Self {
            config: SubdomainGeneratorConfig::default(),
        }
    }

    /// Create a new subdomain generator with custom configuration
    pub fn with_config(config: SubdomainGeneratorConfig) -> Self {
        Self { config }
    }

    /// Generate subdomain permutations from a base domain
    pub fn generate_from_base(&self, base_domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();

        // Extract base name from subdomain (e.g., "api" from "api.example.com")
        let parts: Vec<&str> = base_domain.split('.').collect();
        if parts.len() < 2 {
            return subdomains;
        }

        let base_name = parts[0];
        let parent_domain = parts[1..].join(".");

        // Add original
        subdomains.insert(base_domain.to_string());

        // Generate variations based on the base name
        let variations = self.mutate_name(base_name);

        for variation in variations {
            let subdomain = format!("{}.{}", variation, parent_domain);
            subdomains.insert(subdomain);

            if subdomains.len() >= self.config.max_per_technique * 5 {
                break;
            }
        }

        subdomains
    }

    /// Generate subdomain permutations for a parent domain
    pub fn generate_for_domain(&self, parent_domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();

        // Add common prefixes
        if self.config.enable_services {
            for prefix in SERVICE_PREFIXES.iter().take(self.config.max_per_technique) {
                subdomains.insert(format!("{}.{}", prefix, parent_domain));
            }
        }

        // Add environment variations
        if self.config.enable_environments {
            for env in ENVIRONMENT_PREFIXES.iter().take(self.config.max_per_technique) {
                subdomains.insert(format!("{}.{}", env, parent_domain));
            }
        }

        // Add region variations
        if self.config.enable_regions {
            for region in REGION_PREFIXES.iter().take(self.config.max_per_technique / 2) {
                subdomains.insert(format!("{}.{}", region, parent_domain));

                // Also combine with common services
                for svc in &["api", "app", "web", "cdn", "db"] {
                    subdomains.insert(format!("{}-{}.{}", svc, region, parent_domain));
                    subdomains.insert(format!("{}-{}.{}", region, svc, parent_domain));
                }
            }
        }

        // Add cloud patterns
        if self.config.enable_cloud {
            for pattern in CLOUD_PATTERNS.iter() {
                subdomains.insert(format!("{}.{}", pattern, parent_domain));
            }
        }

        // Add custom prefixes
        for prefix in &self.config.custom_prefixes {
            subdomains.insert(format!("{}.{}", prefix, parent_domain));
        }

        // Add numbered variations
        if self.config.enable_numbers {
            for base in &["app", "api", "web", "server", "node", "host", "srv", "vm", "db"] {
                for i in 1..=9 {
                    subdomains.insert(format!("{}{}.{}", base, i, parent_domain));
                    subdomains.insert(format!("{}-{}.{}", base, i, parent_domain));
                }
                for i in &[01, 02, 03, 10, 20, 100] {
                    subdomains.insert(format!("{}{:02}.{}", base, i, parent_domain));
                }
            }
        }

        subdomains
    }

    /// Mutate a single subdomain name to generate variations
    pub fn mutate_name(&self, name: &str) -> HashSet<String> {
        let mut mutations = HashSet::new();

        // Original
        mutations.insert(name.to_string());

        // Extract any existing numbers
        let (base_name, existing_number) = extract_number_suffix(name);

        // Environment prefix/suffix mutations
        if self.config.enable_environments {
            for env in ENVIRONMENT_PREFIXES {
                mutations.insert(format!("{}-{}", env, name));
                mutations.insert(format!("{}{}", env, name));
                mutations.insert(format!("{}-{}", name, env));
                mutations.insert(format!("{}{}", name, env));
            }

            for suffix in ENVIRONMENT_SUFFIXES {
                mutations.insert(format!("{}{}", name, suffix));
            }
        }

        // Service prefix/suffix mutations
        if self.config.enable_services {
            for suffix in SERVICE_SUFFIXES {
                mutations.insert(format!("{}{}", name, suffix));
            }
        }

        // Number increment mutations
        if self.config.enable_numbers {
            // If there's an existing number, generate increment sequence
            if let Some(num) = existing_number {
                for i in (num.saturating_sub(5))..=(num + 10) {
                    if i >= 0 {
                        mutations.insert(format!("{}{}", base_name, i));
                        mutations.insert(format!("{}-{}", base_name, i));
                        mutations.insert(format!("{}{:02}", base_name, i));
                    }
                }
            } else {
                // Add numbered versions
                for i in 1..=5 {
                    mutations.insert(format!("{}{}", name, i));
                    mutations.insert(format!("{}-{}", name, i));
                }
                for i in &[01, 02, 03, 10, 100] {
                    mutations.insert(format!("{}{:02}", name, i));
                }
            }
        }

        // Region mutations
        if self.config.enable_regions {
            for region in &["us", "eu", "ap", "east", "west"] {
                mutations.insert(format!("{}-{}", region, name));
                mutations.insert(format!("{}-{}", name, region));
            }
        }

        // Custom suffixes
        for suffix in &self.config.custom_suffixes {
            mutations.insert(format!("{}{}", name, suffix));
            mutations.insert(format!("{}-{}", name, suffix));
        }

        mutations
    }

    /// Generate subdomains from a list of known subdomains
    pub fn generate_from_discovered(&self, discovered: &[String]) -> HashSet<String> {
        let mut new_subdomains = HashSet::new();

        for subdomain in discovered {
            // Generate mutations from each discovered subdomain
            let mutations = self.generate_from_base(subdomain);
            new_subdomains.extend(mutations);

            // Limit total generated
            if new_subdomains.len() >= self.config.max_per_technique * 10 {
                break;
            }
        }

        // Remove already discovered ones
        for discovered in discovered {
            new_subdomains.remove(discovered);
        }

        new_subdomains
    }

    /// Generate wildcard detection probes
    pub fn generate_wildcard_probes(&self, parent_domain: &str) -> Vec<String> {
        vec![
            format!("heroforge-wildcard-test-{}.{}", uuid::Uuid::new_v4(), parent_domain),
            format!("random-nonexistent-subdomain-12345.{}", parent_domain),
            format!("thissubdomainshouldnotexist.{}", parent_domain),
        ]
    }

    /// Check if a subdomain follows common naming patterns
    pub fn analyze_pattern(&self, subdomain: &str) -> SubdomainPattern {
        let name = subdomain.split('.').next().unwrap_or("");

        SubdomainPattern {
            has_number: extract_number_suffix(name).1.is_some(),
            has_environment: ENVIRONMENT_PREFIXES.iter().any(|e| name.contains(e)),
            has_region: REGION_PREFIXES.iter().any(|r| name.contains(r)),
            has_service: SERVICE_PREFIXES.iter().any(|s| name.contains(s)),
            has_cloud: CLOUD_PATTERNS.iter().any(|c| name.contains(c)),
            pattern_type: detect_pattern_type(name),
        }
    }
}

impl Default for SubdomainGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pattern analysis result
#[derive(Debug, Clone)]
pub struct SubdomainPattern {
    pub has_number: bool,
    pub has_environment: bool,
    pub has_region: bool,
    pub has_service: bool,
    pub has_cloud: bool,
    pub pattern_type: PatternType,
}

/// Types of naming patterns
#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    /// Simple name (api, www)
    Simple,
    /// Name with number (app1, server2)
    Numbered,
    /// Environment prefixed (dev-api, staging-app)
    EnvironmentPrefixed,
    /// Environment suffixed (api-dev, app-staging)
    EnvironmentSuffixed,
    /// Region based (us-east-api, eu-west-app)
    RegionBased,
    /// Combined pattern
    Combined,
    /// Unknown pattern
    Unknown,
}

/// Extract number suffix from a name (e.g., "app1" -> ("app", Some(1)))
fn extract_number_suffix(name: &str) -> (&str, Option<i32>) {
    let mut split_pos = name.len();
    let mut has_number = false;

    for (i, c) in name.char_indices().rev() {
        if c.is_ascii_digit() {
            has_number = true;
            split_pos = i;
        } else {
            break;
        }
    }

    if has_number && split_pos < name.len() {
        let base = &name[..split_pos];
        let num_str = &name[split_pos..];
        match num_str.parse::<i32>() {
            Ok(n) => (base.trim_end_matches('-'), Some(n)),
            Err(_) => (name, None),
        }
    } else {
        (name, None)
    }
}

/// Detect the pattern type of a subdomain name
fn detect_pattern_type(name: &str) -> PatternType {
    let lower = name.to_lowercase();

    // Check for numbered pattern
    if extract_number_suffix(name).1.is_some() {
        return PatternType::Numbered;
    }

    // Check for environment patterns
    for env in ENVIRONMENT_PREFIXES {
        if lower.starts_with(env) {
            return PatternType::EnvironmentPrefixed;
        }
    }

    for suffix in ENVIRONMENT_SUFFIXES {
        if lower.ends_with(suffix) {
            return PatternType::EnvironmentSuffixed;
        }
    }

    // Check for region patterns
    for region in REGION_PREFIXES {
        if lower.contains(region) {
            return PatternType::RegionBased;
        }
    }

    // Simple service names
    if SERVICE_PREFIXES.contains(&lower.as_str()) {
        return PatternType::Simple;
    }

    PatternType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_number_suffix() {
        assert_eq!(extract_number_suffix("app1"), ("app", Some(1)));
        assert_eq!(extract_number_suffix("server-2"), ("server", Some(2)));
        assert_eq!(extract_number_suffix("api"), ("api", None));
        assert_eq!(extract_number_suffix("node01"), ("node", Some(1)));
        assert_eq!(extract_number_suffix("web100"), ("web", Some(100)));
    }

    #[test]
    fn test_generate_for_domain() {
        let generator = SubdomainGenerator::new();
        let subdomains = generator.generate_for_domain("example.com");

        assert!(subdomains.contains("api.example.com"));
        assert!(subdomains.contains("dev.example.com"));
        assert!(subdomains.contains("staging.example.com"));
        assert!(subdomains.contains("app1.example.com"));
    }

    #[test]
    fn test_generate_from_base() {
        let generator = SubdomainGenerator::new();
        let subdomains = generator.generate_from_base("api.example.com");

        assert!(subdomains.contains("api.example.com"));
        assert!(subdomains.contains("dev-api.example.com"));
        assert!(subdomains.contains("api1.example.com"));
        assert!(subdomains.contains("api-staging.example.com"));
    }

    #[test]
    fn test_mutate_name_numbered() {
        let generator = SubdomainGenerator::new();
        let mutations = generator.mutate_name("app1");

        assert!(mutations.contains("app1"));
        assert!(mutations.contains("app2"));
        assert!(mutations.contains("app0"));
        assert!(mutations.contains("dev-app1"));
    }

    #[test]
    fn test_pattern_detection() {
        let generator = SubdomainGenerator::new();

        assert_eq!(
            generator.analyze_pattern("app1.example.com").pattern_type,
            PatternType::Numbered
        );
        assert_eq!(
            generator.analyze_pattern("dev-api.example.com").pattern_type,
            PatternType::EnvironmentPrefixed
        );
        assert_eq!(
            generator.analyze_pattern("api-staging.example.com").pattern_type,
            PatternType::EnvironmentSuffixed
        );
    }
}
