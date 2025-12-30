//! Cloud Asset Discovery Module
//!
//! This module provides passive reconnaissance capabilities to discover
//! cloud assets associated with a target domain. It focuses on discovering
//! publicly accessible cloud resources without authentication.
//!
//! ## Discovery Methods
//!
//! - **DNS-based Discovery**: CNAME records pointing to cloud providers
//! - **Bucket Enumeration**: Common naming patterns for S3/Azure Blob/GCP Storage
//! - **Certificate Transparency**: Cloud subdomains from CT logs
//! - **Known Cloud IP Ranges**: Matching resolved IPs against provider ranges
//!
//! ## Supported Providers
//!
//! - AWS (S3, CloudFront, Elastic Beanstalk, API Gateway)
//! - Azure (Blob Storage, Azure CDN, App Services)
//! - GCP (Cloud Storage, Cloud Functions, App Engine)
//! - DigitalOcean (Spaces)
//! - Alibaba Cloud (OSS)
//!
//! **WARNING: This is for AUTHORIZED SECURITY TESTING ONLY.**
//! This performs passive reconnaissance and does NOT attempt to access any discovered assets.

use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;
use uuid::Uuid;

// ============================================================================
// Types and Structures
// ============================================================================

/// Cloud provider enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProviderType {
    Aws,
    Azure,
    Gcp,
    DigitalOcean,
    Alibaba,
    Cloudflare,
    Fastly,
    Akamai,
    Unknown,
}

impl std::fmt::Display for CloudProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "aws"),
            Self::Azure => write!(f, "azure"),
            Self::Gcp => write!(f, "gcp"),
            Self::DigitalOcean => write!(f, "digitalocean"),
            Self::Alibaba => write!(f, "alibaba"),
            Self::Cloudflare => write!(f, "cloudflare"),
            Self::Fastly => write!(f, "fastly"),
            Self::Akamai => write!(f, "akamai"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for CloudProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" => Ok(Self::Aws),
            "azure" => Ok(Self::Azure),
            "gcp" => Ok(Self::Gcp),
            "digitalocean" => Ok(Self::DigitalOcean),
            "alibaba" => Ok(Self::Alibaba),
            "cloudflare" => Ok(Self::Cloudflare),
            "fastly" => Ok(Self::Fastly),
            "akamai" => Ok(Self::Akamai),
            "unknown" | _ => Ok(Self::Unknown),
        }
    }
}

/// Type of cloud asset discovered
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudAssetType {
    /// S3 bucket or equivalent object storage
    StorageBucket,
    /// Content delivery network endpoint
    CdnEndpoint,
    /// Web application/API endpoint
    WebApplication,
    /// Serverless function endpoint
    ServerlessFunction,
    /// Database endpoint
    DatabaseEndpoint,
    /// Container service
    ContainerService,
    /// Virtual machine with public IP
    ComputeInstance,
    /// Load balancer
    LoadBalancer,
    /// DNS service (Route53, Cloud DNS, etc.)
    DnsService,
    /// API Gateway
    ApiGateway,
    /// Other cloud service
    Other(String),
}

impl std::fmt::Display for CloudAssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StorageBucket => write!(f, "storage_bucket"),
            Self::CdnEndpoint => write!(f, "cdn_endpoint"),
            Self::WebApplication => write!(f, "web_application"),
            Self::ServerlessFunction => write!(f, "serverless_function"),
            Self::DatabaseEndpoint => write!(f, "database_endpoint"),
            Self::ContainerService => write!(f, "container_service"),
            Self::ComputeInstance => write!(f, "compute_instance"),
            Self::LoadBalancer => write!(f, "load_balancer"),
            Self::DnsService => write!(f, "dns_service"),
            Self::ApiGateway => write!(f, "api_gateway"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Source of the discovery
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    /// DNS CNAME resolution
    DnsCname,
    /// Bucket name enumeration
    BucketEnumeration,
    /// Certificate transparency logs
    CertificateTransparency,
    /// IP range matching
    IpRangeMatching,
    /// HTTP header analysis
    HttpHeaders,
    /// Subdomain enumeration
    SubdomainEnumeration,
    /// Manual input
    Manual,
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DnsCname => write!(f, "dns_cname"),
            Self::BucketEnumeration => write!(f, "bucket_enumeration"),
            Self::CertificateTransparency => write!(f, "certificate_transparency"),
            Self::IpRangeMatching => write!(f, "ip_range_matching"),
            Self::HttpHeaders => write!(f, "http_headers"),
            Self::SubdomainEnumeration => write!(f, "subdomain_enumeration"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

/// Accessibility status of a discovered asset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityStatus {
    /// Publicly accessible (no auth required)
    Public,
    /// Requires authentication
    AuthRequired,
    /// Access denied (exists but blocked)
    AccessDenied,
    /// Does not exist
    NotFound,
    /// Unknown (couldn't determine)
    Unknown,
}

impl std::fmt::Display for AccessibilityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::AuthRequired => write!(f, "auth_required"),
            Self::AccessDenied => write!(f, "access_denied"),
            Self::NotFound => write!(f, "not_found"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for AccessibilityStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "public" => Ok(Self::Public),
            "auth_required" => Ok(Self::AuthRequired),
            "access_denied" => Ok(Self::AccessDenied),
            "not_found" => Ok(Self::NotFound),
            _ => Ok(Self::Unknown),
        }
    }
}

/// A discovered cloud asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAsset {
    /// Unique identifier
    pub id: String,
    /// Cloud provider
    pub provider: CloudProviderType,
    /// Type of asset
    pub asset_type: CloudAssetType,
    /// Name/identifier of the asset
    pub name: String,
    /// Full URL to access the asset
    pub url: Option<String>,
    /// Region if known
    pub region: Option<String>,
    /// Accessibility status
    pub accessibility: AccessibilityStatus,
    /// How this asset was discovered
    pub discovery_method: DiscoveryMethod,
    /// CNAME chain if discovered via DNS
    pub cname_chain: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// When this asset was discovered
    pub discovered_at: DateTime<Utc>,
    /// Risk level (info, low, medium, high, critical)
    pub risk_level: String,
    /// Notes about the finding
    pub notes: Option<String>,
}

impl CloudAsset {
    /// Create a new cloud asset
    pub fn new(
        provider: CloudProviderType,
        asset_type: CloudAssetType,
        name: String,
        method: DiscoveryMethod,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            provider,
            asset_type,
            name,
            url: None,
            region: None,
            accessibility: AccessibilityStatus::Unknown,
            discovery_method: method,
            cname_chain: Vec::new(),
            metadata: HashMap::new(),
            discovered_at: Utc::now(),
            risk_level: "info".to_string(),
            notes: None,
        }
    }
}

/// Configuration for cloud discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudDiscoveryConfig {
    /// Target domain to discover cloud assets for
    pub domain: String,
    /// Enable DNS-based discovery
    pub enable_dns_discovery: bool,
    /// Enable bucket name enumeration
    pub enable_bucket_enumeration: bool,
    /// Enable CT log search for cloud subdomains
    pub enable_ct_logs: bool,
    /// Custom bucket name patterns to try
    pub custom_bucket_patterns: Vec<String>,
    /// Providers to check
    pub providers: Vec<CloudProviderType>,
    /// Timeout for requests in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent requests
    pub concurrency: usize,
    /// Whether to check bucket accessibility (makes HTTP requests)
    pub check_accessibility: bool,
}

impl Default for CloudDiscoveryConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            enable_dns_discovery: true,
            enable_bucket_enumeration: true,
            enable_ct_logs: true,
            custom_bucket_patterns: Vec::new(),
            providers: vec![
                CloudProviderType::Aws,
                CloudProviderType::Azure,
                CloudProviderType::Gcp,
                CloudProviderType::DigitalOcean,
            ],
            timeout_secs: 10,
            concurrency: 10,
            check_accessibility: false, // Default to passive only
        }
    }
}

/// Status of a cloud discovery scan
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudDiscoveryStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for CloudDiscoveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for CloudDiscoveryStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// Statistics from the discovery
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryStatistics {
    pub total_assets: usize,
    pub assets_by_provider: HashMap<String, usize>,
    pub assets_by_type: HashMap<String, usize>,
    pub public_assets: usize,
    pub buckets_checked: usize,
    pub dns_lookups: usize,
}

/// Result of a cloud discovery scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudDiscoveryResult {
    /// Unique scan ID
    pub id: String,
    /// User who initiated the scan
    pub user_id: String,
    /// Target domain
    pub domain: String,
    /// Configuration used
    pub config: CloudDiscoveryConfig,
    /// Scan status
    pub status: CloudDiscoveryStatus,
    /// Discovered assets
    pub assets: Vec<CloudAsset>,
    /// Statistics
    pub statistics: DiscoveryStatistics,
    /// Errors encountered
    pub errors: Vec<String>,
    /// When the scan started
    pub started_at: DateTime<Utc>,
    /// When the scan completed
    pub completed_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Cloud Discovery Scanner
// ============================================================================

/// Cloud asset discovery scanner
pub struct CloudDiscoveryScanner {
    config: CloudDiscoveryConfig,
    client: Client,
    resolver: TokioAsyncResolver,
}

impl CloudDiscoveryScanner {
    /// Create a new cloud discovery scanner
    pub async fn new(config: CloudDiscoveryConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent("Mozilla/5.0 (compatible; Genial Architect Scanner)")
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(false)
            .build()?;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self {
            config,
            client,
            resolver,
        })
    }

    /// Run the cloud discovery scan
    pub async fn run(&self) -> Result<CloudDiscoveryResult> {
        let started_at = Utc::now();
        let mut assets = Vec::new();
        let mut errors = Vec::new();
        let mut statistics = DiscoveryStatistics::default();

        log::info!("Starting cloud asset discovery for domain: {}", self.config.domain);

        // DNS-based discovery
        if self.config.enable_dns_discovery {
            log::info!("Running DNS-based cloud discovery...");
            match self.discover_via_dns().await {
                Ok(mut dns_assets) => {
                    statistics.dns_lookups += dns_assets.len();
                    assets.append(&mut dns_assets);
                }
                Err(e) => {
                    log::warn!("DNS discovery error: {}", e);
                    errors.push(format!("DNS discovery: {}", e));
                }
            }
        }

        // Bucket enumeration
        if self.config.enable_bucket_enumeration {
            log::info!("Running bucket name enumeration...");
            match self.enumerate_buckets().await {
                Ok(mut bucket_assets) => {
                    statistics.buckets_checked += bucket_assets.len();
                    assets.append(&mut bucket_assets);
                }
                Err(e) => {
                    log::warn!("Bucket enumeration error: {}", e);
                    errors.push(format!("Bucket enumeration: {}", e));
                }
            }
        }

        // CT log discovery
        if self.config.enable_ct_logs {
            log::info!("Searching CT logs for cloud subdomains...");
            match self.discover_via_ct_logs().await {
                Ok(mut ct_assets) => {
                    assets.append(&mut ct_assets);
                }
                Err(e) => {
                    log::warn!("CT log discovery error: {}", e);
                    errors.push(format!("CT log discovery: {}", e));
                }
            }
        }

        // Deduplicate assets
        assets = self.deduplicate_assets(assets);

        // Calculate statistics
        statistics.total_assets = assets.len();
        for asset in &assets {
            *statistics.assets_by_provider.entry(asset.provider.to_string()).or_insert(0) += 1;
            *statistics.assets_by_type.entry(asset.asset_type.to_string()).or_insert(0) += 1;
            if asset.accessibility == AccessibilityStatus::Public {
                statistics.public_assets += 1;
            }
        }

        log::info!(
            "Cloud discovery completed. Found {} assets for {}",
            assets.len(),
            self.config.domain
        );

        Ok(CloudDiscoveryResult {
            id: Uuid::new_v4().to_string(),
            user_id: String::new(), // Set by caller
            domain: self.config.domain.clone(),
            config: self.config.clone(),
            status: CloudDiscoveryStatus::Completed,
            assets,
            statistics,
            errors,
            started_at,
            completed_at: Some(Utc::now()),
        })
    }

    /// Discover cloud assets via DNS CNAME resolution
    async fn discover_via_dns(&self) -> Result<Vec<CloudAsset>> {
        let mut assets = Vec::new();

        // Common cloud subdomains to check
        let subdomains = vec![
            "s3", "cdn", "static", "assets", "media", "files", "storage",
            "backup", "backups", "data", "api", "app", "web", "www",
            "dev", "staging", "prod", "production", "test", "uat",
            "images", "img", "downloads", "upload", "uploads", "docs",
        ];

        for subdomain in subdomains {
            let hostname = format!("{}.{}", subdomain, self.config.domain);
            if let Ok(cname_assets) = self.resolve_cname_chain(&hostname).await {
                assets.extend(cname_assets);
            }
        }

        // Also check the base domain
        if let Ok(base_assets) = self.resolve_cname_chain(&self.config.domain).await {
            assets.extend(base_assets);
        }

        Ok(assets)
    }

    /// Resolve CNAME chain and identify cloud providers
    async fn resolve_cname_chain(&self, hostname: &str) -> Result<Vec<CloudAsset>> {
        let mut assets = Vec::new();
        let mut cname_chain = Vec::new();

        // Resolve CNAME records using the generic lookup method
        match self.resolver.lookup(hostname, RecordType::CNAME).await {
            Ok(response) => {
                for record in response.record_iter() {
                    if let Some(rdata) = record.data() {
                        // Extract CNAME value from RData
                        let cname_str = match rdata {
                            trust_dns_resolver::proto::rr::RData::CNAME(name) => {
                                name.to_string().trim_end_matches('.').to_string()
                            }
                            _ => continue,
                        };
                        cname_chain.push(cname_str.clone());

                        // Check if CNAME points to a cloud provider
                        if let Some(provider) = self.identify_provider_from_cname(&cname_str) {
                            let asset_type = self.identify_asset_type_from_cname(&cname_str);
                            let mut asset = CloudAsset::new(
                                provider,
                                asset_type,
                                hostname.to_string(),
                                DiscoveryMethod::DnsCname,
                            );
                            asset.cname_chain = cname_chain.clone();
                            asset.url = Some(format!("https://{}", hostname));
                            asset.region = self.extract_region_from_cname(&cname_str);
                            asset.metadata.insert(
                                "cname_target".to_string(),
                                serde_json::Value::String(cname_str),
                            );
                            assets.push(asset);
                        }
                    }
                }
            }
            Err(_) => {
                // No CNAME, try A record and check if in cloud IP range
                // This is a fallback - in a full implementation, we'd check IP ranges
            }
        }

        Ok(assets)
    }

    /// Identify cloud provider from CNAME
    fn identify_provider_from_cname(&self, cname: &str) -> Option<CloudProviderType> {
        let cname_lower = cname.to_lowercase();

        // AWS patterns
        if cname_lower.ends_with(".s3.amazonaws.com")
            || cname_lower.ends_with(".s3-website")
            || cname_lower.contains(".s3.")
            || cname_lower.ends_with(".cloudfront.net")
            || cname_lower.ends_with(".elasticbeanstalk.com")
            || cname_lower.ends_with(".execute-api.")
            || cname_lower.ends_with(".elb.amazonaws.com")
            || cname_lower.ends_with(".awsglobalaccelerator.com")
        {
            return Some(CloudProviderType::Aws);
        }

        // Azure patterns
        if cname_lower.ends_with(".blob.core.windows.net")
            || cname_lower.ends_with(".azurewebsites.net")
            || cname_lower.ends_with(".azure-api.net")
            || cname_lower.ends_with(".azureedge.net")
            || cname_lower.ends_with(".trafficmanager.net")
            || cname_lower.ends_with(".cloudapp.azure.com")
            || cname_lower.ends_with(".azurefd.net")
        {
            return Some(CloudProviderType::Azure);
        }

        // GCP patterns
        if cname_lower.ends_with(".storage.googleapis.com")
            || cname_lower.ends_with(".appspot.com")
            || cname_lower.ends_with(".cloudfunctions.net")
            || cname_lower.ends_with(".run.app")
            || cname_lower.ends_with(".firebaseapp.com")
            || cname_lower.ends_with(".web.app")
        {
            return Some(CloudProviderType::Gcp);
        }

        // DigitalOcean
        if cname_lower.ends_with(".digitaloceanspaces.com")
            || cname_lower.ends_with(".ondigitalocean.app")
        {
            return Some(CloudProviderType::DigitalOcean);
        }

        // Alibaba Cloud
        if cname_lower.ends_with(".aliyuncs.com") || cname_lower.ends_with(".alicdn.com") {
            return Some(CloudProviderType::Alibaba);
        }

        // Cloudflare
        if cname_lower.ends_with(".cloudflare.com") || cname_lower.ends_with(".cdn.cloudflare.net") {
            return Some(CloudProviderType::Cloudflare);
        }

        // Fastly
        if cname_lower.ends_with(".fastly.net") || cname_lower.ends_with(".fastlylb.net") {
            return Some(CloudProviderType::Fastly);
        }

        // Akamai
        if cname_lower.ends_with(".akamaiedge.net")
            || cname_lower.ends_with(".akamaitechnologies.com")
            || cname_lower.ends_with(".akamaized.net")
        {
            return Some(CloudProviderType::Akamai);
        }

        None
    }

    /// Identify asset type from CNAME
    fn identify_asset_type_from_cname(&self, cname: &str) -> CloudAssetType {
        let cname_lower = cname.to_lowercase();

        // Storage buckets
        if cname_lower.contains("s3.")
            || cname_lower.contains("blob.core.windows.net")
            || cname_lower.contains("storage.googleapis.com")
            || cname_lower.contains("digitaloceanspaces.com")
        {
            return CloudAssetType::StorageBucket;
        }

        // CDN endpoints
        if cname_lower.contains("cloudfront.net")
            || cname_lower.contains("azureedge.net")
            || cname_lower.contains("azurefd.net")
            || cname_lower.contains("fastly.net")
            || cname_lower.contains("akamai")
            || cname_lower.contains("cdn.cloudflare.net")
        {
            return CloudAssetType::CdnEndpoint;
        }

        // Web applications
        if cname_lower.contains("azurewebsites.net")
            || cname_lower.contains("elasticbeanstalk.com")
            || cname_lower.contains("appspot.com")
            || cname_lower.contains("run.app")
            || cname_lower.contains("ondigitalocean.app")
        {
            return CloudAssetType::WebApplication;
        }

        // Serverless
        if cname_lower.contains("cloudfunctions.net")
            || cname_lower.contains("execute-api")
            || cname_lower.contains("azure-api.net")
        {
            return CloudAssetType::ServerlessFunction;
        }

        // Load balancer
        if cname_lower.contains("elb.amazonaws.com") || cname_lower.contains("trafficmanager.net") {
            return CloudAssetType::LoadBalancer;
        }

        // API Gateway
        if cname_lower.contains("execute-api.") || cname_lower.contains("azure-api.net") {
            return CloudAssetType::ApiGateway;
        }

        CloudAssetType::WebApplication
    }

    /// Extract region from CNAME if present
    fn extract_region_from_cname(&self, cname: &str) -> Option<String> {
        let cname_lower = cname.to_lowercase();

        // AWS region patterns
        let aws_regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
            "ap-south-1", "sa-east-1", "ca-central-1",
        ];
        for region in &aws_regions {
            if cname_lower.contains(region) {
                return Some(region.to_string());
            }
        }

        // Azure regions (less commonly in URLs)
        // GCP regions
        let gcp_regions = [
            "us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
            "europe-west1", "europe-west2", "europe-west3", "europe-west4",
            "asia-east1", "asia-east2", "asia-southeast1", "asia-northeast1",
        ];
        for region in &gcp_regions {
            if cname_lower.contains(region) {
                return Some(region.to_string());
            }
        }

        None
    }

    /// Enumerate potential bucket names
    async fn enumerate_buckets(&self) -> Result<Vec<CloudAsset>> {
        let mut assets = Vec::new();

        // Generate bucket name permutations
        let base_names = self.generate_bucket_permutations();

        for name in base_names {
            // Check each enabled provider
            if self.config.providers.contains(&CloudProviderType::Aws) {
                if let Some(asset) = self.check_s3_bucket(&name).await {
                    assets.push(asset);
                }
            }

            if self.config.providers.contains(&CloudProviderType::Azure) {
                if let Some(asset) = self.check_azure_blob(&name).await {
                    assets.push(asset);
                }
            }

            if self.config.providers.contains(&CloudProviderType::Gcp) {
                if let Some(asset) = self.check_gcs_bucket(&name).await {
                    assets.push(asset);
                }
            }

            if self.config.providers.contains(&CloudProviderType::DigitalOcean) {
                if let Some(asset) = self.check_do_space(&name).await {
                    assets.push(asset);
                }
            }
        }

        Ok(assets)
    }

    /// Generate bucket name permutations based on domain
    fn generate_bucket_permutations(&self) -> Vec<String> {
        let mut names = HashSet::new();

        // Extract domain parts
        let domain_parts: Vec<&str> = self.config.domain.split('.').collect();
        let base_name = domain_parts.first().unwrap_or(&"");
        let domain_no_tld = if domain_parts.len() >= 2 {
            domain_parts[..domain_parts.len() - 1].join(".")
        } else {
            self.config.domain.clone()
        };

        // Common patterns
        let patterns = vec![
            base_name.to_string(),
            domain_no_tld.replace('.', "-"),
            self.config.domain.replace('.', "-"),
        ];

        // Common suffixes
        let suffixes = vec![
            "", "-backup", "-backups", "-data", "-files", "-static",
            "-assets", "-media", "-dev", "-staging", "-prod", "-production",
            "-test", "-uat", "-images", "-docs", "-downloads", "-uploads",
            "-public", "-private", "-internal", "-external", "-web",
            "-api", "-logs", "-archive", "-temp", "-tmp",
        ];

        // Common prefixes
        let prefixes = vec![
            "", "backup-", "data-", "files-", "static-", "assets-",
            "media-", "dev-", "staging-", "prod-", "test-",
        ];

        for pattern in &patterns {
            for suffix in &suffixes {
                names.insert(format!("{}{}", pattern, suffix));
            }
            for prefix in &prefixes {
                names.insert(format!("{}{}", prefix, pattern));
            }
        }

        // Add custom patterns
        for custom in &self.config.custom_bucket_patterns {
            names.insert(custom.clone());
        }

        // Filter out empty and invalid names
        names
            .into_iter()
            .filter(|n| !n.is_empty() && n.len() >= 3)
            .collect()
    }

    /// Check if an S3 bucket exists (passive DNS check only)
    async fn check_s3_bucket(&self, name: &str) -> Option<CloudAsset> {
        // Try to resolve the bucket DNS name
        let bucket_url = format!("{}.s3.amazonaws.com", name);

        match self.resolver.lookup_ip(&bucket_url).await {
            Ok(_) => {
                let mut asset = CloudAsset::new(
                    CloudProviderType::Aws,
                    CloudAssetType::StorageBucket,
                    name.to_string(),
                    DiscoveryMethod::BucketEnumeration,
                );
                asset.url = Some(format!("https://{}", bucket_url));

                // If accessibility check is enabled, make an HTTP request
                if self.config.check_accessibility {
                    asset.accessibility = self.check_bucket_accessibility(&bucket_url).await;
                    if asset.accessibility == AccessibilityStatus::Public {
                        asset.risk_level = "high".to_string();
                        asset.notes = Some("Bucket may be publicly accessible".to_string());
                    }
                }

                Some(asset)
            }
            Err(_) => None,
        }
    }

    /// Check if an Azure Blob storage account exists
    async fn check_azure_blob(&self, name: &str) -> Option<CloudAsset> {
        let blob_url = format!("{}.blob.core.windows.net", name);

        match self.resolver.lookup_ip(&blob_url).await {
            Ok(_) => {
                let mut asset = CloudAsset::new(
                    CloudProviderType::Azure,
                    CloudAssetType::StorageBucket,
                    name.to_string(),
                    DiscoveryMethod::BucketEnumeration,
                );
                asset.url = Some(format!("https://{}", blob_url));

                if self.config.check_accessibility {
                    asset.accessibility = self.check_bucket_accessibility(&blob_url).await;
                    if asset.accessibility == AccessibilityStatus::Public {
                        asset.risk_level = "high".to_string();
                        asset.notes = Some("Storage account may be publicly accessible".to_string());
                    }
                }

                Some(asset)
            }
            Err(_) => None,
        }
    }

    /// Check if a GCS bucket exists
    async fn check_gcs_bucket(&self, name: &str) -> Option<CloudAsset> {
        let gcs_url = format!("{}.storage.googleapis.com", name);

        match self.resolver.lookup_ip(&gcs_url).await {
            Ok(_) => {
                let mut asset = CloudAsset::new(
                    CloudProviderType::Gcp,
                    CloudAssetType::StorageBucket,
                    name.to_string(),
                    DiscoveryMethod::BucketEnumeration,
                );
                asset.url = Some(format!("https://{}", gcs_url));

                if self.config.check_accessibility {
                    asset.accessibility = self.check_bucket_accessibility(&gcs_url).await;
                    if asset.accessibility == AccessibilityStatus::Public {
                        asset.risk_level = "high".to_string();
                        asset.notes = Some("Bucket may be publicly accessible".to_string());
                    }
                }

                Some(asset)
            }
            Err(_) => None,
        }
    }

    /// Check if a DigitalOcean Space exists
    async fn check_do_space(&self, name: &str) -> Option<CloudAsset> {
        // DigitalOcean Spaces format: <name>.<region>.digitaloceanspaces.com
        let regions = ["nyc3", "sfo2", "sfo3", "ams3", "sgp1", "fra1", "blr1", "syd1"];

        for region in &regions {
            let space_url = format!("{}.{}.digitaloceanspaces.com", name, region);
            if self.resolver.lookup_ip(&space_url).await.is_ok() {
                let mut asset = CloudAsset::new(
                    CloudProviderType::DigitalOcean,
                    CloudAssetType::StorageBucket,
                    name.to_string(),
                    DiscoveryMethod::BucketEnumeration,
                );
                asset.url = Some(format!("https://{}", space_url));
                asset.region = Some(region.to_string());

                if self.config.check_accessibility {
                    asset.accessibility = self.check_bucket_accessibility(&space_url).await;
                    if asset.accessibility == AccessibilityStatus::Public {
                        asset.risk_level = "high".to_string();
                        asset.notes = Some("Space may be publicly accessible".to_string());
                    }
                }

                return Some(asset);
            }
        }

        None
    }

    /// Check bucket accessibility via HTTP HEAD request
    async fn check_bucket_accessibility(&self, url: &str) -> AccessibilityStatus {
        let full_url = if url.starts_with("http") {
            url.to_string()
        } else {
            format!("https://{}", url)
        };

        match self.client.head(&full_url).send().await {
            Ok(response) => match response.status().as_u16() {
                200..=299 => AccessibilityStatus::Public,
                401 | 403 => AccessibilityStatus::AccessDenied,
                404 => AccessibilityStatus::NotFound,
                _ => AccessibilityStatus::Unknown,
            },
            Err(_) => AccessibilityStatus::Unknown,
        }
    }

    /// Discover cloud assets from Certificate Transparency logs
    async fn discover_via_ct_logs(&self) -> Result<Vec<CloudAsset>> {
        let mut assets = Vec::new();

        // Query crt.sh for subdomains
        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            self.config.domain
        );

        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to query CT logs: {}", e);
                return Ok(assets);
            }
        };

        if !response.status().is_success() {
            return Ok(assets);
        }

        #[derive(Deserialize)]
        struct CrtShEntry {
            name_value: String,
        }

        let entries: Vec<CrtShEntry> = match response.json().await {
            Ok(e) => e,
            Err(_) => return Ok(assets),
        };

        // Extract unique hostnames that look like cloud resources
        let mut seen = HashSet::new();
        for entry in entries {
            for name in entry.name_value.lines() {
                let name = name.trim().to_lowercase();
                if seen.contains(&name) {
                    continue;
                }
                seen.insert(name.clone());

                // Check if the subdomain contains cloud-related keywords
                if self.is_cloud_related_subdomain(&name) {
                    // Try to resolve and check if it's a cloud CNAME
                    if let Ok(mut ct_assets) = self.resolve_cname_chain(&name).await {
                        if !ct_assets.is_empty() {
                            for asset in &mut ct_assets {
                                asset.discovery_method = DiscoveryMethod::CertificateTransparency;
                            }
                            assets.extend(ct_assets);
                        }
                    }
                }
            }
        }

        Ok(assets)
    }

    /// Check if a subdomain is likely cloud-related
    fn is_cloud_related_subdomain(&self, subdomain: &str) -> bool {
        let cloud_keywords = [
            "s3", "cdn", "static", "assets", "media", "storage", "blob",
            "bucket", "files", "upload", "download", "backup", "api",
            "app", "web", "lambda", "function", "cloud", "aws", "azure",
            "gcp", "digitalocean", "do", "spaces", "container", "docker",
            "k8s", "kubernetes", "ecs", "eks", "aks", "gke",
        ];

        for keyword in &cloud_keywords {
            if subdomain.contains(keyword) {
                return true;
            }
        }

        false
    }

    /// Deduplicate discovered assets
    fn deduplicate_assets(&self, assets: Vec<CloudAsset>) -> Vec<CloudAsset> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        for asset in assets {
            let key = format!("{}:{}:{}", asset.provider, asset.asset_type, asset.name);
            if !seen.contains(&key) {
                seen.insert(key);
                result.push(asset);
            }
        }

        result
    }
}

/// Convenience function to run a cloud discovery scan
pub async fn run_cloud_discovery(config: CloudDiscoveryConfig) -> Result<CloudDiscoveryResult> {
    let scanner = CloudDiscoveryScanner::new(config).await?;
    scanner.run().await
}

/// Check specific bucket names across providers
pub async fn check_bucket_names(
    names: Vec<String>,
    providers: Vec<CloudProviderType>,
    check_accessibility: bool,
) -> Result<Vec<CloudAsset>> {
    let config = CloudDiscoveryConfig {
        domain: "manual-check".to_string(),
        enable_dns_discovery: false,
        enable_bucket_enumeration: true,
        enable_ct_logs: false,
        custom_bucket_patterns: names,
        providers,
        check_accessibility,
        ..Default::default()
    };

    let scanner = CloudDiscoveryScanner::new(config).await?;

    // Just run the bucket enumeration part
    scanner.enumerate_buckets().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_display() {
        assert_eq!(CloudProviderType::Aws.to_string(), "aws");
        assert_eq!(CloudProviderType::Azure.to_string(), "azure");
        assert_eq!(CloudProviderType::Gcp.to_string(), "gcp");
    }

    #[test]
    fn test_asset_type_display() {
        assert_eq!(CloudAssetType::StorageBucket.to_string(), "storage_bucket");
        assert_eq!(CloudAssetType::CdnEndpoint.to_string(), "cdn_endpoint");
    }

    #[test]
    fn test_discovery_method_display() {
        assert_eq!(DiscoveryMethod::DnsCname.to_string(), "dns_cname");
        assert_eq!(DiscoveryMethod::BucketEnumeration.to_string(), "bucket_enumeration");
    }

    #[test]
    fn test_default_config() {
        let config = CloudDiscoveryConfig::default();
        assert!(config.enable_dns_discovery);
        assert!(config.enable_bucket_enumeration);
        assert!(config.enable_ct_logs);
        assert!(!config.check_accessibility); // Default to passive
    }

    #[tokio::test]
    async fn test_bucket_permutation_generation() {
        let config = CloudDiscoveryConfig {
            domain: "example.com".to_string(),
            ..Default::default()
        };

        let scanner = CloudDiscoveryScanner::new(config).await.unwrap();
        let permutations = scanner.generate_bucket_permutations();

        // Should generate various permutations
        assert!(!permutations.is_empty());
        assert!(permutations.iter().any(|p| p.contains("example")));
    }
}
