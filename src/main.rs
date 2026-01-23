#![recursion_limit = "512"]
// Suppress warnings across the codebase
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![allow(deprecated)]
#![allow(private_interfaces)]
#![allow(unexpected_cfgs)]
// Clippy lints
#![allow(clippy::redundant_closure)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::collapsible_str_replace)]
#![allow(clippy::type_complexity)]
#![allow(clippy::manual_strip)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::mixed_attributes_style)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::useless_format)]
#![allow(clippy::useless_vec)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::useless_asref)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::single_char_add_str)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::map_flatten)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::manual_range_patterns)]
#![allow(clippy::get_first)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::needless_return)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::option_as_ref_deref)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::match_result_ok)]
#![allow(clippy::len_zero)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::bool_comparison)]
#![allow(clippy::op_ref)]
#![allow(clippy::identity_op)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::cmp_owned)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::redundant_locals)]
#![allow(clippy::redundant_guards)]
#![allow(clippy::let_and_return)]
#![allow(clippy::let_unit_value)]
#![allow(clippy::single_match)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::arc_with_non_send_sync)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::iter_kv_map)]
#![allow(clippy::filter_next)]
#![allow(clippy::map_identity)]
#![allow(clippy::bind_instead_of_map)]
#![allow(clippy::manual_map)]
#![allow(clippy::manual_find)]
#![allow(clippy::manual_flatten)]
#![allow(clippy::manual_contains)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_ignore_case_cmp)]
#![allow(clippy::manual_retain)]
#![allow(clippy::manual_repeat_n)]
#![allow(clippy::manual_unwrap_or)]
#![allow(clippy::manual_unwrap_or_default)]
#![allow(clippy::lines_filter_map_ok)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_late_init)]
#![allow(clippy::needless_character_iteration)]
#![allow(clippy::question_mark)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(clippy::unnecessary_sort_by)]
#![allow(clippy::unnecessary_min_or_max)]
#![allow(clippy::unnecessary_filter_map)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::to_string_in_format_args)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::trim_split_whitespace)]
#![allow(clippy::regex_creation_in_loops)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::implicit_saturating_sub)]
#![allow(clippy::inherent_to_string)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::wildcard_in_or_patterns)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::double_ended_iterator_last)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::iter_out_of_bounds)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use log::{error, info};
use std::time::Duration;

mod agents;
mod ai;
mod ai_security;
mod api_governance;
mod asm;
mod backup;
mod bi;
mod binary_analysis;
mod communications;
mod compliance;
mod compliance_automation;
mod config;
mod context;
mod cracking;
mod credentials;
mod cve;
mod data_lake;
mod db;
mod devsecops;
mod dlp;
mod dns_analytics;
mod dr;
mod email;
mod email_validation;
mod event_bus;
mod findings;
mod forensics;
mod fuzzing;
mod hardening;
mod honeypots;
mod honeytokens;
mod incident_response;
mod insider_threat;
mod detection_engineering;
mod integrations;
mod iot;
mod jobs;
mod k8s_security;
mod malware_analysis;
mod ml;
mod monitoring;
mod netflow;
mod notifications;
mod output;
mod password_validation;
mod phishing;
mod c2;
mod plugins;
mod purple_team;
mod rbac;
mod replication;
mod resilience;
mod reports;
mod scap;
mod scan_processor;
mod scanner;
mod screenshots;
mod siem;
mod supply_chain;
mod testing;
mod threat_feeds;
mod threat_hunting;
mod threat_intel;
mod traffic_analysis;
mod types;
mod yellow_team;
mod orange_team;
mod green_team;
mod white_team;
mod red_team;
mod blue_team;
mod vpn;
mod vuln;
mod web;
mod exploit_research;
mod ot_ics;
mod webhooks;
mod workflows;
// Phase 4 Sprint 2-10
mod investigation;
mod cti_automation;
mod patch_management;
mod orchestration;
mod predictive_security;
// Phase 4 Sprint 11-18
mod web3;
mod emerging_tech;
mod performance;
mod analytics_engine;
mod intelligence_platform;
mod subscriptions;
mod methodology;
mod legal_documents;
mod passive_recon;
mod license;

use types::{OutputFormat, ScanConfig, ScanType};

#[derive(Parser)]
#[command(
    name = "HeroForge",
    version,
    about = "Network triage and reconnaissance tool for penetration testing",
    long_about = "HeroForge automates the initial network triage phase of penetration testing,\n\
                  including host discovery, port scanning, service detection, OS fingerprinting,\n\
                  and basic vulnerability assessment."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, value_enum, global = true, default_value = "terminal")]
    output: CliOutputFormat,
}

#[derive(Clone, clap::ValueEnum)]
enum CliOutputFormat {
    Json,
    Csv,
    Terminal,
    All,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(val: CliOutputFormat) -> Self {
        match val {
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Csv => OutputFormat::Csv,
            CliOutputFormat::Terminal => OutputFormat::Terminal,
            CliOutputFormat::All => OutputFormat::All,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Perform full network triage scan
    Scan {
        /// Target IP addresses or CIDR ranges (e.g., 192.168.1.0/24)
        #[arg(required = true)]
        targets: Vec<String>,

        /// Port range to scan (e.g., 1-1000)
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "100")]
        threads: usize,

        /// Timeout per port in milliseconds
        #[arg(short = 'T', long, default_value = "3000")]
        timeout: u64,

        /// Scan type
        #[arg(short, long, value_enum, default_value = "tcp-connect")]
        scan_type: CliScanType,

        /// Skip OS detection
        #[arg(long)]
        no_os_detect: bool,

        /// Skip service detection
        #[arg(long)]
        no_service_detect: bool,

        /// Enable vulnerability scanning
        #[arg(long)]
        vuln_scan: bool,

        /// Enable service enumeration
        #[arg(long)]
        r#enum: bool,

        /// Enumeration depth level
        #[arg(long, value_enum, default_value = "light")]
        enum_depth: CliEnumDepth,

        /// Custom wordlist file path for enumeration
        #[arg(long)]
        enum_wordlist: Option<String>,

        /// UDP-specific port range or list (e.g., "53,123,161" or "1-500")
        /// If not specified with UDP scan type, uses common UDP ports
        #[arg(long)]
        udp_ports: Option<String>,

        /// Number of UDP probe retries (default: 2)
        #[arg(long, default_value = "2")]
        udp_retries: u8,

        /// Skip host discovery and scan targets directly
        #[arg(long)]
        skip_discovery: bool,

        /// Output file path
        #[arg(short, long)]
        output_file: Option<String>,

        /// CI/CD mode: minimal output, exit codes based on severity
        #[arg(long)]
        ci: bool,

        /// Fail scan if vulnerabilities at or above this severity are found (for --ci mode)
        #[arg(long, value_enum, default_value = "high")]
        fail_on: CliSeverity,

        /// Output results in SARIF format (for GitHub Security)
        #[arg(long)]
        output_sarif: Option<String>,

        /// Output results in JUnit XML format (for Jenkins/CI)
        #[arg(long)]
        output_junit: Option<String>,
    },

    /// Discover live hosts on the network
    Discover {
        /// Target IP addresses or CIDR ranges
        #[arg(required = true)]
        targets: Vec<String>,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "100")]
        threads: usize,

        /// Timeout in milliseconds
        #[arg(short = 'T', long, default_value = "1000")]
        timeout: u64,
    },

    /// Scan ports on specific hosts
    Portscan {
        /// Target IP addresses
        #[arg(required = true)]
        targets: Vec<String>,

        /// Port range to scan
        #[arg(short, long, default_value = "1-65535")]
        ports: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "100")]
        threads: usize,

        /// Scan type
        #[arg(short, long, value_enum, default_value = "tcp-connect")]
        scan_type: CliScanType,
    },

    /// Generate default configuration file
    Config {
        /// Output path for config file
        #[arg(default_value = "heroforge.toml")]
        path: String,
    },

    /// Start web server with dashboard
    Serve {
        /// Database URL
        #[arg(short, long, default_value = "sqlite://heroforge.db")]
        database: String,

        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum CliScanType {
    TcpConnect,
    TcpSyn,
    Udp,
    Comprehensive,
}

impl From<CliScanType> for ScanType {
    fn from(val: CliScanType) -> Self {
        match val {
            CliScanType::TcpConnect => ScanType::TCPConnect,
            CliScanType::TcpSyn => ScanType::TCPSyn,
            CliScanType::Udp => ScanType::UDPScan,
            CliScanType::Comprehensive => ScanType::Comprehensive,
        }
    }
}

#[derive(Clone, clap::ValueEnum)]
enum CliEnumDepth {
    Passive,
    Light,
    Aggressive,
}

impl From<CliEnumDepth> for scanner::enumeration::types::EnumDepth {
    fn from(val: CliEnumDepth) -> Self {
        match val {
            CliEnumDepth::Passive => scanner::enumeration::types::EnumDepth::Passive,
            CliEnumDepth::Light => scanner::enumeration::types::EnumDepth::Light,
            CliEnumDepth::Aggressive => scanner::enumeration::types::EnumDepth::Aggressive,
        }
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CliSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<CliSeverity> for types::Severity {
    fn from(val: CliSeverity) -> Self {
        match val {
            CliSeverity::Low => types::Severity::Low,
            CliSeverity::Medium => types::Severity::Medium,
            CliSeverity::High => types::Severity::High,
            CliSeverity::Critical => types::Severity::Critical,
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize Sentry for error tracking (must be done first)
    // The guard must be held for the lifetime of the application
    let _sentry_guard = sentry::init((
        std::env::var("SENTRY_DSN").unwrap_or_default(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(
                std::env::var("SENTRY_ENVIRONMENT")
                    .unwrap_or_else(|_| "production".to_string())
                    .into(),
            ),
            // Capture 100% of transactions for performance monitoring
            traces_sample_rate: 0.1,
            // Enable session tracking
            auto_session_tracking: true,
            ..Default::default()
        },
    ));

    let cli = Cli::parse();

    // Initialize logger
    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    // Initialize rustls crypto provider for TLS operations
    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        log::warn!("Failed to install default crypto provider: {:?}", e);
    }

    print_banner();

    let result = match cli.command {
        Commands::Scan {
            targets,
            ports,
            threads,
            timeout,
            scan_type,
            no_os_detect,
            no_service_detect,
            vuln_scan,
            r#enum,
            enum_depth,
            enum_wordlist,
            udp_ports,
            udp_retries,
            skip_discovery,
            output_file,
            ci,
            fail_on,
            output_sarif,
            output_junit,
        } => {
            let config = build_scan_config(
                targets,
                ports,
                threads,
                timeout,
                scan_type,
                !no_os_detect,
                !no_service_detect,
                vuln_scan,
                r#enum,
                enum_depth,
                enum_wordlist,
                udp_ports,
                udp_retries,
                skip_discovery,
                cli.output,
            );
            run_full_scan(config, output_file, ci, fail_on, output_sarif, output_junit).await
        }
        Commands::Discover {
            targets,
            threads,
            timeout,
        } => run_discovery(targets, threads, timeout).await,
        Commands::Portscan {
            targets,
            ports,
            threads,
            scan_type,
        } => run_portscan(targets, ports, threads, scan_type, cli.output).await,
        Commands::Config { path } => generate_config(path),
        Commands::Serve { database, bind } => {
            println!("{}", "Starting HeroForge Web Server...".bright_green().bold());

            // Initialize license system
            let license_key = std::env::var("HEROFORGE_LICENSE_KEY").ok();
            match license::init_license(license_key.as_deref()) {
                Ok(Some(lic)) => {
                    println!("{} {} ({})",
                        "License:".bright_white(),
                        lic.tier.to_string().bright_green(),
                        if lic.expires_at.is_some() {
                            format!("expires in {} days", lic.days_until_expiry().unwrap_or(0))
                        } else {
                            "never expires".to_string()
                        }
                    );
                }
                Ok(None) => {
                    println!("{} {}", "License:".bright_white(), "Free tier (no license key)".yellow());
                }
                Err(e) => {
                    println!("{} {}", "License Error:".bright_red(), e);
                    println!("{}", "Starting in Free tier mode...".yellow());
                    let _ = license::init_license(None);
                }
            }

            println!("{} {}", "Database:".bright_white(), database.cyan());
            println!("{} {}", "Bind Address:".bright_white(), bind.cyan());
            println!("\n{}", "Access the dashboard at:".bright_white().bold());
            println!("  {}", format!("http://{}", bind).bright_cyan().underline());
            println!();
            web::run_web_server(&database, &bind).await.map_err(|e| e.into())
        }
    };

    if let Err(e) = result {
        error!("{}", format!("Error: {}", e).red());
        std::process::exit(1);
    }
}

fn print_banner() {
    println!("{}", r#"
    ╦ ╦╔═╗╦═╗╔═╗╔═╗╔═╗╦═╗╔═╗╔═╗
    ╠═╣║╣ ╠╦╝║ ║╠╣ ║ ║╠╦╝║ ╦║╣
    ╩ ╩╚═╝╩╚═╚═╝╚  ╚═╝╩╚═╚═╝╚═╝
    "#.bright_cyan().bold());
    println!("{}", "    Network Triage for Penetration Testing\n".bright_white());
}

fn build_scan_config(
    targets: Vec<String>,
    ports: String,
    threads: usize,
    timeout: u64,
    scan_type: CliScanType,
    os_detect: bool,
    service_detect: bool,
    vuln_scan: bool,
    enable_enum: bool,
    enum_depth: CliEnumDepth,
    enum_wordlist: Option<String>,
    udp_ports: Option<String>,
    udp_retries: u8,
    skip_discovery: bool,
    output: CliOutputFormat,
) -> ScanConfig {
    let port_range = parse_port_range(&ports).unwrap_or((1, 1000));
    let udp_port_range = udp_ports.as_ref().and_then(|p| parse_udp_ports(p).ok());

    ScanConfig {
        targets,
        port_range,
        threads,
        timeout: Duration::from_millis(timeout),
        scan_type: scan_type.into(),
        enable_os_detection: os_detect,
        enable_service_detection: service_detect,
        enable_vuln_scan: vuln_scan,
        enable_enumeration: enable_enum,
        enum_depth: enum_depth.into(),
        enum_wordlist_path: enum_wordlist.map(std::path::PathBuf::from),
        enum_services: Vec::new(), // Empty = enumerate all services
        output_format: output.into(),
        udp_port_range,
        udp_retries,
        skip_host_discovery: skip_discovery,
        // Use defaults for scanner-specific timeouts (will use config.timeout as fallback)
        service_detection_timeout: None,
        dns_timeout: None,
        syn_timeout: None,
        udp_timeout: None,
        // CLI doesn't support VPN (only web API does)
        vpn_config_id: None,
        exclusions: Vec::new(),
    }
}

/// Parse UDP ports from either a range (e.g., "1-500") or comma-separated list (e.g., "53,123,161")
fn parse_udp_ports(ports: &str) -> Result<(u16, u16)> {
    if ports.contains('-') {
        // Range format: "1-500"
        parse_port_range(ports)
    } else if ports.contains(',') {
        // Comma-separated list: "53,123,161"
        let port_list: Vec<u16> = ports
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect();

        if port_list.is_empty() {
            return Err(anyhow::anyhow!("No valid UDP ports specified"));
        }

        let min = *port_list.iter().min().unwrap();
        let max = *port_list.iter().max().unwrap();
        Ok((min, max))
    } else {
        // Single port
        let port: u16 = ports
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid UDP port"))?;
        Ok((port, port))
    }
}

fn parse_port_range(range: &str) -> Result<(u16, u16)> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid port range format"));
    }

    let start = parts[0]
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("Invalid start port"))?;
    let end = parts[1]
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("Invalid end port"))?;

    if start > end {
        return Err(anyhow::anyhow!("Start port must be less than end port"));
    }

    Ok((start, end))
}

async fn run_full_scan(
    config: ScanConfig,
    output_file: Option<String>,
    ci_mode: bool,
    fail_on: CliSeverity,
    output_sarif: Option<String>,
    output_junit: Option<String>,
) -> Result<()> {
    info!("Starting full network triage scan...");
    info!("Targets: {:?}", config.targets);
    info!("Port range: {}-{}", config.port_range.0, config.port_range.1);

    let results = scanner::run_scan(&config, None).await?;

    // Display normal output unless in CI mode with report outputs
    if !ci_mode || (output_sarif.is_none() && output_junit.is_none()) {
        output::display_results(&results, &config.output_format, output_file.as_deref())?;
    }

    // Generate SARIF report if requested
    if let Some(sarif_path) = output_sarif {
        let sarif = integrations::cicd::github_actions::generate_sarif_report(
            "cli-scan",
            &results,
            "HeroForge CLI Scan",
        )?;
        let sarif_json = serde_json::to_string_pretty(&sarif)?;
        std::fs::write(&sarif_path, sarif_json)?;
        if !ci_mode {
            println!("{}", format!("SARIF report saved to: {}", sarif_path).green());
        }
    }

    // Generate JUnit report if requested
    if let Some(junit_path) = output_junit {
        let junit = integrations::cicd::jenkins::generate_junit_report(
            "cli-scan",
            &results,
            "HeroForge CLI Scan",
            None,
        )?;
        std::fs::write(&junit_path, junit)?;
        if !ci_mode {
            println!("{}", format!("JUnit report saved to: {}", junit_path).green());
        }
    }

    // In CI mode, check vulnerabilities against threshold and exit with appropriate code
    if ci_mode {
        let fail_severity: types::Severity = fail_on.into();
        let mut should_fail = false;
        let mut fail_reason = String::new();

        for host in &results {
            for vuln in &host.vulnerabilities {
                if vuln.severity >= fail_severity {
                    should_fail = true;
                    fail_reason = format!(
                        "Found {} severity vulnerability: {}",
                        format!("{:?}", vuln.severity).to_uppercase(),
                        vuln.title
                    );
                    break;
                }
            }
            if should_fail {
                break;
            }
        }

        // Count vulnerabilities for summary
        let counts = integrations::cicd::count_vulnerabilities(&results);

        // Print CI summary
        println!("\n{}", "=== CI/CD Scan Summary ===".bright_cyan().bold());
        println!("  Critical: {}", if counts.critical > 0 { counts.critical.to_string().red() } else { counts.critical.to_string().normal() });
        println!("  High:     {}", if counts.high > 0 { counts.high.to_string().yellow() } else { counts.high.to_string().normal() });
        println!("  Medium:   {}", counts.medium);
        println!("  Low:      {}", counts.low);
        println!("  Total:    {}", counts.total);
        println!();

        if should_fail {
            error!("{}", format!("FAILED: {}", fail_reason).red().bold());
            std::process::exit(1);
        } else {
            println!("{}", "PASSED: No vulnerabilities above threshold".green().bold());
        }
    }

    Ok(())
}

async fn run_discovery(
    targets: Vec<String>,
    threads: usize,
    timeout: u64,
) -> Result<()> {
    info!("Starting host discovery...");

    let config = ScanConfig {
        targets,
        threads,
        timeout: Duration::from_millis(timeout),
        ..Default::default()
    };

    let live_hosts = scanner::host_discovery::discover_hosts(&config).await?;

    println!("\n{}", "Live Hosts Discovered:".green().bold());
    for host in &live_hosts {
        println!("  {} {}", "✓".green(), host.ip);
        if let Some(hostname) = &host.hostname {
            println!("    Hostname: {}", hostname.cyan());
        }
    }

    println!("\n{} hosts found", live_hosts.len().to_string().yellow().bold());

    Ok(())
}

async fn run_portscan(
    targets: Vec<String>,
    ports: String,
    threads: usize,
    scan_type: CliScanType,
    output: CliOutputFormat,
) -> Result<()> {
    info!("Starting port scan...");

    let port_range = parse_port_range(&ports)?;
    let config = ScanConfig {
        targets,
        port_range,
        threads,
        scan_type: scan_type.into(),
        output_format: output.into(),
        ..Default::default()
    };

    let results = scanner::port_scanner::scan_ports(&config).await?;

    output::display_port_results(&results, &config.output_format)?;

    Ok(())
}

fn generate_config(path: String) -> Result<()> {
    config::generate_default_config(&path)?;
    println!("{}", format!("Config file generated at: {}", path).green());
    Ok(())
}
