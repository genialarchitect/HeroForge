//! Red Team - Offensive Security Operations
//!
//! This module provides a unified facade for all offensive security capabilities.
//! Red Team operations focus on simulating real-world attacks to identify vulnerabilities
//! and weaknesses in systems, networks, and applications.
//!
//! ## Core Capabilities
//!
//! ### Network Reconnaissance & Scanning
//! - Host discovery (ARP, ICMP, TCP probes)
//! - Port scanning (TCP Connect, SYN stealth, UDP)
//! - Service detection and version fingerprinting
//! - OS fingerprinting
//! - SSL/TLS certificate and cipher analysis
//! - DNS reconnaissance and zone transfers
//!
//! ### Web Application Security
//! - Crawling and spidering
//! - SQL injection testing
//! - Cross-site scripting (XSS) detection
//! - Security header analysis
//! - Form analysis and CSRF detection
//! - Secret/credential detection
//!
//! ### Cloud Security
//! - AWS security scanning (IAM, S3, EC2, RDS)
//! - Azure security scanning (storage, network, RBAC)
//! - GCP security scanning (IAM, compute, storage)
//!
//! ### Container Security
//! - Docker image vulnerability scanning
//! - Dockerfile security analysis
//! - Kubernetes manifest analysis
//! - Kubernetes cluster security assessment
//!
//! ### Exploitation
//! - Password spraying and credential testing
//! - Kerberos attacks (Kerberoasting, AS-REP roasting)
//! - Reverse shell generation
//! - Post-exploitation modules
//! - Tunneling (DNS, HTTPS, ICMP C2)
//! - Payload encoding and AV evasion
//!
//! ### Specialized Assessments
//! - Active Directory assessment
//! - BloodHound integration for attack path analysis
//! - Wireless security (WPA/WPA2 cracking, rogue AP detection)
//! - IoT device security
//! - OT/ICS industrial control systems
//! - CI/CD pipeline security
//! - Infrastructure as Code scanning
//!
//! ### Password Cracking
//! - Native hash attacks (MD5, SHA, NTLM, bcrypt, etc.)
//! - Hashcat and John the Ripper integration
//! - Wordlist management
//!
//! ### Research & Intelligence
//! - Exploit database integration (ExploitDB, Metasploit)
//! - PoC repository management
//! - CVE research and mapping
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::red_team;
//!
//! // Access scanner capabilities
//! let scan_result = red_team::scanner::run_scan(&config).await?;
//!
//! // Access exploitation framework
//! let campaign = red_team::exploitation::ExploitationEngine::new();
//!
//! // Access C2 framework
//! let c2 = red_team::c2::C2Manager::new();
//! ```

#![allow(unused_imports)]

// =============================================================================
// CORE SCANNING ENGINE
// =============================================================================

/// Core network scanning and reconnaissance
pub(crate) use crate::scanner;

// Re-export key scanner components for convenience
pub mod scanning {
    //! Network scanning and reconnaissance tools

    pub use crate::scanner::{
        run_scan,
        host_discovery,
        port_scanner,
        syn_scanner,
        service_detection,
        os_fingerprint,
        udp_scanner,
    };

    // SSL/TLS analysis
    pub use crate::scanner::ssl_scanner;
    pub use crate::scanner::tls_analysis;

    // DNS reconnaissance
    pub use crate::scanner::dns_recon;
    pub use crate::scanner::dns_analysis;

    // Scan comparison
    pub use crate::scanner::comparison;
}

// =============================================================================
// WEB APPLICATION SECURITY
// =============================================================================

/// Web application security testing
pub mod webapp {
    //! Web application vulnerability scanning
    //!
    //! Includes crawling, SQLi, XSS, header analysis, form testing, and secret detection

    pub use crate::scanner::webapp::*;
}

// =============================================================================
// CLOUD SECURITY
// =============================================================================

/// Multi-cloud security scanning
pub mod cloud {
    //! AWS, Azure, and GCP security assessment

    pub use crate::scanner::cloud::*;
}

// =============================================================================
// CONTAINER & KUBERNETES SECURITY
// =============================================================================

/// Container and Kubernetes security
pub mod container {
    //! Docker and Kubernetes security scanning

    pub use crate::scanner::container::*;
}

// =============================================================================
// EXPLOITATION FRAMEWORK
// =============================================================================

/// Exploitation and post-exploitation
pub mod exploitation {
    //! Exploitation framework including password spray, Kerberos attacks,
    //! shell generation, post-exploitation, tunneling, and evasion

    pub use crate::scanner::exploitation::*;
}

// =============================================================================
// COMMAND & CONTROL
// =============================================================================

/// C2 framework integration
pub(crate) use crate::c2;

// =============================================================================
// PASSWORD CRACKING
// =============================================================================

/// Password cracking and hash attacks
pub(crate) use crate::cracking;

// =============================================================================
// PHISHING CAMPAIGNS
// =============================================================================

/// Phishing campaign management (offensive)
pub(crate) use crate::phishing;

// =============================================================================
// FUZZING
// =============================================================================

/// Protocol, HTTP, and file format fuzzing
pub(crate) use crate::fuzzing;

// =============================================================================
// SPECIALIZED ASSESSMENTS
// =============================================================================

/// Active Directory security assessment
pub mod ad_assessment {
    //! Active Directory enumeration and security checks

    pub use crate::scanner::ad_assessment::*;
}

/// BloodHound integration
pub mod bloodhound {
    //! BloodHound data import and attack path analysis

    pub use crate::scanner::bloodhound::*;
}

/// Wireless security assessment
pub mod wireless {
    //! Wireless network reconnaissance and cracking

    pub use crate::scanner::wireless::*;
    pub use crate::scanner::wireless_native::*;
}

/// IoT device security
pub(crate) use crate::iot;

/// OT/ICS industrial control systems
pub(crate) use crate::ot_ics;

/// CI/CD pipeline security
pub mod cicd {
    //! CI/CD pipeline security scanning

    pub use crate::scanner::cicd::*;
}

/// Infrastructure as Code security
pub mod iac {
    //! Terraform, CloudFormation, ARM template scanning

    pub use crate::scanner::iac::*;
}

/// Privilege escalation detection
pub mod privesc {
    //! Linux and Windows privilege escalation vectors

    pub use crate::scanner::privesc::*;
}

/// Credential auditing
pub mod credential_audit {
    //! Default credential testing and password policy auditing

    pub use crate::scanner::credential_audit::*;
}

/// Breach detection
pub mod breach_detection {
    //! HIBP, Dehashed, and local breach database integration

    pub use crate::scanner::breach_detection::*;
}

/// Git repository reconnaissance
pub mod git_recon {
    //! Git repository security scanning

    pub use crate::scanner::git_recon::*;
}

/// API security testing
pub mod api_security {
    //! API endpoint scanning and OpenAPI analysis

    pub use crate::scanner::api_security::*;
}

/// YARA rule scanning
pub mod yara {
    //! YARA rule matching for malware detection

    pub use crate::scanner::yara::*;
}

/// Nuclei template scanning
pub mod nuclei {
    //! ProjectDiscovery Nuclei template engine

    pub use crate::scanner::nuclei::*;
}

/// Attack path analysis
pub mod attack_paths {
    //! Attack path discovery and risk analysis

    pub use crate::scanner::attack_paths::*;
}

/// Breach and attack simulation
pub mod bas {
    //! Automated breach and attack simulation with MITRE ATT&CK

    pub use crate::scanner::bas::*;
}

/// Google dorking and OSINT
pub mod dorks {
    //! Search engine dorking and reconnaissance

    pub use crate::scanner::dorks::*;
}

/// Secret detection
pub mod secrets {
    //! API key, token, and credential detection in code

    pub use crate::scanner::secret_detection::*;
}

// =============================================================================
// RESEARCH & INTELLIGENCE
// =============================================================================

/// Exploit research and database integration
pub(crate) use crate::exploit_research;

/// Binary analysis
pub(crate) use crate::binary_analysis;

/// Malware analysis
pub(crate) use crate::malware_analysis;

// =============================================================================
// SUPPORTING INFRASTRUCTURE
// =============================================================================

/// Service enumeration modules
pub mod enumeration {
    //! Service-specific enumeration (HTTP, DNS, SMB, FTP, SSH, SNMP)

    pub use crate::scanner::enumeration::*;
}

/// Asset discovery
pub mod asset_discovery {
    //! Certificate transparency, WHOIS, Shodan integration

    pub use crate::scanner::asset_discovery::*;
}

/// IDS signature matching
pub mod ids {
    //! Intrusion detection signature testing

    pub use crate::scanner::ids::*;
}
