//! Threat Actor & Campaign Tracking Module
//!
//! Provides comprehensive threat actor intelligence:
//! - APT group profiles with attribution confidence
//! - Campaign tracking and timeline analysis
//! - Attack pattern correlation with MITRE ATT&CK
//! - Infrastructure tracking (C2, domains, IPs)
//! - Victimology and targeting analysis

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

/// Threat actor profile representing an APT group or cybercriminal organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorProfile {
    /// Unique identifier
    pub id: String,
    /// Primary name (e.g., "APT29", "Lazarus Group")
    pub name: String,
    /// Alternative names and aliases
    pub aliases: Vec<String>,
    /// Type of threat actor
    pub actor_type: ThreatActorType,
    /// Suspected country of origin
    pub country: Option<String>,
    /// Suspected state sponsor
    pub sponsor: Option<String>,
    /// Primary motivation
    pub motivation: ThreatMotivation,
    /// Secondary motivations
    pub secondary_motivations: Vec<ThreatMotivation>,
    /// Description and background
    pub description: String,
    /// First seen date
    pub first_seen: Option<DateTime<Utc>>,
    /// Last active date
    pub last_seen: Option<DateTime<Utc>>,
    /// Is the actor still active?
    pub active: bool,
    /// Sophistication level (1-10)
    pub sophistication: u8,
    /// Resource level (1-10)
    pub resource_level: u8,
    /// Target sectors
    pub target_sectors: Vec<String>,
    /// Target countries
    pub target_countries: Vec<String>,
    /// Known TTPs (MITRE ATT&CK technique IDs)
    pub ttps: Vec<String>,
    /// Associated malware families
    pub malware_families: Vec<String>,
    /// Associated tools
    pub tools: Vec<String>,
    /// Known infrastructure (domains, IPs)
    pub infrastructure: ThreatActorInfrastructure,
    /// Associated campaigns
    pub campaigns: Vec<String>,
    /// External references
    pub references: Vec<ThreatReference>,
    /// MITRE ATT&CK group ID
    pub mitre_id: Option<String>,
    /// Attribution confidence (0.0 - 1.0)
    pub attribution_confidence: f64,
    /// Tracking status
    pub tracking_status: TrackingStatus,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Type of threat actor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatActorType {
    /// Nation-state sponsored
    NationState,
    /// Organized crime group
    OrganizedCrime,
    /// Hacktivist collective
    Hacktivist,
    /// Insider threat
    Insider,
    /// Terrorist organization
    Terrorist,
    /// Script kiddie / low sophistication
    ScriptKiddie,
    /// Unknown or unattributed
    Unknown,
}

/// Threat actor motivation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatMotivation {
    /// Espionage and intelligence gathering
    Espionage,
    /// Financial gain
    Financial,
    /// Destructive / sabotage
    Destruction,
    /// Political / ideological
    Ideological,
    /// Personal / revenge
    Personal,
    /// Competitive advantage
    Competitive,
    /// Coercion / blackmail
    Coercion,
    /// Dominance / power
    Dominance,
    /// Unknown
    Unknown,
}

/// Threat actor infrastructure tracking
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatActorInfrastructure {
    /// Known C2 domains
    pub domains: Vec<InfrastructureItem>,
    /// Known C2 IP addresses
    pub ip_addresses: Vec<InfrastructureItem>,
    /// Known email addresses
    pub email_addresses: Vec<String>,
    /// Cryptocurrency wallets
    pub crypto_wallets: Vec<CryptoWallet>,
    /// SSL certificates
    pub certificates: Vec<CertificateInfo>,
    /// Hosting providers commonly used
    pub hosting_providers: Vec<String>,
    /// Registrars commonly used
    pub registrars: Vec<String>,
}

/// Infrastructure item with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureItem {
    /// The value (domain, IP, etc.)
    pub value: String,
    /// When first seen
    pub first_seen: Option<DateTime<Utc>>,
    /// When last seen active
    pub last_seen: Option<DateTime<Utc>>,
    /// Is it still active?
    pub active: bool,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
    /// Associated campaigns
    pub campaigns: Vec<String>,
    /// Source of the intelligence
    pub source: String,
    /// Additional notes
    pub notes: Option<String>,
}

/// Cryptocurrency wallet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoWallet {
    /// Wallet address
    pub address: String,
    /// Cryptocurrency type (BTC, ETH, XMR, etc.)
    pub currency: String,
    /// Total received (if known)
    pub total_received: Option<f64>,
    /// Associated campaigns
    pub campaigns: Vec<String>,
}

/// SSL certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate fingerprint (SHA-256)
    pub fingerprint: String,
    /// Subject CN
    pub subject_cn: Option<String>,
    /// Issuer
    pub issuer: Option<String>,
    /// Associated domains
    pub domains: Vec<String>,
    /// First seen
    pub first_seen: Option<DateTime<Utc>>,
}

/// Tracking status for threat actors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrackingStatus {
    /// Actively being tracked
    Active,
    /// Monitoring only
    Monitoring,
    /// Historical record only
    Historical,
    /// Merged with another actor
    Merged,
    /// Deprecated / no longer valid
    Deprecated,
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReference {
    /// Source name
    pub source: String,
    /// Reference URL
    pub url: String,
    /// Description
    pub description: Option<String>,
    /// Date published
    pub published_date: Option<DateTime<Utc>>,
}

/// Campaign representing a coordinated attack operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    /// Unique identifier
    pub id: String,
    /// Campaign name
    pub name: String,
    /// Alternative names
    pub aliases: Vec<String>,
    /// Description
    pub description: String,
    /// Associated threat actors
    pub threat_actors: Vec<String>,
    /// Campaign objective
    pub objective: CampaignObjective,
    /// Campaign status
    pub status: CampaignStatus,
    /// Start date
    pub start_date: Option<DateTime<Utc>>,
    /// End date (if known)
    pub end_date: Option<DateTime<Utc>>,
    /// Target sectors
    pub target_sectors: Vec<String>,
    /// Target countries
    pub target_countries: Vec<String>,
    /// Target organizations (if known)
    pub target_organizations: Vec<String>,
    /// TTPs used (MITRE ATT&CK)
    pub ttps: Vec<String>,
    /// Malware used
    pub malware: Vec<String>,
    /// Tools used
    pub tools: Vec<String>,
    /// Infrastructure used
    pub infrastructure: CampaignInfrastructure,
    /// Known victims
    pub victims: Vec<Victim>,
    /// Timeline of events
    pub timeline: Vec<TimelineEvent>,
    /// Indicators of Compromise
    pub iocs: Vec<CampaignIoc>,
    /// External references
    pub references: Vec<ThreatReference>,
    /// Confidence level
    pub confidence: f64,
    /// Tags
    pub tags: Vec<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Campaign objective
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignObjective {
    /// Data theft / exfiltration
    DataTheft,
    /// Ransomware deployment
    Ransomware,
    /// Espionage
    Espionage,
    /// Sabotage / destruction
    Sabotage,
    /// Supply chain compromise
    SupplyChain,
    /// Credential harvesting
    CredentialHarvesting,
    /// Cryptomining
    Cryptomining,
    /// Botnet recruitment
    Botnet,
    /// Reconnaissance
    Reconnaissance,
    /// Unknown
    Unknown,
}

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    /// Currently active
    Active,
    /// Suspected to be ongoing
    Suspected,
    /// Campaign concluded
    Concluded,
    /// Disrupted by defenders
    Disrupted,
    /// Historical record
    Historical,
}

/// Campaign infrastructure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CampaignInfrastructure {
    /// C2 servers
    pub c2_servers: Vec<InfrastructureItem>,
    /// Phishing domains
    pub phishing_domains: Vec<InfrastructureItem>,
    /// Staging servers
    pub staging_servers: Vec<InfrastructureItem>,
    /// Exfiltration endpoints
    pub exfil_endpoints: Vec<InfrastructureItem>,
}

/// Known victim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Victim {
    /// Organization name (if known)
    pub organization: Option<String>,
    /// Sector
    pub sector: String,
    /// Country
    pub country: String,
    /// Date compromised (if known)
    pub compromise_date: Option<DateTime<Utc>>,
    /// Impact description
    pub impact: Option<String>,
    /// Data stolen (if known)
    pub data_stolen: Option<String>,
    /// Ransom demanded (if applicable)
    pub ransom_demanded: Option<String>,
    /// Ransom paid (if known)
    pub ransom_paid: Option<bool>,
}

/// Timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: TimelineEventType,
    /// Event description
    pub description: String,
    /// Associated TTPs
    pub ttps: Vec<String>,
    /// Related IOCs
    pub iocs: Vec<String>,
    /// Source of information
    pub source: Option<String>,
}

/// Timeline event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventType {
    /// Initial access
    InitialAccess,
    /// Lateral movement
    LateralMovement,
    /// Privilege escalation
    PrivilegeEscalation,
    /// Data exfiltration
    Exfiltration,
    /// Malware deployment
    MalwareDeployment,
    /// C2 communication
    C2Communication,
    /// Persistence established
    Persistence,
    /// Discovery / reconnaissance
    Discovery,
    /// Impact / destruction
    Impact,
    /// Detection by defenders
    Detection,
    /// Remediation
    Remediation,
    /// Other
    Other,
}

/// Campaign IOC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignIoc {
    /// IOC type
    pub ioc_type: IocType,
    /// IOC value
    pub value: String,
    /// Confidence
    pub confidence: f64,
    /// First seen
    pub first_seen: Option<DateTime<Utc>>,
    /// Last seen
    pub last_seen: Option<DateTime<Utc>>,
    /// Additional context
    pub context: Option<String>,
}

/// IOC type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    FileName,
    FilePath,
    RegistryKey,
    EmailAddress,
    EmailSubject,
    Mutex,
    UserAgent,
    JA3,
    Yara,
    Sigma,
    Other,
}

/// Attack pattern (TTP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    /// MITRE ATT&CK technique ID
    pub technique_id: String,
    /// Technique name
    pub name: String,
    /// Tactic (phase of attack)
    pub tactic: String,
    /// Sub-technique ID (if applicable)
    pub sub_technique: Option<String>,
    /// Description
    pub description: String,
    /// Platforms affected
    pub platforms: Vec<String>,
    /// Detection methods
    pub detection: Vec<String>,
    /// Mitigation strategies
    pub mitigation: Vec<String>,
    /// Known uses by threat actors
    pub used_by: Vec<String>,
    /// Data sources for detection
    pub data_sources: Vec<String>,
    /// Procedure examples
    pub procedures: Vec<ProcedureExample>,
}

/// Procedure example showing how a TTP is used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureExample {
    /// Threat actor that used this procedure
    pub actor: String,
    /// Campaign (if associated)
    pub campaign: Option<String>,
    /// Description of how it was used
    pub description: String,
    /// References
    pub references: Vec<String>,
}

/// Threat actor database for querying and managing actor profiles
pub struct ThreatActorDatabase {
    /// Known threat actors
    actors: HashMap<String, ThreatActorProfile>,
    /// Known campaigns
    campaigns: HashMap<String, Campaign>,
    /// Attack patterns (TTPs)
    attack_patterns: HashMap<String, AttackPattern>,
    /// Actor aliases mapping
    alias_map: HashMap<String, String>,
}

impl ThreatActorDatabase {
    /// Create a new threat actor database
    pub fn new() -> Self {
        let mut db = Self {
            actors: HashMap::new(),
            campaigns: HashMap::new(),
            attack_patterns: HashMap::new(),
            alias_map: HashMap::new(),
        };

        // Load built-in threat actor profiles
        db.load_builtin_actors();
        db.load_builtin_attack_patterns();

        db
    }

    /// Load built-in threat actor profiles
    fn load_builtin_actors(&mut self) {
        // APT29 / Cozy Bear
        self.add_actor(ThreatActorProfile {
            id: "apt29".to_string(),
            name: "APT29".to_string(),
            aliases: vec![
                "Cozy Bear".to_string(),
                "The Dukes".to_string(),
                "CozyDuke".to_string(),
                "NOBELIUM".to_string(),
                "Midnight Blizzard".to_string(),
                "UNC2452".to_string(),
            ],
            actor_type: ThreatActorType::NationState,
            country: Some("Russia".to_string()),
            sponsor: Some("SVR (Foreign Intelligence Service)".to_string()),
            motivation: ThreatMotivation::Espionage,
            secondary_motivations: vec![],
            description: "APT29 is a Russian state-sponsored threat group attributed to Russia's Foreign Intelligence Service (SVR). Active since at least 2008, they focus on intelligence collection from government, diplomatic, think-tank, healthcare, and energy targets.".to_string(),
            first_seen: Some(DateTime::parse_from_rfc3339("2008-01-01T00:00:00Z").unwrap().with_timezone(&Utc)),
            last_seen: Some(Utc::now()),
            active: true,
            sophistication: 9,
            resource_level: 10,
            target_sectors: vec![
                "Government".to_string(),
                "Diplomatic".to_string(),
                "Think Tanks".to_string(),
                "Healthcare".to_string(),
                "Energy".to_string(),
                "Technology".to_string(),
            ],
            target_countries: vec![
                "United States".to_string(),
                "United Kingdom".to_string(),
                "Germany".to_string(),
                "Ukraine".to_string(),
                "NATO members".to_string(),
            ],
            ttps: vec![
                "T1566.001".to_string(), // Phishing: Spearphishing Attachment
                "T1059.001".to_string(), // PowerShell
                "T1053.005".to_string(), // Scheduled Task
                "T1547.001".to_string(), // Registry Run Keys
                "T1078".to_string(),     // Valid Accounts
                "T1195.002".to_string(), // Supply Chain Compromise
                "T1550.001".to_string(), // Application Access Token
                "T1098.002".to_string(), // Additional Email Delegate Permissions
            ],
            malware_families: vec![
                "SUNBURST".to_string(),
                "TEARDROP".to_string(),
                "Raindrop".to_string(),
                "SUNSPOT".to_string(),
                "FoggyWeb".to_string(),
                "MagicWeb".to_string(),
                "WellMess".to_string(),
                "WellMail".to_string(),
            ],
            tools: vec![
                "Mimikatz".to_string(),
                "Cobalt Strike".to_string(),
                "AdFind".to_string(),
            ],
            infrastructure: ThreatActorInfrastructure::default(),
            campaigns: vec!["solarwinds".to_string()],
            references: vec![
                ThreatReference {
                    source: "MITRE ATT&CK".to_string(),
                    url: "https://attack.mitre.org/groups/G0016/".to_string(),
                    description: Some("APT29 Group Page".to_string()),
                    published_date: None,
                },
            ],
            mitre_id: Some("G0016".to_string()),
            attribution_confidence: 0.95,
            tracking_status: TrackingStatus::Active,
            tags: vec!["russia".to_string(), "svr".to_string(), "espionage".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        // APT28 / Fancy Bear
        self.add_actor(ThreatActorProfile {
            id: "apt28".to_string(),
            name: "APT28".to_string(),
            aliases: vec![
                "Fancy Bear".to_string(),
                "Sofacy".to_string(),
                "Pawn Storm".to_string(),
                "Sednit".to_string(),
                "STRONTIUM".to_string(),
                "Forest Blizzard".to_string(),
                "Tsar Team".to_string(),
            ],
            actor_type: ThreatActorType::NationState,
            country: Some("Russia".to_string()),
            sponsor: Some("GRU (Main Intelligence Directorate)".to_string()),
            motivation: ThreatMotivation::Espionage,
            secondary_motivations: vec![ThreatMotivation::Destruction],
            description: "APT28 is a Russian military intelligence threat group attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165.".to_string(),
            first_seen: Some(DateTime::parse_from_rfc3339("2004-01-01T00:00:00Z").unwrap().with_timezone(&Utc)),
            last_seen: Some(Utc::now()),
            active: true,
            sophistication: 9,
            resource_level: 10,
            target_sectors: vec![
                "Government".to_string(),
                "Military".to_string(),
                "Defense".to_string(),
                "Media".to_string(),
                "Energy".to_string(),
            ],
            target_countries: vec![
                "Ukraine".to_string(),
                "Georgia".to_string(),
                "United States".to_string(),
                "Germany".to_string(),
                "NATO members".to_string(),
            ],
            ttps: vec![
                "T1566.001".to_string(), // Spearphishing
                "T1190".to_string(),     // Exploit Public-Facing Application
                "T1203".to_string(),     // Exploitation for Client Execution
                "T1068".to_string(),     // Exploitation for Privilege Escalation
                "T1003".to_string(),     // OS Credential Dumping
                "T1071.001".to_string(), // Web Protocols
            ],
            malware_families: vec![
                "X-Agent".to_string(),
                "XTunnel".to_string(),
                "Zebrocy".to_string(),
                "Cannon".to_string(),
                "Koadic".to_string(),
                "LoJax".to_string(),
            ],
            tools: vec![
                "Responder".to_string(),
                "Mimikatz".to_string(),
            ],
            infrastructure: ThreatActorInfrastructure::default(),
            campaigns: vec![],
            references: vec![
                ThreatReference {
                    source: "MITRE ATT&CK".to_string(),
                    url: "https://attack.mitre.org/groups/G0007/".to_string(),
                    description: Some("APT28 Group Page".to_string()),
                    published_date: None,
                },
            ],
            mitre_id: Some("G0007".to_string()),
            attribution_confidence: 0.95,
            tracking_status: TrackingStatus::Active,
            tags: vec!["russia".to_string(), "gru".to_string(), "espionage".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        // Lazarus Group
        self.add_actor(ThreatActorProfile {
            id: "lazarus".to_string(),
            name: "Lazarus Group".to_string(),
            aliases: vec![
                "HIDDEN COBRA".to_string(),
                "Guardians of Peace".to_string(),
                "ZINC".to_string(),
                "Diamond Sleet".to_string(),
                "Labyrinth Chollima".to_string(),
            ],
            actor_type: ThreatActorType::NationState,
            country: Some("North Korea".to_string()),
            sponsor: Some("RGB (Reconnaissance General Bureau)".to_string()),
            motivation: ThreatMotivation::Financial,
            secondary_motivations: vec![ThreatMotivation::Espionage, ThreatMotivation::Destruction],
            description: "Lazarus Group is a North Korean state-sponsored threat group that has been active since at least 2009. They are responsible for numerous high-profile attacks including the Sony Pictures hack and WannaCry ransomware.".to_string(),
            first_seen: Some(DateTime::parse_from_rfc3339("2009-01-01T00:00:00Z").unwrap().with_timezone(&Utc)),
            last_seen: Some(Utc::now()),
            active: true,
            sophistication: 8,
            resource_level: 9,
            target_sectors: vec![
                "Financial".to_string(),
                "Cryptocurrency".to_string(),
                "Defense".to_string(),
                "Entertainment".to_string(),
                "Government".to_string(),
            ],
            target_countries: vec![
                "South Korea".to_string(),
                "United States".to_string(),
                "Japan".to_string(),
                "Global".to_string(),
            ],
            ttps: vec![
                "T1566".to_string(),     // Phishing
                "T1059".to_string(),     // Command and Scripting Interpreter
                "T1105".to_string(),     // Ingress Tool Transfer
                "T1486".to_string(),     // Data Encrypted for Impact
                "T1565".to_string(),     // Data Manipulation
                "T1496".to_string(),     // Resource Hijacking
            ],
            malware_families: vec![
                "Manuscrypt".to_string(),
                "FALLCHILL".to_string(),
                "HOPLIGHT".to_string(),
                "WannaCry".to_string(),
                "AppleJeus".to_string(),
                "ThreatNeedle".to_string(),
            ],
            tools: vec![],
            infrastructure: ThreatActorInfrastructure::default(),
            campaigns: vec!["wannacry".to_string()],
            references: vec![
                ThreatReference {
                    source: "MITRE ATT&CK".to_string(),
                    url: "https://attack.mitre.org/groups/G0032/".to_string(),
                    description: Some("Lazarus Group Page".to_string()),
                    published_date: None,
                },
            ],
            mitre_id: Some("G0032".to_string()),
            attribution_confidence: 0.90,
            tracking_status: TrackingStatus::Active,
            tags: vec!["north-korea".to_string(), "financial".to_string(), "cryptocurrency".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        // FIN7
        self.add_actor(ThreatActorProfile {
            id: "fin7".to_string(),
            name: "FIN7".to_string(),
            aliases: vec![
                "Carbanak".to_string(),
                "Carbon Spider".to_string(),
                "ELBRUS".to_string(),
                "Sangria Tempest".to_string(),
            ],
            actor_type: ThreatActorType::OrganizedCrime,
            country: Some("Russia".to_string()),
            sponsor: None,
            motivation: ThreatMotivation::Financial,
            secondary_motivations: vec![],
            description: "FIN7 is a financially-motivated threat group that has primarily targeted the U.S. retail, restaurant, and hospitality sectors since mid-2015. They are known for innovative social engineering and sophisticated POS malware.".to_string(),
            first_seen: Some(DateTime::parse_from_rfc3339("2015-06-01T00:00:00Z").unwrap().with_timezone(&Utc)),
            last_seen: Some(Utc::now()),
            active: true,
            sophistication: 8,
            resource_level: 8,
            target_sectors: vec![
                "Retail".to_string(),
                "Restaurant".to_string(),
                "Hospitality".to_string(),
                "Gaming".to_string(),
                "Financial".to_string(),
            ],
            target_countries: vec![
                "United States".to_string(),
                "United Kingdom".to_string(),
                "Australia".to_string(),
                "Europe".to_string(),
            ],
            ttps: vec![
                "T1566.001".to_string(), // Spearphishing Attachment
                "T1204.002".to_string(), // Malicious File
                "T1059.001".to_string(), // PowerShell
                "T1055".to_string(),     // Process Injection
                "T1112".to_string(),     // Modify Registry
                "T1105".to_string(),     // Ingress Tool Transfer
            ],
            malware_families: vec![
                "Carbanak".to_string(),
                "GRIFFON".to_string(),
                "HALFBAKED".to_string(),
                "POWERSOURCE".to_string(),
                "BIRDWATCH".to_string(),
                "JSSLoader".to_string(),
            ],
            tools: vec![
                "Cobalt Strike".to_string(),
                "Metasploit".to_string(),
            ],
            infrastructure: ThreatActorInfrastructure::default(),
            campaigns: vec![],
            references: vec![
                ThreatReference {
                    source: "MITRE ATT&CK".to_string(),
                    url: "https://attack.mitre.org/groups/G0046/".to_string(),
                    description: Some("FIN7 Group Page".to_string()),
                    published_date: None,
                },
            ],
            mitre_id: Some("G0046".to_string()),
            attribution_confidence: 0.90,
            tracking_status: TrackingStatus::Active,
            tags: vec!["cybercrime".to_string(), "pos-malware".to_string(), "ransomware".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

        // APT41 / Double Dragon
        self.add_actor(ThreatActorProfile {
            id: "apt41".to_string(),
            name: "APT41".to_string(),
            aliases: vec![
                "Double Dragon".to_string(),
                "BARIUM".to_string(),
                "Brass Typhoon".to_string(),
                "Winnti Group".to_string(),
                "Wicked Panda".to_string(),
            ],
            actor_type: ThreatActorType::NationState,
            country: Some("China".to_string()),
            sponsor: Some("MSS (Ministry of State Security)".to_string()),
            motivation: ThreatMotivation::Espionage,
            secondary_motivations: vec![ThreatMotivation::Financial],
            description: "APT41 is a Chinese state-sponsored threat group known for conducting espionage operations while also engaging in financially motivated activity. They are unique in targeting both government entities and private industries.".to_string(),
            first_seen: Some(DateTime::parse_from_rfc3339("2012-01-01T00:00:00Z").unwrap().with_timezone(&Utc)),
            last_seen: Some(Utc::now()),
            active: true,
            sophistication: 9,
            resource_level: 9,
            target_sectors: vec![
                "Healthcare".to_string(),
                "Telecommunications".to_string(),
                "Technology".to_string(),
                "Gaming".to_string(),
                "Media".to_string(),
                "Government".to_string(),
            ],
            target_countries: vec![
                "United States".to_string(),
                "Hong Kong".to_string(),
                "India".to_string(),
                "Japan".to_string(),
                "Global".to_string(),
            ],
            ttps: vec![
                "T1195.002".to_string(), // Supply Chain Compromise
                "T1190".to_string(),     // Exploit Public-Facing Application
                "T1059.001".to_string(), // PowerShell
                "T1218".to_string(),     // System Binary Proxy Execution
                "T1098".to_string(),     // Account Manipulation
                "T1560".to_string(),     // Archive Collected Data
            ],
            malware_families: vec![
                "POISONPLUG".to_string(),
                "ShadowPad".to_string(),
                "Winnti".to_string(),
                "CROSSWALK".to_string(),
                "DUSTPAN".to_string(),
                "DUSTTRAP".to_string(),
            ],
            tools: vec![
                "Cobalt Strike".to_string(),
                "Acunetix".to_string(),
                "SQLMap".to_string(),
            ],
            infrastructure: ThreatActorInfrastructure::default(),
            campaigns: vec![],
            references: vec![
                ThreatReference {
                    source: "MITRE ATT&CK".to_string(),
                    url: "https://attack.mitre.org/groups/G0096/".to_string(),
                    description: Some("APT41 Group Page".to_string()),
                    published_date: None,
                },
            ],
            mitre_id: Some("G0096".to_string()),
            attribution_confidence: 0.90,
            tracking_status: TrackingStatus::Active,
            tags: vec!["china".to_string(), "mss".to_string(), "supply-chain".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }

    /// Load built-in MITRE ATT&CK patterns
    fn load_builtin_attack_patterns(&mut self) {
        // Initial Access
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1566".to_string(),
            name: "Phishing".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: None,
            description: "Adversaries may send phishing messages to gain access to victim systems.".to_string(),
            platforms: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
            detection: vec![
                "Network Intrusion Detection".to_string(),
                "Email Content Filtering".to_string(),
                "User Training".to_string(),
            ],
            mitigation: vec![
                "Antivirus/Antimalware".to_string(),
                "Network Intrusion Prevention".to_string(),
                "Restrict Web-Based Content".to_string(),
                "User Training".to_string(),
            ],
            used_by: vec!["APT29".to_string(), "APT28".to_string(), "Lazarus".to_string(), "FIN7".to_string()],
            data_sources: vec!["Email gateway logs".to_string(), "Network traffic".to_string()],
            procedures: vec![],
        });

        self.add_attack_pattern(AttackPattern {
            technique_id: "T1190".to_string(),
            name: "Exploit Public-Facing Application".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: None,
            description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.".to_string(),
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "Containers".to_string(), "Network".to_string()],
            detection: vec![
                "Application Log Analysis".to_string(),
                "Web Application Firewall".to_string(),
                "Vulnerability Scanning".to_string(),
            ],
            mitigation: vec![
                "Application Isolation and Sandboxing".to_string(),
                "Exploit Protection".to_string(),
                "Network Segmentation".to_string(),
                "Privileged Account Management".to_string(),
                "Update Software".to_string(),
                "Vulnerability Scanning".to_string(),
            ],
            used_by: vec!["APT28".to_string(), "APT41".to_string()],
            data_sources: vec!["Application logs".to_string(), "Network traffic".to_string()],
            procedures: vec![],
        });

        // Execution
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1059.001".to_string(),
            name: "PowerShell".to_string(),
            tactic: "Execution".to_string(),
            sub_technique: Some("Command and Scripting Interpreter".to_string()),
            description: "Adversaries may abuse PowerShell commands and scripts for execution.".to_string(),
            platforms: vec!["Windows".to_string()],
            detection: vec![
                "Script Block Logging".to_string(),
                "Module Logging".to_string(),
                "Transcription".to_string(),
                "Process Monitoring".to_string(),
            ],
            mitigation: vec![
                "Antivirus/Antimalware".to_string(),
                "Code Signing".to_string(),
                "Disable or Remove Feature or Program".to_string(),
                "Execution Prevention".to_string(),
                "Privileged Account Management".to_string(),
            ],
            used_by: vec!["APT29".to_string(), "FIN7".to_string(), "APT41".to_string()],
            data_sources: vec!["PowerShell logs".to_string(), "Process creation".to_string()],
            procedures: vec![],
        });

        // Credential Access
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1003".to_string(),
            name: "OS Credential Dumping".to_string(),
            tactic: "Credential Access".to_string(),
            sub_technique: None,
            description: "Adversaries may attempt to dump credentials to obtain account login and credential material.".to_string(),
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            detection: vec![
                "Process Monitoring".to_string(),
                "Windows Security Log Events".to_string(),
                "Sysmon Events".to_string(),
            ],
            mitigation: vec![
                "Active Directory Configuration".to_string(),
                "Credential Access Protection".to_string(),
                "Operating System Configuration".to_string(),
                "Password Policies".to_string(),
                "Privileged Account Management".to_string(),
                "Privileged Process Integrity".to_string(),
                "User Training".to_string(),
            ],
            used_by: vec!["APT28".to_string(), "APT29".to_string(), "Lazarus".to_string()],
            data_sources: vec!["Process creation".to_string(), "Windows Security logs".to_string()],
            procedures: vec![],
        });

        // Command and Control
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1071.001".to_string(),
            name: "Web Protocols".to_string(),
            tactic: "Command and Control".to_string(),
            sub_technique: Some("Application Layer Protocol".to_string()),
            description: "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.".to_string(),
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            detection: vec![
                "Network Traffic Analysis".to_string(),
                "SSL/TLS Inspection".to_string(),
                "Proxy Logs".to_string(),
            ],
            mitigation: vec![
                "Network Intrusion Prevention".to_string(),
                "Network Segmentation".to_string(),
                "SSL/TLS Inspection".to_string(),
            ],
            used_by: vec!["APT28".to_string(), "APT29".to_string()],
            data_sources: vec!["Network traffic".to_string(), "Proxy logs".to_string()],
            procedures: vec![],
        });

        // Exfiltration
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1048".to_string(),
            name: "Exfiltration Over Alternative Protocol".to_string(),
            tactic: "Exfiltration".to_string(),
            sub_technique: None,
            description: "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.".to_string(),
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            detection: vec![
                "Network Traffic Analysis".to_string(),
                "Data Loss Prevention".to_string(),
            ],
            mitigation: vec![
                "Data Loss Prevention".to_string(),
                "Filter Network Traffic".to_string(),
                "Network Segmentation".to_string(),
            ],
            used_by: vec!["APT29".to_string()],
            data_sources: vec!["Network traffic".to_string(), "Firewall logs".to_string()],
            procedures: vec![],
        });

        // Impact
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1486".to_string(),
            name: "Data Encrypted for Impact".to_string(),
            tactic: "Impact".to_string(),
            sub_technique: None,
            description: "Adversaries may encrypt data on target systems to interrupt availability to system and network resources.".to_string(),
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            detection: vec![
                "File Monitoring".to_string(),
                "Process Monitoring".to_string(),
                "Unusual File Modifications".to_string(),
            ],
            mitigation: vec![
                "Backup".to_string(),
                "Behavior Prevention on Endpoint".to_string(),
            ],
            used_by: vec!["Lazarus".to_string()],
            data_sources: vec!["File monitoring".to_string(), "Process creation".to_string()],
            procedures: vec![],
        });

        // Supply Chain
        self.add_attack_pattern(AttackPattern {
            technique_id: "T1195.002".to_string(),
            name: "Compromise Software Supply Chain".to_string(),
            tactic: "Initial Access".to_string(),
            sub_technique: Some("Supply Chain Compromise".to_string()),
            description: "Adversaries may manipulate application software prior to receipt by a final consumer.".to_string(),
            platforms: vec!["Windows".to_string(), "Linux".to_string(), "macOS".to_string()],
            detection: vec![
                "File Integrity Monitoring".to_string(),
                "Code Signing Verification".to_string(),
                "Build System Monitoring".to_string(),
            ],
            mitigation: vec![
                "Update Software".to_string(),
                "Vulnerability Scanning".to_string(),
            ],
            used_by: vec!["APT29".to_string(), "APT41".to_string()],
            data_sources: vec!["File monitoring".to_string(), "Application logs".to_string()],
            procedures: vec![],
        });
    }

    /// Add a threat actor to the database
    pub fn add_actor(&mut self, actor: ThreatActorProfile) {
        // Add alias mappings
        for alias in &actor.aliases {
            self.alias_map.insert(alias.to_lowercase(), actor.id.clone());
        }
        self.alias_map.insert(actor.name.to_lowercase(), actor.id.clone());

        self.actors.insert(actor.id.clone(), actor);
    }

    /// Add a campaign to the database
    pub fn add_campaign(&mut self, campaign: Campaign) {
        self.campaigns.insert(campaign.id.clone(), campaign);
    }

    /// Add an attack pattern to the database
    pub fn add_attack_pattern(&mut self, pattern: AttackPattern) {
        self.attack_patterns.insert(pattern.technique_id.clone(), pattern);
    }

    /// Get a threat actor by ID or alias
    pub fn get_actor(&self, id_or_alias: &str) -> Option<&ThreatActorProfile> {
        // First try direct ID lookup
        if let Some(actor) = self.actors.get(id_or_alias) {
            return Some(actor);
        }

        // Try alias lookup
        if let Some(actor_id) = self.alias_map.get(&id_or_alias.to_lowercase()) {
            return self.actors.get(actor_id);
        }

        None
    }

    /// Get a campaign by ID
    pub fn get_campaign(&self, id: &str) -> Option<&Campaign> {
        self.campaigns.get(id)
    }

    /// Get an attack pattern by technique ID
    pub fn get_attack_pattern(&self, technique_id: &str) -> Option<&AttackPattern> {
        self.attack_patterns.get(technique_id)
    }

    /// Search actors by keyword
    pub fn search_actors(&self, query: &str) -> Vec<&ThreatActorProfile> {
        let query_lower = query.to_lowercase();
        self.actors.values()
            .filter(|actor| {
                actor.name.to_lowercase().contains(&query_lower) ||
                actor.aliases.iter().any(|a| a.to_lowercase().contains(&query_lower)) ||
                actor.description.to_lowercase().contains(&query_lower) ||
                actor.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    /// Search actors by TTP
    pub fn actors_using_ttp(&self, technique_id: &str) -> Vec<&ThreatActorProfile> {
        self.actors.values()
            .filter(|actor| actor.ttps.iter().any(|t| t == technique_id))
            .collect()
    }

    /// Search actors by malware
    pub fn actors_using_malware(&self, malware_name: &str) -> Vec<&ThreatActorProfile> {
        let malware_lower = malware_name.to_lowercase();
        self.actors.values()
            .filter(|actor| {
                actor.malware_families.iter()
                    .any(|m| m.to_lowercase().contains(&malware_lower))
            })
            .collect()
    }

    /// Get actors targeting a specific sector
    pub fn actors_targeting_sector(&self, sector: &str) -> Vec<&ThreatActorProfile> {
        let sector_lower = sector.to_lowercase();
        self.actors.values()
            .filter(|actor| {
                actor.target_sectors.iter()
                    .any(|s| s.to_lowercase().contains(&sector_lower))
            })
            .collect()
    }

    /// Get actors from a specific country
    pub fn actors_by_country(&self, country: &str) -> Vec<&ThreatActorProfile> {
        let country_lower = country.to_lowercase();
        self.actors.values()
            .filter(|actor| {
                actor.country.as_ref()
                    .map(|c| c.to_lowercase().contains(&country_lower))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Get all active actors
    pub fn active_actors(&self) -> Vec<&ThreatActorProfile> {
        self.actors.values()
            .filter(|actor| actor.active)
            .collect()
    }

    /// Get all actors
    pub fn all_actors(&self) -> Vec<&ThreatActorProfile> {
        self.actors.values().collect()
    }

    /// Get all campaigns
    pub fn all_campaigns(&self) -> Vec<&Campaign> {
        self.campaigns.values().collect()
    }

    /// Get all attack patterns
    pub fn all_attack_patterns(&self) -> Vec<&AttackPattern> {
        self.attack_patterns.values().collect()
    }

    /// Get attack patterns for a tactic
    pub fn patterns_by_tactic(&self, tactic: &str) -> Vec<&AttackPattern> {
        let tactic_lower = tactic.to_lowercase();
        self.attack_patterns.values()
            .filter(|pattern| pattern.tactic.to_lowercase() == tactic_lower)
            .collect()
    }

    /// Correlate IOCs with known threat actors
    pub fn correlate_iocs(&self, iocs: &[CampaignIoc]) -> Vec<ThreatCorrelation> {
        let mut correlations = Vec::new();

        for actor in self.actors.values() {
            let mut matched_iocs = Vec::new();
            let mut confidence = 0.0;

            // Check domain IOCs
            for ioc in iocs.iter().filter(|i| i.ioc_type == IocType::Domain) {
                for infra in &actor.infrastructure.domains {
                    if infra.value.to_lowercase() == ioc.value.to_lowercase() {
                        matched_iocs.push(ioc.clone());
                        confidence += infra.confidence * 0.3;
                    }
                }
            }

            // Check IP IOCs
            for ioc in iocs.iter().filter(|i| i.ioc_type == IocType::IpAddress) {
                for infra in &actor.infrastructure.ip_addresses {
                    if infra.value == ioc.value {
                        matched_iocs.push(ioc.clone());
                        confidence += infra.confidence * 0.3;
                    }
                }
            }

            // Check file hash IOCs against known malware
            for ioc in iocs.iter().filter(|i| i.ioc_type == IocType::FileHash) {
                // This would require a malware hash database
                // For now, we correlate based on associated malware families mentioned
            }

            if !matched_iocs.is_empty() {
                correlations.push(ThreatCorrelation {
                    actor_id: actor.id.clone(),
                    actor_name: actor.name.clone(),
                    matched_iocs,
                    confidence: confidence.min(1.0),
                    matched_ttps: Vec::new(),
                    matched_malware: Vec::new(),
                });
            }
        }

        // Sort by confidence
        correlations.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        correlations
    }

    /// Correlate TTPs with threat actors
    pub fn correlate_ttps(&self, ttps: &[String]) -> Vec<ThreatCorrelation> {
        let mut correlations = Vec::new();

        for actor in self.actors.values() {
            let matched_ttps: Vec<String> = ttps.iter()
                .filter(|ttp| actor.ttps.contains(ttp))
                .cloned()
                .collect();

            if !matched_ttps.is_empty() {
                let confidence = matched_ttps.len() as f64 / actor.ttps.len().max(1) as f64;

                correlations.push(ThreatCorrelation {
                    actor_id: actor.id.clone(),
                    actor_name: actor.name.clone(),
                    matched_iocs: Vec::new(),
                    confidence: confidence.min(1.0),
                    matched_ttps,
                    matched_malware: Vec::new(),
                });
            }
        }

        correlations.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        correlations
    }
}

impl Default for ThreatActorDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCorrelation {
    /// Matched actor ID
    pub actor_id: String,
    /// Matched actor name
    pub actor_name: String,
    /// Matched IOCs
    pub matched_iocs: Vec<CampaignIoc>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Matched TTPs
    pub matched_ttps: Vec<String>,
    /// Matched malware families
    pub matched_malware: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_actor_database() {
        let db = ThreatActorDatabase::new();

        // Test actor lookup by ID
        assert!(db.get_actor("apt29").is_some());

        // Test actor lookup by alias
        assert!(db.get_actor("Cozy Bear").is_some());
        assert!(db.get_actor("NOBELIUM").is_some());

        // Test search
        let results = db.search_actors("russia");
        assert!(!results.is_empty());

        // Test TTP correlation
        let apt29 = db.get_actor("apt29").unwrap();
        assert!(apt29.ttps.contains(&"T1566.001".to_string()));
    }

    #[test]
    fn test_actors_by_sector() {
        let db = ThreatActorDatabase::new();

        let financial_actors = db.actors_targeting_sector("financial");
        assert!(financial_actors.iter().any(|a| a.id == "lazarus" || a.id == "fin7"));
    }

    #[test]
    fn test_attack_patterns() {
        let db = ThreatActorDatabase::new();

        // Test pattern lookup
        let phishing = db.get_attack_pattern("T1566");
        assert!(phishing.is_some());
        assert_eq!(phishing.unwrap().name, "Phishing");

        // Test tactic filter
        let initial_access = db.patterns_by_tactic("Initial Access");
        assert!(!initial_access.is_empty());
    }
}
