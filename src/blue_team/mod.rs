//! Blue Team - Defensive Security Operations
//!
//! This module provides a unified facade for all defensive security capabilities.
//! Blue Team operations focus on detecting, analyzing, and responding to threats
//! to protect systems, networks, and applications.
//!
//! ## Core Capabilities
//!
//! ### SIEM (Security Information and Event Management)
//! - Log collection (Syslog, HTTP, agents)
//! - Log parsing (CEF, LEEF, JSON, syslog RFC 3164/5424)
//! - Detection rules and Sigma rule support
//! - Real-time correlation engine
//! - Alert management and dashboards
//! - UEBA (User Entity Behavior Analytics)
//!
//! ### Detection Engineering
//! - Detection-as-Code definitions
//! - MITRE ATT&CK coverage mapping
//! - False positive management
//! - Detection testing framework
//!
//! ### Incident Response
//! - Incident lifecycle management
//! - Event timeline builder
//! - Evidence collection with chain of custody
//! - Response playbook automation
//!
//! ### Threat Hunting
//! - IOC management
//! - MITRE ATT&CK integration
//! - Hunting playbooks
//! - Retrospective search
//! - Hypothesis-driven hunting
//! - Hunt automation
//!
//! ### Digital Forensics
//! - Memory analysis (native and Volatility)
//! - Disk analysis and timeline
//! - Network forensics
//! - Artifact collection
//!
//! ### Network Analysis
//! - Traffic analysis (PCAP, protocols, IDS)
//! - DNS analytics (DGA, tunneling, fast-flux)
//! - NetFlow/IPFIX/sFlow analysis
//! - Beacon detection and C2 analysis
//!
//! ### Threat Intelligence
//! - Shodan and Censys integration
//! - ExploitDB and CVE feeds
//! - MISP and STIX/TAXII support
//! - Threat actor tracking
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::blue_team;
//!
//! // Access SIEM capabilities
//! let siem = blue_team::siem::IngestionService::new(storage, config);
//!
//! // Access threat hunting
//! let ioc = blue_team::hunting::IocManager::new(pool);
//!
//! // Access forensics
//! let memory_analysis = blue_team::forensics::memory_native::analyze_dump(&path)?;
//! ```

#![allow(unused_imports)]

// =============================================================================
// SIEM (SECURITY INFORMATION AND EVENT MANAGEMENT)
// =============================================================================

/// Full SIEM capabilities including log collection, parsing, and alerting
pub(crate) use crate::siem;

/// Re-export key SIEM components for convenience
pub mod security_monitoring {
    //! Log collection, parsing, correlation, and alerting

    // Core SIEM types
    pub use crate::siem::{
        // Ingestion
        IngestionConfig, IngestionHandle, IngestionMessage, IngestionService,
        // Parsing
        LogParser,
        // Storage
        LogStorage, StorageStats,
        // Core types
        AlertStatus, IngestionStats, LogEntry, LogFormat, LogQuery, LogQueryResult,
        LogSource, LogSourceStatus, RuleStatus, RuleType, SiemAlert, SiemId,
        SiemRule, SiemSeverity, SyslogFacility, TransportProtocol,
    };

    // Sigma rules
    pub use crate::siem::{
        CompiledSigmaRule, SigmaParser, SigmaRule, SigmaSeverity, SigmaStatus,
        SigmaValidationResult,
    };

    // Sigma conversion
    pub use crate::siem::{
        convert_to_all_backends, ConversionResult, FieldMappings, SigmaBackend,
        SigmaConverter,
    };

    // Correlation engine
    pub use crate::siem::{
        CorrelationAlert, CorrelationEngine, CorrelationRule, CorrelationRuleType,
        CorrelationStats,
    };

    // Dashboard and alerting
    pub use crate::siem::{
        AlertDeduplicator, AlertGroup, AlertWorkflow, DashboardOverview,
        DashboardWidget, DeduplicationConfig, SavedSearch, SeverityScorer,
        SiemDashboard, TimeRange, WidgetType,
    };
}

/// User and Entity Behavior Analytics
pub mod ueba {
    //! Behavioral analytics for threat detection

    pub use crate::siem::ueba::{
        // Engine
        UebaEngine, UebaEngineConfig, ProcessActivityResult, DetectedAnomaly,
        // Entities
        EntityType, UebaEntity, CreateEntityRequest, UpdateEntityRequest,
        // Peer groups
        UebaPeerGroup, PeerGroupCriteria, CreatePeerGroupRequest,
        // Activities
        ActivityType, UebaActivity, RecordActivityRequest,
        // Anomalies
        AnomalyType, AnomalyStatus, UebaAnomaly, AnomalyEvidence, UpdateAnomalyRequest,
        // Risk
        RiskLevel, RiskFactorType, UebaRiskFactor,
        // Baselines
        UebaBaseline, MetricCategory,
        // Sessions
        UebaSession, RecordSessionRequest,
        // Dashboard
        UebaDashboardStats, AnomalyTypeCount, RiskDistribution, EntityRiskSummary,
        // Misc
        GeoLocation, ListEntitiesQuery, ListAnomaliesQuery, ListActivitiesQuery,
    };
}

// =============================================================================
// DETECTION ENGINEERING
// =============================================================================

/// Detection rule development and management
pub(crate) use crate::detection_engineering;

/// Re-export detection engineering components
pub mod detections {
    //! Detection-as-Code, coverage mapping, and testing

    // Detection definitions
    pub use crate::detection_engineering::{
        Detection, DetectionSeverity, DetectionStatus, DetectionLogic,
        DetectionMetadata, DataSource, DetectionVersion,
    };

    // Coverage mapping
    pub use crate::detection_engineering::{
        CoverageMapping, CoverageType, CoverageGap, CoverageScore,
        TacticCoverage, TechniqueCoverage,
    };

    // False positive management
    pub use crate::detection_engineering::{
        FalsePositive, FalsePositiveStatus, FalsePositivePattern,
        TuningRecommendation, TuningType,
    };

    // Testing framework
    pub use crate::detection_engineering::{
        DetectionTest, TestCase, TestResult, TestType,
        SampleLogGenerator, TestRun,
    };
}

// =============================================================================
// INCIDENT RESPONSE
// =============================================================================

/// Incident response and management
pub(crate) use crate::incident_response;

/// Re-export incident response components
pub mod incidents {
    //! Incident lifecycle, timeline, evidence, and automation

    pub use crate::incident_response::*;
}

// =============================================================================
// THREAT HUNTING
// =============================================================================

/// Threat hunting operations
pub(crate) use crate::threat_hunting;

/// Re-export threat hunting components
pub mod hunting {
    //! IOC management, playbooks, hypothesis testing, and analytics

    pub use crate::threat_hunting::{
        // IOC management
        ioc::*,
        // MITRE ATT&CK
        mitre::*,
        // Playbooks
        playbooks::*,
        // Retrospective search
        retrospective::*,
        // Types
        types::*,
        // Hypothesis
        hypothesis::*,
        // Query DSL
        query_dsl::*,
        // Analytics
        analytics::*,
        // Automation
        automation::*,
        // Collaboration
        collaboration::*,
    };
}

// =============================================================================
// DIGITAL FORENSICS
// =============================================================================

/// Digital forensics capabilities
pub(crate) use crate::forensics;

/// Re-export forensics components
pub mod forensic_analysis {
    //! Memory, disk, network forensics, and artifact collection

    // Core types
    pub use crate::forensics::types::*;

    // Memory analysis
    pub use crate::forensics::memory::*;

    // Native memory forensics
    pub use crate::forensics::memory_native;

    // Disk analysis
    pub use crate::forensics::disk::*;

    // Network forensics
    pub use crate::forensics::network::*;

    // Artifact collection
    pub use crate::forensics::artifacts::*;

    // Volatility integration
    pub use crate::forensics::{
        VolatilityClient, VolatilityConfig, VolatilityAnalysis, VolatilityVersion,
        VolProcess, VolConnection, VolModule, VolMalfind, MemoryDumpInfo,
    };
}

// =============================================================================
// NETWORK TRAFFIC ANALYSIS
// =============================================================================

/// Network traffic analysis
pub(crate) use crate::traffic_analysis;

/// Re-export traffic analysis components
pub mod traffic {
    //! PCAP parsing, protocol analysis, IDS, and credential extraction

    // Core types
    pub use crate::traffic_analysis::types::*;

    // PCAP parsing
    pub use crate::traffic_analysis::PcapParser;

    // Protocol analysis
    pub use crate::traffic_analysis::ProtocolAnalyzer;

    // IDS engine
    pub use crate::traffic_analysis::{IdsEngine, load_emerging_threats_rules};

    // TLS fingerprinting
    pub use crate::traffic_analysis::Ja3Fingerprinter;

    // Beacon detection
    pub use crate::traffic_analysis::BeaconDetector;

    // File carving
    pub use crate::traffic_analysis::FileCarver;

    // Credential extraction
    pub use crate::traffic_analysis::{CredentialExtractor, NetworkCredential, NetworkCredType};
}

// =============================================================================
// DNS ANALYTICS
// =============================================================================

/// DNS security analytics
pub(crate) use crate::dns_analytics;

/// Re-export DNS analytics components
pub mod dns {
    //! DGA detection, tunneling, fast-flux, and passive DNS

    // Core types
    pub use crate::dns_analytics::{
        DnsRecordType, DnsResponseCode, PassiveDnsRecord, DnsThreatType,
        DnsAnomaly, DnsAnomalyType, DnsAnomalySeverity, DnsAnomalyStatus,
        TunnelIndicators, FastFluxIndicators, DgaAnalysis, DgaConfidence,
        NewlyObservedDomain, NodStatus, NodStats, NodAlert, NodAlertSeverity,
        DnsBaseline, DnsBaselineType, BaselinePeriod,
        DnsQuery, DnsStats, DomainCount, QueryTypeCount, ClientQueryCount, TimeSeriesPoint,
        DnsThreatIntel, ThreatIntelSource,
        DnsCollectorConfig, DnsCollectorType,
        DnsDashboard,
    };

    // Detectors
    pub use crate::dns_analytics::{
        DgaDetector, DgaConfig,
        TunnelDetector, TunnelDetectorConfig,
        FastFluxDetector, FastFluxConfig, DnsResolution,
        PassiveDnsStore, PassiveDnsConfig,
        NodTracker, NodConfig,
        WhoisClient, WhoisConfig, WhoisResult, WhoisError,
    };

    // Analytics engine
    pub use crate::dns_analytics::DnsAnalyticsEngine;
}

// =============================================================================
// NETFLOW ANALYSIS
// =============================================================================

/// NetFlow/IPFIX/sFlow analysis
pub(crate) use crate::netflow;

/// Re-export NetFlow components
pub mod flows {
    //! Flow collection, parsing, aggregation, and anomaly detection

    // Core types
    pub use crate::netflow::{
        CollectorType, CollectorStatus, FlowCollector,
        IpProtocol, TcpFlags, GeoLocation,
        FlowRecord, FlowRecordRow,
        AggregationPeriod, FlowAggregate,
        TopTalker, PortCount, ProtocolDistribution,
        FlowAnomalyType, FlowAnomaly,
        BandwidthUtilization, FlowStats, FlowTimelineEntry,
        port_to_application, is_suspicious_port,
    };

    // Parser
    pub use crate::netflow::{
        ParseError, ParsedFlow, TemplateCache,
        parse_netflow_v5, parse_netflow_v9, parse_ipfix, parse_sflow,
    };

    // Collector
    pub use crate::netflow::{
        FlowCollectorManager, CollectorStats, CollectorError,
        UniversalCollector, detect_flow_protocol,
    };

    // Analyzer
    pub use crate::netflow::{FlowAnalyzer, AnalyzerConfig};
}

// =============================================================================
// THREAT INTELLIGENCE
// =============================================================================

/// Threat intelligence feeds and enrichment
pub(crate) use crate::threat_intel;

/// Re-export threat intel components
pub mod intel {
    //! Shodan, Censys, ExploitDB, CVE feeds, MISP, STIX/TAXII

    // Core types
    pub use crate::threat_intel::types::*;

    // Manager
    pub use crate::threat_intel::{ThreatIntelManager, ApiStatus, ShodanApiStatus};

    // Shodan
    pub use crate::threat_intel::ShodanClient;

    // Censys
    pub use crate::threat_intel::{
        CensysClient, CensysHostInfo, CensysService, CensysCertificate,
        merge_host_intel, MergedHostIntel,
    };

    // ExploitDB
    pub use crate::threat_intel::ExploitDbClient;

    // CVE feeds
    pub use crate::threat_intel::CveFeedsClient;

    // MISP
    pub use crate::threat_intel::{MispClient, MispEvent, MispAttribute};

    // STIX/TAXII
    pub use crate::threat_intel::{StixBundle, StixObject, TaxiiClient};

    // Threat actors
    pub use crate::threat_intel::{ThreatActorDatabase, ThreatActorProfile, Campaign, AttackPattern};

    // Enhanced TI platform (P2 Sprint 3)
    pub use crate::threat_intel::aggregation;
    pub use crate::threat_intel::correlation;
    pub use crate::threat_intel::scoring;
    pub use crate::threat_intel::dissemination;
    pub use crate::threat_intel::lifecycle;
}

// =============================================================================
// SCANNER DEFENSIVE FEATURES
// =============================================================================

/// IDS signature matching (from scanner)
pub mod ids {
    //! Intrusion detection signature testing

    pub use crate::scanner::ids::*;
}

/// YARA rule scanning (from scanner)
pub mod yara {
    //! YARA rule matching for malware detection

    pub use crate::scanner::yara::*;
}

// =============================================================================
// AI-POWERED DEFENSE
// =============================================================================

/// AI/ML for defensive operations
pub mod ai_defense {
    //! AI-powered threat detection and analysis

    pub use crate::ai::AIPrioritizationManager;
}
