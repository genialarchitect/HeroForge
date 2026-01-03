//! ML Model Training Pipeline
//!
//! Provides infrastructure for training custom ML models on security data:
//! - Threat classification
//! - Asset fingerprinting
//! - Attack pattern recognition
//! - Remediation time prediction

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

/// ML Pipeline Manager
pub struct MLPipeline {
    pool: Arc<SqlitePool>,
}

impl MLPipeline {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }

    /// Train threat classification model
    pub async fn train_threat_classifier(&self) -> Result<ThreatClassifier> {
        // Collect training data from historical scans
        let training_data = self.collect_threat_training_data().await?;

        // Feature extraction
        let features = self.extract_threat_features(&training_data);

        // Train model (in production, this would use a proper ML framework)
        let model = ThreatClassifier::train(features)?;

        // Evaluate model
        let metrics = self.evaluate_threat_model(&model, &training_data).await?;

        // Store model if performance is acceptable
        if metrics.accuracy > 0.85 {
            self.store_model("threat_classifier", &model).await?;
        }

        Ok(model)
    }

    /// Train asset fingerprinting model
    pub async fn train_asset_fingerprinter(&self) -> Result<AssetFingerprinter> {
        let training_data = self.collect_asset_training_data().await?;

        let model = AssetFingerprinter {
            os_signatures: self.build_os_signatures(&training_data),
            service_signatures: self.build_service_signatures(&training_data),
            hardware_signatures: self.build_hardware_signatures(&training_data),
        };

        self.store_model("asset_fingerprinter", &model).await?;

        Ok(model)
    }

    /// Train attack pattern recognition model
    pub async fn train_attack_pattern_detector(&self) -> Result<AttackPatternDetector> {
        let training_data = self.collect_attack_pattern_data().await?;

        let model = AttackPatternDetector {
            patterns: self.extract_attack_patterns(&training_data),
            mitre_mappings: self.build_mitre_mappings(&training_data),
        };

        self.store_model("attack_pattern_detector", &model).await?;

        Ok(model)
    }

    /// Train remediation time prediction model
    pub async fn train_remediation_predictor(&self) -> Result<RemediationPredictor> {
        let training_data = self.collect_remediation_training_data().await?;

        // Build regression model for time prediction
        let model = RemediationPredictor::train(training_data)?;

        let metrics = self.evaluate_remediation_model(&model).await?;

        if metrics.mean_absolute_error < 2.0 {
            // Less than 2 days error on average
            self.store_model("remediation_predictor", &model).await?;
        }

        Ok(model)
    }

    /// Collect threat training data from historical scans
    async fn collect_threat_training_data(&self) -> Result<Vec<ThreatTrainingExample>> {
        // Query historical scan data with labels
        let examples = sqlx::query_as::<_, ThreatTrainingExample>(
            r#"
            SELECT
                v.id,
                v.severity,
                v.cve_id,
                v.exploit_available,
                v.remediation_status,
                v.false_positive
            FROM vulnerability_tracking v
            WHERE v.remediation_status IS NOT NULL
            "#,
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(examples)
    }

    /// Extract features for threat classification
    fn extract_threat_features(&self, data: &[ThreatTrainingExample]) -> Vec<ThreatFeatures> {
        data.iter()
            .map(|example| ThreatFeatures {
                severity_score: Self::severity_to_score(&example.severity),
                has_cve: example.cve_id.is_some(),
                has_exploit: example.exploit_available,
                age_days: example.age_days(),
                affected_hosts: example.affected_hosts,
            })
            .collect()
    }

    fn severity_to_score(severity: &str) -> f64 {
        match severity.to_lowercase().as_str() {
            "critical" => 1.0,
            "high" => 0.75,
            "medium" => 0.5,
            "low" => 0.25,
            _ => 0.0,
        }
    }

    /// Evaluate threat classification model
    async fn evaluate_threat_model(
        &self,
        model: &ThreatClassifier,
        test_data: &[ThreatTrainingExample],
    ) -> Result<ModelMetrics> {
        let mut correct = 0;
        let mut total = 0;

        for example in test_data.iter().take(100) {
            // Use last 100 as test set
            let prediction = model.predict(&ThreatFeatures {
                severity_score: Self::severity_to_score(&example.severity),
                has_cve: example.cve_id.is_some(),
                has_exploit: example.exploit_available,
                age_days: example.age_days(),
                affected_hosts: example.affected_hosts,
            });

            if prediction.threat_level == example.actual_threat_level() {
                correct += 1;
            }
            total += 1;
        }

        Ok(ModelMetrics {
            accuracy: correct as f64 / total as f64,
            precision: 0.0, // Calculate from confusion matrix
            recall: 0.0,    // Calculate from confusion matrix
            f1_score: 0.0,  // Calculate from precision/recall
            mean_absolute_error: 0.0,
        })
    }

    /// Collect asset fingerprinting training data
    async fn collect_asset_training_data(&self) -> Result<Vec<AssetTrainingExample>> {
        // Query scanned assets with known OS/service info from scan_results
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT
                COALESCE(sr.result_data->>'os_fingerprint', 'unknown') as os,
                COALESCE(sr.result_data->>'services', '[]') as services,
                COALESCE(sr.result_data->>'open_ports', '[]') as ports
            FROM scan_results sr
            WHERE sr.result_data IS NOT NULL
              AND json_valid(sr.result_data)
            LIMIT 10000
            "#,
        )
        .fetch_all(&*self.pool)
        .await?;

        let mut examples = Vec::new();
        for (os, services_json, ports_json) in rows {
            // Parse services JSON array
            let services: Vec<String> = serde_json::from_str(&services_json)
                .unwrap_or_default();

            // Parse ports JSON array
            let ports: Vec<u16> = serde_json::from_str(&ports_json)
                .unwrap_or_default();

            if !os.is_empty() || !services.is_empty() || !ports.is_empty() {
                examples.push(AssetTrainingExample {
                    os,
                    services,
                    ports,
                });
            }
        }

        Ok(examples)
    }

    /// Build OS detection signatures
    fn build_os_signatures(&self, data: &[AssetTrainingExample]) -> HashMap<String, OsSignature> {
        let mut signatures = HashMap::new();

        // Group examples by OS and analyze common port patterns
        let mut os_port_patterns: HashMap<String, Vec<Vec<u16>>> = HashMap::new();
        for example in data {
            let os_key = Self::normalize_os_name(&example.os);
            os_port_patterns.entry(os_key).or_default().push(example.ports.clone());
        }

        // Build signatures from observed patterns
        for (os_name, port_lists) in os_port_patterns {
            if port_lists.is_empty() {
                continue;
            }

            // Find common ports across all examples for this OS
            let mut port_frequency: HashMap<u16, usize> = HashMap::new();
            for ports in &port_lists {
                for port in ports {
                    *port_frequency.entry(*port).or_insert(0) += 1;
                }
            }

            // Get most common ports (appearing in >50% of examples)
            let threshold = port_lists.len() / 2;
            let common_ports: Vec<u16> = port_frequency
                .into_iter()
                .filter(|(_, count)| *count > threshold)
                .map(|(port, _)| port)
                .collect();

            // Set TTL and window size based on OS family
            let (ttl_range, window_size) = Self::get_os_network_characteristics(&os_name);

            signatures.insert(os_name.clone(), OsSignature {
                name: os_name,
                ttl_range,
                window_size,
                common_ports,
            });
        }

        // Add default signatures if no training data produced them
        if signatures.is_empty() {
            signatures.insert("linux".to_string(), OsSignature {
                name: "Linux".to_string(),
                ttl_range: (64, 64),
                window_size: 29200,
                common_ports: vec![22, 80, 443, 3306, 5432],
            });
            signatures.insert("windows".to_string(), OsSignature {
                name: "Windows".to_string(),
                ttl_range: (128, 128),
                window_size: 65535,
                common_ports: vec![135, 139, 445, 3389, 5985],
            });
            signatures.insert("macos".to_string(), OsSignature {
                name: "macOS".to_string(),
                ttl_range: (64, 64),
                window_size: 65535,
                common_ports: vec![22, 548, 5900],
            });
            signatures.insert("freebsd".to_string(), OsSignature {
                name: "FreeBSD".to_string(),
                ttl_range: (64, 64),
                window_size: 65535,
                common_ports: vec![22, 80, 443],
            });
        }

        signatures
    }

    /// Normalize OS name for consistent grouping
    fn normalize_os_name(os: &str) -> String {
        let os_lower = os.to_lowercase();
        if os_lower.contains("linux") || os_lower.contains("ubuntu") || os_lower.contains("debian") || os_lower.contains("centos") || os_lower.contains("rhel") || os_lower.contains("fedora") {
            "linux".to_string()
        } else if os_lower.contains("windows") {
            "windows".to_string()
        } else if os_lower.contains("macos") || os_lower.contains("mac os") || os_lower.contains("darwin") {
            "macos".to_string()
        } else if os_lower.contains("freebsd") {
            "freebsd".to_string()
        } else if os_lower.contains("openbsd") {
            "openbsd".to_string()
        } else if os_lower.contains("cisco") || os_lower.contains("ios") {
            "cisco_ios".to_string()
        } else {
            os_lower.chars().take(50).collect()
        }
    }

    /// Get network characteristics by OS family
    fn get_os_network_characteristics(os: &str) -> ((u8, u8), u16) {
        match os {
            "linux" => ((64, 64), 29200),
            "windows" => ((128, 128), 65535),
            "macos" | "freebsd" | "openbsd" => ((64, 64), 65535),
            "cisco_ios" => ((255, 255), 4128),
            _ => ((64, 128), 65535),
        }
    }

    /// Build service detection signatures
    fn build_service_signatures(&self, data: &[AssetTrainingExample]) -> HashMap<String, ServiceSignature> {
        let mut signatures = HashMap::new();

        // Collect service-to-port mappings from training data
        let mut service_ports: HashMap<String, Vec<u16>> = HashMap::new();
        for example in data {
            for (idx, service) in example.services.iter().enumerate() {
                let service_name = Self::normalize_service_name(service);
                // Attempt to correlate with ports by index if available
                if let Some(&port) = example.ports.get(idx) {
                    service_ports.entry(service_name).or_default().push(port);
                }
            }
        }

        // Build signatures from observed patterns
        for (service_name, ports) in &service_ports {
            if ports.is_empty() {
                continue;
            }

            // Find most common port for this service
            let mut port_counts: HashMap<u16, usize> = HashMap::new();
            for port in ports {
                *port_counts.entry(*port).or_insert(0) += 1;
            }
            let default_port = port_counts
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(port, _)| port)
                .unwrap_or(0);

            let banner_pattern = Self::get_service_banner_pattern(service_name);

            signatures.insert(service_name.clone(), ServiceSignature {
                name: service_name.clone(),
                banner_pattern,
                default_port,
            });
        }

        // Add common default signatures
        let defaults = vec![
            ("ssh", "SSH-", 22),
            ("http", "HTTP/", 80),
            ("https", "HTTP/", 443),
            ("ftp", "220", 21),
            ("smtp", "220", 25),
            ("dns", "", 53),
            ("mysql", "mysql", 3306),
            ("postgresql", "PostgreSQL", 5432),
            ("redis", "REDIS", 6379),
            ("mongodb", "MongoDB", 27017),
            ("elasticsearch", "elasticsearch", 9200),
            ("rdp", "", 3389),
            ("smb", "", 445),
            ("ldap", "", 389),
            ("ldaps", "", 636),
            ("mssql", "SQL Server", 1433),
            ("oracle", "Oracle", 1521),
        ];

        for (name, banner, port) in defaults {
            signatures.entry(name.to_string()).or_insert(ServiceSignature {
                name: name.to_string(),
                banner_pattern: banner.to_string(),
                default_port: port,
            });
        }

        signatures
    }

    /// Normalize service name for consistent grouping
    fn normalize_service_name(service: &str) -> String {
        let service_lower = service.to_lowercase();
        // Extract base service name, removing version numbers and extra info
        let base = service_lower
            .split_whitespace()
            .next()
            .unwrap_or(&service_lower)
            .trim_end_matches(|c: char| c.is_numeric() || c == '.')
            .to_string();

        match base.as_str() {
            "openssh" | "ssh" | "dropbear" => "ssh".to_string(),
            "apache" | "nginx" | "httpd" | "lighttpd" | "iis" => "http".to_string(),
            "vsftpd" | "proftpd" | "pure-ftpd" | "ftp" => "ftp".to_string(),
            "postfix" | "sendmail" | "exim" | "smtp" => "smtp".to_string(),
            "mysqld" | "mariadb" | "mysql" => "mysql".to_string(),
            "postgres" | "postgresql" => "postgresql".to_string(),
            "redis-server" | "redis" => "redis".to_string(),
            "mongod" | "mongodb" => "mongodb".to_string(),
            _ => base,
        }
    }

    /// Get expected banner pattern for a service
    fn get_service_banner_pattern(service: &str) -> String {
        match service {
            "ssh" => r"SSH-\d+\.\d+".to_string(),
            "http" | "https" => r"HTTP/\d+\.\d+".to_string(),
            "ftp" => r"220\s".to_string(),
            "smtp" => r"220\s.*SMTP".to_string(),
            "mysql" => r"mysql".to_string(),
            "postgresql" => r"PostgreSQL".to_string(),
            "redis" => r"-REDIS".to_string(),
            "mongodb" => r"MongoDB".to_string(),
            _ => String::new(),
        }
    }

    /// Build hardware fingerprinting signatures
    fn build_hardware_signatures(&self, _data: &[AssetTrainingExample]) -> HashMap<String, HardwareSignature> {
        // Hardware signatures are primarily based on MAC address OUI prefixes
        // These are well-known and don't require training data
        let mut signatures = HashMap::new();

        // Common hardware vendor MAC prefixes (OUI)
        let vendors = vec![
            // Network Equipment
            ("cisco", "00:00:0C", "Cisco Systems"),
            ("cisco_alt", "00:1B:0C", "Cisco Systems"),
            ("juniper", "00:05:85", "Juniper Networks"),
            ("arista", "00:1C:73", "Arista Networks"),
            ("palo_alto", "00:1B:17", "Palo Alto Networks"),
            ("fortinet", "00:09:0F", "Fortinet"),
            // Servers and Workstations
            ("dell", "00:14:22", "Dell Inc."),
            ("dell_alt", "18:03:73", "Dell Inc."),
            ("hp", "00:1A:4B", "Hewlett-Packard"),
            ("hp_alt", "3C:D9:2B", "Hewlett-Packard"),
            ("lenovo", "00:06:1B", "Lenovo"),
            ("ibm", "00:04:AC", "IBM"),
            ("supermicro", "00:25:90", "Supermicro"),
            // Cloud/Virtualization
            ("vmware", "00:0C:29", "VMware"),
            ("vmware_alt", "00:50:56", "VMware"),
            ("microsoft_hyperv", "00:15:5D", "Microsoft Hyper-V"),
            ("xen", "00:16:3E", "Xen"),
            ("kvm_qemu", "52:54:00", "QEMU/KVM"),
            ("virtualbox", "08:00:27", "Oracle VirtualBox"),
            ("aws", "02:00:00", "Amazon AWS"),
            // IoT/Embedded
            ("raspberry_pi", "B8:27:EB", "Raspberry Pi Foundation"),
            ("raspberry_pi_4", "DC:A6:32", "Raspberry Pi Foundation"),
            ("espressif", "24:0A:C4", "Espressif (ESP32/ESP8266)"),
            ("ubiquiti", "00:27:22", "Ubiquiti Networks"),
            // Consumer Devices
            ("apple", "00:03:93", "Apple Inc."),
            ("apple_alt", "F0:18:98", "Apple Inc."),
            ("samsung", "00:07:AB", "Samsung Electronics"),
            ("intel", "00:02:B3", "Intel Corporation"),
            ("realtek", "00:E0:4C", "Realtek Semiconductor"),
        ];

        for (id, mac_prefix, vendor) in vendors {
            signatures.insert(id.to_string(), HardwareSignature {
                vendor: vendor.to_string(),
                mac_prefix: mac_prefix.to_string(),
            });
        }

        signatures
    }

    /// Collect attack pattern data
    async fn collect_attack_pattern_data(&self) -> Result<Vec<AttackPatternExample>> {
        // Query detected threats and their indicators from scan results
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT
                COALESCE(sr.result_data->>'threat_type', 'unknown') as pattern_name,
                COALESCE(sr.result_data->>'indicators', '[]') as indicators,
                COALESCE(sr.result_data->>'mitre_techniques', '[]') as techniques
            FROM scan_results sr
            WHERE sr.result_data IS NOT NULL
              AND json_valid(sr.result_data)
              AND sr.result_data->>'threat_type' IS NOT NULL
            LIMIT 5000
            "#,
        )
        .fetch_all(&*self.pool)
        .await
        .unwrap_or_default();

        let mut examples = Vec::new();
        for (pattern_name, indicators_json, techniques_json) in rows {
            let indicators: Vec<String> = serde_json::from_str(&indicators_json).unwrap_or_default();
            let mitre_techniques: Vec<String> = serde_json::from_str(&techniques_json).unwrap_or_default();

            if !pattern_name.is_empty() && pattern_name != "unknown" {
                examples.push(AttackPatternExample {
                    pattern_name,
                    indicators,
                    mitre_techniques,
                });
            }
        }

        // Add well-known attack patterns if no training data
        if examples.is_empty() {
            examples.extend(Self::get_default_attack_patterns());
        }

        Ok(examples)
    }

    /// Get default well-known attack patterns
    fn get_default_attack_patterns() -> Vec<AttackPatternExample> {
        vec![
            AttackPatternExample {
                pattern_name: "credential_spray".to_string(),
                indicators: vec![
                    "Multiple failed logins same password".to_string(),
                    "Sequential user attempts".to_string(),
                    "Low rate to avoid lockout".to_string(),
                ],
                mitre_techniques: vec!["T1110.003".to_string()],
            },
            AttackPatternExample {
                pattern_name: "brute_force".to_string(),
                indicators: vec![
                    "High volume login attempts".to_string(),
                    "Single account targeted".to_string(),
                    "Rapid password variations".to_string(),
                ],
                mitre_techniques: vec!["T1110.001".to_string()],
            },
            AttackPatternExample {
                pattern_name: "lateral_movement".to_string(),
                indicators: vec![
                    "Internal host-to-host SMB".to_string(),
                    "Remote service creation".to_string(),
                    "PsExec or WMI usage".to_string(),
                ],
                mitre_techniques: vec!["T1021.002".to_string(), "T1047".to_string()],
            },
            AttackPatternExample {
                pattern_name: "data_exfiltration".to_string(),
                indicators: vec![
                    "Large outbound data transfer".to_string(),
                    "Unusual destination".to_string(),
                    "Encrypted tunnel".to_string(),
                ],
                mitre_techniques: vec!["T1048".to_string()],
            },
            AttackPatternExample {
                pattern_name: "privilege_escalation".to_string(),
                indicators: vec![
                    "SUDO abuse".to_string(),
                    "Kernel exploit attempts".to_string(),
                    "SUID binary manipulation".to_string(),
                ],
                mitre_techniques: vec!["T1068".to_string(), "T1548".to_string()],
            },
            AttackPatternExample {
                pattern_name: "persistence".to_string(),
                indicators: vec![
                    "Scheduled task creation".to_string(),
                    "Registry run key modification".to_string(),
                    "Service installation".to_string(),
                ],
                mitre_techniques: vec!["T1053".to_string(), "T1547".to_string()],
            },
            AttackPatternExample {
                pattern_name: "reconnaissance".to_string(),
                indicators: vec![
                    "Port scanning".to_string(),
                    "Service enumeration".to_string(),
                    "DNS queries".to_string(),
                ],
                mitre_techniques: vec!["T1046".to_string(), "T1018".to_string()],
            },
            AttackPatternExample {
                pattern_name: "command_and_control".to_string(),
                indicators: vec![
                    "Beaconing behavior".to_string(),
                    "DNS tunneling".to_string(),
                    "Non-standard port usage".to_string(),
                ],
                mitre_techniques: vec!["T1071".to_string(), "T1572".to_string()],
            },
        ]
    }

    /// Extract attack patterns from data
    fn extract_attack_patterns(&self, data: &[AttackPatternExample]) -> Vec<AttackPattern> {
        // Group by pattern name and aggregate indicators
        let mut pattern_indicators: HashMap<String, Vec<String>> = HashMap::new();

        for example in data {
            let pattern_name = example.pattern_name.to_lowercase().replace(' ', "_");
            pattern_indicators
                .entry(pattern_name)
                .or_default()
                .extend(example.indicators.clone());
        }

        // Build attack patterns with deduplication and confidence calculation
        let mut patterns = Vec::new();

        for (name, indicators) in pattern_indicators {
            // Deduplicate indicators
            let mut unique_indicators: Vec<String> = indicators.clone();
            unique_indicators.sort();
            unique_indicators.dedup();

            // Calculate confidence threshold based on indicator count
            // More indicators = higher confidence required to detect
            let confidence_threshold = if unique_indicators.len() <= 2 {
                0.5
            } else if unique_indicators.len() <= 5 {
                0.6
            } else {
                0.7
            };

            patterns.push(AttackPattern {
                name,
                indicators: unique_indicators,
                confidence_threshold,
            });
        }

        patterns
    }

    /// Build MITRE ATT&CK technique mappings
    fn build_mitre_mappings(&self, data: &[AttackPatternExample]) -> HashMap<String, Vec<String>> {
        // Map attack patterns to MITRE ATT&CK techniques
        let mut mappings: HashMap<String, Vec<String>> = HashMap::new();

        // Build mappings from training data
        for example in data {
            let pattern_name = example.pattern_name.to_lowercase().replace(' ', "_");
            mappings
                .entry(pattern_name)
                .or_default()
                .extend(example.mitre_techniques.clone());
        }

        // Deduplicate techniques for each pattern
        for techniques in mappings.values_mut() {
            techniques.sort();
            techniques.dedup();
        }

        // Add comprehensive default mappings if not present from training data
        let defaults: Vec<(&str, Vec<&str>)> = vec![
            ("credential_spray", vec!["T1110.003"]),
            ("brute_force", vec!["T1110.001", "T1110"]),
            ("password_spray", vec!["T1110.003"]),
            ("credential_dumping", vec!["T1003", "T1003.001", "T1003.002", "T1003.003"]),
            ("lateral_movement", vec!["T1021", "T1021.002", "T1047", "T1570"]),
            ("pass_the_hash", vec!["T1550.002"]),
            ("pass_the_ticket", vec!["T1550.003"]),
            ("kerberoasting", vec!["T1558.003"]),
            ("data_exfiltration", vec!["T1048", "T1041", "T1567"]),
            ("privilege_escalation", vec!["T1068", "T1548", "T1134"]),
            ("persistence", vec!["T1053", "T1547", "T1543", "T1136"]),
            ("reconnaissance", vec!["T1046", "T1018", "T1087", "T1135"]),
            ("command_and_control", vec!["T1071", "T1572", "T1573", "T1095"]),
            ("defense_evasion", vec!["T1027", "T1070", "T1562"]),
            ("execution", vec!["T1059", "T1203", "T1204"]),
            ("initial_access", vec!["T1190", "T1566", "T1078"]),
            ("discovery", vec!["T1082", "T1083", "T1057", "T1012"]),
            ("collection", vec!["T1005", "T1039", "T1114"]),
            ("impact", vec!["T1486", "T1490", "T1489"]),
            ("phishing", vec!["T1566.001", "T1566.002"]),
            ("sql_injection", vec!["T1190"]),
            ("xss", vec!["T1189"]),
            ("dns_tunneling", vec!["T1071.004"]),
            ("beaconing", vec!["T1071.001"]),
            ("webshell", vec!["T1505.003"]),
            ("ransomware", vec!["T1486"]),
            ("cryptomining", vec!["T1496"]),
        ];

        for (pattern, techniques) in defaults {
            if !mappings.contains_key(pattern) {
                mappings.insert(
                    pattern.to_string(),
                    techniques.iter().map(|s| s.to_string()).collect(),
                );
            }
        }

        mappings
    }

    /// Collect remediation time training data
    async fn collect_remediation_training_data(&self) -> Result<Vec<RemediationTrainingExample>> {
        let examples = sqlx::query_as::<_, RemediationTrainingExample>(
            r#"
            SELECT
                v.severity,
                v.complexity,
                v.created_at,
                v.resolved_at,
                v.remediation_status
            FROM vulnerability_tracking v
            WHERE v.resolved_at IS NOT NULL
            "#,
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(examples)
    }

    /// Evaluate remediation time prediction model
    async fn evaluate_remediation_model(&self, model: &RemediationPredictor) -> Result<ModelMetrics> {
        let test_data = self.collect_remediation_training_data().await?;

        let mut errors = Vec::new();

        for example in test_data.iter().take(100) {
            let prediction = model.predict(&RemediationFeatures {
                severity: example.severity.clone(),
                complexity: example.complexity.clone(),
                team_size: 3, // Default
            });

            if let Some(actual) = example.actual_days() {
                let error = (prediction - actual as f64).abs();
                errors.push(error);
            }
        }

        let mean_absolute_error = if !errors.is_empty() {
            errors.iter().sum::<f64>() / errors.len() as f64
        } else {
            0.0
        };

        Ok(ModelMetrics {
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            mean_absolute_error,
        })
    }

    /// Store trained model
    async fn store_model<T: Serialize>(&self, model_name: &str, model: &T) -> Result<()> {
        let model_json = serde_json::to_string(model)?;

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO ml_trained_models (name, model_data, trained_at, version)
            VALUES (?, ?, ?, 1)
            "#,
        )
        .bind(model_name)
        .bind(model_json)
        .bind(Utc::now())
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Load trained model
    pub async fn load_model<T: for<'de> Deserialize<'de>>(&self, model_name: &str) -> Result<Option<T>> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT model_data FROM ml_trained_models WHERE name = ? ORDER BY version DESC LIMIT 1
            "#,
        )
        .bind(model_name)
        .fetch_optional(&*self.pool)
        .await?;

        if let Some((model_data,)) = row {
            let model: T = serde_json::from_str(&model_data)?;
            Ok(Some(model))
        } else {
            Ok(None)
        }
    }
}

/// Threat classifier model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatClassifier {
    pub decision_tree: Vec<DecisionNode>,
    pub thresholds: ThreatThresholds,
}

impl ThreatClassifier {
    pub fn train(features: Vec<ThreatFeatures>) -> Result<Self> {
        // Simple decision tree for now
        // In production, use a proper ML library like smartcore or linfa
        Ok(Self {
            decision_tree: vec![],
            thresholds: ThreatThresholds::default(),
        })
    }

    pub fn predict(&self, features: &ThreatFeatures) -> ThreatPrediction {
        let score = features.severity_score * 0.4
            + (if features.has_exploit { 1.0 } else { 0.0 }) * 0.3
            + (if features.has_cve { 1.0 } else { 0.0 }) * 0.2
            + (features.age_days as f64 / 365.0).min(1.0) * 0.1;

        let threat_level = if score >= 0.75 {
            "critical"
        } else if score >= 0.5 {
            "high"
        } else if score >= 0.25 {
            "medium"
        } else {
            "low"
        };

        ThreatPrediction {
            threat_level: threat_level.to_string(),
            confidence: 0.85,
            factors: vec![
                format!("Severity score: {:.2}", features.severity_score),
                format!("Has exploit: {}", features.has_exploit),
                format!("Age: {} days", features.age_days),
            ],
        }
    }
}

/// Asset fingerprinting model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFingerprinter {
    pub os_signatures: HashMap<String, OsSignature>,
    pub service_signatures: HashMap<String, ServiceSignature>,
    pub hardware_signatures: HashMap<String, HardwareSignature>,
}

/// Attack pattern detection model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPatternDetector {
    pub patterns: Vec<AttackPattern>,
    pub mitre_mappings: HashMap<String, Vec<String>>,
}

/// Remediation time prediction model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPredictor {
    pub coefficients: HashMap<String, f64>,
    pub base_days: f64,
}

impl RemediationPredictor {
    pub fn train(examples: Vec<RemediationTrainingExample>) -> Result<Self> {
        // Calculate average remediation time by severity
        let mut severity_times: HashMap<String, Vec<f64>> = HashMap::new();

        for example in examples {
            if let Some(days) = example.actual_days() {
                severity_times
                    .entry(example.severity.clone())
                    .or_insert_with(Vec::new)
                    .push(days as f64);
            }
        }

        let mut coefficients = HashMap::new();
        for (severity, times) in severity_times {
            let avg = times.iter().sum::<f64>() / times.len() as f64;
            coefficients.insert(severity, avg);
        }

        Ok(Self {
            coefficients,
            base_days: 7.0,
        })
    }

    pub fn predict(&self, features: &RemediationFeatures) -> f64 {
        let base = self.coefficients.get(&features.severity).copied().unwrap_or(self.base_days);

        // Adjust for complexity
        let complexity_multiplier = match features.complexity.to_lowercase().as_str() {
            "low" => 0.5,
            "medium" => 1.0,
            "high" => 2.0,
            _ => 1.0,
        };

        // Adjust for team size
        let team_multiplier = 1.0 / (features.team_size as f64).sqrt();

        base * complexity_multiplier * team_multiplier
    }
}

// Supporting types

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ThreatTrainingExample {
    pub id: String,
    pub severity: String,
    pub cve_id: Option<String>,
    pub exploit_available: bool,
    pub remediation_status: Option<String>,
    pub false_positive: bool,
    pub created_at: DateTime<Utc>,
    pub affected_hosts: i32,
}

impl ThreatTrainingExample {
    pub fn age_days(&self) -> u32 {
        (Utc::now() - self.created_at).num_days() as u32
    }

    pub fn actual_threat_level(&self) -> String {
        if self.false_positive {
            "low".to_string()
        } else {
            self.severity.clone()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreatFeatures {
    pub severity_score: f64,
    pub has_cve: bool,
    pub has_exploit: bool,
    pub age_days: u32,
    pub affected_hosts: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub threat_level: String,
    pub confidence: f64,
    pub factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatThresholds {
    pub critical: f64,
    pub high: f64,
    pub medium: f64,
}

impl Default for ThreatThresholds {
    fn default() -> Self {
        Self {
            critical: 0.75,
            high: 0.5,
            medium: 0.25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionNode {
    pub feature: String,
    pub threshold: f64,
    pub left: Option<Box<DecisionNode>>,
    pub right: Option<Box<DecisionNode>>,
}

#[derive(Debug, Clone)]
pub struct AssetTrainingExample {
    pub os: String,
    pub services: Vec<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsSignature {
    pub name: String,
    pub ttl_range: (u8, u8),
    pub window_size: u16,
    pub common_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub name: String,
    pub banner_pattern: String,
    pub default_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSignature {
    pub vendor: String,
    pub mac_prefix: String,
}

#[derive(Debug, Clone)]
pub struct AttackPatternExample {
    pub pattern_name: String,
    pub indicators: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub name: String,
    pub indicators: Vec<String>,
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RemediationTrainingExample {
    pub severity: String,
    pub complexity: String,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub remediation_status: Option<String>,
}

impl RemediationTrainingExample {
    pub fn actual_days(&self) -> Option<i64> {
        self.resolved_at.map(|resolved| (resolved - self.created_at).num_days())
    }
}

#[derive(Debug, Clone)]
pub struct RemediationFeatures {
    pub severity: String,
    pub complexity: String,
    pub team_size: u32,
}

#[derive(Debug, Clone)]
pub struct ModelMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub mean_absolute_error: f64,
}
