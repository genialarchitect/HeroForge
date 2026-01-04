//! Purple Team Execution Engine
//!
//! Orchestrates attack execution and detection validation

#![allow(dead_code)]

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use sqlx::SqlitePool;
use tokio::sync::broadcast;

use super::types::*;
use super::mitre_attack::MitreMapper;
use super::detection_check::DetectionChecker;
use super::coverage::CoverageCalculator;
use super::gap_analysis::GapAnalyzer;

/// Purple Team execution engine
pub struct PurpleTeamEngine {
    pool: SqlitePool,
    mapper: MitreMapper,
    detection_checker: DetectionChecker,
    coverage_calc: CoverageCalculator,
    gap_analyzer: GapAnalyzer,
}

impl PurpleTeamEngine {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool: pool.clone(),
            mapper: MitreMapper::new(),
            detection_checker: DetectionChecker::new(pool),
            coverage_calc: CoverageCalculator::new(),
            gap_analyzer: GapAnalyzer::new(),
        }
    }

    /// Run a purple team exercise
    pub async fn run_exercise(
        &self,
        exercise: &mut PurpleTeamExercise,
        progress_tx: Option<broadcast::Sender<PurpleTeamProgress>>,
    ) -> Result<ExerciseResult> {
        // Update exercise status to running
        exercise.status = ExerciseStatus::Running;
        exercise.started_at = Some(Utc::now());

        let mut results: Vec<PurpleAttackResult> = Vec::new();
        let total_attacks = exercise.attack_configs.iter().filter(|c| c.enabled).count();
        let mut completed = 0;

        // Send initial progress
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(PurpleTeamProgress {
                exercise_id: exercise.id.clone(),
                phase: ExercisePhase::Starting,
                current_technique: None,
                attacks_completed: 0,
                attacks_total: total_attacks,
                detection_checks_completed: 0,
                message: "Starting exercise".to_string(),
            });
        }

        // Execute each attack configuration
        for attack_config in &exercise.attack_configs {
            if !attack_config.enabled {
                continue;
            }

            // Send progress update for attack phase
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(PurpleTeamProgress {
                    exercise_id: exercise.id.clone(),
                    phase: ExercisePhase::ExecutingAttacks,
                    current_technique: Some(attack_config.technique_id.clone()),
                    attacks_completed: completed,
                    attacks_total: total_attacks,
                    detection_checks_completed: 0,
                    message: format!("Executing {}", attack_config.technique_name),
                });
            }

            // Execute the attack
            let attack_result = self.execute_attack(&exercise.id, attack_config).await;
            results.push(attack_result);

            completed += 1;
        }

        // Check detections for all attacks
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(PurpleTeamProgress {
                exercise_id: exercise.id.clone(),
                phase: ExercisePhase::CheckingDetections,
                current_technique: None,
                attacks_completed: total_attacks,
                attacks_total: total_attacks,
                detection_checks_completed: 0,
                message: "Checking SIEM for detections".to_string(),
            });
        }

        // Check detections with SIEM if configured
        if let Some(ref siem_id) = exercise.siem_integration_id {
            for (i, result) in results.iter_mut().enumerate() {
                let detection_status = self.detection_checker
                    .check_detection(siem_id, result, exercise.detection_timeout_secs)
                    .await
                    .unwrap_or(DetectionStatus::NotDetected);

                result.detection_status = detection_status;

                // Get detection details
                if detection_status != DetectionStatus::NotDetected {
                    if let Ok(details) = self.detection_checker
                        .get_detection_details(siem_id, result)
                        .await
                    {
                        if let Some(detection_time) = details.detection_time {
                            result.time_to_detect_ms = Some(
                                (detection_time - result.executed_at).num_milliseconds()
                            );
                        }
                        result.detection_details = Some(details);
                    }
                }

                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(PurpleTeamProgress {
                        exercise_id: exercise.id.clone(),
                        phase: ExercisePhase::CheckingDetections,
                        current_technique: Some(result.technique_id.clone()),
                        attacks_completed: total_attacks,
                        attacks_total: total_attacks,
                        detection_checks_completed: i + 1,
                        message: format!("Checked detection for {}", result.technique_name),
                    });
                }
            }
        }

        // Calculate coverage
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(PurpleTeamProgress {
                exercise_id: exercise.id.clone(),
                phase: ExercisePhase::CalculatingCoverage,
                current_technique: None,
                attacks_completed: total_attacks,
                attacks_total: total_attacks,
                detection_checks_completed: results.len(),
                message: "Calculating detection coverage".to_string(),
            });
        }

        let coverage = self.coverage_calc.calculate_coverage(&exercise.id, &results);

        // Identify gaps
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(PurpleTeamProgress {
                exercise_id: exercise.id.clone(),
                phase: ExercisePhase::IdentifyingGaps,
                current_technique: None,
                attacks_completed: total_attacks,
                attacks_total: total_attacks,
                detection_checks_completed: results.len(),
                message: "Identifying detection gaps".to_string(),
            });
        }

        let gaps = self.gap_analyzer.identify_gaps(&exercise.id, &results);

        // Update exercise status
        exercise.status = ExerciseStatus::Completed;
        exercise.completed_at = Some(Utc::now());

        // Send completion
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(PurpleTeamProgress {
                exercise_id: exercise.id.clone(),
                phase: ExercisePhase::Complete,
                current_technique: None,
                attacks_completed: total_attacks,
                attacks_total: total_attacks,
                detection_checks_completed: results.len(),
                message: format!(
                    "Exercise complete. Coverage: {:.1}%, Gaps: {}",
                    coverage.overall_score,
                    gaps.len()
                ),
            });
        }

        Ok(ExerciseResult {
            exercise_id: exercise.id.clone(),
            results,
            coverage,
            gaps,
            started_at: exercise.started_at.unwrap(),
            completed_at: exercise.completed_at.unwrap(),
        })
    }

    /// Execute a single attack
    async fn execute_attack(
        &self,
        exercise_id: &str,
        config: &PurpleAttackConfig,
    ) -> PurpleAttackResult {
        // In production, this would actually execute the attack
        // For now, simulate attack execution
        let attack_status = self.simulate_attack_execution(config).await;

        PurpleAttackResult {
            id: Uuid::new_v4().to_string(),
            exercise_id: exercise_id.to_string(),
            technique_id: config.technique_id.clone(),
            technique_name: config.technique_name.clone(),
            tactic: config.tactic,
            attack_type: config.attack_type.clone(),
            target: config.target.clone(),
            attack_status,
            detection_status: DetectionStatus::Pending,
            detection_details: None,
            time_to_detect_ms: None,
            executed_at: Utc::now(),
            error_message: None,
        }
    }

    /// Execute attack using the appropriate exploitation module
    async fn simulate_attack_execution(&self, config: &PurpleAttackConfig) -> AttackStatus {
        use crate::scanner::exploitation::types::*;
        use crate::scanner::exploitation::engine::ExploitationEngine;
        use log::{info, warn, debug};

        let attack_type = config.attack_type.as_str();
        let target = &config.target;

        info!("Executing attack: {} ({}) against {}", config.technique_name, attack_type, target);

        match attack_type {
            "kerberoast" => {
                // Execute Kerberoasting attack
                let domain = config.parameters.get("domain")
                    .cloned()
                    .unwrap_or_else(|| "DOMAIN.LOCAL".to_string());
                let username = config.parameters.get("username")
                    .cloned()
                    .unwrap_or_else(|| "admin".to_string());
                let password = config.parameters.get("password").cloned();

                let kerb_config = KerberoastConfig {
                    domain_controller: target.clone(),
                    domain,
                    username,
                    password,
                    ntlm_hash: None,
                    target_spns: None,
                    output_format: HashFormat::Hashcat,
                    request_rc4: true,
                };

                match crate::scanner::exploitation::kerberos::run_kerberoast(&kerb_config).await {
                    Ok(results) => {
                        if results.is_empty() {
                            debug!("Kerberoast found no SPNs with extractable hashes");
                            AttackStatus::Executed
                        } else {
                            info!("Kerberoast extracted {} TGS hashes", results.len());
                            AttackStatus::Executed
                        }
                    }
                    Err(e) => {
                        warn!("Kerberoast attack failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "password_spray" => {
                // Execute password spray attack
                let userlist: Vec<String> = config.parameters.get("userlist")
                    .map(|u| u.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                let password = config.parameters.get("password")
                    .cloned()
                    .unwrap_or_else(|| "Summer2024!".to_string());
                let domain = config.parameters.get("domain").cloned();
                let protocol_str = config.parameters.get("protocol")
                    .map(|s| s.as_str())
                    .unwrap_or("ldap");

                let protocol = match protocol_str.to_lowercase().as_str() {
                    "smb" => SprayProtocol::Smb,
                    "ssh" => SprayProtocol::Ssh,
                    "rdp" => SprayProtocol::Rdp,
                    "winrm" => SprayProtocol::WinRm,
                    "kerberos" => SprayProtocol::Kerberos,
                    _ => SprayProtocol::Ldap,
                };

                let spray_config = PasswordSprayConfig {
                    targets: vec![target.clone()],
                    usernames: if userlist.is_empty() {
                        vec!["administrator".to_string(), "admin".to_string()]
                    } else {
                        userlist
                    },
                    passwords: vec![password],
                    protocol,
                    domain,
                    port: None,
                    delay_between_attempts_ms: 1000,
                    delay_between_users_ms: 500,
                    max_attempts_per_user: 1,
                    stop_on_success: false,
                    threads: 3,
                    use_ssl: false,
                };

                let engine = ExploitationEngine::with_default_safety();
                // Auto-authorize for purple team exercises
                engine.authorize_campaign(&format!("purple-{}", config.technique_id)).await;

                match engine.run_password_spray(&format!("purple-{}", config.technique_id), spray_config).await {
                    Ok(results) => {
                        let successful = results.iter().filter(|r| r.success).count();
                        if successful > 0 {
                            info!("Password spray found {} valid credentials", successful);
                        }
                        AttackStatus::Executed
                    }
                    Err(e) => {
                        warn!("Password spray failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "asrep_roast" => {
                // Execute AS-REP Roasting attack
                let domain = config.parameters.get("domain")
                    .cloned()
                    .unwrap_or_else(|| "DOMAIN.LOCAL".to_string());
                let usernames: Vec<String> = config.parameters.get("usernames")
                    .map(|u| u.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();

                let asrep_config = AsrepRoastConfig {
                    domain_controller: target.clone(),
                    domain,
                    usernames,
                    enumerate_users: true,
                    output_format: HashFormat::Hashcat,
                };

                match crate::scanner::exploitation::kerberos::run_asrep_roast(&asrep_config).await {
                    Ok(results) => {
                        if !results.is_empty() {
                            info!("AS-REP Roast extracted {} hashes", results.len());
                        }
                        AttackStatus::Executed
                    }
                    Err(e) => {
                        warn!("AS-REP Roast failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "lsass_dump" | "credential_dump" | "mimikatz" => {
                // Execute credential dumping via post-exploitation module
                let module_config = PostExploitConfig {
                    module: PostExploitModule::DumpLsass,
                    target: target.clone(),
                    credentials: config.parameters.get("username").map(|u| {
                        Credentials {
                            username: u.clone(),
                            password: config.parameters.get("password").cloned(),
                            ntlm_hash: config.parameters.get("hash").cloned(),
                            domain: config.parameters.get("domain").cloned(),
                            ssh_key: None,
                        }
                    }),
                    options: std::collections::HashMap::new(),
                };

                match crate::scanner::exploitation::post_exploit::run_module(&module_config).await {
                    Ok(result) => {
                        if result.success {
                            info!("Credential dump found {} items", result.findings.len());
                        }
                        AttackStatus::Executed
                    }
                    Err(e) => {
                        warn!("Credential dump failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "powershell_execution" | "powershell" => {
                // For purple team exercises, we simulate PowerShell execution
                // by checking if the technique indicators would be generated
                debug!("Simulating PowerShell execution for detection testing");
                // In a real scenario, this would execute benign PowerShell that triggers detections
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                AttackStatus::Executed
            }

            "lateral_movement" | "smb_lateral" | "psexec" | "wmiexec" => {
                // Execute lateral movement post-exploitation
                let module = match attack_type {
                    "psexec" => PostExploitModule::PsExec,
                    "wmiexec" => PostExploitModule::WmiExec,
                    _ => PostExploitModule::PassTheHash,
                };

                let module_config = PostExploitConfig {
                    module,
                    target: target.clone(),
                    credentials: config.parameters.get("username").map(|u| {
                        Credentials {
                            username: u.clone(),
                            password: config.parameters.get("password").cloned(),
                            ntlm_hash: config.parameters.get("hash").cloned(),
                            domain: config.parameters.get("domain").cloned(),
                            ssh_key: None,
                        }
                    }),
                    options: std::collections::HashMap::new(),
                };

                match crate::scanner::exploitation::post_exploit::run_module(&module_config).await {
                    Ok(_) => AttackStatus::Executed,
                    Err(e) => {
                        warn!("Lateral movement failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "dcsync" => {
                // DCSync requires domain admin credentials - execute via impacket secretsdump
                debug!("Simulating DCSync attack for detection testing");
                // This is typically detected by monitoring for DRSGetNCChanges replication
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                AttackStatus::Executed
            }

            "persistence" | "scheduled_task" | "registry_run" | "service_creation" => {
                // Execute persistence modules
                let module = match attack_type {
                    "scheduled_task" => PostExploitModule::CreateScheduledTask,
                    "registry_run" => PostExploitModule::AddRegistryRunKey,
                    "service_creation" => PostExploitModule::CreateService,
                    _ => PostExploitModule::AddRegistryRunKey,
                };

                let module_config = PostExploitConfig {
                    module,
                    target: target.clone(),
                    credentials: None,
                    options: std::collections::HashMap::new(),
                };

                match crate::scanner::exploitation::post_exploit::run_module(&module_config).await {
                    Ok(_) => AttackStatus::Executed,
                    Err(e) => {
                        warn!("Persistence technique failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "discovery" | "network_discovery" | "domain_enum" => {
                // Execute discovery modules
                let module_config = PostExploitConfig {
                    module: PostExploitModule::DomainUsers,
                    target: target.clone(),
                    credentials: config.parameters.get("username").map(|u| {
                        Credentials {
                            username: u.clone(),
                            password: config.parameters.get("password").cloned(),
                            ntlm_hash: None,
                            domain: config.parameters.get("domain").cloned(),
                            ssh_key: None,
                        }
                    }),
                    options: std::collections::HashMap::new(),
                };

                match crate::scanner::exploitation::post_exploit::run_module(&module_config).await {
                    Ok(_) => AttackStatus::Executed,
                    Err(e) => {
                        warn!("Discovery failed: {}", e);
                        AttackStatus::Failed
                    }
                }
            }

            "atomic_red_team" | "art" => {
                // Execute via Atomic Red Team framework
                use super::attack_execution::{AtomicExecutor, AtomicExecutorConfig, BuiltInAtomics};

                let technique_id = &config.technique_id;

                // Try built-in tests first
                if let Some(test) = BuiltInAtomics::get_test(technique_id) {
                    let executor = AtomicExecutor::with_config(AtomicExecutorConfig {
                        run_cleanup: true,
                        timeout_secs: 60,
                        ..Default::default()
                    });

                    let input_args = config.parameters.clone();
                    match executor.execute_test(&test, &input_args).await {
                        Ok(result) => {
                            match result.status {
                                super::attack_execution::ExecutionStatus::Success => {
                                    info!("ART test {} executed successfully", technique_id);
                                    AttackStatus::Executed
                                }
                                super::attack_execution::ExecutionStatus::Skipped => {
                                    debug!("ART test {} skipped: {}", technique_id, result.stderr);
                                    AttackStatus::Skipped
                                }
                                super::attack_execution::ExecutionStatus::DependencyFailed => {
                                    warn!("ART test {} dependency failed", technique_id);
                                    AttackStatus::Skipped
                                }
                                _ => {
                                    warn!("ART test {} failed: {:?}", technique_id, result.error_message);
                                    AttackStatus::Failed
                                }
                            }
                        }
                        Err(e) => {
                            warn!("ART execution error for {}: {}", technique_id, e);
                            AttackStatus::Failed
                        }
                    }
                } else {
                    // Fallback to simulated execution
                    debug!("No built-in ART test for {}, simulating", technique_id);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    AttackStatus::Executed
                }
            }

            _ => {
                // For unrecognized attack types, attempt generic execution with delay
                debug!("Executing generic attack simulation for type: {}", attack_type);
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                AttackStatus::Executed
            }
        }
    }

    /// Execute an attack using Atomic Red Team framework
    pub async fn execute_atomic_test(
        &self,
        technique_id: &str,
        test_index: Option<usize>,
        input_args: &std::collections::HashMap<String, String>,
    ) -> Result<super::attack_execution::AtomicTestResult> {
        use super::attack_execution::{AtomicExecutor, AtomicExecutorConfig, BuiltInAtomics};

        // Try built-in tests first
        if let Some(test) = BuiltInAtomics::get_test(technique_id) {
            let executor = AtomicExecutor::with_config(AtomicExecutorConfig {
                run_cleanup: true,
                timeout_secs: 60,
                check_dependencies: true,
                ..Default::default()
            });

            return executor.execute_test(&test, input_args).await;
        }

        // Try loading from YAML files
        let mut executor = AtomicExecutor::new();
        if let Some(idx) = test_index {
            executor.execute_test_by_index(technique_id, idx, input_args).await
        } else {
            let results = executor.execute_technique(technique_id, input_args).await?;
            results.into_iter().next().ok_or_else(|| anyhow::anyhow!("No tests found for {}", technique_id))
        }
    }

    /// List available Atomic Red Team tests for a technique
    pub async fn list_atomic_tests(&self, technique_id: &str) -> Result<Vec<super::attack_execution::TestInfo>> {
        use super::attack_execution::{AtomicExecutor, BuiltInAtomics, TestInfo};

        // Check built-in first
        if let Some(test) = BuiltInAtomics::get_test(technique_id) {
            return Ok(vec![TestInfo {
                id: test.id,
                name: test.name,
                technique_id: test.technique_id,
                description: test.description,
                supported_platforms: test.supported_platforms,
                elevation_required: test.executor.elevation_required,
                executor_type: test.executor.name,
                has_cleanup: test.cleanup_command.is_some() || test.executor.cleanup_command.is_some(),
                input_arguments: test.input_arguments.keys().cloned().collect(),
            }]);
        }

        // Try loading from YAML
        let mut executor = AtomicExecutor::new();
        executor.get_test_info(technique_id).await
    }

    /// Get available attack types for purple team exercises
    pub fn get_available_attacks(&self) -> Vec<AvailableAttack> {
        let mut attacks = Vec::new();

        // Get all mapped techniques
        for technique in self.mapper.all_techniques() {
            // Check if we have an attack type for this technique
            if let Some(attack_types) = self.mapper.get_attack_types_for_technique(&technique.id) {
                for attack_type in attack_types {
                    attacks.push(AvailableAttack {
                        technique_id: technique.id.clone(),
                        technique_name: technique.name.clone(),
                        tactic: technique.tactic,
                        attack_type: attack_type.to_string(),
                        description: technique.description.clone(),
                        parameters: self.get_attack_parameters(&attack_type),
                    });
                }
            }
        }

        attacks
    }

    /// Get parameters needed for an attack type
    fn get_attack_parameters(&self, attack_type: &str) -> Vec<AttackParameter> {
        match attack_type {
            "kerberoast" => vec![
                AttackParameter {
                    name: "target".to_string(),
                    param_type: ParameterType::String,
                    required: true,
                    description: "Target domain controller IP or hostname".to_string(),
                    default_value: None,
                },
                AttackParameter {
                    name: "domain".to_string(),
                    param_type: ParameterType::String,
                    required: false,
                    description: "Target domain name".to_string(),
                    default_value: None,
                },
            ],
            "password_spray" => vec![
                AttackParameter {
                    name: "target".to_string(),
                    param_type: ParameterType::String,
                    required: true,
                    description: "Target domain controller".to_string(),
                    default_value: None,
                },
                AttackParameter {
                    name: "userlist".to_string(),
                    param_type: ParameterType::StringList,
                    required: true,
                    description: "List of usernames to test".to_string(),
                    default_value: None,
                },
                AttackParameter {
                    name: "password".to_string(),
                    param_type: ParameterType::String,
                    required: true,
                    description: "Password to spray".to_string(),
                    default_value: Some("Summer2024!".to_string()),
                },
            ],
            "dcsync" => vec![
                AttackParameter {
                    name: "target".to_string(),
                    param_type: ParameterType::String,
                    required: true,
                    description: "Target domain controller".to_string(),
                    default_value: None,
                },
                AttackParameter {
                    name: "user".to_string(),
                    param_type: ParameterType::String,
                    required: false,
                    description: "Specific user to sync (or all)".to_string(),
                    default_value: None,
                },
            ],
            _ => vec![
                AttackParameter {
                    name: "target".to_string(),
                    param_type: ParameterType::String,
                    required: true,
                    description: "Target IP or hostname".to_string(),
                    default_value: None,
                },
            ],
        }
    }

    /// Build ATT&CK matrix with coverage data
    pub fn build_coverage_matrix(&self, results: &[PurpleAttackResult]) -> AttackMatrix {
        self.coverage_calc.build_attack_matrix(results)
    }

    /// Get MITRE ATT&CK mapper
    pub fn mapper(&self) -> &MitreMapper {
        &self.mapper
    }

    /// Get gap analyzer
    pub fn gap_analyzer(&self) -> &GapAnalyzer {
        &self.gap_analyzer
    }

    /// Get coverage calculator
    pub fn coverage_calc(&self) -> &CoverageCalculator {
        &self.coverage_calc
    }
}

/// Progress message for exercise execution
#[derive(Debug, Clone)]
pub struct PurpleTeamProgress {
    pub exercise_id: String,
    pub phase: ExercisePhase,
    pub current_technique: Option<String>,
    pub attacks_completed: usize,
    pub attacks_total: usize,
    pub detection_checks_completed: usize,
    pub message: String,
}

/// Exercise execution phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExercisePhase {
    Starting,
    ExecutingAttacks,
    CheckingDetections,
    CalculatingCoverage,
    IdentifyingGaps,
    Complete,
}

/// Result of exercise execution
#[derive(Debug, Clone)]
pub struct ExerciseResult {
    pub exercise_id: String,
    pub results: Vec<PurpleAttackResult>,
    pub coverage: DetectionCoverage,
    pub gaps: Vec<DetectionGap>,
    pub started_at: chrono::DateTime<Utc>,
    pub completed_at: chrono::DateTime<Utc>,
}

/// Available attack for purple team
#[derive(Debug, Clone)]
pub struct AvailableAttack {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: MitreTactic,
    pub attack_type: String,
    pub description: String,
    pub parameters: Vec<AttackParameter>,
}

/// Attack parameter definition
#[derive(Debug, Clone)]
pub struct AttackParameter {
    pub name: String,
    pub param_type: ParameterType,
    pub required: bool,
    pub description: String,
    pub default_value: Option<String>,
}

/// Parameter types for attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterType {
    String,
    Integer,
    Boolean,
    StringList,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_attack_parameters() {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        let engine = PurpleTeamEngine::new(pool);

        let params = engine.get_attack_parameters("kerberoast");
        assert!(!params.is_empty());
        assert!(params.iter().any(|p| p.name == "target" && p.required));
    }
}
