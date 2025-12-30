//! Emerging technology security types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergingTechConfig {
    pub assess_5g: bool,
    pub assess_adversarial_ml: bool,
    pub assess_quantum: bool,
    pub assess_xr: bool,
    pub fiveg_config: FiveGConfig,
    pub ml_models: Vec<MLModelConfig>,
    pub crypto_inventory: CryptoInventory,
    pub xr_devices: Vec<XRDeviceConfig>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EmergingTechAssessment {
    pub fiveg_findings: Vec<FiveGFinding>,
    pub adversarial_ml_findings: Vec<AdversarialMLFinding>,
    pub quantum_readiness: QuantumReadinessAssessment,
    pub xr_findings: Vec<XRFinding>,
}

// ============================================================================
// 5G Security
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FiveGConfig {
    pub network_slices: Vec<String>,
    pub mec_endpoints: Vec<String>,
    pub base_stations: Vec<String>,
    pub core_network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveGFinding {
    pub finding_type: FiveGRiskType,
    pub severity: Severity,
    pub affected_component: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FiveGRiskType {
    NetworkSlicingSecurity,
    MECSecurity,
    FakeBaseStation,
    SS7Attack,
    DiameterAttack,
    SubscriberPrivacy,
    CoreNetworkVulnerability,
    APIExposure,
}

// ============================================================================
// AI/ML Adversarial Security
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLModelConfig {
    pub model_id: String,
    pub model_type: MLModelType,
    pub framework: MLFramework,
    pub endpoint: Option<String>,
    pub model_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MLModelType {
    Classification,
    Regression,
    ObjectDetection,
    NLP,
    Generative,
    Reinforcement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MLFramework {
    TensorFlow,
    PyTorch,
    ScikitLearn,
    Keras,
    ONNX,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialMLFinding {
    pub model_id: String,
    pub attack_type: AdversarialAttackType,
    pub severity: Severity,
    pub success_rate: f64,
    pub description: String,
    pub recommendation: String,
    pub mitigation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdversarialAttackType {
    AdversarialExamples,
    ModelPoisoning,
    BackdoorAttack,
    ModelInversion,
    MembershipInference,
    ModelStealing,
    DataPoisoning,
    EvasionAttack,
}

// ============================================================================
// Quantum Readiness
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoInventory {
    pub tls_endpoints: Vec<String>,
    pub certificate_stores: Vec<String>,
    pub encryption_libraries: Vec<String>,
    pub applications: Vec<ApplicationCrypto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationCrypto {
    pub name: String,
    pub crypto_algorithms: Vec<String>,
    pub key_sizes: Vec<u32>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QuantumReadinessAssessment {
    pub overall_risk: QuantumRisk,
    pub vulnerable_algorithms: Vec<VulnerableAlgorithm>,
    pub pqc_recommendations: Vec<PQCRecommendation>,
    pub migration_plan: MigrationPlan,
    pub harvest_now_decrypt_later_risk: HNDLRisk,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum QuantumRisk {
    #[default]
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableAlgorithm {
    pub algorithm: String,
    pub usage_count: usize,
    pub key_size: u32,
    pub quantum_vulnerability: String,
    pub recommended_replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCRecommendation {
    pub current_algorithm: String,
    pub recommended_pqc: String,
    pub nist_status: String,
    pub implementation_complexity: String,
    pub performance_impact: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub phases: Vec<MigrationPhase>,
    pub estimated_duration: String,
    pub crypto_agility_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPhase {
    pub phase_number: u32,
    pub name: String,
    pub tasks: Vec<String>,
    pub dependencies: Vec<String>,
    pub estimated_effort: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HNDLRisk {
    pub risk_level: QuantumRisk,
    pub sensitive_data_exposure: Vec<String>,
    pub recommended_actions: Vec<String>,
}

// ============================================================================
// Extended Reality (XR) Security
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRDeviceConfig {
    pub device_id: String,
    pub device_type: XRDeviceType,
    pub platform: XRPlatform,
    pub applications: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XRDeviceType {
    AR,  // Augmented Reality
    VR,  // Virtual Reality
    MR,  // Mixed Reality
    Headset,
    Glasses,
    Haptic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XRPlatform {
    MetaQuest,
    HoloLens,
    AppleVisionPro,
    HTCVive,
    PlayStationVR,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRFinding {
    pub device_id: String,
    pub finding_type: XRRiskType,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
    pub privacy_impact: PrivacyImpact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XRRiskType {
    DeviceSecurity,
    PrivacyInSpatialComputing,
    BiometricDataLeakage,
    MetaverseSecurity,
    DigitalTwinSecurity,
    MotionTrackingPrivacy,
    EyeTrackingPrivacy,
    VoiceRecognitionPrivacy,
    EnvironmentScanning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyImpact {
    Critical,  // PII, biometrics
    High,      // Behavioral data
    Medium,    // Usage patterns
    Low,       // Anonymous telemetry
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
