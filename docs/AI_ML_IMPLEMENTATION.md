# HeroForge AI/ML Implementation Guide

## Overview

HeroForge now includes comprehensive LLM and ML capabilities for advanced security operations. This guide covers architecture, implementation, and usage.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    HeroForge AI/ML Platform                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────┐         ┌──────────────────┐              │
│  │  LLM Orchestrator │         │   ML Pipeline    │              │
│  ├──────────────────┤         ├──────────────────┤              │
│  │ - Report Gen     │         │ - Threat Classif │              │
│  │ - Scan Planning  │         │ - Asset Fingerpr │              │
│  │ - Exploit Analys │         │ - Attack Pattern │              │
│  │ - Policy Gen     │         │ - Remediation Pr │              │
│  └──────────────────┘         └──────────────────┘              │
│           │                            │                          │
│           └────────┬───────────────────┘                          │
│                    │                                              │
│           ┌────────▼────────┐                                     │
│           │  AI Prioritizer  │                                     │
│           ├─────────────────┤                                     │
│           │ - Risk Scoring  │                                     │
│           │ - Feedback Loop │                                     │
│           └─────────────────┘                                     │
│                    │                                              │
│           ┌────────▼────────┐                                     │
│           │  AI Security    │                                     │
│           ├─────────────────┤                                     │
│           │ - Alert Priority│                                     │
│           │ - Anomaly Detect│                                     │
│           │ - FP Prediction │                                     │
│           │ - LLM Testing   │                                     │
│           └─────────────────┘                                     │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. LLM Orchestrator (`src/ai/llm_orchestrator.rs`)

Provides high-level LLM operations powered by Claude API.

#### Features:

##### A. Automated Report Generation

Generates executive and technical security reports from scan results.

**Usage:**
```rust
use crate::ai::llm_orchestrator::LLMOrchestrator;

let orchestrator = LLMOrchestrator::new(api_key);

// Generate executive summary
let exec_report = orchestrator
    .generate_executive_report(&scan_results)
    .await?;

println!("Risk Score: {}", exec_report.risk_score);
println!("Summary: {}", exec_report.summary);

// Generate technical report
let tech_report = orchestrator
    .generate_technical_report(&scan_results)
    .await?;

println!("Remediation Roadmap: {:?}", tech_report.remediation_roadmap);
```

**Report Types:**
- **Executive Report**: C-level summary with business impact
- **Technical Report**: Detailed vulnerability analysis for engineers
- **Compliance Report**: Gap analysis for frameworks (PCI-DSS, NIST, HIPAA)

##### B. Intelligent Scan Planning

LLM analyzes targets and suggests optimal scan configurations.

**Usage:**
```rust
let targets = vec![
    "192.168.1.0/24".to_string(),
    "app.example.com".to_string(),
];

let objectives = vec![
    "Identify web vulnerabilities".to_string(),
    "Check for outdated services".to_string(),
];

let scan_plan = orchestrator
    .plan_scan(&targets, &objectives)
    .await?;

println!("Recommended scans: {:?}", scan_plan.recommended_scans);
println!("Estimated duration: {}", scan_plan.estimated_duration);
```

**Scan Plan Includes:**
- Recommended scan types (SYN, UDP, comprehensive)
- Port ranges based on objectives
- Scan order and timing
- Expected findings
- Risk factors

##### C. Exploit Code Analysis

LLM analyzes exploit code and provides security insights.

**Usage:**
```rust
let exploit_code = r#"
#!/usr/bin/python
import socket
payload = b"\x90" * 100 + b"\x31\xc0\x50\x68..."
"#;

let analysis = orchestrator
    .analyze_exploit(exploit_code, Some("WordPress plugin"))
    .await?;

println!("Vulnerability: {:?}", analysis.vulnerability_id);
println!("Attack Flow: {}", analysis.attack_flow);
println!("Impact: {}", analysis.impact_assessment);
println!("MITRE Techniques: {:?}", analysis.mitre_techniques);
println!("Mitigations: {:?}", analysis.mitigations);
```

**Analysis Includes:**
- Vulnerability identification (CVE if applicable)
- Step-by-step attack flow
- Impact assessment
- Indicators of Compromise (IOCs)
- Effective mitigations
- MITRE ATT&CK technique mapping

##### D. Security Policy Generation

LLM generates compliance-ready security policies.

**Usage:**
```rust
use crate::ai::llm_orchestrator::PolicyType;

let policy = orchestrator
    .generate_security_policy(
        PolicyType::VulnerabilityManagement,
        "Acme Corporation",
        &["PCI-DSS", "SOC 2", "NIST CSF"]
    )
    .await?;

println!("{}", policy.content);
println!("Review Schedule: {}", policy.review_schedule);
```

**Policy Types:**
- Access Control
- Data Protection
- Incident Response
- Change Management
- Asset Management
- Vulnerability Management
- Network Security
- Cloud Security

### 2. ML Pipeline (`src/ai/ml_pipeline.rs`)

Trains custom ML models on your security data.

#### Features:

##### A. Threat Classification

Classifies threats based on historical scan data and outcomes.

**Training:**
```rust
use crate::ai::ml_pipeline::MLPipeline;

let pipeline = MLPipeline::new(pool);

// Train model on historical data
let classifier = pipeline.train_threat_classifier().await?;

// Use model to predict threat level
let features = ThreatFeatures {
    severity_score: 0.8,
    has_cve: true,
    has_exploit: true,
    age_days: 30,
    affected_hosts: 5,
};

let prediction = classifier.predict(&features);
println!("Threat Level: {}", prediction.threat_level);
println!("Confidence: {:.2}%", prediction.confidence * 100.0);
```

**Model Metrics:**
- Accuracy: >85% required for deployment
- Precision/Recall: Tracked per threat level
- F1 Score: Harmonic mean of precision/recall

##### B. Asset Fingerprinting

ML-based OS and service detection with higher accuracy than signatures.

**Training:**
```rust
let fingerprinter = pipeline.train_asset_fingerprinter().await?;

// Use for detection
let os = fingerprinter.detect_os(&host_info);
let services = fingerprinter.detect_services(&port_info);
```

**Signatures:**
- OS detection (TTL, window size, port patterns)
- Service detection (banner analysis, behavior)
- Hardware fingerprinting (MAC, vendor info)

##### C. Attack Pattern Recognition

Detects attack patterns and maps to MITRE ATT&CK framework.

**Training:**
```rust
let detector = pipeline.train_attack_pattern_detector().await?;

// Detect patterns in traffic
let patterns = detector.detect_patterns(&network_traffic);

for pattern in patterns {
    println!("Attack: {}", pattern.name);
    println!("MITRE: {:?}", pattern.mitre_techniques);
}
```

**Capabilities:**
- Pattern extraction from historical attacks
- MITRE ATT&CK technique mapping
- Confidence scoring
- Multi-stage attack detection

##### D. Remediation Time Prediction

Predicts how long vulnerabilities will take to fix.

**Training:**
```rust
let predictor = pipeline.train_remediation_predictor().await?;

// Predict remediation time
let features = RemediationFeatures {
    severity: "high".to_string(),
    complexity: "medium".to_string(),
    team_size: 3,
};

let estimated_days = predictor.predict(&features);
println!("Estimated remediation: {:.1} days", estimated_days);
```

**Factors:**
- Vulnerability severity
- Complexity (low/medium/high)
- Team size and expertise
- Historical remediation times
- Dependencies

### 3. AI Prioritization (`src/ai/mod.rs`)

Existing vulnerability prioritization with weighted scoring.

**Usage:**
```rust
use crate::ai::AIPrioritizationManager;

let manager = AIPrioritizationManager::from_database(pool).await?;

// Prioritize scan
let result = manager.prioritize_scan(&scan_id).await?;

println!("Total vulnerabilities: {}", result.summary.total_vulnerabilities);
println!("Critical: {}", result.summary.critical_count);
println!("Average risk score: {:.2}", result.summary.average_risk_score);

// Get remediation priority
for score in result.scores.iter().take(10) {
    println!(
        "#{} - {} (score: {:.2})",
        score.remediation_priority,
        score.vulnerability_id,
        score.effective_risk_score
    );
}
```

### 4. AI Security (`src/ai_security/mod.rs`)

AI-powered security operations features.

**Features:**
- **Alert Prioritization**: Reduce alert fatigue
- **Anomaly Detection**: Statistical threat detection
- **False Positive Prediction**: ML-based FP reduction
- **LLM Testing**: Prompt injection & jailbreak detection

## API Endpoints

### LLM Endpoints

```http
POST /api/ai/reports/executive
{
  "scan_id": "scan_123"
}

POST /api/ai/reports/technical
{
  "scan_id": "scan_123"
}

POST /api/ai/scan-plan
{
  "targets": ["192.168.1.0/24"],
  "objectives": ["Web vulnerability assessment"]
}

POST /api/ai/analyze-exploit
{
  "code": "...",
  "context": "WordPress plugin vulnerability"
}

POST /api/ai/policy/generate
{
  "policy_type": "VulnerabilityManagement",
  "organization": "Acme Corp",
  "frameworks": ["PCI-DSS", "SOC2"]
}
```

### ML Endpoints

```http
POST /api/ml/train/threat-classifier
POST /api/ml/train/asset-fingerprinter
POST /api/ml/train/attack-detector
POST /api/ml/train/remediation-predictor

POST /api/ml/predict/threat
{
  "features": {
    "severity_score": 0.8,
    "has_cve": true,
    "has_exploit": true,
    "age_days": 30
  }
}

POST /api/ml/predict/remediation-time
{
  "severity": "high",
  "complexity": "medium",
  "team_size": 3
}
```

## Configuration

### Environment Variables

```bash
# Claude API (required for LLM features)
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# ML model training
export ML_TRAINING_ENABLED=true
export ML_MIN_TRAINING_SAMPLES=100
export ML_RETRAIN_INTERVAL_DAYS=7

# Model deployment thresholds
export ML_MIN_ACCURACY=0.85
export ML_MIN_CONFIDENCE=0.80
```

### AI Model Configuration

```rust
let config = AIModelConfig {
    weights: WeightConfig {
        cvss_weight: 0.3,
        exploit_weight: 0.25,
        asset_criticality_weight: 0.20,
        network_exposure_weight: 0.15,
        attack_path_weight: 0.05,
        compliance_weight: 0.03,
        business_context_weight: 0.02,
    },
    ..Default::default()
};

let manager = AIPrioritizationManager::with_config(pool, config);
```

## Database Schema

### ML Models Table

```sql
CREATE TABLE ml_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    model_data TEXT NOT NULL,
    trained_at TIMESTAMP NOT NULL,
    version INTEGER NOT NULL,
    metrics TEXT,
    UNIQUE(name, version)
);
```

### AI Feedback Table

```sql
CREATE TABLE ai_feedback (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    predicted_score REAL NOT NULL,
    actual_outcome TEXT,
    user_rating INTEGER,
    feedback_notes TEXT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_tracking(id)
);
```

## Best Practices

### 1. Model Training

- **Minimum Data**: Train only with 100+ samples
- **Retraining**: Retrain models weekly or after significant data changes
- **Validation**: Always validate on hold-out test set
- **Monitoring**: Track model metrics over time

### 2. LLM Usage

- **Rate Limiting**: Respect Claude API rate limits
- **Caching**: Cache common reports to reduce API calls
- **Context**: Provide relevant context for better results
- **Review**: Always review LLM-generated policies before deployment

### 3. Production Deployment

- **Phased Rollout**: Deploy AI features gradually
- **Human Oversight**: Keep humans in the loop for critical decisions
- **Fallback**: Have non-AI fallback for when ML/LLM fails
- **Monitoring**: Track AI performance and user satisfaction

### 4. Security Considerations

- **API Keys**: Secure ANTHROPIC_API_KEY with encryption
- **Data Privacy**: Don't send sensitive data to external LLMs without consent
- **Model Security**: Protect trained models from tampering
- **Audit Trail**: Log all AI-assisted decisions

## Example Workflows

### Workflow 1: Comprehensive Security Assessment

```rust
// 1. Run scan
let scan_id = scanner.scan(&targets, &config).await?;

// 2. AI prioritization
let priorities = ai_manager.prioritize_scan(&scan_id).await?;

// 3. ML threat classification
let classifier = ml_pipeline.load_model("threat_classifier").await?;
let threats = classifier.classify_all(&priorities.scores);

// 4. Generate reports
let exec_report = llm_orchestrator.generate_executive_report(&scan_results).await?;
let tech_report = llm_orchestrator.generate_technical_report(&scan_results).await?;

// 5. Predict remediation times
let predictor = ml_pipeline.load_model("remediation_predictor").await?;
for vuln in vulnerabilities {
    let time = predictor.predict(&vuln.features);
    println!("{}: {} days", vuln.id, time);
}
```

### Workflow 2: Intelligent Penetration Test Planning

```rust
// 1. Get target information
let targets = vec!["app.example.com", "192.168.1.0/24"];
let objectives = vec!["Find web vulnerabilities", "Check for misconfigurations"];

// 2. LLM generates scan plan
let plan = llm_orchestrator.plan_scan(&targets, &objectives).await?;

// 3. Execute recommended scans
for scan_type in plan.recommended_scans {
    execute_scan(&scan_type).await?;
}

// 4. Analyze results with ML
let fingerprinter = ml_pipeline.load_model("asset_fingerprinter").await?;
let assets = fingerprinter.fingerprint_all(&scan_results);

// 5. Generate final report
let report = llm_orchestrator.generate_technical_report(&scan_results).await?;
```

### Workflow 3: Continuous Improvement Loop

```rust
// 1. Deploy model
let classifier = ml_pipeline.train_threat_classifier().await?;

// 2. Use in production
let predictions = classifier.predict_batch(&features);

// 3. Collect feedback
for prediction in predictions {
    let feedback = collect_user_feedback(&prediction);
    ai_manager.record_feedback(feedback).await?;
}

// 4. Retrain weekly
tokio::spawn(async move {
    loop {
        sleep(Duration::from_secs(7 * 24 * 60 * 60)).await; // 7 days

        let new_classifier = ml_pipeline.train_threat_classifier().await?;

        if new_classifier.metrics.accuracy > current.metrics.accuracy {
            deploy_model(new_classifier).await?;
        }
    }
});
```

## Troubleshooting

### LLM Issues

**Problem**: Claude API rate limiting
**Solution**: Implement exponential backoff and caching

**Problem**: Poor report quality
**Solution**: Improve prompts with more context and examples

### ML Issues

**Problem**: Low model accuracy
**Solution**: Collect more training data, tune hyperparameters

**Problem**: Model overfitting
**Solution**: Use cross-validation, regularization, more diverse training data

**Problem**: Slow predictions
**Solution**: Optimize model, use batch predictions, cache results

## Future Enhancements

- [ ] Integration with GPT-4 for alternative LLM option
- [ ] Advanced ML models (XGBoost, neural networks)
- [ ] Automated model retraining pipeline
- [ ] A/B testing framework for model comparison
- [ ] Explainable AI (SHAP values, LIME)
- [ ] Federated learning for privacy-preserving training
- [ ] Real-time ML inference via streaming
- [ ] Custom fine-tuned LLMs for security domain

## References

- [Claude API Documentation](https://docs.anthropic.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [ML Security Best Practices](https://ml-security.github.io/)
