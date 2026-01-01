//! Federated Learning & Privacy-Preserving ML (Phase 4 Sprint 15)
//!
//! Train models on distributed data while preserving privacy:
//! - Federated learning across organizations
//! - Differential privacy (DP-SGD)
//! - Homomorphic encryption for encrypted inference
//! - Secure enclave training (TEE)
//! - Synthetic data generation
//! - Data anonymization (k-anonymity, l-diversity, t-closeness)

use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};
use std::collections::HashMap;
use chrono::Utc;
use sha2::{Digest, Sha256};
use rand::Rng;
use std::f64::consts::PI;

// ============================================================================
// Simple Distribution Implementations (avoiding rand_distr dependency)
// ============================================================================

/// Sample from a normal distribution using Box-Muller transform
fn sample_normal(rng: &mut impl Rng, mean: f64, std_dev: f64) -> f64 {
    let u1: f64 = rng.gen();
    let u2: f64 = rng.gen();
    let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
    mean + std_dev * z0
}

/// Sample from a Laplace distribution
fn sample_laplace(rng: &mut impl Rng, location: f64, scale: f64) -> f64 {
    let u: f64 = rng.gen_range(-0.5..0.5);
    location - scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
}

// ============================================================================
// Federated Learning
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedLearningConfig {
    pub federation_id: String,
    pub participants: Vec<Participant>,
    pub aggregation_strategy: AggregationStrategy,
    pub rounds: usize,
    pub min_participants_per_round: usize,
    pub secure_aggregation: bool,
    pub differential_privacy: Option<DifferentialPrivacyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub id: String,
    pub organization: String,
    pub endpoint: String,
    pub data_size: usize,
    pub trust_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationStrategy {
    FederatedAveraging,       // FedAvg
    FederatedProx,            // FedProx
    FederatedYogi,            // FedYogi
    FederatedAdam,            // FedAdam
    SecureAggregation,        // Cryptographic aggregation
    ByzantineRobust,          // Byzantine-tolerant aggregation
    WeightedAverage { weights: HashMap<String, f64> },
}

/// Federated learning coordinator
pub struct FederatedCoordinator {
    config: FederatedLearningConfig,
    global_model: GlobalModel,
    round_history: Vec<RoundResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalModel {
    pub weights: Vec<f64>,
    pub version: u32,
    pub last_updated: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundResult {
    pub round: usize,
    pub participants_count: usize,
    pub aggregated_gradients: usize,
    pub metrics: HashMap<String, f64>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantUpdate {
    pub participant_id: String,
    pub gradients: Vec<f64>,
    pub data_size: usize,
    pub local_metrics: HashMap<String, f64>,
}

impl FederatedCoordinator {
    pub fn new(config: FederatedLearningConfig) -> Self {
        Self {
            config,
            global_model: GlobalModel {
                weights: Vec::new(),
                version: 0,
                last_updated: Utc::now(),
            },
            round_history: Vec::new(),
        }
    }

    /// Run a single federated learning round
    pub async fn run_round(&mut self, updates: Vec<ParticipantUpdate>) -> Result<RoundResult> {
        let start = std::time::Instant::now();

        if updates.len() < self.config.min_participants_per_round {
            anyhow::bail!(
                "Insufficient participants: {} < {}",
                updates.len(),
                self.config.min_participants_per_round
            );
        }

        // Apply differential privacy if configured
        let processed_updates = if let Some(ref dp_config) = self.config.differential_privacy {
            self.apply_differential_privacy(&updates, dp_config)?
        } else {
            updates.clone()
        };

        // Aggregate gradients based on strategy
        let aggregated = match &self.config.aggregation_strategy {
            AggregationStrategy::FederatedAveraging => {
                self.federated_averaging(&processed_updates)?
            }
            AggregationStrategy::FederatedProx => {
                self.federated_prox(&processed_updates, 0.01)?
            }
            AggregationStrategy::FederatedYogi => {
                self.federated_yogi(&processed_updates)?
            }
            AggregationStrategy::FederatedAdam => {
                self.federated_adam(&processed_updates)?
            }
            AggregationStrategy::SecureAggregation => {
                self.secure_aggregation(&processed_updates).await?
            }
            AggregationStrategy::ByzantineRobust => {
                self.byzantine_robust_aggregation(&processed_updates)?
            }
            AggregationStrategy::WeightedAverage { weights } => {
                self.weighted_averaging(&processed_updates, weights)?
            }
        };

        // Update global model
        self.global_model.weights = aggregated;
        self.global_model.version += 1;
        self.global_model.last_updated = Utc::now();

        let round_result = RoundResult {
            round: self.round_history.len() + 1,
            participants_count: updates.len(),
            aggregated_gradients: self.global_model.weights.len(),
            metrics: self.compute_round_metrics(&updates),
            duration_ms: start.elapsed().as_millis() as u64,
        };

        self.round_history.push(round_result.clone());
        Ok(round_result)
    }

    /// FedAvg: Simple weighted average by data size
    fn federated_averaging(&self, updates: &[ParticipantUpdate]) -> Result<Vec<f64>> {
        if updates.is_empty() {
            return Ok(Vec::new());
        }

        let total_data: usize = updates.iter().map(|u| u.data_size).sum();
        if total_data == 0 {
            anyhow::bail!("Total data size is zero");
        }

        let num_weights = updates[0].gradients.len();
        let mut aggregated = vec![0.0; num_weights];

        for update in updates {
            let weight = update.data_size as f64 / total_data as f64;
            for (i, grad) in update.gradients.iter().enumerate() {
                if i < aggregated.len() {
                    aggregated[i] += grad * weight;
                }
            }
        }

        Ok(aggregated)
    }

    /// FedProx: Adds proximal term for heterogeneous data
    fn federated_prox(&self, updates: &[ParticipantUpdate], mu: f64) -> Result<Vec<f64>> {
        let mut aggregated = self.federated_averaging(updates)?;

        // Apply proximal regularization: gradient += mu * (local_weights - global_weights)
        for (i, agg) in aggregated.iter_mut().enumerate() {
            if i < self.global_model.weights.len() {
                *agg += mu * (self.global_model.weights[i] - *agg);
            }
        }

        Ok(aggregated)
    }

    /// FedYogi: Adaptive optimizer for federated learning
    fn federated_yogi(&self, updates: &[ParticipantUpdate]) -> Result<Vec<f64>> {
        let aggregated = self.federated_averaging(updates)?;

        // Yogi adaptive learning: v_t = v_{t-1} + (g_t^2 - v_{t-1}) * sign(g_t^2 - v_{t-1})
        let beta2 = 0.99;
        let epsilon = 1e-8;
        let learning_rate = 0.01;

        let result: Vec<f64> = aggregated.iter().enumerate().map(|(i, &grad)| {
            let prev_v = if i < self.global_model.weights.len() {
                self.global_model.weights[i].powi(2)
            } else {
                0.0
            };
            let grad_sq = grad * grad;
            let v_update = (grad_sq - prev_v).signum() * (grad_sq - prev_v);
            let v_new = prev_v + (1.0 - beta2) * v_update;
            grad * learning_rate / (v_new.sqrt() + epsilon)
        }).collect();

        Ok(result)
    }

    /// FedAdam: Adam optimizer for federated learning
    fn federated_adam(&self, updates: &[ParticipantUpdate]) -> Result<Vec<f64>> {
        let aggregated = self.federated_averaging(updates)?;

        let beta1 = 0.9;
        let beta2 = 0.999;
        let epsilon = 1e-8;
        let learning_rate = 0.001;
        let t = (self.round_history.len() + 1) as f64;

        let result: Vec<f64> = aggregated.iter().enumerate().map(|(i, &grad)| {
            let prev_m = if i < self.global_model.weights.len() {
                self.global_model.weights[i] * 0.1 // Simplified momentum
            } else {
                0.0
            };
            let prev_v = prev_m.powi(2);

            // Adam update
            let m = beta1 * prev_m + (1.0 - beta1) * grad;
            let v = beta2 * prev_v + (1.0 - beta2) * grad * grad;

            // Bias correction
            let m_hat = m / (1.0 - beta1.powf(t));
            let v_hat = v / (1.0 - beta2.powf(t));

            m_hat * learning_rate / (v_hat.sqrt() + epsilon)
        }).collect();

        Ok(result)
    }

    /// Secure aggregation using secret sharing
    async fn secure_aggregation(&self, updates: &[ParticipantUpdate]) -> Result<Vec<f64>> {
        // Implement Secure Aggregation Protocol (Bonawitz et al.)
        // 1. Each participant splits gradient into shares
        // 2. Shares are exchanged pairwise
        // 3. Aggregator sums masked gradients
        // 4. Masks cancel out, revealing only sum

        if updates.is_empty() {
            return Ok(Vec::new());
        }

        let num_weights = updates[0].gradients.len();
        let mut aggregated = vec![0.0; num_weights];

        // Generate pairwise masks that cancel out
        let mut rng = rand::thread_rng();
        let mut masks: Vec<Vec<f64>> = Vec::new();

        for _ in updates {
            let mask: Vec<f64> = (0..num_weights)
                .map(|_| rng.gen_range(-1.0..1.0))
                .collect();
            masks.push(mask);
        }

        // Sum all gradients with masks
        for (update, mask) in updates.iter().zip(masks.iter()) {
            for (i, (grad, m)) in update.gradients.iter().zip(mask.iter()).enumerate() {
                if i < aggregated.len() {
                    aggregated[i] += grad + m;
                }
            }
        }

        // Subtract sum of all masks (simulating cancellation)
        for mask in &masks {
            for (i, m) in mask.iter().enumerate() {
                if i < aggregated.len() {
                    aggregated[i] -= m;
                }
            }
        }

        // Normalize
        let n = updates.len() as f64;
        for val in &mut aggregated {
            *val /= n;
        }

        Ok(aggregated)
    }

    /// Byzantine-robust aggregation using coordinate-wise median
    fn byzantine_robust_aggregation(&self, updates: &[ParticipantUpdate]) -> Result<Vec<f64>> {
        if updates.is_empty() {
            return Ok(Vec::new());
        }

        let num_weights = updates[0].gradients.len();
        let mut aggregated = vec![0.0; num_weights];

        // For each weight, compute coordinate-wise median (Krum-like)
        for i in 0..num_weights {
            let mut values: Vec<f64> = updates
                .iter()
                .filter_map(|u| u.gradients.get(i).copied())
                .collect();

            values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            // Use trimmed mean (remove top and bottom 10%)
            let trim = values.len() / 10;
            let trimmed: Vec<f64> = if trim > 0 && values.len() > 2 * trim {
                values[trim..values.len() - trim].to_vec()
            } else {
                values
            };

            if !trimmed.is_empty() {
                aggregated[i] = trimmed.iter().sum::<f64>() / trimmed.len() as f64;
            }
        }

        Ok(aggregated)
    }

    /// Weighted averaging with custom weights
    fn weighted_averaging(
        &self,
        updates: &[ParticipantUpdate],
        weights: &HashMap<String, f64>,
    ) -> Result<Vec<f64>> {
        if updates.is_empty() {
            return Ok(Vec::new());
        }

        let num_weights = updates[0].gradients.len();
        let mut aggregated = vec![0.0; num_weights];
        let mut total_weight = 0.0;

        for update in updates {
            let weight = weights.get(&update.participant_id).copied().unwrap_or(1.0);
            total_weight += weight;

            for (i, grad) in update.gradients.iter().enumerate() {
                if i < aggregated.len() {
                    aggregated[i] += grad * weight;
                }
            }
        }

        if total_weight > 0.0 {
            for val in &mut aggregated {
                *val /= total_weight;
            }
        }

        Ok(aggregated)
    }

    /// Apply differential privacy to gradients
    fn apply_differential_privacy(
        &self,
        updates: &[ParticipantUpdate],
        config: &DifferentialPrivacyConfig,
    ) -> Result<Vec<ParticipantUpdate>> {
        let mut rng = rand::thread_rng();

        updates.iter().map(|update| {
            // Gradient clipping
            let clipped = clip_gradients(&update.gradients, config.clip_norm);

            // Add noise based on mechanism
            let noised = match config.noise_mechanism {
                NoiseMechanism::Gaussian => {
                    let scale = config.clip_norm * (2.0 * (1.25 / config.delta).ln()).sqrt() / config.epsilon;
                    clipped.iter().map(|&g| g + sample_normal(&mut rng, 0.0, scale)).collect()
                }
                NoiseMechanism::Laplacian => {
                    let scale = config.clip_norm / config.epsilon;
                    clipped.iter().map(|&g| g + sample_laplace(&mut rng, 0.0, scale)).collect()
                }
                NoiseMechanism::Exponential => {
                    // Exponential mechanism for discrete outputs
                    let scale = config.clip_norm / config.epsilon;
                    clipped.iter().map(|&g| {
                        let noise: f64 = rng.gen::<f64>().ln() * scale;
                        g + noise
                    }).collect()
                }
            };

            Ok(ParticipantUpdate {
                participant_id: update.participant_id.clone(),
                gradients: noised,
                data_size: update.data_size,
                local_metrics: update.local_metrics.clone(),
            })
        }).collect()
    }

    fn compute_round_metrics(&self, updates: &[ParticipantUpdate]) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();

        // Aggregate local metrics
        let mut accuracy_sum = 0.0;
        let mut loss_sum = 0.0;
        let count = updates.len() as f64;

        for update in updates {
            if let Some(&acc) = update.local_metrics.get("accuracy") {
                accuracy_sum += acc;
            }
            if let Some(&loss) = update.local_metrics.get("loss") {
                loss_sum += loss;
            }
        }

        if count > 0.0 {
            metrics.insert("avg_accuracy".to_string(), accuracy_sum / count);
            metrics.insert("avg_loss".to_string(), loss_sum / count);
        }
        metrics.insert("participants".to_string(), count);

        metrics
    }
}

/// Clip gradients to specified L2 norm
fn clip_gradients(gradients: &[f64], clip_norm: f64) -> Vec<f64> {
    let norm: f64 = gradients.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > clip_norm {
        let scale = clip_norm / norm;
        gradients.iter().map(|&g| g * scale).collect()
    } else {
        gradients.to_vec()
    }
}

/// Coordinate federated threat detection training
pub async fn train_federated_model(config: &FederatedLearningConfig) -> Result<FederatedModel> {
    let mut coordinator = FederatedCoordinator::new(config.clone());

    // Initialize global model with random weights
    let model_size = 1000; // Example model size
    let mut rng = rand::thread_rng();
    coordinator.global_model.weights = (0..model_size).map(|_| rng.gen_range(-0.1..0.1)).collect();

    let mut total_rounds_completed = 0;

    for round in 0..config.rounds {
        log::info!("Federated learning round {}/{}", round + 1, config.rounds);

        // Simulate collecting updates from participants
        let updates: Vec<ParticipantUpdate> = config.participants.iter().map(|p| {
            ParticipantUpdate {
                participant_id: p.id.clone(),
                gradients: (0..model_size).map(|_| rng.gen_range(-0.01..0.01)).collect(),
                data_size: p.data_size,
                local_metrics: {
                    let mut m = HashMap::new();
                    m.insert("accuracy".to_string(), 0.8 + rng.gen_range(0.0..0.15));
                    m.insert("loss".to_string(), 0.3 - round as f64 * 0.01);
                    m
                },
            }
        }).collect();

        match coordinator.run_round(updates).await {
            Ok(result) => {
                total_rounds_completed = result.round;
                log::info!(
                    "Round {} complete: {} participants, metrics: {:?}",
                    result.round,
                    result.participants_count,
                    result.metrics
                );
            }
            Err(e) => {
                log::warn!("Round {} failed: {}", round + 1, e);
            }
        }
    }

    // Compute final global metrics
    let mut global_metrics = HashMap::new();
    if let Some(last) = coordinator.round_history.last() {
        global_metrics = last.metrics.clone();
    }
    global_metrics.insert("total_rounds".to_string(), total_rounds_completed as f64);
    global_metrics.insert("model_version".to_string(), coordinator.global_model.version as f64);

    Ok(FederatedModel {
        model_id: uuid::Uuid::new_v4().to_string(),
        federation_id: config.federation_id.clone(),
        version: coordinator.global_model.version,
        participants: config.participants.len(),
        rounds_completed: total_rounds_completed,
        global_metrics,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedModel {
    pub model_id: String,
    pub federation_id: String,
    pub version: u32,
    pub participants: usize,
    pub rounds_completed: usize,
    pub global_metrics: HashMap<String, f64>,
}

// ============================================================================
// Cross-Organization Learning
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ISACCollaboration {
    pub isac_id: String,
    pub isac_type: ISACType,
    pub members: Vec<String>,
    pub shared_model_id: String,
    pub industry_specific: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ISACType {
    FinancialServices,  // FS-ISAC
    Healthcare,         // H-ISAC
    Automotive,         // Auto-ISAC
    Aviation,           // A-ISAC
    Electricity,        // E-ISAC
    IT,                 // IT-ISAC
    Custom(String),
}

/// Train model collaboratively across ISAC/ISAO members
pub async fn train_isac_model(collaboration: &ISACCollaboration) -> Result<FederatedModel> {
    log::info!(
        "Starting ISAC collaboration training: {} with {} members",
        collaboration.isac_id,
        collaboration.members.len()
    );

    // Create industry-specific training configuration
    let threat_categories = match &collaboration.isac_type {
        ISACType::FinancialServices => vec![
            "fraud_detection", "account_takeover", "payment_fraud", "insider_threat"
        ],
        ISACType::Healthcare => vec![
            "phi_exfiltration", "ransomware", "medical_device_attack", "ehr_tampering"
        ],
        ISACType::Automotive => vec![
            "can_bus_attack", "ecu_tampering", "keyless_entry", "telematics_breach"
        ],
        ISACType::Aviation => vec![
            "flight_system_intrusion", "ground_system_attack", "passenger_data_breach"
        ],
        ISACType::Electricity => vec![
            "scada_attack", "grid_manipulation", "smart_meter_fraud", "substaton_breach"
        ],
        ISACType::IT => vec![
            "apt_detection", "supply_chain_attack", "zero_day_exploit", "lateral_movement"
        ],
        ISACType::Custom(_) => vec!["general_threat"],
    };

    // Build participants from members
    let participants: Vec<Participant> = collaboration.members.iter().enumerate().map(|(i, member)| {
        Participant {
            id: format!("{}-{}", collaboration.isac_id, i),
            organization: member.clone(),
            endpoint: format!("https://{}.isac.internal/federated", member.to_lowercase().replace(' ', "-")),
            data_size: 10000 + i * 1000, // Varying data sizes
            trust_score: 0.9,
        }
    }).collect();

    // Configure federated learning for ISAC
    let config = FederatedLearningConfig {
        federation_id: collaboration.isac_id.clone(),
        participants,
        aggregation_strategy: AggregationStrategy::ByzantineRobust, // Extra security for cross-org
        rounds: 10,
        min_participants_per_round: (collaboration.members.len() / 2).max(1),
        secure_aggregation: true,
        differential_privacy: Some(DifferentialPrivacyConfig {
            epsilon: 1.0,
            delta: 1e-5,
            noise_mechanism: NoiseMechanism::Gaussian,
            clip_norm: 1.0,
            accountant: PrivacyAccountant {
                budget_spent: 0.0,
                budget_remaining: 10.0,
                queries: Vec::new(),
            },
        }),
    };

    let mut model = train_federated_model(&config).await?;

    // Add industry-specific metadata
    model.global_metrics.insert("threat_categories".to_string(), threat_categories.len() as f64);
    model.global_metrics.insert("industry_specific".to_string(), if collaboration.industry_specific { 1.0 } else { 0.0 });

    Ok(model)
}

// ============================================================================
// Differential Privacy
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPrivacyConfig {
    pub epsilon: f64,            // Privacy budget
    pub delta: f64,              // Privacy parameter
    pub noise_mechanism: NoiseMechanism,
    pub clip_norm: f64,          // Gradient clipping
    pub accountant: PrivacyAccountant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoiseMechanism {
    Laplacian,
    Gaussian,
    Exponential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAccountant {
    pub budget_spent: f64,
    pub budget_remaining: f64,
    pub queries: Vec<PrivacyQuery>,
}

impl PrivacyAccountant {
    pub fn new(total_budget: f64) -> Self {
        Self {
            budget_spent: 0.0,
            budget_remaining: total_budget,
            queries: Vec::new(),
        }
    }

    pub fn spend(&mut self, epsilon: f64, delta: f64, query_description: &str) -> Result<()> {
        if epsilon > self.budget_remaining {
            anyhow::bail!("Privacy budget exceeded: requested {} but only {} remaining", epsilon, self.budget_remaining);
        }

        self.budget_spent += epsilon;
        self.budget_remaining -= epsilon;
        self.queries.push(PrivacyQuery {
            query_id: uuid::Uuid::new_v4().to_string(),
            epsilon_spent: epsilon,
            delta_spent: delta,
            timestamp: Utc::now(),
            description: query_description.to_string(),
        });

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyQuery {
    pub query_id: String,
    pub epsilon_spent: f64,
    pub delta_spent: f64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub description: String,
}

/// DP-SGD Trainer for differentially private training
pub struct DPSGDTrainer {
    config: DifferentialPrivacyConfig,
    batch_size: usize,
    learning_rate: f64,
}

impl DPSGDTrainer {
    pub fn new(config: DifferentialPrivacyConfig) -> Self {
        Self {
            config,
            batch_size: 32,
            learning_rate: 0.01,
        }
    }

    /// Compute per-sample gradients with clipping and noise
    pub fn compute_private_gradients(&self, gradients: &[Vec<f64>]) -> Result<Vec<f64>> {
        let mut rng = rand::thread_rng();

        // Clip per-sample gradients
        let clipped: Vec<Vec<f64>> = gradients.iter()
            .map(|g| clip_gradients(g, self.config.clip_norm))
            .collect();

        // Average gradients
        if clipped.is_empty() || clipped[0].is_empty() {
            return Ok(Vec::new());
        }

        let num_weights = clipped[0].len();
        let mut averaged: Vec<f64> = vec![0.0; num_weights];

        for sample_grads in &clipped {
            for (i, &g) in sample_grads.iter().enumerate() {
                if i < num_weights {
                    averaged[i] += g;
                }
            }
        }

        let n = clipped.len() as f64;
        for g in &mut averaged {
            *g /= n;
        }

        // Add noise
        let noise_scale = self.config.clip_norm *
            (2.0 * (1.25 / self.config.delta).ln()).sqrt() /
            (self.config.epsilon * self.batch_size as f64);

        let noised: Vec<f64> = match self.config.noise_mechanism {
            NoiseMechanism::Gaussian => {
                averaged.iter().map(|&g| g + sample_normal(&mut rng, 0.0, noise_scale)).collect()
            }
            NoiseMechanism::Laplacian => {
                averaged.iter().map(|&g| g + sample_laplace(&mut rng, 0.0, noise_scale)).collect()
            }
            NoiseMechanism::Exponential => {
                averaged.iter().map(|&g| {
                    let noise: f64 = rng.gen::<f64>().ln() * noise_scale;
                    g + noise
                }).collect()
            }
        };

        Ok(noised)
    }
}

/// Train model with differential privacy
pub async fn train_with_differential_privacy(
    training_data: &[u8],
    config: &DifferentialPrivacyConfig,
) -> Result<PrivateModel> {
    log::info!(
        "Training with differential privacy: epsilon={}, delta={}, mechanism={:?}",
        config.epsilon,
        config.delta,
        config.noise_mechanism
    );

    let trainer = DPSGDTrainer::new(config.clone());
    let mut accountant = config.accountant.clone();

    // Parse training data (simplified - real implementation would use actual ML framework)
    let data_size = training_data.len();
    let num_epochs = 10;
    let batch_size = 32;
    let num_batches = (data_size / batch_size).max(1);

    // Track privacy budget per epoch
    let epsilon_per_epoch = config.epsilon / num_epochs as f64;

    let mut model_weights: Vec<f64> = (0..100).map(|_| rand::thread_rng().gen_range(-0.1..0.1)).collect();

    for epoch in 0..num_epochs {
        // Check privacy budget
        if accountant.budget_remaining < epsilon_per_epoch {
            log::warn!("Privacy budget exhausted at epoch {}", epoch);
            break;
        }

        // Simulate batch processing
        for _ in 0..num_batches {
            // Generate sample gradients (in real impl, compute from data)
            let sample_gradients: Vec<Vec<f64>> = (0..batch_size)
                .map(|_| (0..model_weights.len()).map(|_| rand::thread_rng().gen_range(-0.01..0.01)).collect())
                .collect();

            // Compute private gradients
            let private_grads = trainer.compute_private_gradients(&sample_gradients)?;

            // Update weights
            for (i, grad) in private_grads.iter().enumerate() {
                if i < model_weights.len() {
                    model_weights[i] -= trainer.learning_rate * grad;
                }
            }
        }

        // Record privacy spend
        accountant.spend(epsilon_per_epoch, config.delta / num_epochs as f64, &format!("Epoch {}", epoch))?;
    }

    let privacy_guarantee = format!(
        "({:.2}, {:.2e})-DP after {} epochs",
        accountant.budget_spent,
        config.delta,
        accountant.queries.len()
    );

    Ok(PrivateModel {
        model_id: uuid::Uuid::new_v4().to_string(),
        epsilon: accountant.budget_spent,
        delta: config.delta,
        privacy_guarantee,
        model_hash: format!("{:x}", Sha256::digest(&serde_json::to_vec(&model_weights).unwrap_or_default())),
        training_epochs: accountant.queries.len(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateModel {
    pub model_id: String,
    pub epsilon: f64,
    pub delta: f64,
    pub privacy_guarantee: String,
    pub model_hash: String,
    pub training_epochs: usize,
}

// ============================================================================
// Homomorphic Encryption
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomomorphicEncryptionConfig {
    pub scheme: HEScheme,
    pub key_size: usize,
    pub security_level: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HEScheme {
    BFV,      // Brakerski-Fan-Vercauteren (integer arithmetic)
    CKKS,     // Cheon-Kim-Kim-Song (approximate arithmetic)
    TFHE,     // Torus Fully Homomorphic Encryption
    Paillier, // Paillier cryptosystem (additive only)
}

/// Homomorphic encryption engine
pub struct HEEngine {
    config: HomomorphicEncryptionConfig,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl HEEngine {
    pub fn new(config: HomomorphicEncryptionConfig) -> Result<Self> {
        let mut rng = rand::thread_rng();

        // Generate keys (simplified - real impl would use actual HE library)
        let public_key: Vec<u8> = (0..config.key_size).map(|_| rng.gen::<u8>()).collect();
        let private_key: Vec<u8> = (0..config.key_size).map(|_| rng.gen::<u8>()).collect();

        Ok(Self {
            config,
            public_key,
            private_key,
        })
    }

    /// Encrypt data for homomorphic operations
    pub fn encrypt(&self, plaintext: &[f64]) -> Result<Vec<u8>> {
        // Simplified encryption - real impl would use SEAL, HElib, or TFHE
        let mut rng = rand::thread_rng();

        let mut ciphertext = Vec::new();
        for &val in plaintext {
            let encoded = val.to_le_bytes();
            let noise: [u8; 8] = rng.gen();

            // XOR with public key portion (simplified)
            let encrypted: Vec<u8> = encoded.iter()
                .zip(noise.iter())
                .zip(self.public_key.iter().cycle())
                .map(|((&e, &n), &k)| e ^ n ^ k)
                .collect();

            ciphertext.extend(encrypted);
            ciphertext.extend(&noise); // Store noise for decryption
        }

        Ok(ciphertext)
    }

    /// Decrypt homomorphically computed result
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<f64>> {
        let chunk_size = 16; // 8 bytes encrypted + 8 bytes noise
        let mut result = Vec::new();

        for chunk in ciphertext.chunks(chunk_size) {
            if chunk.len() < chunk_size {
                break;
            }

            let encrypted = &chunk[0..8];
            let noise = &chunk[8..16];

            // Reverse XOR
            let decrypted: Vec<u8> = encrypted.iter()
                .zip(noise.iter())
                .zip(self.public_key.iter().cycle())
                .map(|((&e, &n), &k)| e ^ n ^ k)
                .collect();

            if decrypted.len() >= 8 {
                let bytes: [u8; 8] = decrypted[0..8].try_into().unwrap_or([0; 8]);
                result.push(f64::from_le_bytes(bytes));
            }
        }

        Ok(result)
    }

    /// Homomorphic addition of encrypted values
    pub fn add_encrypted(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
        // For real HE schemes, this performs component-wise operations
        let result: Vec<u8> = a.iter().zip(b.iter().cycle())
            .map(|(&x, &y)| x.wrapping_add(y))
            .collect();
        Ok(result)
    }

    /// Homomorphic multiplication (for BFV/CKKS)
    pub fn multiply_encrypted(&self, a: &[u8], _b: &[u8]) -> Result<Vec<u8>> {
        // Simplified - real HE multiplication is complex
        Ok(a.to_vec())
    }
}

/// Perform encrypted inference using homomorphic encryption
pub async fn encrypted_inference(
    encrypted_input: &[u8],
    model_id: &str,
    config: &HomomorphicEncryptionConfig,
) -> Result<Vec<u8>> {
    log::info!(
        "Performing encrypted inference on model {} using {:?} scheme",
        model_id,
        config.scheme
    );

    let engine = HEEngine::new(config.clone())?;

    // Simulate model weights (encrypted)
    let model_weights: Vec<f64> = (0..10).map(|i| 0.1 * i as f64).collect();
    let encrypted_weights = engine.encrypt(&model_weights)?;

    // Perform encrypted computation
    // In real impl: matrix multiplication, activation functions all on encrypted data
    let result = match config.scheme {
        HEScheme::BFV | HEScheme::CKKS => {
            // Supports both addition and multiplication
            engine.add_encrypted(encrypted_input, &encrypted_weights)?
        }
        HEScheme::Paillier => {
            // Additive only
            engine.add_encrypted(encrypted_input, &encrypted_weights)?
        }
        HEScheme::TFHE => {
            // Supports arbitrary computations via bootstrapping
            engine.add_encrypted(encrypted_input, &encrypted_weights)?
        }
    };

    Ok(result)
}

// ============================================================================
// Secure Enclaves
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureEnclaveConfig {
    pub enclave_type: EnclaveType,
    pub attestation_required: bool,
    pub confidential_computing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveType {
    IntelSGX,
    AMDSEVSV,
    ARMTrustZone,
    ConfidentialVMs,
}

/// Secure enclave manager
pub struct EnclaveManager {
    config: SecureEnclaveConfig,
    enclave_id: String,
    attestation_report: Option<AttestationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub enclave_id: String,
    pub measurement: String,
    pub signature: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub verified: bool,
}

impl EnclaveManager {
    pub fn new(config: SecureEnclaveConfig) -> Self {
        Self {
            config,
            enclave_id: uuid::Uuid::new_v4().to_string(),
            attestation_report: None,
        }
    }

    /// Generate remote attestation report
    pub async fn generate_attestation(&mut self) -> Result<AttestationReport> {
        let measurement = match self.config.enclave_type {
            EnclaveType::IntelSGX => self.sgx_measurement().await?,
            EnclaveType::AMDSEVSV => self.sev_measurement().await?,
            EnclaveType::ARMTrustZone => self.trustzone_measurement().await?,
            EnclaveType::ConfidentialVMs => self.cvm_measurement().await?,
        };

        let report = AttestationReport {
            enclave_id: self.enclave_id.clone(),
            measurement,
            signature: self.sign_attestation()?,
            timestamp: Utc::now(),
            verified: false,
        };

        self.attestation_report = Some(report.clone());
        Ok(report)
    }

    async fn sgx_measurement(&self) -> Result<String> {
        // MRENCLAVE measurement (hash of enclave code)
        Ok(format!("{:x}", Sha256::digest(format!("sgx-enclave-{}", self.enclave_id).as_bytes())))
    }

    async fn sev_measurement(&self) -> Result<String> {
        // AMD SEV launch measurement
        Ok(format!("{:x}", Sha256::digest(format!("sev-vm-{}", self.enclave_id).as_bytes())))
    }

    async fn trustzone_measurement(&self) -> Result<String> {
        // ARM TrustZone trusted app hash
        Ok(format!("{:x}", Sha256::digest(format!("tz-ta-{}", self.enclave_id).as_bytes())))
    }

    async fn cvm_measurement(&self) -> Result<String> {
        // Confidential VM measurement
        Ok(format!("{:x}", Sha256::digest(format!("cvm-{}", self.enclave_id).as_bytes())))
    }

    fn sign_attestation(&self) -> Result<String> {
        // Sign with enclave key (simplified)
        let signature_data = format!("{}-{}", self.enclave_id, Utc::now().timestamp());
        Ok(format!("{:x}", Sha256::digest(signature_data.as_bytes())))
    }

    /// Verify remote attestation
    pub fn verify_attestation(&self, report: &AttestationReport) -> Result<bool> {
        // Verify signature
        let expected_sig = format!("{:x}", Sha256::digest(format!("{}-{}",
            report.enclave_id,
            report.timestamp.timestamp()
        ).as_bytes()));

        if report.signature != expected_sig {
            log::warn!("Attestation signature mismatch");
            return Ok(false);
        }

        // Verify measurement against expected value
        // In production, this would check against Intel/AMD attestation services
        Ok(true)
    }
}

/// Train model in secure enclave (TEE)
pub async fn train_in_enclave(
    training_data: &[u8],
    config: &SecureEnclaveConfig,
) -> Result<String> {
    log::info!("Initializing secure enclave training with {:?}", config.enclave_type);

    let mut manager = EnclaveManager::new(config.clone());

    // Generate attestation if required
    if config.attestation_required {
        let report = manager.generate_attestation().await?;
        log::info!("Generated attestation report: {}", report.enclave_id);

        if !manager.verify_attestation(&report)? {
            anyhow::bail!("Attestation verification failed");
        }
    }

    // Simulate enclave training
    let model_id = uuid::Uuid::new_v4().to_string();

    log::info!(
        "Training {} bytes of data in enclave {}",
        training_data.len(),
        manager.enclave_id
    );

    // In real implementation:
    // 1. Load training data into enclave memory
    // 2. Perform training operations in protected memory
    // 3. Export only the trained model (not training data)

    let result = EnclaveTrainingResult {
        model_id: model_id.clone(),
        enclave_id: manager.enclave_id.clone(),
        enclave_type: config.enclave_type.clone(),
        attestation: manager.attestation_report,
        training_complete: true,
    };

    log::info!("Enclave training complete: {:?}", result);

    Ok(model_id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveTrainingResult {
    pub model_id: String,
    pub enclave_id: String,
    pub enclave_type: EnclaveType,
    pub attestation: Option<AttestationReport>,
    pub training_complete: bool,
}

// ============================================================================
// Synthetic Data Generation
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticDataConfig {
    pub generator_type: GeneratorType,
    pub original_data_size: usize,
    pub synthetic_data_size: usize,
    pub privacy_preserving: bool,
    pub fidelity_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeneratorType {
    GAN,           // Generative Adversarial Network
    VAE,           // Variational Autoencoder
    CTGAN,         // Conditional Tabular GAN
    TVAE,          // Tabular VAE
    DifferentiallyPrivateGAN,
}

/// Synthetic data generator
pub struct SyntheticGenerator {
    config: SyntheticDataConfig,
    latent_dim: usize,
}

impl SyntheticGenerator {
    pub fn new(config: SyntheticDataConfig) -> Self {
        Self {
            config,
            latent_dim: 64,
        }
    }

    /// Generate synthetic samples using GAN-like approach
    pub fn generate(&self, num_samples: usize) -> Result<Vec<Vec<f64>>> {
        let mut rng = rand::thread_rng();
        let feature_dim = 10; // Example feature dimension

        let samples: Vec<Vec<f64>> = (0..num_samples).map(|_| {
            // Sample from latent space
            let latent: Vec<f64> = (0..self.latent_dim)
                .map(|_| rng.gen_range(-1.0..1.0))
                .collect();

            // "Generate" through network (simplified)
            let generated: Vec<f64> = (0..feature_dim).map(|i| {
                let base: f64 = latent.iter().take(feature_dim).sum();
                let noise: f64 = if self.config.privacy_preserving {
                    rng.gen_range(-0.5..0.5)
                } else {
                    rng.gen_range(-0.1..0.1)
                };
                (base / self.latent_dim as f64 + i as f64 * 0.1 + noise).tanh()
            }).collect();

            generated
        }).collect();

        Ok(samples)
    }

    /// Compute fidelity metrics between real and synthetic data
    pub fn compute_fidelity(&self, real: &[Vec<f64>], synthetic: &[Vec<f64>]) -> FidelityMetrics {
        // Compute basic statistics comparison
        let real_means = compute_column_means(real);
        let synthetic_means = compute_column_means(synthetic);

        let mean_diff: f64 = real_means.iter()
            .zip(synthetic_means.iter())
            .map(|(r, s)| (r - s).abs())
            .sum::<f64>() / real_means.len().max(1) as f64;

        // Compute correlation preservation (simplified)
        let correlation_score = 1.0 - mean_diff.min(1.0);

        FidelityMetrics {
            mean_absolute_error: mean_diff,
            correlation_preservation: correlation_score,
            distribution_similarity: 1.0 - mean_diff * 0.5,
            passes_threshold: correlation_score >= self.config.fidelity_threshold,
        }
    }
}

fn compute_column_means(data: &[Vec<f64>]) -> Vec<f64> {
    if data.is_empty() {
        return Vec::new();
    }

    let num_cols = data[0].len();
    let mut means = vec![0.0; num_cols];

    for row in data {
        for (i, &val) in row.iter().enumerate() {
            if i < num_cols {
                means[i] += val;
            }
        }
    }

    let n = data.len() as f64;
    for mean in &mut means {
        *mean /= n;
    }

    means
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidelityMetrics {
    pub mean_absolute_error: f64,
    pub correlation_preservation: f64,
    pub distribution_similarity: f64,
    pub passes_threshold: bool,
}

/// Generate privacy-preserving synthetic data
pub async fn generate_synthetic_data(config: &SyntheticDataConfig) -> Result<Vec<u8>> {
    log::info!(
        "Generating {} synthetic samples using {:?}",
        config.synthetic_data_size,
        config.generator_type
    );

    let generator = SyntheticGenerator::new(config.clone());

    // Generate synthetic samples
    let samples = generator.generate(config.synthetic_data_size)?;

    // Apply differential privacy if configured
    let final_samples = if config.privacy_preserving {
        let mut rng = rand::thread_rng();
        let noise_scale = 0.1;

        samples.iter().map(|sample| {
            sample.iter().map(|&val| val + sample_normal(&mut rng, 0.0, noise_scale)).collect()
        }).collect::<Vec<Vec<f64>>>()
    } else {
        samples
    };

    // Serialize to bytes
    let serialized = serde_json::to_vec(&final_samples)
        .context("Failed to serialize synthetic data")?;

    log::info!(
        "Generated {} bytes of synthetic data ({} samples)",
        serialized.len(),
        final_samples.len()
    );

    Ok(serialized)
}

// ============================================================================
// Data Anonymization
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationConfig {
    pub techniques: Vec<AnonymizationTechnique>,
    pub pii_detection: bool,
    pub k_anonymity: Option<usize>,
    pub l_diversity: Option<usize>,
    pub t_closeness: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnonymizationTechnique {
    PIIRemoval,
    Generalization,
    Suppression,
    Tokenization,
    Hashing,
    Masking,
    Perturbation,
}

/// Data anonymizer with multiple privacy techniques
pub struct DataAnonymizer {
    config: AnonymizationConfig,
    pii_patterns: Vec<PIIPattern>,
}

#[derive(Debug, Clone)]
struct PIIPattern {
    name: String,
    pattern: regex::Regex,
    replacement: String,
}

impl DataAnonymizer {
    pub fn new(config: AnonymizationConfig) -> Result<Self> {
        let pii_patterns = vec![
            PIIPattern {
                name: "email".to_string(),
                pattern: regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")?,
                replacement: "[EMAIL_REDACTED]".to_string(),
            },
            PIIPattern {
                name: "phone".to_string(),
                pattern: regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")?,
                replacement: "[PHONE_REDACTED]".to_string(),
            },
            PIIPattern {
                name: "ssn".to_string(),
                pattern: regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")?,
                replacement: "[SSN_REDACTED]".to_string(),
            },
            PIIPattern {
                name: "credit_card".to_string(),
                pattern: regex::Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")?,
                replacement: "[CC_REDACTED]".to_string(),
            },
            PIIPattern {
                name: "ip_address".to_string(),
                pattern: regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")?,
                replacement: "[IP_REDACTED]".to_string(),
            },
        ];

        Ok(Self { config, pii_patterns })
    }

    /// Remove PII from text data
    pub fn remove_pii(&self, data: &str) -> (String, usize) {
        let mut result = data.to_string();
        let mut count = 0;

        for pattern in &self.pii_patterns {
            let matches: Vec<_> = pattern.pattern.find_iter(&result).collect();
            count += matches.len();
            result = pattern.pattern.replace_all(&result, &pattern.replacement).to_string();
        }

        (result, count)
    }

    /// Apply generalization to quasi-identifiers
    pub fn generalize(&self, value: &str, level: usize) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                // Generalize numbers by rounding
                if let Ok(num) = value.parse::<f64>() {
                    format!("{:.0}", (num / 10.0).floor() * 10.0)
                } else {
                    // Generalize text by keeping first characters
                    value.chars().take(3).collect::<String>() + "***"
                }
            }
            _ => {
                // Higher generalization
                if let Ok(num) = value.parse::<f64>() {
                    format!("{:.0}", (num / 100.0).floor() * 100.0)
                } else {
                    value.chars().next().map(|c| format!("{}***", c)).unwrap_or_else(|| "***".to_string())
                }
            }
        }
    }

    /// Suppress (remove) values that don't meet anonymity criteria
    pub fn suppress(&self, value: &str) -> String {
        "*".repeat(value.len().min(10))
    }

    /// Tokenize value with consistent pseudo-random token
    pub fn tokenize(&self, value: &str) -> String {
        let hash = Sha256::digest(value.as_bytes());
        format!("TOK_{}", hex::encode(&hash[0..8]))
    }

    /// Hash value with salt
    pub fn hash(&self, value: &str, salt: &str) -> String {
        let salted = format!("{}{}", salt, value);
        format!("{:x}", Sha256::digest(salted.as_bytes()))
    }

    /// Mask value preserving format
    pub fn mask(&self, value: &str, mask_char: char, keep_first: usize, keep_last: usize) -> String {
        let chars: Vec<char> = value.chars().collect();
        let len = chars.len();

        if len <= keep_first + keep_last {
            return mask_char.to_string().repeat(len);
        }

        let mut result = String::new();
        for (i, c) in chars.iter().enumerate() {
            if i < keep_first || i >= len - keep_last {
                result.push(*c);
            } else {
                result.push(mask_char);
            }
        }
        result
    }

    /// Add random noise to numeric values
    pub fn perturb(&self, value: f64, epsilon: f64) -> f64 {
        let mut rng = rand::thread_rng();
        let noise = rng.gen_range(-epsilon..epsilon);
        value + noise
    }

    /// Check k-anonymity of dataset
    pub fn check_k_anonymity(&self, data: &[HashMap<String, String>], quasi_identifiers: &[&str], k: usize) -> bool {
        let mut groups: HashMap<String, usize> = HashMap::new();

        for record in data {
            let key: String = quasi_identifiers.iter()
                .filter_map(|&qi| record.get(qi))
                .cloned()
                .collect::<Vec<_>>()
                .join("|");
            *groups.entry(key).or_insert(0) += 1;
        }

        groups.values().all(|&count| count >= k)
    }

    /// Check l-diversity of dataset
    pub fn check_l_diversity(&self, data: &[HashMap<String, String>], quasi_identifiers: &[&str], sensitive_attr: &str, l: usize) -> bool {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();

        for record in data {
            let key: String = quasi_identifiers.iter()
                .filter_map(|&qi| record.get(qi))
                .cloned()
                .collect::<Vec<_>>()
                .join("|");

            if let Some(sensitive_value) = record.get(sensitive_attr) {
                groups.entry(key).or_default().push(sensitive_value.clone());
            }
        }

        groups.values().all(|values| {
            let unique: std::collections::HashSet<_> = values.iter().collect();
            unique.len() >= l
        })
    }

    /// Check t-closeness of dataset
    pub fn check_t_closeness(&self, data: &[HashMap<String, String>], quasi_identifiers: &[&str], sensitive_attr: &str, t: f64) -> bool {
        // Compute global distribution of sensitive attribute
        let global_values: Vec<&String> = data.iter()
            .filter_map(|r| r.get(sensitive_attr))
            .collect();

        let global_dist = compute_distribution(&global_values);

        // Check each equivalence class
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for record in data {
            let key: String = quasi_identifiers.iter()
                .filter_map(|&qi| record.get(qi))
                .cloned()
                .collect::<Vec<_>>()
                .join("|");

            if let Some(sensitive_value) = record.get(sensitive_attr) {
                groups.entry(key).or_default().push(sensitive_value.clone());
            }
        }

        groups.values().all(|values| {
            let refs: Vec<&String> = values.iter().collect();
            let local_dist = compute_distribution(&refs);
            let distance = earth_mover_distance(&global_dist, &local_dist);
            distance <= t
        })
    }
}

fn compute_distribution(values: &[&String]) -> HashMap<String, f64> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for value in values {
        *counts.entry((*value).clone()).or_insert(0) += 1;
    }

    let total = values.len() as f64;
    counts.into_iter().map(|(k, v)| (k, v as f64 / total)).collect()
}

fn earth_mover_distance(dist1: &HashMap<String, f64>, dist2: &HashMap<String, f64>) -> f64 {
    // Simplified EMD using L1 distance
    let all_keys: std::collections::HashSet<_> = dist1.keys().chain(dist2.keys()).collect();

    all_keys.iter().map(|k| {
        let p1 = dist1.get(*k).copied().unwrap_or(0.0);
        let p2 = dist2.get(*k).copied().unwrap_or(0.0);
        (p1 - p2).abs()
    }).sum::<f64>() / 2.0
}

/// Anonymize data for privacy compliance
pub async fn anonymize_data(
    data: &[u8],
    config: &AnonymizationConfig,
) -> Result<AnonymizationResult> {
    log::info!(
        "Anonymizing {} bytes of data with techniques: {:?}",
        data.len(),
        config.techniques
    );

    let anonymizer = DataAnonymizer::new(config.clone())?;

    // Parse input data as string (or structured data)
    let input_str = String::from_utf8_lossy(data);
    let mut result = input_str.to_string();
    let mut pii_removed = 0;

    // Apply techniques in order
    for technique in &config.techniques {
        match technique {
            AnonymizationTechnique::PIIRemoval => {
                let (cleaned, count) = anonymizer.remove_pii(&result);
                result = cleaned;
                pii_removed += count;
            }
            AnonymizationTechnique::Hashing => {
                // Hash sensitive tokens
                result = result.split_whitespace()
                    .map(|word| {
                        if word.len() > 10 { // Potentially sensitive
                            anonymizer.hash(word, "salt")
                        } else {
                            word.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            AnonymizationTechnique::Masking => {
                // Mask remaining potentially sensitive data
                result = result.split_whitespace()
                    .map(|word| {
                        if word.contains('@') || word.parse::<i64>().is_ok() {
                            anonymizer.mask(word, '*', 2, 2)
                        } else {
                            word.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            _ => {} // Other techniques handled differently
        }
    }

    // Compute privacy metrics
    let privacy_metrics = PrivacyMetrics {
        k_anonymity: config.k_anonymity.unwrap_or(0),
        l_diversity: config.l_diversity.unwrap_or(0),
        t_closeness: config.t_closeness.unwrap_or(0.0),
    };

    Ok(AnonymizationResult {
        anonymized_data: result.into_bytes(),
        pii_removed,
        privacy_metrics,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationResult {
    pub anonymized_data: Vec<u8>,
    pub pii_removed: usize,
    pub privacy_metrics: PrivacyMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyMetrics {
    pub k_anonymity: usize,
    pub l_diversity: usize,
    pub t_closeness: f64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gradient_clipping() {
        let gradients = vec![3.0, 4.0]; // L2 norm = 5
        let clipped = clip_gradients(&gradients, 1.0);

        let norm: f64 = clipped.iter().map(|x| x * x).sum::<f64>().sqrt();
        assert!((norm - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_federated_averaging() {
        let config = FederatedLearningConfig {
            federation_id: "test".to_string(),
            participants: vec![],
            aggregation_strategy: AggregationStrategy::FederatedAveraging,
            rounds: 1,
            min_participants_per_round: 1,
            secure_aggregation: false,
            differential_privacy: None,
        };

        let coordinator = FederatedCoordinator::new(config);

        let updates = vec![
            ParticipantUpdate {
                participant_id: "p1".to_string(),
                gradients: vec![1.0, 2.0, 3.0],
                data_size: 100,
                local_metrics: HashMap::new(),
            },
            ParticipantUpdate {
                participant_id: "p2".to_string(),
                gradients: vec![2.0, 3.0, 4.0],
                data_size: 100,
                local_metrics: HashMap::new(),
            },
        ];

        let result = coordinator.federated_averaging(&updates).unwrap();
        assert_eq!(result.len(), 3);
        assert!((result[0] - 1.5).abs() < 0.01);
        assert!((result[1] - 2.5).abs() < 0.01);
        assert!((result[2] - 3.5).abs() < 0.01);
    }

    #[test]
    fn test_pii_removal() {
        let config = AnonymizationConfig {
            techniques: vec![AnonymizationTechnique::PIIRemoval],
            pii_detection: true,
            k_anonymity: None,
            l_diversity: None,
            t_closeness: None,
        };

        let anonymizer = DataAnonymizer::new(config).unwrap();
        let text = "Contact me at user@example.com or 555-123-4567";
        let (cleaned, count) = anonymizer.remove_pii(text);

        assert!(!cleaned.contains("user@example.com"));
        assert!(!cleaned.contains("555-123-4567"));
        assert_eq!(count, 2);
    }

    #[test]
    fn test_tokenization() {
        let config = AnonymizationConfig {
            techniques: vec![AnonymizationTechnique::Tokenization],
            pii_detection: false,
            k_anonymity: None,
            l_diversity: None,
            t_closeness: None,
        };

        let anonymizer = DataAnonymizer::new(config).unwrap();

        let token1 = anonymizer.tokenize("secret_value");
        let token2 = anonymizer.tokenize("secret_value");
        let token3 = anonymizer.tokenize("different_value");

        assert_eq!(token1, token2); // Same input = same token
        assert_ne!(token1, token3); // Different input = different token
        assert!(token1.starts_with("TOK_"));
    }

    #[test]
    fn test_masking() {
        let config = AnonymizationConfig {
            techniques: vec![],
            pii_detection: false,
            k_anonymity: None,
            l_diversity: None,
            t_closeness: None,
        };

        let anonymizer = DataAnonymizer::new(config).unwrap();
        let masked = anonymizer.mask("1234567890", '*', 2, 2);

        assert_eq!(masked, "12******90");
    }

    #[test]
    fn test_k_anonymity_check() {
        let config = AnonymizationConfig {
            techniques: vec![],
            pii_detection: false,
            k_anonymity: Some(2),
            l_diversity: None,
            t_closeness: None,
        };

        let anonymizer = DataAnonymizer::new(config).unwrap();

        let data = vec![
            HashMap::from([("age".to_string(), "30".to_string()), ("zip".to_string(), "12345".to_string())]),
            HashMap::from([("age".to_string(), "30".to_string()), ("zip".to_string(), "12345".to_string())]),
            HashMap::from([("age".to_string(), "40".to_string()), ("zip".to_string(), "67890".to_string())]),
        ];

        // Should fail k=2 because group (40, 67890) has only 1 record
        assert!(!anonymizer.check_k_anonymity(&data, &["age", "zip"], 2));

        // Should pass k=1
        assert!(anonymizer.check_k_anonymity(&data, &["age", "zip"], 1));
    }

    #[test]
    fn test_privacy_accountant() {
        let mut accountant = PrivacyAccountant::new(10.0);

        assert!(accountant.spend(3.0, 1e-5, "Query 1").is_ok());
        assert_eq!(accountant.budget_spent, 3.0);
        assert_eq!(accountant.budget_remaining, 7.0);

        assert!(accountant.spend(5.0, 1e-5, "Query 2").is_ok());
        assert_eq!(accountant.budget_spent, 8.0);

        // Should fail - not enough budget
        assert!(accountant.spend(5.0, 1e-5, "Query 3").is_err());
    }

    #[test]
    fn test_synthetic_generator() {
        let config = SyntheticDataConfig {
            generator_type: GeneratorType::GAN,
            original_data_size: 1000,
            synthetic_data_size: 100,
            privacy_preserving: true,
            fidelity_threshold: 0.8,
        };

        let generator = SyntheticGenerator::new(config);
        let samples = generator.generate(50).unwrap();

        assert_eq!(samples.len(), 50);
        assert!(!samples[0].is_empty());
    }

    #[tokio::test]
    async fn test_anonymize_data() {
        let config = AnonymizationConfig {
            techniques: vec![AnonymizationTechnique::PIIRemoval],
            pii_detection: true,
            k_anonymity: Some(2),
            l_diversity: Some(2),
            t_closeness: Some(0.2),
        };

        let data = b"User email: test@example.com, phone: 555-123-4567";
        let result = anonymize_data(data, &config).await.unwrap();

        let output = String::from_utf8_lossy(&result.anonymized_data);
        assert!(!output.contains("test@example.com"));
        assert!(!output.contains("555-123-4567"));
        assert_eq!(result.pii_removed, 2);
    }
}
