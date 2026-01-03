//! Quantum readiness assessment

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// Quantum-vulnerable algorithm definitions with their properties
const QUANTUM_VULNERABLE_ALGORITHMS: &[(&str, &str, i32, &str, &str)] = &[
    // (algorithm, replacement, default_key_size, vulnerability, nist_status)
    ("RSA-1024", "CRYSTALS-Kyber-512", 1024, "Vulnerable to Shor's algorithm - critical risk", "NIST FIPS 203"),
    ("RSA-2048", "CRYSTALS-Kyber-768", 2048, "Vulnerable to Shor's algorithm", "NIST FIPS 203"),
    ("RSA-4096", "CRYSTALS-Kyber-1024", 4096, "Vulnerable to Shor's algorithm - lower priority", "NIST FIPS 203"),
    ("ECDSA-P256", "CRYSTALS-Dilithium-2", 256, "Vulnerable to Shor's algorithm", "NIST FIPS 204"),
    ("ECDSA-P384", "CRYSTALS-Dilithium-3", 384, "Vulnerable to Shor's algorithm", "NIST FIPS 204"),
    ("ECDSA-P521", "CRYSTALS-Dilithium-5", 521, "Vulnerable to Shor's algorithm", "NIST FIPS 204"),
    ("ECDH-P256", "CRYSTALS-Kyber-512 KEM", 256, "Vulnerable to Shor's algorithm", "NIST FIPS 203"),
    ("ECDH-P384", "CRYSTALS-Kyber-768 KEM", 384, "Vulnerable to Shor's algorithm", "NIST FIPS 203"),
    ("DSA-2048", "Falcon-512", 2048, "Vulnerable to Shor's algorithm", "NIST FIPS 206"),
    ("DSA-3072", "Falcon-1024", 3072, "Vulnerable to Shor's algorithm", "NIST FIPS 206"),
    ("DH-2048", "CRYSTALS-Kyber-768", 2048, "Vulnerable to Shor's algorithm", "NIST FIPS 203"),
    ("ElGamal", "CRYSTALS-Kyber", 2048, "Vulnerable to Shor's algorithm", "NIST FIPS 203"),
];

/// Assess quantum computing readiness and cryptographic vulnerabilities
pub async fn assess_quantum_readiness(inventory: &CryptoInventory) -> Result<QuantumReadinessAssessment> {
    let mut assessment = QuantumReadinessAssessment::default();

    // Build a map of algorithm usage from inventory
    let mut algo_usage: HashMap<String, usize> = HashMap::new();
    for asset in &inventory.assets {
        for algo in &asset.algorithms {
            *algo_usage.entry(algo.clone()).or_insert(0) += 1;
        }
    }

    // Analyze each quantum-vulnerable algorithm
    for (algo, replacement, key_size, vulnerability, nist_status) in QUANTUM_VULNERABLE_ALGORITHMS {
        // Count usage including partial matches (e.g., "RSA" matches "RSA-2048")
        let usage_count = algo_usage
            .iter()
            .filter(|(k, _)| k.starts_with(&algo.split('-').next().unwrap_or(algo)))
            .map(|(_, v)| v)
            .sum::<usize>();

        let complexity = estimate_migration_complexity(algo, inventory);
        let performance_impact = estimate_performance_impact(algo, replacement);

        assessment.vulnerable_algorithms.push(VulnerableAlgorithm {
            algorithm: algo.to_string(),
            usage_count,
            key_size: *key_size as u32,
            quantum_vulnerability: vulnerability.to_string(),
            recommended_replacement: replacement.to_string(),
        });

        assessment.pqc_recommendations.push(PQCRecommendation {
            current_algorithm: algo.to_string(),
            recommended_pqc: replacement.to_string(),
            nist_status: nist_status.to_string(),
            implementation_complexity: complexity,
            performance_impact,
        });
    }

    // Evaluate crypto agility (ability to swap algorithms)
    let crypto_agility = evaluate_crypto_agility(inventory);

    // Calculate harvest-now-decrypt-later (HNDL) risk
    let hndl_risk = calculate_hndl_risk(inventory);

    // Create migration roadmap
    let migration_plan = create_migration_roadmap(inventory, &assessment.vulnerable_algorithms);

    // Calculate overall risk based on multiple factors
    let overall_risk = calculate_overall_quantum_risk(
        &assessment.vulnerable_algorithms,
        crypto_agility,
        hndl_risk,
        inventory,
    );

    assessment.overall_risk = overall_risk;
    assessment.migration_plan = migration_plan;
    assessment.migration_plan.crypto_agility_score = crypto_agility;

    // Add hybrid scheme recommendations for high-value assets
    add_hybrid_scheme_recommendations(&mut assessment, inventory);

    Ok(assessment)
}

/// Estimate migration complexity based on algorithm type and inventory
fn estimate_migration_complexity(algo: &str, inventory: &CryptoInventory) -> String {
    // Count how many assets use this algorithm
    let affected_assets = inventory.assets
        .iter()
        .filter(|a| a.algorithms.iter().any(|alg| alg.contains(algo.split('-').next().unwrap_or(algo))))
        .count();

    // Check for hardcoded implementations
    let has_hardcoded = inventory.assets
        .iter()
        .any(|a| a.has_hardcoded_crypto && a.algorithms.iter().any(|alg| alg.contains(algo.split('-').next().unwrap_or(algo))));

    if has_hardcoded {
        "Very High - Hardcoded implementations detected".to_string()
    } else if affected_assets > 50 {
        "High - Many systems affected".to_string()
    } else if affected_assets > 20 {
        "Medium - Moderate number of systems".to_string()
    } else if affected_assets > 5 {
        "Low - Few systems affected".to_string()
    } else {
        "Minimal - Limited exposure".to_string()
    }
}

/// Estimate performance impact of migration to PQC
fn estimate_performance_impact(current: &str, replacement: &str) -> String {
    // PQC algorithms generally have larger key sizes and different performance characteristics
    match replacement {
        r if r.contains("Kyber-512") => "Low (5-15% overhead for KEM operations)".to_string(),
        r if r.contains("Kyber-768") => "Moderate (10-20% overhead for KEM operations)".to_string(),
        r if r.contains("Kyber-1024") => "Moderate (15-25% overhead for KEM operations)".to_string(),
        r if r.contains("Dilithium-2") => "Low (signatures ~20% slower, verification faster)".to_string(),
        r if r.contains("Dilithium-3") => "Moderate (signatures ~30% slower)".to_string(),
        r if r.contains("Dilithium-5") => "Moderate-High (signatures ~40% slower)".to_string(),
        r if r.contains("Falcon-512") => "Moderate (compact signatures but complex signing)".to_string(),
        r if r.contains("Falcon-1024") => "Moderate-High (larger signatures, complex signing)".to_string(),
        _ => "Variable - requires benchmarking".to_string(),
    }
}

/// Evaluate the organization's crypto agility (0.0 to 1.0)
fn evaluate_crypto_agility(inventory: &CryptoInventory) -> f64 {
    let total_assets = inventory.assets.len();
    if total_assets == 0 {
        return 0.5; // Unknown/default
    }

    let mut agility_score = 0.0;

    // Check for abstraction layers
    let uses_abstraction = inventory.assets
        .iter()
        .filter(|a| a.uses_crypto_abstraction)
        .count();
    agility_score += (uses_abstraction as f64 / total_assets as f64) * 0.4;

    // Check for hardcoded crypto (negative impact)
    let hardcoded_count = inventory.assets
        .iter()
        .filter(|a| a.has_hardcoded_crypto)
        .count();
    agility_score -= (hardcoded_count as f64 / total_assets as f64) * 0.3;

    // Check for crypto library usage (positive if centralized)
    let uses_central_lib = inventory.assets
        .iter()
        .filter(|a| a.uses_central_crypto_lib)
        .count();
    agility_score += (uses_central_lib as f64 / total_assets as f64) * 0.3;

    // Normalize to 0.0-1.0
    agility_score.max(0.0).min(1.0)
}

/// Calculate harvest-now-decrypt-later risk
fn calculate_hndl_risk(inventory: &CryptoInventory) -> f64 {
    // HNDL risk depends on:
    // 1. Data sensitivity (how valuable is the encrypted data)
    // 2. Data retention period (how long will the data be sensitive)
    // 3. Estimated time to quantum (when will quantum computers be able to break current crypto)

    let mut risk = 0.0;
    let total_assets = inventory.assets.len();
    if total_assets == 0 {
        return 0.5;
    }

    for asset in &inventory.assets {
        // Higher sensitivity = higher risk
        let sensitivity_factor = match asset.data_sensitivity.as_str() {
            "critical" | "top_secret" => 1.0,
            "high" | "secret" => 0.8,
            "medium" | "confidential" => 0.5,
            "low" | "public" => 0.2,
            _ => 0.5,
        };

        // Longer retention = higher risk
        let retention_factor = if asset.data_retention_years > 10 {
            1.0
        } else if asset.data_retention_years > 5 {
            0.7
        } else if asset.data_retention_years > 2 {
            0.4
        } else {
            0.2
        };

        risk += sensitivity_factor * retention_factor;
    }

    // Normalize and return
    (risk / total_assets as f64).min(1.0)
}

/// Create a migration roadmap to post-quantum cryptography
fn create_migration_roadmap(inventory: &CryptoInventory, vulnerable: &[VulnerableAlgorithm]) -> MigrationPlan {
    let mut plan = MigrationPlan::default();

    // Calculate total vulnerable assets
    let total_vulnerable: usize = vulnerable.iter().map(|v| v.usage_count).sum();

    // Phase 1: Inventory and Assessment (Current)
    plan.phases.push(MigrationPhase {
        phase_number: 1,
        name: "Inventory and Assessment".to_string(),
        description: "Complete cryptographic inventory and risk assessment".to_string(),
        duration_months: 3,
        tasks: vec![
            "Complete crypto asset inventory".to_string(),
            "Identify all quantum-vulnerable implementations".to_string(),
            "Assess business criticality of each system".to_string(),
            "Document crypto dependencies".to_string(),
        ],
        dependencies: vec![],
        estimated_effort: "1-2 FTEs".to_string(),
        estimated_cost: "$50,000 - $150,000".to_string(),
    });

    // Phase 2: Crypto Agility Implementation
    plan.phases.push(MigrationPhase {
        phase_number: 2,
        name: "Crypto Agility Implementation".to_string(),
        description: "Implement abstraction layers and prepare for algorithm swapping".to_string(),
        duration_months: 6,
        tasks: vec![
            "Implement crypto abstraction layers".to_string(),
            "Remove hardcoded cryptographic implementations".to_string(),
            "Centralize crypto library usage".to_string(),
            "Update key management systems".to_string(),
        ],
        dependencies: vec!["Phase 1 completion".to_string()],
        estimated_effort: "3-4 FTEs".to_string(),
        estimated_cost: "$200,000 - $500,000".to_string(),
    });

    // Phase 3: Hybrid Implementation
    plan.phases.push(MigrationPhase {
        phase_number: 3,
        name: "Hybrid PQC Implementation".to_string(),
        description: "Deploy hybrid classical/PQC schemes for high-value assets".to_string(),
        duration_months: 12,
        tasks: vec![
            "Deploy hybrid TLS with Kyber for external connections".to_string(),
            "Implement hybrid signatures for code signing".to_string(),
            "Update certificate infrastructure".to_string(),
            "Test interoperability with partners".to_string(),
        ],
        dependencies: vec!["Phase 2 completion".to_string(), "NIST PQC standards finalization".to_string()],
        estimated_effort: "5-8 FTEs".to_string(),
        estimated_cost: "$500,000 - $1,500,000".to_string(),
    });

    // Phase 4: Full PQC Migration
    plan.phases.push(MigrationPhase {
        phase_number: 4,
        name: "Full PQC Migration".to_string(),
        description: "Complete migration to post-quantum cryptography".to_string(),
        duration_months: 24,
        tasks: vec![
            "Replace all vulnerable algorithms with PQC".to_string(),
            "Re-encrypt long-term sensitive data".to_string(),
            "Update all certificates to PQC".to_string(),
            "Deprecate classical-only cryptography".to_string(),
        ],
        dependencies: vec!["Phase 3 completion".to_string(), "Industry-wide PQC adoption".to_string()],
        estimated_effort: "8-12 FTEs".to_string(),
        estimated_cost: "$1,000,000 - $5,000,000".to_string(),
    });

    // Set timeline
    plan.estimated_total_months = 45; // ~4 years
    plan.priority = if total_vulnerable > 100 { "Critical" } else if total_vulnerable > 50 { "High" } else { "Medium" }.to_string();

    plan
}

/// Calculate overall quantum risk level
fn calculate_overall_quantum_risk(
    vulnerable: &[VulnerableAlgorithm],
    crypto_agility: f64,
    hndl_risk: f64,
    inventory: &CryptoInventory,
) -> QuantumRisk {
    let total_vulnerable: usize = vulnerable.iter().map(|v| v.usage_count).sum();

    // Weight factors
    let vulnerability_score = (total_vulnerable as f64 / 100.0).min(1.0);
    let agility_penalty = (1.0 - crypto_agility) * 0.3;

    let risk_score = (vulnerability_score * 0.4) + (hndl_risk * 0.3) + agility_penalty;

    if risk_score > 0.7 {
        QuantumRisk::Critical
    } else if risk_score > 0.5 {
        QuantumRisk::High
    } else if risk_score > 0.3 {
        QuantumRisk::Medium
    } else {
        QuantumRisk::Low
    }
}

/// Add recommendations for hybrid classical/PQC schemes
fn add_hybrid_scheme_recommendations(assessment: &mut QuantumReadinessAssessment, inventory: &CryptoInventory) {
    // Recommend hybrid schemes for high-value assets
    assessment.hybrid_recommendations.push(HybridSchemeRecommendation {
        use_case: "TLS Key Exchange".to_string(),
        classical_algorithm: "ECDH-P384".to_string(),
        pqc_algorithm: "CRYSTALS-Kyber-768".to_string(),
        combination_method: "Concatenated key derivation".to_string(),
        standards_reference: "draft-ietf-tls-hybrid-design".to_string(),
    });

    assessment.hybrid_recommendations.push(HybridSchemeRecommendation {
        use_case: "Code Signing".to_string(),
        classical_algorithm: "ECDSA-P384".to_string(),
        pqc_algorithm: "CRYSTALS-Dilithium-3".to_string(),
        combination_method: "Dual signature".to_string(),
        standards_reference: "NIST SP 800-208".to_string(),
    });

    assessment.hybrid_recommendations.push(HybridSchemeRecommendation {
        use_case: "Document Signing".to_string(),
        classical_algorithm: "RSA-4096".to_string(),
        pqc_algorithm: "CRYSTALS-Dilithium-5".to_string(),
        combination_method: "Dual signature with timestamp".to_string(),
        standards_reference: "ETSI TS 119 312".to_string(),
    });

    assessment.hybrid_recommendations.push(HybridSchemeRecommendation {
        use_case: "Key Encapsulation for Email".to_string(),
        classical_algorithm: "RSA-2048 OAEP".to_string(),
        pqc_algorithm: "CRYSTALS-Kyber-768".to_string(),
        combination_method: "KEM combination (X-Wing)".to_string(),
        standards_reference: "draft-ietf-lamps-cms-kyber".to_string(),
    });
}
