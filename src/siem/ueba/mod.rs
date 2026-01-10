//! UEBA (User Entity Behavior Analytics) module for HeroForge.
//!
//! This module provides comprehensive behavioral analytics capabilities including:
//! - Entity tracking (users, hosts, service accounts, applications)
//! - Activity monitoring and logging
//! - Behavioral baseline calculation
//! - Anomaly detection (impossible travel, off-hours, unusual access patterns)
//! - Risk scoring and management
//! - Peer group analysis
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! |   Data Sources   | --> |   UEBA Engine    | --> |    Anomalies     |
//! | (SIEM, Logs)     |     | (Analysis)       |     | (Detection)      |
//! +------------------+     +------------------+     +------------------+
//!                                  |
//!                                  v
//! +------------------+     +------------------+     +------------------+
//! |   Risk Scores    | <-- |    Baselines     | <-- |   Activities     |
//! |   (Entity Risk)  |     | (Statistics)     |     |   (Events)       |
//! +------------------+     +------------------+     +------------------+
//! ```
//!
//! # Key Features
//!
//! - **Impossible Travel Detection**: Detects when a user logs in from geographically
//!   distant locations within an impossibly short time frame
//! - **Off-Hours Activity**: Identifies activities outside normal working hours
//! - **Baseline Deviation**: Alerts when behavior significantly deviates from established patterns
//! - **Failed Login Analysis**: Detects brute-force attempts and credential stuffing
//! - **Risk Scoring**: Calculates and tracks entity risk scores over time
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use heroforge::siem::ueba::{UebaEngine, RecordActivityRequest};
//!
//! // Create engine
//! let engine = UebaEngine::new(pool);
//!
//! // Record an activity
//! let activity = RecordActivityRequest {
//!     entity_id: "user@example.com".to_string(),
//!     activity_type: "login".to_string(),
//!     source_ip: Some("1.2.3.4".to_string()),
//!     source_country: Some("US".to_string()),
//!     source_lat: Some(40.7128),
//!     source_lon: Some(-74.0060),
//!     ..Default::default()
//! };
//!
//! let result = engine.process_activity("user_id", &activity).await?;
//! if result.is_anomalous {
//!     println!("Anomalies detected: {:?}", result.detected_anomalies);
//! }
//! ```

#![allow(dead_code)]

pub mod advanced_detection;
pub mod engine;
pub mod types;

// Re-export commonly used types
pub use engine::{
    DetectedAnomaly, ProcessActivityResult, UebaEngine, UebaEngineConfig,
};

pub use types::{
    // Entity types
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

    // Geo
    GeoLocation,

    // Queries
    ListEntitiesQuery, ListAnomaliesQuery, ListActivitiesQuery,
};

// Advanced detection exports

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all types are accessible
        let _entity_type = EntityType::User;
        let _risk_level = RiskLevel::High;
        let _activity_type = ActivityType::Login;
        let _anomaly_type = AnomalyType::ImpossibleTravel;
        let _anomaly_status = AnomalyStatus::New;
        let _factor_type = RiskFactorType::Anomaly;
        let _metric_cat = MetricCategory::LoginActivity;
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_geo_location_distance() {
        let loc1 = GeoLocation {
            lat: 40.7128,
            lon: -74.0060,
            country: Some("US".to_string()),
            city: Some("New York".to_string()),
        };
        let loc2 = GeoLocation {
            lat: 34.0522,
            lon: -118.2437,
            country: Some("US".to_string()),
            city: Some("Los Angeles".to_string()),
        };

        let distance = loc1.distance_km(&loc2);
        // NY to LA is approximately 3935 km
        assert!(distance > 3900.0 && distance < 4000.0);
    }
}
