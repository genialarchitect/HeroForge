//! ML model management

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingData {
    pub features: Vec<Vec<f32>>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub class: String,
    pub confidence: f32,
    pub probabilities: Vec<(String, f32)>,
}

pub async fn predict(model_id: &str, features: Vec<f32>) -> anyhow::Result<Prediction> {
    // TODO: Make prediction using trained model
    Ok(Prediction {
        class: "benign".to_string(),
        confidence: 0.95,
        probabilities: vec![
            ("benign".to_string(), 0.95),
            ("malicious".to_string(), 0.05),
        ],
    })
}
