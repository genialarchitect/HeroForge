//! Custom dashboard builder

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub id: String,
    pub name: String,
    pub widgets: Vec<Widget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub widget_type: String,
    pub title: String,
    pub config: serde_json::Value,
}

pub struct DashboardBuilder {}

impl DashboardBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_dashboard(&self, name: &str) -> Dashboard {
        Dashboard {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            widgets: vec![],
        }
    }

    pub async fn render_dashboard(&self, dashboard: &Dashboard) -> Result<String> {
        // TODO: Render dashboard to HTML/JSON
        Ok(String::new())
    }
}

impl Default for DashboardBuilder {
    fn default() -> Self {
        Self::new()
    }
}
