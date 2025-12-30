//! GitLab integration

use anyhow::Result;

pub struct GitLabIntegration {
    token: String,
}

impl GitLabIntegration {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub async fn scan_project(&self, project_id: &str) -> Result<Vec<String>> {
        // TODO: Scan GitLab project
        Ok(vec![])
    }
}
