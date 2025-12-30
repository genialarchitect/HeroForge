//! Bitbucket integration

use anyhow::Result;

pub struct BitbucketIntegration {
    token: String,
}

impl BitbucketIntegration {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub async fn scan_repository(&self, repo: &str) -> Result<Vec<String>> {
        // TODO: Scan Bitbucket repository
        Ok(vec![])
    }
}
