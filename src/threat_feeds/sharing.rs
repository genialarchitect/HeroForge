//! Threat intelligence sharing platforms

use anyhow::Result;

pub struct ThreatIntelSharing {}

impl ThreatIntelSharing {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn share_indicator(&self, ioc: &str, context: &str) -> Result<()> {
        // TODO: Share to MISP/ThreatStream/etc
        Ok(())
    }
}

impl Default for ThreatIntelSharing {
    fn default() -> Self {
        Self::new()
    }
}
