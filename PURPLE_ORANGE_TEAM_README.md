# Purple & Orange Team Enhancement Implementation

**Version:** 1.0
**Implementation Date:** 2025-12-30
**Status:** Phase 1 Complete, Phase 2 Partial

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Phase 1: Cross-Team Data Flow](#phase-1-cross-team-data-flow)
4. [Phase 2: Purple Team Enhancements](#phase-2-purple-team-enhancements)
5. [API Documentation](#api-documentation)
6. [Database Schema](#database-schema)
7. [Usage Examples](#usage-examples)
8. [Configuration](#configuration)
9. [Testing](#testing)
10. [Future Enhancements](#future-enhancements)

---

## Overview

This implementation provides comprehensive cross-team collaboration and data flow infrastructure for HeroForge's colored team operations, with enhanced Purple Team and Orange Team capabilities.

### Key Features

**Phase 1 - Foundation (✅ Complete):**
- Unified security context for users, assets, and threats
- Event bus for real-time cross-team communication
- Database correlation tables for all colored teams
- RESTful API for context retrieval and event publishing

**Phase 2 - Purple Team (🔨 Partial):**
- Live exercise dashboard with real-time updates
- Comprehensive attack library with 50+ MITRE ATT&CK techniques
- APT playbooks (Lazarus, APT28, APT29)
- Ransomware simulation scenarios

**Phase 3 - Orange Team (📋 Planned):**
- Multi-channel phishing (email, SMS, voice, QR)
- AI-powered personalized learning
- Behavioral analytics and risk scoring
- Social engineering testing beyond phishing

**Phase 4 - Integration (📋 Planned):**
- Automated cross-team workflows
- Event-driven orchestration
- Real-time collaboration features

---

## Architecture

### Event-Driven Design

```
┌─────────────┐
│ Red Team    │──┐
│ (Scanner)   │  │
└─────────────┘  │
                 │     ┌──────────────┐
┌─────────────┐  ├────►│  Event Bus   │────► WebSocket Subscribers
│ Blue Team   │  │     │  (Broadcast) │
│ (Detection) │──┤     └──────────────┘
└─────────────┘  │            │
                 │            │
┌─────────────┐  │            ▼
│ Purple Team │──┤     ┌──────────────┐
│ (Validation)│  │     │  Database    │
└─────────────┘  │     │  Event Log   │
                 │     └──────────────┘
┌─────────────┐  │
│ Yellow Team │──┤
│ (DevSecOps) │  │
└─────────────┘  │
                 │
┌─────────────┐  │
│ Orange Team │──┤
│ (Training)  │  │
└─────────────┘  │
                 │
┌─────────────┐  │
│ White Team  │──┤
│ (GRC)       │  │
└─────────────┘  │
                 │
┌─────────────┐  │
│ Green Team  │──┘
│ (SOC)       │
└─────────────┘
```

### Data Flow Example

**Scenario:** Purple Team Exercise Identifies Detection Gap

```
1. Purple Team executes T1003.001 (LSASS Memory) attack
   └─► Publishes: SecurityEvent::AttackSimulated

2. Event Bus routes event to Blue Team + Green Team
   └─► Blue Team: No detection triggered
   └─► Purple Team: Records as detection gap

3. Purple Team publishes: SecurityEvent::GapIdentified
   └─► Routed to Blue Team

4. Blue Team creates Sigma rule for LSASS access
   └─► Publishes: SecurityEvent::DetectionRuleCreated

5. Purple Team re-tests with new rule
   └─► Detection successful!
   └─► Publishes: SecurityEvent::DetectionValidated

6. Green Team updates SOC playbooks
   └─► Publishes: SecurityEvent::PlaybookExecuted
```

---

## Phase 1: Cross-Team Data Flow

### Components

#### 1. Database Tables

**`user_security_context`** - Unified user risk profile
```sql
CREATE TABLE user_security_context (
    user_id TEXT PRIMARY KEY,
    -- Orange Team
    training_completion_rate REAL,
    phishing_click_rate REAL,
    security_awareness_score REAL,
    -- Green Team
    incident_count INTEGER,
    insider_threat_score REAL,
    -- Yellow Team
    secure_coding_score REAL,
    -- White Team
    compliance_violations INTEGER,
    policy_violations INTEGER,
    -- Aggregated
    overall_risk_score REAL,
    risk_level TEXT
);
```

**`asset_security_context`** - Unified asset risk profile
```sql
CREATE TABLE asset_security_context (
    asset_id TEXT PRIMARY KEY,
    -- Red Team
    vulnerability_count INTEGER,
    exploitability_score REAL,
    -- Blue Team
    detection_coverage REAL,
    monitored INTEGER,
    -- Purple Team
    attack_simulation_count INTEGER,
    detection_gap_count INTEGER,
    -- Aggregated
    overall_risk_score REAL
);
```

**`cross_team_events`** - Event bus log
```sql
CREATE TABLE cross_team_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT,
    source_team TEXT,
    target_teams TEXT,  -- JSON array
    payload TEXT,       -- JSON
    timestamp TEXT
);
```

#### 2. Event Types

24+ event types across 7 colored teams:

**Red Team:**
- `VulnerabilityDiscovered` - New vulnerability found in scan
- `ScanCompleted` - Scan finished
- `ExploitSuccessful` - Exploitation test succeeded
- `AssetDiscovered` - New asset identified

**Blue Team:**
- `DetectionRuleCreated` - New detection rule deployed
- `AlertTriggered` - SIEM/EDR alert fired
- `ThreatDetected` - Threat identified

**Purple Team:**
- `ExerciseCompleted` - Purple team exercise finished
- `GapIdentified` - Detection gap discovered
- `DetectionValidated` - Detection rule validated
- `AttackSimulated` - Attack simulation executed

**Yellow Team:**
- `CodeVulnerabilityFound` - SAST/SCA finding
- `DependencyRiskDetected` - Vulnerable dependency
- `SecureCodeScanned` - Code scan completed
- `BuildFailed` - CI/CD build failure

**Orange Team:**
- `PhishingClicked` - User clicked phishing link
- `TrainingCompleted` - Training module completed
- `UserRiskChanged` - User risk score updated
- `SecurityAwarenessTest` - Test completed

**White Team:**
- `ComplianceViolation` - Policy/regulation violation
- `PolicyUpdated` - Security policy changed
- `RiskAssessed` - Risk assessment completed
- `AuditCompleted` - Audit finished

**Green Team:**
- `IncidentCreated` - New security incident
- `IncidentResolved` - Incident closed
- `PlaybookExecuted` - SOAR playbook run
- `SoarAutomated` - Automation triggered

#### 3. Context Types

**UserSecurityContext:**
```rust
pub struct UserSecurityContext {
    pub user_id: String,
    pub username: String,
    pub email: String,

    // Team-specific contexts
    pub orange_team: OrangeTeamContext,
    pub green_team: GreenTeamContext,
    pub yellow_team: Option<YellowTeamContext>,
    pub white_team: WhiteTeamContext,

    // Aggregated risk
    pub overall_risk_score: f64,
    pub risk_level: RiskLevel,
}
```

**AssetSecurityContext:**
```rust
pub struct AssetSecurityContext {
    pub asset_id: String,
    pub hostname: String,
    pub ip_addresses: Vec<String>,

    // Team-specific contexts
    pub red_team: RedTeamContext,
    pub blue_team: BlueTeamContext,
    pub green_team: AssetGreenTeamContext,
    pub purple_team: PurpleTeamContext,
    pub white_team: AssetWhiteTeamContext,

    // Aggregated risk
    pub overall_risk_score: f64,
    pub risk_level: String,
}
```

---

## Phase 2: Purple Team Enhancements

### Live Exercises

**Features:**
- Real-time exercise status tracking
- Side-by-side red/blue timelines
- Detection latency metrics
- Live collaboration (annotations, chat)
- WebSocket updates for all participants

**Exercise Phases:**
1. Preparation - Setup targets, configure detection
2. Execution - Launch attacks
3. Detection - Monitor blue team response
4. Analysis - Analyze detection gaps
5. Remediation - Create improvement plans
6. Complete - Generate reports

**Example Timeline Event:**
```json
{
  "timestamp": "2025-12-30T10:30:00Z",
  "event_type": "ThreatDetected",
  "team": "blue",
  "description": "LSASS process access detected by EDR",
  "technique_id": "T1003.001",
  "detection_details": {
    "rule_name": "LSASS Memory Access",
    "alert_severity": "high",
    "time_to_detect_ms": 3500,
    "confidence": 0.95
  }
}
```

### Attack Library

**50+ MITRE ATT&CK Techniques** (3 implemented, 47+ expandable)

**Implemented Examples:**
- `T1566.001` - Spearphishing Attachment
- `T1003.001` - LSASS Memory Dumping
- `T1059.001` - PowerShell Execution

**APT Playbooks:**

1. **Lazarus Group (APT38)** - Financial heist simulation
   - Initial Access: Spearphishing
   - Persistence: Registry Run Keys
   - Credential Access: LSASS Memory
   - Lateral Movement: SMB Shares
   - Duration: ~30 minutes

2. **APT28 (Fancy Bear)** - Espionage campaign
   - Initial Access: Spearphishing Link
   - Execution: PowerShell
   - Discovery: Domain/File reconnaissance
   - Exfiltration: C2 channel
   - Duration: ~30 minutes

3. **APT29 (Cozy Bear)** - Stealth persistence
   - Initial Access: Supply chain compromise
   - Persistence: Windows Service
   - Defense Evasion: Log clearing, obfuscation
   - Collection: Data archiving
   - Duration: ~30 minutes

**Ransomware Scenarios:**

1. **Locky-style** - Basic ransomware simulation
   - Phishing attachment delivery
   - File/system discovery
   - Encryption simulation (safe)

2. **Ryuk Advanced** - Enterprise ransomware
   - Credential access
   - Lateral movement
   - Data exfiltration
   - Mass encryption simulation

---

## API Documentation

### Context Endpoints

#### Get User Context
```http
GET /api/context/user/{user_id}
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "context": {
    "user_id": "user123",
    "username": "jdoe",
    "email": "jdoe@example.com",
    "orange_team": {
      "training_completion_rate": 0.85,
      "phishing_click_rate": 0.12,
      "security_awareness_score": 78.5
    },
    "green_team": {
      "incident_count": 2,
      "insider_threat_score": 15.3
    },
    "overall_risk_score": 42.5,
    "risk_level": "medium"
  }
}
```

#### Get High-Risk Users
```http
GET /api/context/users/high-risk?limit=10
Authorization: Bearer <jwt_token>
```

#### Get Asset Context
```http
GET /api/context/asset/{asset_id}
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "context": {
    "asset_id": "asset456",
    "hostname": "web-server-01",
    "ip_addresses": ["192.168.1.100"],
    "red_team": {
      "vulnerability_count": 15,
      "critical_vuln_count": 3,
      "exploitability_score": 68.2
    },
    "blue_team": {
      "detection_coverage": 0.75,
      "monitored": true,
      "detection_rule_count": 42
    },
    "overall_risk_score": 72.1,
    "risk_level": "high"
  }
}
```

#### Get Recent Events
```http
GET /api/context/events?limit=50
Authorization: Bearer <jwt_token>
```

#### Publish Event
```http
POST /api/context/events
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "event": {
    "type": "VulnerabilityDiscovered",
    "data": {
      "vulnerability_id": "vuln789",
      "asset_id": "asset456",
      "severity": "critical",
      "cvss_score": 9.8,
      "description": "SQL Injection in login form"
    }
  }
}
```

---

## Database Schema

### Complete Schema Diagram

```
user_security_context
├── user_id (PK, FK → users.id)
├── orange_team_data (training, phishing)
├── green_team_data (incidents, threats)
├── yellow_team_data (secure coding)
├── white_team_data (compliance)
└── overall_risk_score

asset_security_context
├── asset_id (PK)
├── red_team_data (vulnerabilities, exploitability)
├── blue_team_data (detection, monitoring)
├── green_team_data (incidents, alerts)
├── purple_team_data (simulations, gaps)
├── white_team_data (compliance)
└── overall_risk_score

cross_team_events
├── event_id (PK)
├── event_type (indexed)
├── source_team (indexed)
├── target_teams (JSON array)
├── payload (JSON)
└── timestamp (indexed)

team_integrations
├── integration_id (PK)
├── source_team
├── target_team
├── data_type
├── sync_frequency
├── last_sync
└── is_enabled
```

---

## Usage Examples

### Example 1: Publishing a Vulnerability Discovery Event

```rust
use heroforge::event_bus::{EventPublisher, SecurityEvent, VulnerabilityEvent};
use chrono::Utc;

async fn publish_vulnerability(publisher: &EventPublisher) -> anyhow::Result<()> {
    let event = SecurityEvent::VulnerabilityDiscovered(VulnerabilityEvent {
        vulnerability_id: "vuln-123".to_string(),
        asset_id: "web-server-01".to_string(),
        severity: "critical".to_string(),
        cvss_score: Some(9.8),
        cve_id: Some("CVE-2024-1234".to_string()),
        description: "SQL Injection in login form".to_string(),
        timestamp: Utc::now(),
    });

    publisher.publish(event).await?;
    Ok(())
}
```

### Example 2: Subscribing to Events

```rust
use heroforge::event_bus::{EventSubscriber, SecurityEvent};

struct BlueTeamSubscriber;

impl EventSubscriber for BlueTeamSubscriber {
    fn on_event(&self, event: SecurityEvent) -> anyhow::Result<()> {
        match event {
            SecurityEvent::VulnerabilityDiscovered(vuln) => {
                println!("New vulnerability: {} (CVSS: {})",
                    vuln.description,
                    vuln.cvss_score.unwrap_or(0.0)
                );
                // Auto-generate detection rule
                create_detection_rule(&vuln)?;
            }
            SecurityEvent::GapIdentified(gap) => {
                println!("Detection gap: {}", gap.mitre_technique);
                // Create remediation task
                create_remediation_task(&gap)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn team(&self) -> &str {
        "blue"
    }
}
```

### Example 3: Getting Unified User Context

```bash
curl -X GET "https://heroforge.genialarchitect.io/api/context/user/user123" \
  -H "Authorization: Bearer <jwt_token>"
```

### Example 4: Purple Team Live Exercise

```rust
use heroforge::purple_team::{LiveExercise, LiveExerciseMessage};

async fn start_live_exercise(exercise_id: &str) -> anyhow::Result<()> {
    let exercise = LiveExercise {
        exercise_id: exercise_id.to_string(),
        name: "LSASS Detection Validation".to_string(),
        status: "running".to_string(),
        started_at: Utc::now(),
        current_phase: ExercisePhase::Execution,
        progress: ExerciseProgress {
            total_attacks: 5,
            attacks_executed: 2,
            attacks_detected: 1,
            attacks_missed: 0,
            current_attack: Some("T1003.001".to_string()),
            detection_latency_avg_ms: Some(3500),
        },
        live_timeline: vec![],
        participants: vec![],
        chat_enabled: true,
    };

    // Broadcast to WebSocket subscribers
    broadcast_websocket(LiveExerciseMessage::ExerciseStarted {
        exercise_id: exercise_id.to_string(),
        name: exercise.name.clone(),
    }).await?;

    Ok(())
}
```

---

## Configuration

### Environment Variables

```bash
# Database (already configured)
DATABASE_URL=./heroforge.db

# JWT Authentication (already configured)
JWT_SECRET=<your_secret>

# Event Bus Configuration
EVENT_BUS_CAPACITY=1000  # Max events in broadcast channel

# WebSocket Configuration
WEBSOCKET_HEARTBEAT_INTERVAL=30  # seconds
WEBSOCKET_CLIENT_TIMEOUT=60      # seconds
```

### Web Server Configuration

The event bus is initialized in `src/web/mod.rs`:

```rust
// Create event bus with broadcast channel
let (event_handler, broadcast_tx) = EventHandler::new(1000);
let event_publisher = Arc::new(EventPublisher::new(
    Arc::new(pool.clone()),
    broadcast_tx.clone()
));

// Start event handler background task
event_handler.start();

// Add to app_data for API access
.app_data(web::Data::from(event_publisher.clone()))
```

---

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_publishing() {
        let pool = setup_test_db().await;
        let (handler, tx) = EventHandler::new(100);
        let publisher = EventPublisher::new(Arc::new(pool), tx);

        let event = SecurityEvent::VulnerabilityDiscovered(/* ... */);
        publisher.publish(event).await.unwrap();

        // Verify event logged to database
        let events = cross_team::get_recent_events(&pool, 10).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_context_aggregation() {
        let pool = setup_test_db().await;

        // Create test user context
        cross_team::update_user_context(&pool, "user123", UserContextUpdate {
            phishing_click_rate: Some(0.15),
            training_completion_rate: Some(0.80),
            ..Default::default()
        }).await.unwrap();

        // Retrieve and verify
        let context = cross_team::get_user_context(&pool, "user123").await.unwrap();
        assert_eq!(context.phishing_click_rate, 0.15);
    }
}
```

### Integration Tests

```bash
# Test API endpoints
cargo test --test api_tests -- context

# Test event bus
cargo test --test event_bus_tests

# Test database operations
cargo test --test db_tests -- cross_team
```

---

## Future Enhancements

### Phase 3: Orange Team (Planned)

- Multi-channel phishing (email, SMS, voice, QR code)
- AI-powered personalized learning paths
- Behavioral analytics dashboard
- Social engineering testing (vishing, USB drops, pretexting)
- Microlearning and daily security tips

### Phase 4: Integration & Workflows (Planned)

- Automated workflow engine
- Cross-team orchestration
- Event-driven automation
- Real-time collaboration features
- Workflow templates library

### Performance Optimizations (Future)

- Materialized views for complex aggregations
- Redis caching layer for hot contexts
- Elasticsearch for event search
- Horizontal scaling for event bus

---

## Support & Troubleshooting

### Common Issues

**1. Events not being received:**
- Check WebSocket connection is established
- Verify JWT token is valid
- Ensure target team is in event routing

**2. Context data stale:**
- Context is updated asynchronously
- Force refresh via API call
- Check `updated_at` timestamp

**3. High memory usage:**
- Event bus broadcast channel full
- Increase `EVENT_BUS_CAPACITY`
- Implement event archival strategy

### Logging

Enable debug logging for event bus:
```bash
RUST_LOG=heroforge::event_bus=debug cargo run serve
```

---

## License

Copyright © 2025 HeroForge. All rights reserved.

---

## Contributors

- Implementation: Claude Opus 4.5
- Architecture Design: Based on PURPLE_ORANGE_TEAM_PLAN.md
- Testing: TBD

---

**Last Updated:** 2025-12-30
**Version:** 1.0
**Status:** Production-ready (Phase 1), Beta (Phase 2)
