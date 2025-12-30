# Purple & Orange Team Menu Plan + Cross-Team Data Flow

**Version:** 1.0
**Date:** 2025-12-30
**Scope:** Menu design, features, and optimal data flow across all colored teams

---

## Table of Contents
1. [Purple Team Menu & Features](#purple-team-menu--features)
2. [Orange Team Menu & Features](#orange-team-menu--features)
3. [Cross-Team Data Flow Architecture](#cross-team-data-flow-architecture)
4. [Implementation Priorities](#implementation-priorities)

---

## Purple Team Menu & Features

### 📋 **Current Implementation Status**

**✅ Existing Modules:**
- MITRE ATT&CK mapping (`mitre_attack.rs`)
- Detection checking (`detection_check.rs`)
- Coverage calculation (`coverage.rs`)
- Gap analysis (`gap_analysis.rs`)
- Exercise engine (`engine.rs`)

**🔍 Current Features:**
- Execute simulated attacks
- Validate SIEM detection coverage
- Map to MITRE ATT&CK framework
- Calculate detection coverage percentage
- Identify gaps in detection capabilities
- Generate detection rules (Sigma, Splunk, Elastic)

### 🎯 **Proposed Menu Structure**

```
Purple Team Dashboard
│
├── 📊 Dashboard Overview
│   ├── Detection Coverage Score (%)
│   ├── Recent Exercises (timeline)
│   ├── Critical Gaps (by severity)
│   ├── MITRE ATT&CK Heatmap
│   └── Blue vs Red Win Rate
│
├── 🎮 Exercise Management
│   ├── Create New Exercise
│   │   ├── Select Attack Scenarios
│   │   ├── Configure Targets
│   │   ├── Set Detection Parameters
│   │   └── Schedule Execution
│   ├── Active Exercises (live monitoring)
│   ├── Exercise History
│   └── Exercise Templates
│
├── 🎯 Attack Library
│   ├── MITRE ATT&CK Techniques
│   │   ├── By Tactic (14 tactics)
│   │   ├── By Technique (200+ techniques)
│   │   └── Custom Attacks
│   ├── Attack Chains (multi-step scenarios)
│   ├── Ransomware Simulations
│   ├── APT Playbooks (Lazarus, APT28, APT29, etc.)
│   └── Insider Threat Scenarios
│
├── 🔍 Detection Validation
│   ├── Real-Time Detection Monitoring
│   ├── SIEM Log Correlation
│   ├── EDR Alert Validation
│   ├── Network IDS/IPS Validation
│   └── Cloud Security Alerts
│
├── 📈 Coverage Analysis
│   ├── MITRE ATT&CK Coverage Heatmap
│   ├── Detection Gap Analysis
│   │   ├── By Tactic
│   │   ├── By Asset Type
│   │   └── By Severity
│   ├── Coverage Trends (over time)
│   └── Benchmark Comparison
│
├── 🛠️ Detection Improvement
│   ├── Gap Remediation Tracker
│   ├── Recommended Detection Rules
│   │   ├── Sigma Rules
│   │   ├── Splunk Queries
│   │   ├── Elastic Queries
│   │   ├── YARA Rules
│   │   └── Custom Rules
│   ├── Rule Testing & Validation
│   └── Rule Deployment Automation
│
├── 📊 Reporting & Analytics
│   ├── Executive Summaries
│   ├── Technical Reports
│   ├── Trend Analysis
│   ├── ROI Metrics (time to detect, cost savings)
│   └── Export to PDF/CSV/JSON
│
└── ⚙️ Settings
    ├── SIEM Integration (Splunk, Elastic, QRadar, etc.)
    ├── EDR Integration (CrowdStrike, SentinelOne, etc.)
    ├── Notification Preferences
    └── Exercise Templates Management
```

### 🚀 **New Features to Implement**

#### 1. **Live Exercise Dashboard**
```typescript
- Real-time attack execution visualization
- Blue team detection timeline (side-by-side)
- Attack success/failure indicators
- Detection latency metrics (time to detect)
- Live chat/collaboration between red & blue teams
```

#### 2. **Automated Purple Team Exercises**
```typescript
- Scheduled recurring exercises (daily/weekly/monthly)
- Randomized attack selection
- Automated result aggregation
- Auto-generated improvement recommendations
- Integration with CI/CD for continuous validation
```

#### 3. **Advanced Attack Scenarios**
```typescript
- Multi-stage APT campaigns (realistic threat actor TTPs)
- Zero-day simulation (behavior-based)
- Supply chain attack scenarios
- Insider threat combined with external access
- Ransomware with data exfiltration
- Living-off-the-land (LotL) techniques
```

#### 4. **Blue Team Collaboration Features**
```typescript
- Shared annotation on detection events
- Collaborative gap remediation planning
- Detection rule A/B testing
- Feedback loop: blue team marks false positives
- Joint after-action reports (AAR)
```

#### 5. **Detection Engineering Workflow**
```typescript
PurpleTeamExercise → GapDetected → RuleGeneration → RuleTesting → RuleDeployment → ReTest
```

---

## Orange Team Menu & Features

### 📋 **Current Implementation Status**

**✅ Existing Modules:**
- Training courses (`training/courses.rs`)
- Training modules (`training/modules.rs`)
- Quizzes (`training/quizzes.rs`)
- Certificates (`training/certificates.rs`)
- Gamification (`gamification/points.rs`, `badges.rs`, `leaderboards.rs`, `challenges.rs`)
- Phishing analytics (`phishing_analytics/mod.rs`)
- JIT training (`jit_training/mod.rs`)
- Compliance training (`compliance_training/mod.rs`)

**🔍 Current Features:**
- Security awareness courses
- Gamification with points, badges, leaderboards
- Phishing simulation analytics
- Just-in-time training (contextual)
- Compliance-specific training

### 🎯 **Proposed Menu Structure**

```
Orange Team Dashboard
│
├── 📊 Dashboard Overview
│   ├── Organization Security Awareness Score
│   ├── Training Completion Rate
│   ├── Phishing Click Rate (trend)
│   ├── High-Risk Users (bottom 10%)
│   ├── Recent Training Activity
│   └── Upcoming Compliance Deadlines
│
├── 🎓 Training Catalog
│   ├── Browse All Courses
│   │   ├── By Category (12 categories)
│   │   ├── By Difficulty (Beginner → Expert)
│   │   ├── By Content Type (Video, Interactive, Quiz, Game, etc.)
│   │   └── Custom/Uploaded Courses
│   ├── Learning Paths (curated course sequences)
│   ├── Compliance Training Tracks
│   │   ├── PCI-DSS Training
│   │   ├── HIPAA Training
│   │   ├── GDPR Training
│   │   ├── SOC 2 Training
│   │   └── Industry-Specific Training
│   └── Role-Based Training
│       ├── Developers (Secure Coding)
│       ├── Executives (Security Leadership)
│       ├── IT Admins (Infrastructure Security)
│       └── General Employees (Baseline Awareness)
│
├── 🎣 Phishing Simulations
│   ├── Create Campaign
│   │   ├── Template Library (100+ templates)
│   │   ├── Difficulty Level (Easy → Advanced)
│   │   ├── Target Users/Groups
│   │   └── Schedule & Frequency
│   ├── Active Campaigns (live monitoring)
│   ├── Campaign History & Analytics
│   ├── Phishing Email Templates
│   │   ├── Generic Phishing
│   │   ├── Spear Phishing (personalized)
│   │   ├── Business Email Compromise (BEC)
│   │   ├── Credential Harvesting
│   │   └── Malware Delivery Simulation
│   └── Phishing Landing Pages (fake login pages)
│
├── 📊 Phishing Analytics
│   ├── Click Rate Trends
│   ├── Reporting Rate Trends
│   ├── User Risk Scoring
│   │   ├── Repeat Clickers (high risk)
│   │   ├── Improved Users (low risk)
│   │   └── Risk Distribution Heatmap
│   ├── Campaign Performance Comparison
│   ├── Industry Benchmarking
│   └── Phishing Susceptibility by Department
│
├── 🎮 Gamification & Engagement
│   ├── Leaderboard
│   │   ├── Overall (organization-wide)
│   │   ├── By Department
│   │   └── By Location
│   ├── Points & Achievements
│   ├── Badges & Milestones
│   │   ├── Training Completion Badges
│   │   ├── Phishing Hunter Badge (reported phishing)
│   │   ├── Security Champion Badge
│   │   └── Custom Badges
│   ├── Challenges & Competitions
│   │   ├── Weekly Challenges
│   │   ├── Department vs Department
│   │   └── Quarterly Tournaments
│   └── Rewards & Recognition
│       ├── Gift Cards
│       ├── Public Recognition
│       └── Custom Rewards
│
├── 🎯 Just-in-Time (JIT) Training
│   ├── Triggered Training Rules
│   │   ├── Failed Phishing Test → Phishing Awareness Module
│   │   ├── Weak Password Detected → Password Security Module
│   │   ├── Clicked Suspicious Link → Link Safety Module
│   │   ├── Failed Quiz → Re-training
│   │   └── Custom Triggers (based on events)
│   ├── Microlearning Modules (2-5 min lessons)
│   ├── Contextual Tips (in-app guidance)
│   └── JIT Analytics (effectiveness metrics)
│
├── 📋 Compliance Training
│   ├── Mandatory Training Assignments
│   ├── Compliance Tracking
│   │   ├── By User
│   │   ├── By Department
│   │   └── By Regulation
│   ├── Certificate Management
│   ├── Attestation & Sign-offs
│   ├── Audit Reports (for compliance)
│   └── Deadline Reminders & Escalations
│
├── 👥 User Management
│   ├── User Profiles & Progress
│   ├── Training Assignments
│   │   ├── Manual Assignment
│   │   ├── Auto-Assignment (by role/department)
│   │   └── Bulk Assignment
│   ├── High-Risk User Monitoring
│   ├── User Groups & Cohorts
│   └── User Analytics
│       ├── Engagement Score
│       ├── Learning Velocity
│       └── Retention Rate
│
├── 📈 Reporting & Analytics
│   ├── Executive Dashboard (high-level KPIs)
│   ├── Training Effectiveness Reports
│   │   ├── Pre-training vs Post-training scores
│   │   ├── Knowledge retention (6-month follow-up)
│   │   └── Behavioral change metrics
│   ├── Phishing Simulation Reports
│   ├── Compliance Reports
│   ├── Custom Reports (query builder)
│   └── Export to PDF/CSV/Excel
│
└── ⚙️ Settings
    ├── Organization Branding
    ├── Training Policies (mandatory intervals, etc.)
    ├── Notification Templates
    ├── Integration Settings
    │   ├── HRIS/LDAP Sync
    │   ├── LMS Integration
    │   └── Email Gateway Integration
    └── Custom Training Content Upload
```

### 🚀 **New Features to Implement**

#### 1. **AI-Powered Personalized Learning**
```typescript
- Adaptive learning paths based on user performance
- Skill gap analysis with targeted recommendations
- Learning style detection (visual, auditory, kinesthetic)
- Predictive analytics: identify users likely to fail phishing tests
- Auto-generate personalized training plans
```

#### 2. **Advanced Phishing Simulations**
```typescript
- Multi-channel phishing (email + SMS + voice)
- QR code phishing
- Deepfake phishing (AI-generated voice/video)
- Social media phishing scenarios
- Real-world threat actor TTPs (credential harvesting, BEC, etc.)
- Integration with real phishing threat intel (auto-generate simulations)
```

#### 3. **Behavioral Analytics**
```typescript
- Predict user risk score based on behavior patterns
- Identify security culture by department
- Measure security awareness maturity (beginner → advanced)
- Track behavioral change over time
- Correlation: training completion vs actual security incidents
```

#### 4. **Social Engineering Testing**
```typescript
- In-person social engineering (physical security tests)
- Phone-based social engineering (vishing)
- USB drop campaigns
- Tailgating simulations
- Pretexting scenarios
- Combined phishing + vishing attacks
```

#### 5. **Microlearning & Nudges**
```typescript
- Daily security tips (push notifications)
- Weekly security challenges (2-min quizzes)
- Security tips based on current threat landscape
- Contextual nudges (e.g., password strength indicator)
- Integration with Slack/Teams for in-app training
```

---

## Cross-Team Data Flow Architecture

### 🔗 **Unified Data Pipeline**

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HeroForge Central Data Hub                  │
│                     (Unified Analytics & Correlation)               │
└─────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
   ┌────▼────┐                 ┌────▼────┐                ┌────▼────┐
   │  Event  │                 │  Asset  │                │  User   │
   │  Store  │                 │Inventory│                │ Context │
   └─────────┘                 └─────────┘                └─────────┘
```

### 🎨 **Colored Team Interactions**

#### **Red Team → Blue Team → Purple Team Flow**

```mermaid
Red Team (Scanner)
│  Vulnerability Discovered
│  Attack Simulation Executed
└──► Feed to SIEM/EDR
         │
         ▼
Blue Team (Detection Engineering)
│  Detection Rule Created (Sigma/Splunk/Elastic)
│  Alert Triggered
└──► Validate with Purple Team
         │
         ▼
Purple Team (Validation)
│  Re-execute Attack
│  Verify Detection
│  Calculate Coverage
└──► Report Back to Blue Team
```

**Key Data Points:**
- Red Team: `vulnerability_id`, `attack_technique`, `exploit_used`, `target_asset`
- Blue Team: `detection_rule_id`, `alert_triggered`, `time_to_detect`, `false_positive`
- Purple Team: `exercise_id`, `detection_status`, `coverage_score`, `gap_severity`

---

#### **Red Team → Orange Team → Incident Response Flow**

```mermaid
Red Team (Scanner/Phishing)
│  Phishing Email Sent (simulation)
│  User Clicked / Entered Credentials
└──► Trigger Orange Team
         │
         ▼
Orange Team (JIT Training)
│  User Risk Score Increased
│  Just-in-Time Training Assigned
│  Phishing Awareness Module Delivered
└──► Track User Improvement
         │
         ▼
Incident Response (Green Team)
│  Real Phishing Detected (from Orange Team intel)
│  Automatically Quarantine Similar Emails
│  Notify Affected Users
└──► Coordinate with Orange Team for Remediation Training
```

**Key Data Points:**
- Red Team: `simulation_id`, `user_id`, `clicked`, `credentials_entered`, `timestamp`
- Orange Team: `user_risk_score`, `training_assigned`, `completion_status`, `improvement_metric`
- Green Team: `incident_id`, `affected_users`, `response_action`, `training_triggered`

---

#### **Yellow Team → White Team → Orange Team Flow**

```mermaid
Yellow Team (SAST/SCA)
│  Insecure Code Detected (SQL Injection)
│  Developer: john@company.com
└──► Alert White Team (GRC)
         │
         ▼
White Team (Risk & Compliance)
│  Risk Assessment: High (PCI-DSS violation)
│  Policy Violation Recorded
│  Escalate to Orange Team for Training
└──► Assign Compliance Training
         │
         ▼
Orange Team (Training)
│  Assign "Secure Coding: SQL Injection Prevention"
│  Track Completion
│  Re-test Developer with Quiz
└──► Report to White Team (Compliance Satisfied)
```

**Key Data Points:**
- Yellow Team: `finding_id`, `vulnerability_type`, `developer_id`, `severity`, `cwe_id`
- White Team: `risk_id`, `compliance_violation`, `policy_id`, `remediation_status`
- Orange Team: `training_assignment_id`, `user_id`, `course_id`, `completion_status`

---

#### **Green Team (SOC) → All Teams Flow**

```mermaid
Green Team (SOAR/SIEM)
│  Security Incident Detected
│  Incident: Ransomware Attempt
└──► Coordinate Response Across Teams
         │
         ├──► Red Team: Re-scan affected systems for vulnerabilities
         ├──► Blue Team: Create new detection rules for this ransomware variant
         ├──► Purple Team: Validate new detection rules
         ├──► Yellow Team: Scan codebase for potential entry points
         ├──► Orange Team: Send JIT training to all users (ransomware awareness)
         └──► White Team: Document incident for compliance audit
```

**Key Data Points:**
- Green Team: `incident_id`, `threat_type`, `affected_assets`, `response_playbook_id`, `status`
- Shared Context: `timestamp`, `incident_severity`, `indicators_of_compromise`, `remediation_steps`

---

### 🔄 **Bi-Directional Data Flows**

| Source Team | Data Provided | Consuming Team | Action Taken |
|-------------|---------------|----------------|--------------|
| **Red Team** | Vulnerabilities, Attack Paths | **Blue Team** | Create Detection Rules |
| **Red Team** | Phishing Simulations | **Orange Team** | JIT Training Assignment |
| **Red Team** | Web App Vulnerabilities | **Yellow Team** | Code Fix Prioritization |
| **Red Team** | Asset Inventory | **White Team** | Risk Assessment |
| **Blue Team** | Detection Rules (Sigma) | **Purple Team** | Validation Testing |
| **Blue Team** | SIEM Alerts | **Green Team** | Incident Triage |
| **Yellow Team** | SAST Findings | **Orange Team** | Secure Coding Training |
| **Yellow Team** | SBOM | **White Team** | Supply Chain Risk |
| **Orange Team** | User Risk Scores | **Green Team** | Insider Threat Detection |
| **Orange Team** | Phishing Click Rates | **Red Team** | Target High-Risk Users |
| **White Team** | Compliance Requirements | **Orange Team** | Mandatory Training |
| **White Team** | Policy Violations | **Yellow Team** | Code Review Triggers |
| **Green Team** | Incidents | **All Teams** | Cross-Team Coordination |
| **Purple Team** | Detection Gaps | **Blue Team** | Rule Improvements |
| **Purple Team** | Coverage Metrics | **White Team** | Security Posture Reporting |

---

### 📊 **Centralized Data Models**

#### **1. Unified User Context**
```rust
pub struct UserSecurityContext {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub department: String,
    pub role: String,

    // Orange Team Data
    pub training_completion_rate: f64,
    pub phishing_click_rate: f64,
    pub security_awareness_score: f64,
    pub last_training: Option<DateTime<Utc>>,

    // Green Team Data
    pub incident_count: usize,
    pub insider_threat_score: f64,
    pub suspicious_activity_count: usize,

    // Yellow Team Data (for developers)
    pub secure_coding_score: Option<f64>,
    pub code_review_compliance: Option<f64>,

    // White Team Data
    pub compliance_status: Vec<ComplianceStatus>,
    pub policy_violations: Vec<PolicyViolation>,

    // Aggregated Risk
    pub overall_risk_score: f64,  // Computed from all sources
}
```

#### **2. Unified Asset Context**
```rust
pub struct AssetSecurityContext {
    pub asset_id: String,
    pub asset_type: AssetType,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub owner: String,

    // Red Team Data
    pub vulnerabilities: Vec<VulnerabilitySummary>,
    pub last_scan: Option<DateTime<Utc>>,
    pub exploitability_score: f64,

    // Blue Team Data
    pub detection_coverage: f64,
    pub monitored: bool,
    pub detection_rules: Vec<String>,

    // Green Team Data
    pub incidents: Vec<IncidentSummary>,
    pub alerts: Vec<AlertSummary>,

    // Purple Team Data
    pub attack_simulations: Vec<ExerciseSummary>,
    pub detection_gaps: Vec<GapSummary>,

    // White Team Data
    pub compliance_scope: Vec<String>,  // PCI-DSS, HIPAA, etc.
    pub risk_rating: String,

    // Aggregated Risk
    pub overall_risk_score: f64,
}
```

#### **3. Unified Threat Intelligence**
```rust
pub struct ThreatIntelligenceContext {
    pub threat_id: String,
    pub threat_type: ThreatType,
    pub indicators: Vec<IOC>,

    // Red Team Contribution
    pub discovered_via_scan: bool,
    pub exploitability: Exploitability,

    // Blue Team Contribution
    pub detection_signatures: Vec<DetectionSignature>,
    pub siem_rules: Vec<String>,

    // Purple Team Contribution
    pub validated: bool,
    pub detection_effectiveness: f64,

    // Green Team Contribution
    pub active_incidents: Vec<String>,
    pub response_playbooks: Vec<String>,

    // Orange Team Contribution
    pub training_modules: Vec<String>,  // Related awareness training

    // External Intel
    pub cve_ids: Vec<String>,
    pub mitre_attack_ids: Vec<String>,
    pub threat_actors: Vec<String>,
}
```

---

### 🛠️ **Technical Implementation**

#### **1. Event Bus Architecture**

```rust
// Central event bus for cross-team communication
pub enum SecurityEvent {
    // Red Team Events
    VulnerabilityDiscovered(VulnerabilityEvent),
    ScanCompleted(ScanEvent),
    ExploitSuccessful(ExploitEvent),

    // Blue Team Events
    DetectionRuleCreated(DetectionRuleEvent),
    AlertTriggered(AlertEvent),

    // Purple Team Events
    ExerciseCompleted(ExerciseEvent),
    GapIdentified(GapEvent),

    // Yellow Team Events
    CodeVulnerabilityFound(CodeVulnEvent),
    DependencyRiskDetected(DependencyEvent),

    // Orange Team Events
    PhishingClicked(PhishingEvent),
    TrainingCompleted(TrainingEvent),
    UserRiskChanged(UserRiskEvent),

    // White Team Events
    ComplianceViolation(ComplianceEvent),
    PolicyUpdated(PolicyEvent),

    // Green Team Events
    IncidentCreated(IncidentEvent),
    IncidentResolved(IncidentEvent),
}

// Subscribers can listen to specific event types
pub trait SecurityEventSubscriber {
    fn on_event(&self, event: SecurityEvent) -> Result<()>;
}
```

#### **2. API Integration Layer**

```rust
// Cross-team API endpoints
// GET /api/context/user/{user_id} - Unified user security context
// GET /api/context/asset/{asset_id} - Unified asset security context
// GET /api/context/threat/{threat_id} - Unified threat intelligence
// POST /api/events - Publish security event to event bus
// GET /api/events/stream - Subscribe to event stream (WebSocket)
```

#### **3. Database Schema**

```sql
-- Central correlation tables

CREATE TABLE user_security_context (
    user_id TEXT PRIMARY KEY,
    training_score REAL,
    phishing_risk REAL,
    incident_count INTEGER,
    overall_risk REAL,
    updated_at TEXT
);

CREATE TABLE asset_security_context (
    asset_id TEXT PRIMARY KEY,
    vulnerability_score REAL,
    detection_coverage REAL,
    incident_count INTEGER,
    overall_risk REAL,
    updated_at TEXT
);

CREATE TABLE cross_team_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT,
    source_team TEXT,
    target_teams TEXT,  -- JSON array
    payload TEXT,       -- JSON
    timestamp TEXT
);

CREATE TABLE team_integrations (
    integration_id TEXT PRIMARY KEY,
    source_team TEXT,
    target_team TEXT,
    data_type TEXT,
    sync_frequency TEXT,
    last_sync TEXT
);
```

---

## Implementation Priorities

### 🎯 **Phase 1: Foundation (Week 1-2)**

1. **Database Schema Updates**
   - Create cross-team correlation tables
   - Add indexes for performance
   - Implement event logging table

2. **Event Bus Implementation**
   - Build `SecurityEvent` enum
   - Implement event publishing
   - Implement event subscription

3. **API Endpoints**
   - `/api/context/user/{id}` - Unified user context
   - `/api/context/asset/{id}` - Unified asset context
   - `/api/events` - Event publishing endpoint

### 🎯 **Phase 2: Purple Team Enhancements (Week 3-4)**

1. **Live Exercise Dashboard**
   - Real-time attack visualization
   - Side-by-side red/blue timelines
   - Detection latency metrics

2. **Attack Library Expansion**
   - Add 50+ MITRE ATT&CK techniques
   - Implement APT playbooks (Lazarus, APT28, APT29)
   - Ransomware simulation scenarios

3. **Automated Exercises**
   - Scheduled exercises
   - Auto-generated reports
   - Integration with CI/CD

### 🎯 **Phase 3: Orange Team Enhancements (Week 5-6)**

1. **Advanced Phishing Simulations**
   - Multi-channel phishing (email + SMS + voice)
   - QR code phishing templates
   - Real-world threat actor TTPs

2. **AI-Powered Personalization**
   - Adaptive learning paths
   - Predictive risk scoring
   - Auto-generated training plans

3. **Behavioral Analytics Dashboard**
   - User risk scoring
   - Department security culture metrics
   - Behavioral change tracking

### 🎯 **Phase 4: Cross-Team Integration (Week 7-8)**

1. **Bi-Directional Data Flows**
   - Red → Blue → Purple pipeline
   - Yellow → White → Orange pipeline
   - Green → All Teams coordination

2. **Unified Dashboards**
   - Executive security posture dashboard
   - Cross-team correlation views
   - Real-time event stream viewer

3. **Automation & Orchestration**
   - Auto-trigger training on phishing clicks
   - Auto-create detection rules from purple team gaps
   - Auto-assign compliance training on policy violations

---

## Success Metrics

### Purple Team
- **Detection Coverage:** >85% MITRE ATT&CK coverage
- **Exercise Frequency:** ≥1 purple team exercise per week
- **Gap Remediation:** 90% of critical gaps remediated within 30 days
- **Detection Latency:** <5 minutes mean time to detect

### Orange Team
- **Training Completion:** 95%+ completion rate for mandatory training
- **Phishing Click Rate:** <10% click rate organization-wide
- **User Engagement:** 70%+ participation in gamification
- **Behavioral Change:** 50% reduction in repeat clickers after JIT training

### Cross-Team Integration
- **Data Freshness:** Event correlation within 5 seconds
- **API Latency:** <100ms for unified context APIs
- **Automation Rate:** 80% of routine cross-team workflows automated
- **Coverage:** All 7 colored teams integrated with event bus

---

## Technical Dependencies

### Frontend
- React components for Purple/Orange team dashboards
- WebSocket support for real-time exercise monitoring
- Chart.js / D3.js for analytics visualizations
- MITRE ATT&CK Navigator integration

### Backend
- Event bus (using Tokio channels or RabbitMQ)
- WebSocket server for real-time updates
- Background job queue for scheduled exercises
- Cross-team API layer

### Database
- Additional tables for correlation data
- Indexes for performance optimization
- Materialized views for analytics

### External Integrations
- SIEM APIs (Splunk, Elastic, QRadar)
- EDR APIs (CrowdStrike, SentinelOne)
- LMS integration (for Orange Team)
- Email gateway (for phishing simulations)

---

## Conclusion

This plan provides a comprehensive roadmap for:
1. **Purple Team** enhancements with live exercises, advanced attack scenarios, and automated validation
2. **Orange Team** enhancements with AI-powered training, advanced phishing, and behavioral analytics
3. **Cross-team integration** with unified data models, event-driven architecture, and bi-directional workflows

**Estimated Timeline:** 8 weeks for full implementation
**Estimated Effort:** ~120 developer-days
**Priority:** High (improves overall platform cohesion and value)

---

**Next Steps:**
1. Review and approve plan
2. Prioritize Phase 1 foundation work
3. Begin database schema updates
4. Implement event bus architecture
5. Build unified context APIs

