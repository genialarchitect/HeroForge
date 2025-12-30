# Phase 3 Quick Reference Guide

## Module Organization

### Sprint 1: Performance & Caching
```rust
// Job Queue System
use heroforge::jobs::{JobQueue, JobExecutor, JobScheduler, Job, JobType, JobPriority};

// Database Optimization
use heroforge::db::optimization::{QueryOptimizer, QueryCache, QueryMonitor};

// API Compression
use heroforge::web::middleware::Compression;
```

### Sprint 2: Testing
```rust
// Test Utilities
use heroforge::testing::{TestUser, TestScan, create_test_database};
use heroforge::testing::fixtures::{sample_host_info, sample_vulnerability};
use heroforge::testing::mocks::{MockEmailService, MockWebhookService};
use heroforge::testing::helpers::generators::{random_ip, random_port};
```

### Sprint 3: Monitoring
```rust
// Logging
use heroforge::monitoring::{LogEntry, SecurityLogger, JsonLogger};

// Metrics
use heroforge::monitoring::{MetricsCollector, Metrics};

// Alerts
use heroforge::monitoring::{AlertManager, AlertRule, AlertSeverity};

// Health Checks - API endpoints:
// GET /health/live
// GET /health/ready
// GET /health
```

### Sprint 4: High Availability
```rust
// Backup
use heroforge::backup::{create_backup, restore_backup, BackupConfig};

// Disaster Recovery
use heroforge::dr::{initiate_failover, get_dr_status, DRConfig};

// Load Balancer: config/loadbalancer.conf (HAProxy)
```

### Sprint 5: Zero Trust
```rust
// WebAuthn
use heroforge::web::auth::webauthn::{start_registration, verify_registration};

// Device Trust
use heroforge::web::auth::device_trust::{register_device, check_device_trust, TrustLevel};

// Continuous Auth
use heroforge::web::auth::continuous::{monitor_session, calculate_risk_score};
```

### Sprint 6: AI/ML
```rust
// Machine Learning
use heroforge::ml::{load_model, train_model, ModelType};
use heroforge::ml::models::predict;
use heroforge::ml::threat_prediction::predict_threat;
use heroforge::ml::auto_remediation::generate_remediation_plan;
```

### Sprint 7: Deception
```rust
// Honeypots
use heroforge::honeypots::{create_honeypot, log_interaction, HoneypotType};

// Honeytokens
use heroforge::honeytokens::{create_honeytoken, log_access, HoneytokenType};
```

### Sprint 8: Insider Threat & DLP
```rust
// Insider Threat
use heroforge::insider_threat::{analyze_user_behavior, calculate_user_risk_score, AlertType};

// Data Loss Prevention
use heroforge::dlp::{scan_content, DLPPolicy, PatternType, PolicyAction};
```

### Sprint 9: Multi-Region
```rust
// Replication
use heroforge::replication::{replicate_data, get_replication_status, failover_to_region};

// Region Routing Middleware
use heroforge::web::middleware::region_routing::RegionRouter;

// Configuration: config/regions.toml
```

### Sprint 10: SSO & Advanced RBAC
```rust
// SAML
use heroforge::web::auth::saml::{generate_saml_request, validate_saml_response};

// OAuth/OIDC
use heroforge::web::auth::oauth::{generate_authorization_url, exchange_code_for_token};

// ABAC
use heroforge::rbac::abac::{ABACPolicy, evaluate_policy, EvaluationContext};
```

## Common Usage Patterns

### Job Queue
```rust
// Create job queue
let mut queue = JobQueue::new("redis://localhost:6379").await?;

// Enqueue job
let job = Job::new(
    JobType::Scan { scan_id: "123".to_string(), user_id: "456".to_string() },
    JobPriority::High
);
queue.enqueue(job).await?;

// Start executor
let executor = JobExecutor::new(queue, ExecutorConfig::default());
executor.start().await?;

// Schedule recurring job
let scheduled = ScheduledJob::new(
    "Daily Cleanup".to_string(),
    "0 2 * * *".to_string(),  // 2 AM daily
    JobType::DbCleanup { older_than_days: 30 },
    JobPriority::Low
)?;
```

### Query Optimization
```rust
let optimizer = QueryOptimizer::new(pool, 300); // 5 min cache TTL

// Analyze query
let analysis = optimizer.analyze_query("SELECT * FROM scans WHERE status = 'completed'").await?;

// Get stats
let stats = optimizer.get_db_stats().await?;
println!("Database size: {} MB", stats.size_mb());

// Optimize indexes
optimizer.optimize_indexes().await?;
```

### Monitoring
```rust
// Collect metrics
let metrics = MetricsCollector::new();
metrics.record_request(125.5, true).await; // 125.5ms, success
metrics.increment_counter("api_calls", 1).await;

// Alert on thresholds
let alert_mgr = AlertManager::new();
alert_mgr.add_rule(AlertRule {
    name: "High CPU".to_string(),
    metric: "cpu_usage".to_string(),
    threshold: 90.0,
    comparison: Comparison::GreaterThan,
    severity: AlertSeverity::Warning,
    description: "CPU usage > 90%".to_string(),
}).await;

alert_mgr.check_metric("cpu_usage", 95.0).await;
let alerts = alert_mgr.get_active_alerts().await;
```

### Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use heroforge::testing::*;

    #[tokio::test]
    async fn test_scan_creation() {
        let pool = create_test_database().await.unwrap();
        let user = TestUser::random();
        let scan = TestScan::default_for_user(&user.id.unwrap());

        // Test implementation...
    }
}
```

### DLP
```rust
let policy = DLPPolicy {
    id: "policy-1".to_string(),
    name: "PII Protection".to_string(),
    patterns: vec![
        DataPattern {
            pattern_type: PatternType::SSN,
            regex: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
            sensitivity: Sensitivity::Critical,
        }
    ],
    action: PolicyAction::Block,
};

let violations = scan_content("SSN: 123-45-6789", &[policy]).await;
```

### ABAC
```rust
let policy = ABACPolicy {
    id: "admin-policy".to_string(),
    name: "Admin Access".to_string(),
    rules: vec![ABACRule {
        subject_attributes: {
            let mut attrs = HashMap::new();
            attrs.insert("role".to_string(), AttributeValue::String("admin".to_string()));
            attrs
        },
        resource_attributes: HashMap::new(),
        environment_attributes: HashMap::new(),
        action: "delete".to_string(),
        effect: Effect::Allow,
    }],
};

let context = EvaluationContext {
    subject_attrs: {
        let mut attrs = HashMap::new();
        attrs.insert("role".to_string(), AttributeValue::String("admin".to_string()));
        attrs
    },
    resource_attrs: HashMap::new(),
    environment_attrs: HashMap::new(),
    requested_action: "delete".to_string(),
};

let allowed = evaluate_policy(&policy, &context); // true
```

## Database Migrations

New tables are automatically created on startup:

```sql
-- Deception (Sprint 7)
honeypots
honeypot_interactions
honeytokens
honeytoken_access

-- Insider Threat (Sprint 8)
user_activities
insider_threat_alerts

-- DLP (Sprint 8)
dlp_policies
dlp_violations
```

## API Endpoints

### Health Checks
- `GET /health/live` - Liveness probe (200 if running)
- `GET /health/ready` - Readiness probe (200 if DB connected)
- `GET /health` - Detailed health with metrics

### Future Endpoints (TODO)
- `POST /api/honeypots` - Create honeypot
- `GET /api/honeypots/{id}/interactions` - Get honeypot logs
- `POST /api/dlp/scan` - Scan content for violations
- `GET /api/insider-threat/alerts` - Get threat alerts
- `GET /api/metrics` - Prometheus metrics endpoint

## Environment Variables

```bash
# Job Queue
REDIS_URL=redis://localhost:6379

# Database
DATABASE_URL=sqlite://heroforge.db
DATABASE_ENCRYPTION_KEY=<32-byte-hex-key>

# JWT
JWT_SECRET=<your-secret-key>

# TOTP Encryption
TOTP_ENCRYPTION_KEY=<32-byte-hex-key>

# Monitoring
LOG_LEVEL=info
METRICS_EXPORT_INTERVAL=60

# Backup
BACKUP_GPG_PASSPHRASE=<your-passphrase>
BACKUP_RETENTION_DAYS=30

# Multi-Region
PRIMARY_REGION=us-east
REPLICATION_STRATEGY=multi-master
```

## Configuration Files

- `config/loadbalancer.conf` - HAProxy load balancer config
- `config/regions.toml` - Multi-region configuration
- `.github/workflows/test.yml` - CI/CD pipeline

## Testing

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test '*'

# Load tests (marked as ignored)
cargo test --ignored

# Specific test
cargo test insider_threat::tests::test_risk_calculation

# With output
cargo test -- --nocapture

# Single-threaded (for DB tests)
cargo test -- --test-threads=1
```

## Performance Benchmarks

```bash
# Run benchmarks
cargo bench

# Profile with flamegraph
cargo flamegraph --bench my_benchmark
```

## Next Steps Checklist

- [ ] Add Redis dependency to Cargo.toml
- [ ] Add ML dependencies (linfa, ndarray)
- [ ] Add WebAuthn dependency (webauthn-rs)
- [ ] Implement actual test cases
- [ ] Connect ML models to training data
- [ ] Implement honeypot services (SSH, HTTP listeners)
- [ ] Configure SAML/OAuth providers
- [ ] Set up Prometheus for metrics collection
- [ ] Configure load balancer in production
- [ ] Set up multi-region replication
- [ ] Performance testing and optimization

## Support

For questions or issues:
1. Check `PHASE3_IMPLEMENTATION_SUMMARY.md` for detailed module documentation
2. Review inline code documentation
3. Check test files for usage examples
4. Consult HeroForge main `CLAUDE.md` for architecture overview
