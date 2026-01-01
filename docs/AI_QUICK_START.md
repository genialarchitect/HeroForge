# HeroForge AI/ML Quick Start Guide

## Get Started in 5 Minutes

### Prerequisites

```bash
# Set your Claude API key
export ANTHROPIC_API_KEY="sk-ant-api03-your-key-here"

# Ensure HeroForge is built with AI features
cargo build --release --features ai-ml
```

### 1. Generate Your First AI Report (30 seconds)

```bash
# Run a scan
./heroforge scan 192.168.1.1-10 --output scan_001

# Generate executive report via API
curl -X POST http://localhost:8080/api/ai/reports/executive \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "scan_001"}' \
  | jq '.summary'
```

**Output:**
```
"This security scan identified 23 vulnerabilities across 10 hosts,
including 3 critical issues requiring immediate attention. The most
severe findings include an outdated Apache server with known RCE
vulnerabilities (CVE-2021-41773) and weak SSL/TLS configurations..."
```

### 2. Get an Intelligent Scan Plan (15 seconds)

```bash
curl -X POST http://localhost:8080/api/ai/scan-plan \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["app.example.com", "192.168.1.0/24"],
    "objectives": ["Web vulnerability assessment", "Network mapping"]
  }' | jq
```

**Output:**
```json
{
  "recommended_scans": [
    "Start with TCP SYN scan on ports 80,443,8080,8443",
    "Follow with comprehensive web app scan on discovered HTTP services",
    "Run service version detection on all open ports",
    "Execute SSL/TLS analysis on HTTPS endpoints"
  ],
  "estimated_duration": "2-3 hours",
  "risk_factors": [
    "Public-facing web applications - high priority",
    "Large IP range - recommend scanning in batches"
  ]
}
```

### 3. Analyze Exploit Code (20 seconds)

```bash
curl -X POST http://localhost:8080/api/ai/analyze-exploit \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "#!/usr/bin/python\nimport requests\npayload = \"<?php system($_GET[\"'\"'\"'cmd\"'\"'\"']); ?>\"\nrequests.post(\"http://target/upload.php\", files={\"file\": payload})",
    "context": "PHP file upload vulnerability"
  }' | jq
```

**Output:**
```json
{
  "vulnerability_id": "File Upload RCE",
  "attack_flow": "1. Attacker crafts PHP webshell payload\n2. Uploads via vulnerable upload.php endpoint\n3. Executes arbitrary commands via GET parameter",
  "impact_assessment": "Critical - Full server compromise, remote code execution",
  "mitigations": [
    "Validate file types and extensions",
    "Store uploads outside webroot",
    "Use Content-Type validation",
    "Implement file scanning/sandboxing"
  ],
  "mitre_techniques": ["T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter"]
}
```

### 4. Train Your First ML Model (2 minutes)

```bash
# Train threat classifier on your historical data
curl -X POST http://localhost:8080/api/ml/train/threat-classifier \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" | jq
```

**Output:**
```json
{
  "status": "success",
  "model": "threat_classifier",
  "version": 1,
  "metrics": {
    "accuracy": 0.89,
    "training_samples": 247,
    "training_time_seconds": 12.3
  }
}
```

### 5. Use ML Model for Prediction (1 second)

```bash
curl -X POST http://localhost:8080/api/ml/predict/threat \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "severity_score": 0.9,
      "has_cve": true,
      "has_exploit": true,
      "age_days": 5,
      "affected_hosts": 12
    }
  }' | jq
```

**Output:**
```json
{
  "threat_level": "critical",
  "confidence": 0.92,
  "factors": [
    "Severity score: 0.90",
    "Has exploit: true",
    "Age: 5 days",
    "Affects 12 hosts"
  ],
  "recommendation": "Immediate remediation required"
}
```

## Common Use Cases

### Use Case 1: Automated Reporting for Clients

```bash
# 1. Run scan
./heroforge scan client-network.txt --output client_q4_2025

# 2. Generate both reports
curl -X POST localhost:8080/api/ai/reports/executive \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_id": "client_q4_2025"}' > exec_report.json

curl -X POST localhost:8080/api/ai/reports/technical \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_id": "client_q4_2025"}' > tech_report.json

# 3. Export to PDF
curl -X POST localhost:8080/api/reports/export/pdf \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_id": "client_q4_2025", "include_ai_summary": true}' \
  --output client_report.pdf
```

### Use Case 2: Pre-Engagement Intelligence

```bash
# Get smart scan recommendations before engagement
curl -X POST localhost:8080/api/ai/scan-plan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "targets": ["acmecorp.com", "*.acmecorp.com"],
    "objectives": [
      "External attack surface assessment",
      "Web application security testing",
      "Email security evaluation"
    ]
  }' | jq '.recommended_scans[]'
```

### Use Case 3: Exploit Triage

```bash
# Quickly assess exploit code found in the wild
curl -X POST localhost:8080/api/ai/analyze-exploit \
  -H "Authorization: Bearer $TOKEN" \
  -d @exploit_sample.json | jq '{
    vulnerability: .vulnerability_id,
    impact: .impact_assessment,
    mitigations: .mitigations
  }'
```

### Use Case 4: Policy Generation

```bash
# Generate compliance-ready security policy
curl -X POST localhost:8080/api/ai/policy/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "policy_type": "VulnerabilityManagement",
    "organization": "Acme Corporation",
    "frameworks": ["PCI-DSS", "SOC 2", "NIST CSF"]
  }' | jq '.content' > vulnerability_management_policy.md
```

## Integration Examples

### Python Integration

```python
import requests

class HeroForgeAI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}"}

    def generate_executive_report(self, scan_id):
        response = requests.post(
            f"{self.base_url}/api/ai/reports/executive",
            headers=self.headers,
            json={"scan_id": scan_id}
        )
        return response.json()

    def plan_scan(self, targets, objectives):
        response = requests.post(
            f"{self.base_url}/api/ai/scan-plan",
            headers=self.headers,
            json={"targets": targets, "objectives": objectives}
        )
        return response.json()

    def predict_remediation_time(self, severity, complexity, team_size=3):
        response = requests.post(
            f"{self.base_url}/api/ml/predict/remediation-time",
            headers=self.headers,
            json={
                "severity": severity,
                "complexity": complexity,
                "team_size": team_size
            }
        )
        return response.json()

# Usage
ai = HeroForgeAI("http://localhost:8080", "your_token")
report = ai.generate_executive_report("scan_123")
print(f"Risk Score: {report['risk_score']}")
```

### JavaScript/Node.js Integration

```javascript
const axios = require('axios');

class HeroForgeAI {
    constructor(baseUrl, token) {
        this.client = axios.create({
            baseURL: baseUrl,
            headers: { 'Authorization': `Bearer ${token}` }
        });
    }

    async analyzeExploit(code, context) {
        const response = await this.client.post('/api/ai/analyze-exploit', {
            code,
            context
        });
        return response.data;
    }

    async generatePolicy(policyType, organization, frameworks) {
        const response = await this.client.post('/api/ai/policy/generate', {
            policy_type: policyType,
            organization,
            frameworks
        });
        return response.data;
    }
}

// Usage
const ai = new HeroForgeAI('http://localhost:8080', 'your_token');

(async () => {
    const analysis = await ai.analyzeExploit(exploitCode, 'WordPress');
    console.log(`Impact: ${analysis.impact_assessment}`);
    console.log(`Mitigations: ${analysis.mitigations.join(', ')}`);
})();
```

### Bash Script Automation

```bash
#!/bin/bash
# automated_ai_scan.sh

TOKEN="your_jwt_token"
BASE_URL="http://localhost:8080"

# 1. Get scan plan
PLAN=$(curl -s -X POST $BASE_URL/api/ai/scan-plan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "targets": ["'$1'"],
    "objectives": ["Comprehensive security assessment"]
  }')

echo "Scan Plan:"
echo "$PLAN" | jq '.recommended_scans[]'

# 2. Run scans based on plan
SCAN_ID=$(./heroforge scan $1 --format json | jq -r '.scan_id')

# 3. Wait for completion
while [ "$(curl -s $BASE_URL/api/scans/$SCAN_ID -H "Authorization: Bearer $TOKEN" | jq -r '.status')" != "completed" ]; do
  sleep 10
done

# 4. Generate reports
curl -s -X POST $BASE_URL/api/ai/reports/executive \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"scan_id\": \"$SCAN_ID\"}" \
  | jq '.summary' > executive_summary.txt

curl -s -X POST $BASE_URL/api/ai/reports/technical \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"scan_id\": \"$SCAN_ID\"}" \
  | jq '.technical_summary' > technical_report.txt

echo "Reports generated: executive_summary.txt, technical_report.txt"
```

## Tips & Tricks

### 1. Optimize API Usage

```bash
# Cache common reports to reduce API calls
export HEROFORGE_AI_CACHE=true
export HEROFORGE_AI_CACHE_TTL=3600  # 1 hour
```

### 2. Batch Operations

```bash
# Predict remediation times for all vulnerabilities in parallel
cat vulnerabilities.json | jq -c '.[]' | while read vuln; do
  curl -X POST localhost:8080/api/ml/predict/remediation-time \
    -H "Authorization: Bearer $TOKEN" \
    -d "$vuln" &
done
wait
```

### 3. Custom Prompts

```bash
# Use custom context for better exploit analysis
curl -X POST localhost:8080/api/ai/analyze-exploit \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "code": "'$(cat exploit.py | base64)'",
    "context": "Found in APT29 campaign, targets government networks, uses techniques: T1566.001, T1059.001"
  }'
```

### 4. Model Monitoring

```bash
# Check model performance
curl localhost:8080/api/ml/models/threat_classifier/metrics \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Troubleshooting

### Issue: API Rate Limiting

```bash
# Check rate limit status
curl localhost:8080/api/ai/status -H "Authorization: Bearer $TOKEN"

# Implement retry logic
for i in {1..3}; do
  response=$(curl -s -w "%{http_code}" localhost:8080/api/ai/reports/executive ...)
  if [ "$response" != "429" ]; then break; fi
  sleep $((2**i))
done
```

### Issue: Poor ML Model Accuracy

```bash
# Check training data quality
curl localhost:8080/api/ml/training-data/stats -H "Authorization: Bearer $TOKEN"

# Retrain with more data
curl -X POST localhost:8080/api/ml/train/threat-classifier \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"min_samples": 500}'
```

### Issue: LLM Response Quality

```bash
# Use more specific prompts
curl -X POST localhost:8080/api/ai/reports/technical \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "scan_id": "scan_123",
    "focus_areas": ["SQL injection", "XSS", "Authentication"],
    "detail_level": "high"
  }'
```

## Next Steps

1. **Explore Full Documentation**: See `docs/AI_ML_IMPLEMENTATION.md`
2. **Customize Models**: Train models on your specific environment
3. **Integrate with Workflows**: Add AI/ML to your existing security processes
4. **Provide Feedback**: Help improve models with feedback loop
5. **Monitor Performance**: Track AI/ML effectiveness over time

## Support

- **Documentation**: `/docs/AI_ML_IMPLEMENTATION.md`
- **API Reference**: `http://localhost:8080/api/docs` (Swagger UI)
- **GitHub Issues**: Report bugs and feature requests
- **Community**: Join discussions on advanced use cases

---

**Pro Tip**: Start with report generation and scan planning - they provide immediate value with no training required!
