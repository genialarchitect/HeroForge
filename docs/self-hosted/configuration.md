# HeroForge Configuration Reference

All configuration is done through environment variables in the `.env` file located at `/opt/heroforge/.env`.

After making changes, restart HeroForge:
```bash
heroforge restart
```

---

## Core Settings

### Application Version

```bash
# Docker image version to use
# Options: latest, 2.0.0, 2.1.0, etc.
HEROFORGE_VERSION=latest
```

### Network Port

```bash
# Port HeroForge listens on (default: 8443)
HEROFORGE_PORT=8443
```

### Resource Limits

```bash
# Maximum CPU cores (default: 4)
HEROFORGE_CPU_LIMIT=4

# Maximum memory (default: 8G)
# Supports: 512M, 1G, 2G, 4G, 8G, 16G
HEROFORGE_MEMORY_LIMIT=8G
```

---

## Security Keys

> ⚠️ **Warning:** These keys are generated during installation. **Do NOT change them** after initial setup or you will lose access to encrypted data (MFA secrets, credentials, etc.)

```bash
# JWT signing key (64 hex characters)
# Used for authentication tokens
JWT_SECRET=your-64-char-hex-string

# Database encryption key (64 hex characters)
# Used for encrypting sensitive data at rest
DATABASE_ENCRYPTION_KEY=your-64-char-hex-string

# TOTP encryption key (64 hex characters)
# Used for encrypting MFA secrets
TOTP_ENCRYPTION_KEY=your-64-char-hex-string
```

**To generate new keys (for fresh installations only):**
```bash
openssl rand -hex 32
```

---

## Email Configuration

Configure email to receive scan alerts, reports, and notifications.

```bash
# SMTP server hostname
SMTP_HOST=smtp.gmail.com

# SMTP port (587 for TLS, 465 for SSL, 25 for plain)
SMTP_PORT=587

# SMTP authentication username
SMTP_USER=your-email@gmail.com

# SMTP authentication password or app password
SMTP_PASSWORD=your-app-password

# From address for outgoing emails
SMTP_FROM_ADDRESS=heroforge@yourcompany.com
```

### Gmail Setup

1. Enable 2-factor authentication on your Google account
2. Go to https://myaccount.google.com/apppasswords
3. Generate an app password for "Mail"
4. Use that password as `SMTP_PASSWORD`

### Microsoft 365 Setup

```bash
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=your-email@company.onmicrosoft.com
SMTP_PASSWORD=your-password
```

### Amazon SES Setup

```bash
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
```

---

## License Key

Unlock Pro and Enterprise features with a license key.

```bash
# HeroForge license key
# Purchase at: https://heroforge.io/pricing
HEROFORGE_LICENSE_KEY=HF-XXXX-XXXX-XXXX-XXXX
```

**License Tiers:**

| Tier | Assets | Users | Features |
|------|--------|-------|----------|
| Free | 25 | 2 | Basic scanning, reporting |
| Professional | 500 | 25 | AI features, cloud scanning, API access |
| Enterprise | Unlimited | Unlimited | SSO, premium support, all features |

**To view current license status:**
```bash
heroforge shell
curl -s http://localhost:8080/api/license | jq
exit
```

---

## AI Features (Zeus AI Assistant)

Enable the Zeus AI security assistant for intelligent analysis and recommendations.

```bash
# Anthropic API key for Claude AI
# Get your key at: https://console.anthropic.com
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
```

**Features enabled:**
- AI-powered vulnerability analysis
- Natural language security queries
- Automated report generation
- Remediation recommendations

---

## Single Sign-On (SSO)

### SAML 2.0

For integration with Okta, Azure AD, OneLogin, etc.

```bash
# URL to your IdP's SAML metadata
SAML_IDP_METADATA_URL=https://your-idp.com/app/xxxxx/sso/saml/metadata
```

**HeroForge SAML Settings:**
- ACS URL: `https://your-heroforge-url/api/auth/saml/callback`
- Entity ID: `heroforge`
- Name ID Format: `emailAddress`

### OAuth 2.0 / OpenID Connect

For integration with Google, GitHub, Azure AD, etc.

```bash
# OAuth client credentials
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret

# OpenID Connect issuer URL
OAUTH_ISSUER_URL=https://accounts.google.com
```

---

## Cloud Security Scanning

### AWS

```bash
# AWS credentials for cloud security scanning
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
```

**Required IAM Permissions:**
- `ec2:Describe*`
- `iam:List*`
- `iam:Get*`
- `s3:GetBucketPolicy`
- `s3:GetBucketAcl`
- `rds:Describe*`
- `securityhub:Get*`

### Azure

```bash
# Azure service principal credentials
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_TENANT_ID=your-tenant-id
```

**Required Azure Roles:**
- Reader
- Security Reader

### Google Cloud Platform

```bash
# Path to service account JSON key file (inside container)
# Mount your key file to /data/gcp-key.json
GOOGLE_APPLICATION_CREDENTIALS=/data/gcp-key.json
```

**To mount the key file, add to docker-compose.yml:**
```yaml
volumes:
  - /path/to/your/gcp-key.json:/data/gcp-key.json:ro
```

**Required GCP Roles:**
- Viewer
- Security Reviewer

---

## Data Storage

HeroForge uses Docker volumes for persistent data:

| Volume | Purpose | Location in Container |
|--------|---------|----------------------|
| `heroforge_data` | Database, configurations | `/data` |
| `heroforge_reports` | Generated reports | `/app/reports` |
| `heroforge_vpn` | VPN configurations | `/app/vpn_configs` |

**To change storage location:**

1. Stop HeroForge: `heroforge stop`
2. Copy existing data: `docker cp heroforge:/data /new/path/data`
3. Update `docker-compose.yml`:
   ```yaml
   volumes:
     - /new/path/data:/data
   ```
4. Start HeroForge: `heroforge start`

---

## Logging

Logs are managed by Docker with automatic rotation:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"    # Maximum log file size
    max-file: "3"       # Number of log files to keep
```

**View logs:**
```bash
heroforge logs           # Follow logs
heroforge logs 500       # Last 500 lines
docker logs heroforge    # Direct Docker access
```

---

## Performance Tuning

### For Large Deployments (1000+ assets)

```bash
HEROFORGE_CPU_LIMIT=8
HEROFORGE_MEMORY_LIMIT=16G
```

### For Resource-Constrained Environments

```bash
HEROFORGE_CPU_LIMIT=2
HEROFORGE_MEMORY_LIMIT=4G
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HEROFORGE_VERSION` | No | `latest` | Docker image version |
| `HEROFORGE_PORT` | No | `8443` | HTTP port |
| `HEROFORGE_CPU_LIMIT` | No | `4` | Max CPU cores |
| `HEROFORGE_MEMORY_LIMIT` | No | `8G` | Max memory |
| `JWT_SECRET` | **Yes** | - | JWT signing key (64 hex chars) |
| `DATABASE_ENCRYPTION_KEY` | **Yes** | - | DB encryption key (64 hex chars) |
| `TOTP_ENCRYPTION_KEY` | **Yes** | - | MFA encryption key (64 hex chars) |
| `SMTP_HOST` | No | - | SMTP server |
| `SMTP_PORT` | No | `587` | SMTP port |
| `SMTP_USER` | No | - | SMTP username |
| `SMTP_PASSWORD` | No | - | SMTP password |
| `SMTP_FROM_ADDRESS` | No | - | From email address |
| `ANTHROPIC_API_KEY` | No | - | Claude AI API key |
| `SAML_IDP_METADATA_URL` | No | - | SAML IdP metadata URL |
| `OAUTH_CLIENT_ID` | No | - | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | No | - | OAuth client secret |
| `OAUTH_ISSUER_URL` | No | - | OIDC issuer URL |
| `AWS_ACCESS_KEY_ID` | No | - | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | No | - | AWS secret key |
| `AWS_REGION` | No | `us-east-1` | AWS region |
| `AZURE_CLIENT_ID` | No | - | Azure client ID |
| `AZURE_CLIENT_SECRET` | No | - | Azure client secret |
| `AZURE_TENANT_ID` | No | - | Azure tenant ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | No | - | Path to GCP key |

---

## Next Steps

- [Installation Guide](installation.md) - Initial setup
- [Upgrading](upgrading.md) - How to update
- [Troubleshooting](troubleshooting.md) - Common issues
