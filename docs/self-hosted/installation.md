# HeroForge Self-Hosted Installation Guide

This guide walks you through installing HeroForge on your own server.

## System Requirements

### Minimum Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB | 50+ GB SSD |
| OS | Linux (64-bit) | Ubuntu 22.04 LTS |

### Supported Operating Systems

- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- RHEL/CentOS 8, 9
- Amazon Linux 2023
- Any Linux with Docker support

### Required Software

- Docker 24.0+
- Docker Compose v2

---

## Quick Installation

The fastest way to install HeroForge:

```bash
curl -fsSL https://raw.githubusercontent.com/genialarchitect/HeroForge/main/install/install.sh | sudo bash
```

This will:
1. Check system requirements
2. Download configuration files
3. Generate security keys
4. Pull the Docker image
5. Start HeroForge
6. Install the `heroforge` management CLI

---

## Manual Installation

If you prefer manual control:

### Step 1: Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Log out and back in for group changes to take effect.

### Step 2: Create Installation Directory

```bash
sudo mkdir -p /opt/heroforge
cd /opt/heroforge
```

### Step 3: Download Configuration Files

```bash
sudo curl -fsSL https://raw.githubusercontent.com/genialarchitect/HeroForge/main/install/docker-compose.yml -o docker-compose.yml
sudo curl -fsSL https://raw.githubusercontent.com/genialarchitect/HeroForge/main/install/.env.example -o .env
```

### Step 4: Generate Security Keys

```bash
# Generate random keys
JWT_SECRET=$(openssl rand -hex 32)
DATABASE_ENCRYPTION_KEY=$(openssl rand -hex 32)
TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Update .env file
sudo sed -i "s/^JWT_SECRET=$/JWT_SECRET=${JWT_SECRET}/" .env
sudo sed -i "s/^DATABASE_ENCRYPTION_KEY=$/DATABASE_ENCRYPTION_KEY=${DATABASE_ENCRYPTION_KEY}/" .env
sudo sed -i "s/^TOTP_ENCRYPTION_KEY=$/TOTP_ENCRYPTION_KEY=${TOTP_ENCRYPTION_KEY}/" .env
```

### Step 5: Pull and Start

```bash
sudo docker compose pull
sudo docker compose up -d
```

### Step 6: Verify Installation

```bash
# Check container status
docker ps | grep heroforge

# Check logs
docker logs heroforge --tail 50

# Test health endpoint
curl -f http://localhost:8443/health/live
```

---

## First-Time Setup

1. Open your browser to `http://your-server-ip:8443`
2. Create your admin account
3. Enable two-factor authentication (recommended)
4. Configure email settings (optional)
5. Start scanning!

---

## Network Configuration

### Firewall Rules

Open the following port:

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 8443/tcp

# RHEL/CentOS (firewalld)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### Reverse Proxy (Optional)

For HTTPS with your own domain, use a reverse proxy like nginx or Traefik.

**Example nginx configuration:**

```nginx
server {
    listen 443 ssl http2;
    server_name heroforge.yourcompany.com;

    ssl_certificate /etc/ssl/certs/heroforge.crt;
    ssl_certificate_key /etc/ssl/private/heroforge.key;

    location / {
        proxy_pass http://localhost:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Cloud Deployment

### AWS EC2

1. Launch an EC2 instance (t3.medium or larger)
2. Use Ubuntu 22.04 AMI
3. Security group: Allow inbound TCP 8443
4. SSH in and run the quick install command

### Azure VM

1. Create a VM (Standard_B2ms or larger)
2. Use Ubuntu 22.04 image
3. NSG: Allow inbound TCP 8443
4. SSH in and run the quick install command

### Google Cloud

1. Create a Compute Engine instance (e2-medium or larger)
2. Use Ubuntu 22.04 image
3. Firewall: Allow ingress TCP 8443
4. SSH in and run the quick install command

---

## Air-Gapped Installation

For environments without internet access:

### On a Connected Machine

```bash
# Pull and save the image
docker pull genialarchitect/heroforge:latest
docker save genialarchitect/heroforge:latest | gzip > heroforge-image.tar.gz

# Download install files
curl -fsSL https://raw.githubusercontent.com/genialarchitect/HeroForge/main/install/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/genialarchitect/HeroForge/main/install/.env.example -o .env.example
```

### Transfer Files

Copy `heroforge-image.tar.gz`, `docker-compose.yml`, and `.env.example` to your air-gapped server.

### On the Air-Gapped Server

```bash
# Load the image
gunzip -c heroforge-image.tar.gz | docker load

# Set up configuration
sudo mkdir -p /opt/heroforge
cd /opt/heroforge
sudo cp /path/to/docker-compose.yml .
sudo cp /path/to/.env.example .env

# Generate keys and start (same as manual installation steps 4-5)
```

---

## Verifying Installation

Run these commands to verify HeroForge is working:

```bash
# Container running
docker ps | grep heroforge

# Health check passing
curl http://localhost:8443/health/live

# View startup logs
docker logs heroforge 2>&1 | head -50
```

Expected output:
```
[INFO] Database migrations complete
[INFO] Starting HeroForge server on 0.0.0.0:8080
[INFO] Server started successfully
```

---

## Next Steps

- [Configuration Guide](configuration.md) - Configure email, SSO, cloud integrations
- [Upgrading](upgrading.md) - How to update to new versions
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

---

## Getting Help

- Documentation: https://docs.heroforge.io
- Support: support@heroforge.io
- GitHub Issues: https://github.com/genialarchitect/HeroForge/issues
