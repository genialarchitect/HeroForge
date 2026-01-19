# HeroForge Deployment Guide
## Deploying to heroforge.genialarchitect.io

### Step 1: Prepare DNS

Add an A record for your subdomain:
```
Type: A
Name: heroforge
Value: <your-server-ip>
TTL: 300 (or auto)
```

### Step 2: Install Nginx (if not already installed)

```bash
sudo apt update
sudo apt install nginx -y
```

### Step 3: Deploy Nginx Configuration

```bash
# Copy nginx configuration
sudo cp /root/Development/HeroForge/nginx-heroforge.conf /etc/nginx/sites-available/heroforge

# Create symbolic link
sudo ln -s /etc/nginx/sites-available/heroforge /etc/nginx/sites-enabled/

# Test nginx configuration
sudo nginx -t

# Reload nginx (don't restart yet, SSL not configured)
# We'll do this after SSL setup
```

### Step 4: Install Certbot and Get SSL Certificate

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate (replace with your domain)
sudo certbot --nginx -d your-domain.example.com

# Follow the prompts:
# - Enter email address
# - Agree to terms
# - Choose whether to redirect HTTP to HTTPS (recommended: Yes)
```

Certbot will automatically:
- Obtain the SSL certificate
- Update nginx configuration
- Set up auto-renewal

### Step 5: Set Up HeroForge as a System Service

```bash
# Copy service file
sudo cp /root/Development/HeroForge/heroforge.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable heroforge

# Start the service
sudo systemctl start heroforge

# Check status
sudo systemctl status heroforge
```

### Step 6: Verify Deployment

```bash
# Check if HeroForge is running
sudo systemctl status heroforge

# Check nginx status
sudo systemctl status nginx

# View HeroForge logs
sudo journalctl -u heroforge -f

# View nginx logs
sudo tail -f /var/log/nginx/heroforge-access.log
sudo tail -f /var/log/nginx/heroforge-error.log
```

### Step 7: Access Your Application

Open your browser and navigate to:
```
https://heroforge.genialarchitect.io
```

You should see the HeroForge login page!

### Step 8: Create First Admin User

Using curl:
```bash
curl -X POST https://heroforge.genialarchitect.io/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "your-email@genialarchitect.io",
    "password": "YourSecurePassword123!"
  }'
```

Or use the web interface to register.

### Step 9: Update CORS Settings (Production)

Edit `/root/Development/HeroForge/src/web/mod.rs`:

```rust
let cors = Cors::default()
    .allowed_origin("https://heroforge.genialarchitect.io")
    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
    .allowed_headers(vec![
        actix_web::http::header::AUTHORIZATION,
        actix_web::http::header::ACCEPT,
        actix_web::http::header::CONTENT_TYPE,
    ])
    .max_age(3600);
```

Then rebuild and restart:
```bash
cd /root/Development/HeroForge
cargo build --release
sudo systemctl restart heroforge
```

### Step 10: Change JWT Secret (IMPORTANT!)

Edit `/root/Development/HeroForge/src/web/auth/jwt.rs`:

```rust
const JWT_SECRET: &str = "GENERATE-A-SECURE-RANDOM-STRING-HERE";
```

Generate a secure secret:
```bash
openssl rand -base64 32
```

Then rebuild and restart:
```bash
cd /root/Development/HeroForge
cargo build --release
sudo systemctl restart heroforge
```

## Useful Commands

### Service Management
```bash
# Start service
sudo systemctl start heroforge

# Stop service
sudo systemctl stop heroforge

# Restart service
sudo systemctl restart heroforge

# View status
sudo systemctl status heroforge

# View logs (live)
sudo journalctl -u heroforge -f

# View last 100 lines
sudo journalctl -u heroforge -n 100
```

### Nginx Management
```bash
# Test configuration
sudo nginx -t

# Reload configuration
sudo systemctl reload nginx

# Restart nginx
sudo systemctl restart nginx

# Check status
sudo systemctl status nginx
```

### SSL Certificate Renewal

Certbot auto-renews certificates. To test renewal:
```bash
sudo certbot renew --dry-run
```

To manually renew:
```bash
sudo certbot renew
```

### Database Management

View database:
```bash
sqlite3 /root/Development/HeroForge/heroforge.db

# Inside sqlite3:
.tables
SELECT * FROM users;
SELECT * FROM scan_results;
.quit
```

Backup database:
```bash
cp /root/Development/HeroForge/heroforge.db /root/Development/HeroForge/heroforge.db.backup
```

### Updating HeroForge

When you make changes:
```bash
cd /root/Development/HeroForge
git pull  # if using git
cargo build --release
sudo systemctl restart heroforge
```

## Security Checklist

- [x] SSL/TLS enabled via Let's Encrypt
- [x] JWT authentication required for all scan operations
- [x] CORS configured for production domain
- [ ] Change JWT secret from default
- [ ] Set up firewall rules (only allow 80, 443, 22)
- [ ] Regular database backups
- [ ] Monitor logs for suspicious activity
- [ ] Rate limiting (add to nginx if needed)
- [ ] Consider adding fail2ban for brute force protection

## Firewall Configuration (UFW)

```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP
sudo ufw allow 80/tcp

# Allow HTTPS
sudo ufw allow 443/tcp

# Check status
sudo ufw status
```

## Monitoring

### Set up log rotation
Create `/etc/logrotate.d/heroforge`:
```
/var/log/nginx/heroforge-*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload nginx > /dev/null 2>&1
    endscript
}
```

### Monitor disk space
```bash
# Check database size
du -h /root/Development/HeroForge/heroforge.db

# Check overall usage
df -h
```

## Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u heroforge -n 50

# Check if port is in use
sudo lsof -i :8080

# Check permissions
ls -la /root/Development/HeroForge/heroforge.db
```

### Can't access website
```bash
# Check nginx
sudo nginx -t
sudo systemctl status nginx

# Check SSL certificate
sudo certbot certificates

# Check DNS
nslookup heroforge.genialarchitect.io
```

### WebSocket not working
- Ensure nginx WebSocket proxy is configured
- Check browser console for errors
- Verify firewall allows WebSocket upgrade

## Performance Tuning

For high-traffic scenarios, consider:
1. Using PostgreSQL instead of SQLite
2. Adding Redis for session storage
3. Implementing connection pooling
4. Adding rate limiting in nginx
5. Enabling gzip compression in nginx

Add to nginx config:
```nginx
gzip on;
gzip_types text/plain text/css application/json application/javascript;
gzip_min_length 1000;
```
