#!/bin/bash
# HeroForge Deployment Script for genialarchitect.io

set -e  # Exit on error

echo "====================================="
echo "HeroForge Deployment Script"
echo "====================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./deploy.sh)${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Checking DNS configuration...${NC}"
if host heroforge.genialarchitect.io > /dev/null 2>&1; then
    IP=$(host heroforge.genialarchitect.io | grep "has address" | awk '{print $4}')
    echo -e "${GREEN}✓ DNS resolves to: $IP${NC}"
else
    echo -e "${RED}⚠ DNS not configured yet. Please set up DNS A record first.${NC}"
    echo "Add an A record: heroforge.genialarchitect.io -> your-server-ip"
fi
echo ""

echo -e "${YELLOW}Step 2: Building Frontend...${NC}"
cd /root/Development/HeroForge/frontend
npm install
npm run build
echo -e "${GREEN}✓ Frontend built${NC}"
echo ""

echo -e "${YELLOW}Step 3: Building Backend (Release)...${NC}"
cd /root/Development/HeroForge
sudo -u root ~/.cargo/bin/cargo build --release
echo -e "${GREEN}✓ Backend built${NC}"
echo ""

echo -e "${YELLOW}Step 4: Deploying Nginx configuration...${NC}"
cp nginx-heroforge.conf /etc/nginx/sites-available/heroforge

# Create symlink if it doesn't exist
if [ ! -L /etc/nginx/sites-enabled/heroforge ]; then
    ln -s /etc/nginx/sites-available/heroforge /etc/nginx/sites-enabled/
    echo -e "${GREEN}✓ Nginx config symlink created${NC}"
else
    echo -e "${GREEN}✓ Nginx config already linked${NC}"
fi
echo ""

echo -e "${YELLOW}Step 5: Testing Nginx configuration...${NC}"
nginx -t
echo -e "${GREEN}✓ Nginx config is valid${NC}"
echo ""

echo -e "${YELLOW}Step 6: Installing systemd service...${NC}"
cp heroforge.service /etc/systemd/system/
systemctl daemon-reload
echo -e "${GREEN}✓ Service installed${NC}"
echo ""

echo -e "${YELLOW}Step 7: Enabling and starting HeroForge service...${NC}"
systemctl enable heroforge
systemctl restart heroforge
sleep 2
echo -e "${GREEN}✓ Service started${NC}"
echo ""

echo -e "${YELLOW}Step 8: Checking service status...${NC}"
if systemctl is-active --quiet heroforge; then
    echo -e "${GREEN}✓ HeroForge service is running${NC}"
    systemctl status heroforge --no-pager | head -10
else
    echo -e "${RED}✗ Service failed to start. Check logs with: journalctl -u heroforge -n 50${NC}"
    exit 1
fi
echo ""

echo -e "${YELLOW}Step 9: Reloading Nginx...${NC}"
systemctl reload nginx
echo -e "${GREEN}✓ Nginx reloaded${NC}"
echo ""

echo "====================================="
echo -e "${GREEN}Deployment Complete!${NC}"
echo "====================================="
echo ""
echo "Next steps:"
echo "1. Set up DNS A record: heroforge.genialarchitect.io -> your-server-ip"
echo "2. Get SSL certificate:"
echo "   sudo certbot --nginx -d heroforge.genialarchitect.io"
echo ""
echo "3. Access your application at:"
echo "   https://heroforge.genialarchitect.io"
echo ""
echo "Useful commands:"
echo "  - View logs: sudo journalctl -u heroforge -f"
echo "  - Restart service: sudo systemctl restart heroforge"
echo "  - Check status: sudo systemctl status heroforge"
echo ""
