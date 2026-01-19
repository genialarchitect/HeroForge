#!/bin/bash
# HeroForge Deployment Script
# Deploys via Docker + Traefik (SSL handled automatically)

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

# Domain configuration - can be set via environment variable or .env file
if [ -z "$HEROFORGE_DOMAIN" ]; then
    if [ -f .env ] && grep -q "HEROFORGE_DOMAIN" .env; then
        HEROFORGE_DOMAIN=$(grep "HEROFORGE_DOMAIN" .env | cut -d '=' -f2 | tr -d '"' | tr -d "'")
    fi
fi

if [ -z "$HEROFORGE_DOMAIN" ]; then
    echo -e "${RED}Error: HEROFORGE_DOMAIN is not set.${NC}"
    echo "Set it via environment variable or add to .env file:"
    echo "  export HEROFORGE_DOMAIN=your-domain.example.com"
    echo "  # or"
    echo "  echo 'HEROFORGE_DOMAIN=your-domain.example.com' >> .env"
    exit 1
fi

echo -e "${GREEN}Using domain: ${HEROFORGE_DOMAIN}${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./deploy.sh)${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Checking DNS configuration...${NC}"
if host "${HEROFORGE_DOMAIN}" > /dev/null 2>&1; then
    IP=$(host "${HEROFORGE_DOMAIN}" | grep "has address" | awk '{print $4}')
    echo -e "${GREEN}✓ DNS resolves to: $IP${NC}"
else
    echo -e "${RED}⚠ DNS not configured yet. Please set up DNS A record first.${NC}"
    echo "Add an A record: ${HEROFORGE_DOMAIN} -> your-server-ip"
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
~/.cargo/bin/cargo build --release
echo -e "${GREEN}✓ Backend built${NC}"
echo ""

echo -e "${YELLOW}Step 4: Rebuilding Docker container...${NC}"
cd /root
docker compose build heroforge
echo -e "${GREEN}✓ Docker container built${NC}"
echo ""

echo -e "${YELLOW}Step 5: Restarting HeroForge container...${NC}"
docker compose up -d heroforge
sleep 2
echo -e "${GREEN}✓ Container restarted${NC}"
echo ""

echo -e "${YELLOW}Step 6: Checking container status...${NC}"
if docker ps | grep -q heroforge; then
    echo -e "${GREEN}✓ HeroForge container is running${NC}"
    docker logs heroforge --tail 10
else
    echo -e "${RED}✗ Container failed to start. Check logs with: docker logs heroforge${NC}"
    exit 1
fi
echo ""

echo -e "${YELLOW}Step 7: Verifying API...${NC}"
sleep 2
if curl -s "https://${HEROFORGE_DOMAIN}/api/auth/me" | grep -q "Unauthorized"; then
    echo -e "${GREEN}✓ API is responding${NC}"
else
    echo -e "${YELLOW}⚠ API check inconclusive (may still be starting)${NC}"
fi
echo ""

echo "====================================="
echo -e "${GREEN}Deployment Complete!${NC}"
echo "====================================="
echo ""
echo "Application running at:"
echo "  https://${HEROFORGE_DOMAIN}"
echo ""
echo "Useful commands:"
echo "  - View logs: docker logs heroforge -f"
echo "  - Restart: docker compose up -d heroforge"
echo "  - Rebuild: docker compose build heroforge && docker compose up -d heroforge"
echo ""
