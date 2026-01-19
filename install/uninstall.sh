#!/bin/bash
set -e

#####################################################
# HeroForge Uninstaller
#####################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/heroforge"

echo -e "${YELLOW}"
cat << "EOF"
  _   _                 _____
 | | | | ___ _ __ ___  |  ___|__  _ __ __ _  ___
 | |_| |/ _ \ '__/ _ \ | |_ / _ \| '__/ _` |/ _ \
 |  _  |  __/ | | (_) ||  _| (_) | | | (_| |  __/
 |_| |_|\___|_|  \___/ |_|  \___/|_|  \__, |\___|
                                      |___/
EOF
echo -e "${NC}"
echo "  Uninstaller"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

# Confirm uninstall
echo -e "${YELLOW}Warning: This will remove HeroForge from your system.${NC}"
echo ""
read -p "Are you sure you want to uninstall HeroForge? (y/N): " CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo ""
read -p "Delete all data (database, reports, scans)? (y/N): " DELETE_DATA

echo ""
echo -e "${GREEN}[INFO]${NC} Stopping HeroForge..."

# Stop containers
if [[ -d "$INSTALL_DIR" ]]; then
    cd "$INSTALL_DIR"
    docker compose down 2>/dev/null || true
fi

# Remove data volumes if requested
if [[ "$DELETE_DATA" == "y" || "$DELETE_DATA" == "Y" ]]; then
    echo -e "${GREEN}[INFO]${NC} Removing data volumes..."
    docker volume rm heroforge_data 2>/dev/null || true
    docker volume rm heroforge_reports 2>/dev/null || true
    docker volume rm heroforge_vpn 2>/dev/null || true
    echo -e "${GREEN}[INFO]${NC} Data volumes removed"
else
    echo -e "${YELLOW}[INFO]${NC} Data volumes preserved. Remove manually with:"
    echo "  docker volume rm heroforge_data heroforge_reports heroforge_vpn"
fi

# Remove installation directory
echo -e "${GREEN}[INFO]${NC} Removing installation files..."
rm -rf "$INSTALL_DIR"

# Remove management script
rm -f /usr/local/bin/heroforge

# Remove Docker image (optional)
echo ""
read -p "Remove Docker image to free disk space? (y/N): " REMOVE_IMAGE
if [[ "$REMOVE_IMAGE" == "y" || "$REMOVE_IMAGE" == "Y" ]]; then
    echo -e "${GREEN}[INFO]${NC} Removing Docker image..."
    docker rmi genialarchitect/heroforge:latest 2>/dev/null || true
    docker rmi genialarchitect/heroforge:2.0.0 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  HeroForge has been uninstalled.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Thank you for using HeroForge!"
echo ""
