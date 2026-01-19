#!/bin/bash
set -e

#####################################################
# HeroForge Installer
# Usage: curl -fsSL https://get.heroforge.io/install.sh | sudo bash
#####################################################

VERSION="2.0.0"
INSTALL_DIR="${HEROFORGE_INSTALL_DIR:-/opt/heroforge}"
BASE_URL="${HEROFORGE_BASE_URL:-https://raw.githubusercontent.com/genialarchitect/heroforge/main/install}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
  _   _                 _____
 | | | | ___ _ __ ___  |  ___|__  _ __ __ _  ___
 | |_| |/ _ \ '__/ _ \ | |_ / _ \| '__/ _` |/ _ \
 |  _  |  __/ | | (_) ||  _| (_) | | | (_| |  __/
 |_| |_|\___|_|  \___/ |_|  \___/|_|  \__, |\___|
                                      |___/
EOF
    echo -e "${NC}"
    echo "  Enterprise Security Platform - Installer v${VERSION}"
    echo ""
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_requirements() {
    log_info "Checking system requirements..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed."
        echo ""
        echo "Install Docker first:"
        echo "  curl -fsSL https://get.docker.com | sh"
        echo ""
        exit 1
    fi

    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose v2 is not installed."
        echo ""
        echo "Docker Compose should come with Docker. Try updating Docker:"
        echo "  curl -fsSL https://get.docker.com | sh"
        echo ""
        exit 1
    fi

    # Check Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running."
        echo ""
        echo "Start Docker with:"
        echo "  sudo systemctl start docker"
        echo ""
        exit 1
    fi

    # Check system resources
    TOTAL_MEM=$(free -g 2>/dev/null | awk '/^Mem:/{print $2}' || echo "0")
    if [[ "$TOTAL_MEM" -lt 4 ]]; then
        log_warn "System has ${TOTAL_MEM}GB RAM. Minimum 4GB recommended."
    fi

    CPU_CORES=$(nproc 2>/dev/null || echo "1")
    if [[ "$CPU_CORES" -lt 2 ]]; then
        log_warn "System has ${CPU_CORES} CPU core(s). Minimum 2 recommended."
    fi

    log_info "Requirements check passed"
}

generate_secret() {
    openssl rand -hex 32
}

setup_installation() {
    log_info "Setting up installation directory..."

    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    # Download docker-compose.yml
    log_info "Downloading configuration files..."

    if command -v curl &> /dev/null; then
        curl -fsSL "${BASE_URL}/docker-compose.yml" -o docker-compose.yml
        curl -fsSL "${BASE_URL}/.env.example" -o .env.example
    elif command -v wget &> /dev/null; then
        wget -q "${BASE_URL}/docker-compose.yml" -O docker-compose.yml
        wget -q "${BASE_URL}/.env.example" -O .env.example
    else
        log_error "Neither curl nor wget is available. Please install one."
        exit 1
    fi

    # Create .env if it doesn't exist
    if [[ ! -f .env ]]; then
        cp .env.example .env

        # Auto-generate security keys
        log_info "Generating security keys..."

        JWT_SECRET=$(generate_secret)
        DATABASE_ENCRYPTION_KEY=$(generate_secret)
        TOTP_ENCRYPTION_KEY=$(generate_secret)

        sed -i "s/^JWT_SECRET=$/JWT_SECRET=${JWT_SECRET}/" .env
        sed -i "s/^DATABASE_ENCRYPTION_KEY=$/DATABASE_ENCRYPTION_KEY=${DATABASE_ENCRYPTION_KEY}/" .env
        sed -i "s/^TOTP_ENCRYPTION_KEY=$/TOTP_ENCRYPTION_KEY=${TOTP_ENCRYPTION_KEY}/" .env

        log_info "Security keys generated and saved"
    else
        log_warn ".env already exists, preserving existing configuration"
    fi
}

pull_image() {
    log_info "Pulling HeroForge image (this may take a few minutes)..."
    docker compose pull
}

start_services() {
    log_info "Starting HeroForge..."
    docker compose up -d

    # Wait for health check
    log_info "Waiting for HeroForge to start..."
    local max_attempts=60
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        if docker compose exec -T heroforge curl -sf http://localhost:8080/health/live > /dev/null 2>&1; then
            echo ""
            log_info "HeroForge is running!"
            return 0
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done

    echo ""
    log_warn "HeroForge is taking longer than expected to start."
    log_warn "Check logs with: heroforge logs"
}

create_cli() {
    log_info "Creating management command..."

    cat > /usr/local/bin/heroforge << 'EOFCLI'
#!/bin/bash
INSTALL_DIR="/opt/heroforge"

show_help() {
    echo "HeroForge Management Tool"
    echo ""
    echo "Usage: heroforge <command>"
    echo ""
    echo "Commands:"
    echo "  start       Start HeroForge"
    echo "  stop        Stop HeroForge"
    echo "  restart     Restart HeroForge"
    echo "  status      Show container status"
    echo "  logs        View logs (heroforge logs [lines])"
    echo "  update      Pull latest version and restart"
    echo "  backup      Create data backup"
    echo "  restore     Restore from backup"
    echo "  config      Edit configuration"
    echo "  shell       Open shell in container"
    echo "  version     Show version info"
    echo "  uninstall   Remove HeroForge"
    echo ""
}

case "${1:-help}" in
    start)
        cd "$INSTALL_DIR" && docker compose up -d
        echo "HeroForge started"
        ;;
    stop)
        cd "$INSTALL_DIR" && docker compose down
        echo "HeroForge stopped"
        ;;
    restart)
        cd "$INSTALL_DIR" && docker compose restart
        echo "HeroForge restarted"
        ;;
    status)
        echo "Container Status:"
        docker ps --filter name=heroforge --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        echo "Health Check:"
        docker inspect heroforge --format='{{.State.Health.Status}}' 2>/dev/null || echo "unknown"
        ;;
    logs)
        docker logs heroforge -f --tail="${2:-100}"
        ;;
    update)
        echo "Updating HeroForge..."
        cd "$INSTALL_DIR"
        docker compose pull
        docker compose up -d
        echo "Update complete!"
        docker inspect heroforge --format='Image: {{.Config.Image}}'
        ;;
    backup)
        BACKUP_FILE="${2:-heroforge-backup-$(date +%Y%m%d-%H%M%S).tar.gz}"
        echo "Creating backup: ${BACKUP_FILE}"
        docker run --rm \
            -v heroforge_data:/data \
            -v heroforge_reports:/reports \
            -v "$(pwd):/backup" \
            alpine tar czf "/backup/${BACKUP_FILE}" -C / data reports
        echo "Backup saved to: $(pwd)/${BACKUP_FILE}"
        ;;
    restore)
        if [[ -z "$2" ]]; then
            echo "Usage: heroforge restore <backup-file.tar.gz>"
            exit 1
        fi
        if [[ ! -f "$2" ]]; then
            echo "Error: Backup file not found: $2"
            exit 1
        fi
        echo "Warning: This will overwrite existing data!"
        read -p "Continue? (y/N): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            echo "Stopping HeroForge..."
            cd "$INSTALL_DIR" && docker compose down
            echo "Restoring from backup..."
            docker run --rm \
                -v heroforge_data:/data \
                -v heroforge_reports:/reports \
                -v "$(cd "$(dirname "$2")" && pwd):/backup" \
                alpine tar xzf "/backup/$(basename "$2")" -C /
            echo "Starting HeroForge..."
            docker compose up -d
            echo "Restore complete!"
        else
            echo "Cancelled"
        fi
        ;;
    config)
        ${EDITOR:-nano} "$INSTALL_DIR/.env"
        echo ""
        echo "Configuration updated. Run 'heroforge restart' to apply changes."
        ;;
    shell)
        docker exec -it heroforge /bin/bash
        ;;
    version)
        echo "HeroForge CLI: 2.0.0"
        echo "Install Dir: $INSTALL_DIR"
        docker inspect heroforge --format='Image: {{.Config.Image}}' 2>/dev/null || echo "Container not running"
        ;;
    uninstall)
        echo "This will remove HeroForge and all its data."
        read -p "Are you sure? (y/N): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            read -p "Delete all data volumes? (y/N): " delete_data
            cd "$INSTALL_DIR" && docker compose down
            if [[ "$delete_data" == "y" || "$delete_data" == "Y" ]]; then
                docker volume rm heroforge_data heroforge_reports heroforge_vpn 2>/dev/null || true
            fi
            rm -rf "$INSTALL_DIR"
            rm -f /usr/local/bin/heroforge
            echo "HeroForge has been uninstalled."
        else
            echo "Cancelled"
        fi
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
EOFCLI

    chmod +x /usr/local/bin/heroforge
}

print_success() {
    local PORT
    PORT=$(grep "^HEROFORGE_PORT=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2)
    PORT=${PORT:-8443}

    local IP
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  HeroForge installed successfully!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${CYAN}Access HeroForge:${NC}"
    echo -e "    Local:    http://localhost:${PORT}"
    echo -e "    Network:  http://${IP}:${PORT}"
    echo ""
    echo -e "  ${CYAN}First Time Setup:${NC}"
    echo -e "    1. Open the URL above in your browser"
    echo -e "    2. Create your admin account"
    echo -e "    3. Enable two-factor authentication (recommended)"
    echo ""
    echo -e "  ${CYAN}Management Commands:${NC}"
    echo -e "    heroforge status    - Check status"
    echo -e "    heroforge logs      - View logs"
    echo -e "    heroforge update    - Update to latest version"
    echo -e "    heroforge backup    - Create backup"
    echo -e "    heroforge config    - Edit configuration"
    echo ""
    echo -e "  ${CYAN}Documentation:${NC}"
    echo -e "    https://docs.heroforge.io"
    echo ""
    echo -e "  ${CYAN}Configuration File:${NC}"
    echo -e "    ${INSTALL_DIR}/.env"
    echo ""
}

# Main installation flow
main() {
    print_banner
    check_root
    check_requirements
    setup_installation
    pull_image
    start_services
    create_cli
    print_success
}

main "$@"
