#!/bin/bash
#
# HeroForge Encrypted Database Backup Script
#
# This script creates encrypted backups of the HeroForge SQLite database with:
# - Timestamped backup files
# - Additional GPG encryption layer for security
# - Backup retention policy (daily, weekly, monthly)
# - Integrity verification
# - Email notifications on failure (optional)
#
# Usage: ./backup_encrypted_db.sh [options]
# Options:
#   -d, --database PATH     Database file path (default: /root/Development/HeroForge/heroforge.db)
#   -o, --output DIR        Backup directory (default: /var/backups/heroforge)
#   -k, --gpg-key EMAIL     GPG key for encryption (default: none, symmetric encryption)
#   -r, --retention DAYS    Retention days for backups (default: 30)
#   -n, --notify EMAIL      Email address for failure notifications
#   -v, --verify            Verify backup integrity after creation
#   -h, --help              Show this help message
#
# Environment variables:
#   DATABASE_ENCRYPTION_KEY  - SQLCipher encryption key (required if DB is encrypted)
#   BACKUP_GPG_PASSPHRASE    - GPG passphrase for symmetric encryption
#   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD - For email notifications
#

set -euo pipefail

# Default configuration
DB_PATH="${DATABASE_PATH:-/root/Development/HeroForge/heroforge.db}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/heroforge}"
GPG_KEY=""
RETENTION_DAYS=30
NOTIFY_EMAIL=""
VERIFY_BACKUP=false
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE_ONLY=$(date +%Y%m%d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--database)
            DB_PATH="$2"
            shift 2
            ;;
        -o|--output)
            BACKUP_DIR="$2"
            shift 2
            ;;
        -k|--gpg-key)
            GPG_KEY="$2"
            shift 2
            ;;
        -r|--retention)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        -n|--notify)
            NOTIFY_EMAIL="$2"
            shift 2
            ;;
        -v|--verify)
            VERIFY_BACKUP=true
            shift
            ;;
        -h|--help)
            grep '^#' "$0" | tail -n +2 | head -n -1 | cut -c 3-
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Log function
log() {
    echo -e "${2:-$NC}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Error handling
error() {
    log "ERROR: $1" "$RED"
    if [[ -n "$NOTIFY_EMAIL" ]]; then
        send_notification "HeroForge Backup Failed" "$1"
    fi
    exit 1
}

# Send email notification
send_notification() {
    local subject="$1"
    local message="$2"

    if [[ -n "$SMTP_HOST" ]] && command -v mailx >/dev/null 2>&1; then
        echo "$message" | mailx -s "$subject" \
            -S smtp="$SMTP_HOST:${SMTP_PORT:-587}" \
            -S smtp-use-starttls \
            -S smtp-auth=login \
            -S smtp-auth-user="$SMTP_USER" \
            -S smtp-auth-password="$SMTP_PASSWORD" \
            -S from="${SMTP_FROM_ADDRESS:-backup@heroforge.local}" \
            "$NOTIFY_EMAIL" 2>/dev/null || true
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..." "$YELLOW"

    # Check if database exists
    if [[ ! -f "$DB_PATH" ]]; then
        error "Database file not found: $DB_PATH"
    fi

    # Check if GPG is available
    if ! command -v gpg >/dev/null 2>&1; then
        error "GPG not found. Please install gnupg: apt-get install gnupg"
    fi

    # Check for GPG passphrase if using symmetric encryption
    if [[ -z "$GPG_KEY" ]] && [[ -z "${BACKUP_GPG_PASSPHRASE:-}" ]]; then
        error "BACKUP_GPG_PASSPHRASE environment variable not set for symmetric encryption"
    fi

    # Create backup directory if it doesn't exist
    mkdir -p "$BACKUP_DIR"/{daily,weekly,monthly} || error "Failed to create backup directories"

    log "Prerequisites check passed" "$GREEN"
}

# Calculate database size
get_db_size() {
    du -h "$DB_PATH" | cut -f1
}

# Create backup
create_backup() {
    local backup_name="heroforge_${TIMESTAMP}.db"
    local backup_path="$BACKUP_DIR/daily/$backup_name"
    local encrypted_path="${backup_path}.gpg"

    log "Starting backup of $DB_PATH ($(get_db_size))..." "$YELLOW"

    # Copy database file
    log "Copying database file..."
    cp "$DB_PATH" "$backup_path" || error "Failed to copy database file"

    # Verify the copy if database is encrypted
    if [[ -n "${DATABASE_ENCRYPTION_KEY:-}" ]]; then
        log "Verifying database copy (encrypted database)..."
        if command -v sqlcipher >/dev/null 2>&1; then
            # Quick integrity check
            sqlcipher "$backup_path" << EOF >/dev/null 2>&1 || error "Database copy verification failed"
PRAGMA key = '$DATABASE_ENCRYPTION_KEY';
PRAGMA integrity_check;
EOF
        fi
    else
        # Unencrypted database - use sqlite3
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$backup_path" "PRAGMA integrity_check;" >/dev/null 2>&1 || error "Database copy verification failed"
        fi
    fi

    # Encrypt backup with GPG
    log "Encrypting backup with GPG..."
    if [[ -n "$GPG_KEY" ]]; then
        # Encrypt with public key
        gpg --encrypt --recipient "$GPG_KEY" --trust-model always --output "$encrypted_path" "$backup_path" \
            || error "GPG encryption failed"
    else
        # Symmetric encryption with passphrase
        echo "$BACKUP_GPG_PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 \
            --symmetric --cipher-algo AES256 \
            --output "$encrypted_path" "$backup_path" \
            || error "GPG encryption failed"
    fi

    # Remove unencrypted copy
    rm -f "$backup_path"

    # Set secure permissions
    chmod 600 "$encrypted_path"

    local backup_size=$(du -h "$encrypted_path" | cut -f1)
    log "Backup created successfully: $encrypted_path ($backup_size)" "$GREEN"

    echo "$encrypted_path"
}

# Verify backup integrity
verify_backup() {
    local encrypted_path="$1"

    log "Verifying backup integrity..." "$YELLOW"

    # Create temporary directory
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    local decrypted_path="$temp_dir/heroforge.db"

    # Decrypt
    if [[ -n "$GPG_KEY" ]]; then
        gpg --decrypt --output "$decrypted_path" "$encrypted_path" \
            || error "Failed to decrypt backup for verification"
    else
        echo "$BACKUP_GPG_PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 \
            --decrypt --output "$decrypted_path" "$encrypted_path" \
            || error "Failed to decrypt backup for verification"
    fi

    # Verify database integrity
    if [[ -n "${DATABASE_ENCRYPTION_KEY:-}" ]]; then
        if command -v sqlcipher >/dev/null 2>&1; then
            sqlcipher "$decrypted_path" << EOF >/dev/null 2>&1 || error "Backup integrity check failed"
PRAGMA key = '$DATABASE_ENCRYPTION_KEY';
PRAGMA integrity_check;
SELECT COUNT(*) FROM users;
EOF
        fi
    else
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$decrypted_path" "PRAGMA integrity_check; SELECT COUNT(*) FROM users;" >/dev/null 2>&1 \
                || error "Backup integrity check failed"
        fi
    fi

    log "Backup verification passed" "$GREEN"
}

# Organize backups (daily, weekly, monthly)
organize_backups() {
    local backup_file="$1"

    log "Organizing backups..." "$YELLOW"

    # Copy to weekly if it's Sunday
    if [[ $(date +%u) -eq 7 ]]; then
        local weekly_name="heroforge_weekly_${DATE_ONLY}.db.gpg"
        cp "$backup_file" "$BACKUP_DIR/weekly/$weekly_name"
        log "Created weekly backup: $weekly_name"
    fi

    # Copy to monthly if it's the 1st of the month
    if [[ $(date +%d) -eq 01 ]]; then
        local monthly_name="heroforge_monthly_$(date +%Y%m).db.gpg"
        cp "$backup_file" "$BACKUP_DIR/monthly/$monthly_name"
        log "Created monthly backup: $monthly_name"
    fi
}

# Clean old backups based on retention policy
cleanup_old_backups() {
    log "Cleaning old backups (retention: ${RETENTION_DAYS} days)..." "$YELLOW"

    # Clean daily backups older than retention period
    find "$BACKUP_DIR/daily" -name "heroforge_*.db.gpg" -type f -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

    # Keep last 4 weekly backups
    ls -t "$BACKUP_DIR/weekly"/heroforge_weekly_*.db.gpg 2>/dev/null | tail -n +5 | xargs -r rm -f || true

    # Keep last 12 monthly backups
    ls -t "$BACKUP_DIR/monthly"/heroforge_monthly_*.db.gpg 2>/dev/null | tail -n +13 | xargs -r rm -f || true

    local daily_count=$(find "$BACKUP_DIR/daily" -name "*.gpg" -type f | wc -l)
    local weekly_count=$(find "$BACKUP_DIR/weekly" -name "*.gpg" -type f | wc -l)
    local monthly_count=$(find "$BACKUP_DIR/monthly" -name "*.gpg" -type f | wc -l)

    log "Backup counts - Daily: $daily_count, Weekly: $weekly_count, Monthly: $monthly_count" "$GREEN"
}

# Main execution
main() {
    log "=== HeroForge Database Backup ===" "$GREEN"
    log "Database: $DB_PATH"
    log "Backup directory: $BACKUP_DIR"
    log "Timestamp: $TIMESTAMP"
    echo ""

    check_prerequisites

    backup_file=$(create_backup)

    if [[ "$VERIFY_BACKUP" == true ]]; then
        verify_backup "$backup_file"
    fi

    organize_backups "$backup_file"
    cleanup_old_backups

    echo ""
    log "=== Backup Complete ===" "$GREEN"
    log "Backup location: $backup_file"

    # Send success notification
    if [[ -n "$NOTIFY_EMAIL" ]]; then
        send_notification "HeroForge Backup Successful" \
            "Backup completed successfully at $(date)\nLocation: $backup_file\nSize: $(du -h "$backup_file" | cut -f1)"
    fi
}

# Run main function
main "$@"
