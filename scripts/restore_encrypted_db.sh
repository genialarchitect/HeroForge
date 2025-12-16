#!/bin/bash
#
# HeroForge Encrypted Database Restore Script
#
# This script restores an encrypted backup of the HeroForge database.
# It handles GPG decryption and optionally verifies the restored database.
#
# Usage: ./restore_encrypted_db.sh <backup_file.gpg> [options]
# Options:
#   -o, --output PATH       Output database path (default: /root/Development/HeroForge/heroforge.db)
#   -k, --gpg-key EMAIL     GPG key for decryption (if public key encryption was used)
#   -v, --verify            Verify database integrity after restore
#   --no-backup             Don't backup existing database before restore
#   -h, --help              Show this help message
#
# Environment variables:
#   BACKUP_GPG_PASSPHRASE    - GPG passphrase for symmetric decryption
#   DATABASE_ENCRYPTION_KEY  - SQLCipher encryption key (for verification)
#

set -euo pipefail

# Default configuration
OUTPUT_PATH="/root/Development/HeroForge/heroforge.db"
GPG_KEY=""
VERIFY=false
BACKUP_EXISTING=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Show help if no arguments
if [[ $# -eq 0 ]]; then
    grep '^#' "$0" | tail -n +2 | head -n -1 | cut -c 3-
    exit 1
fi

# Get backup file (first positional argument)
BACKUP_FILE="$1"
shift

# Parse remaining arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        -k|--gpg-key)
            GPG_KEY="$2"
            shift 2
            ;;
        -v|--verify)
            VERIFY=true
            shift
            ;;
        --no-backup)
            BACKUP_EXISTING=false
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
    exit 1
}

# Main restore process
main() {
    log "=== HeroForge Database Restore ===" "$GREEN"
    log "Backup file: $BACKUP_FILE"
    log "Output path: $OUTPUT_PATH"
    echo ""

    # Check if backup file exists
    if [[ ! -f "$BACKUP_FILE" ]]; then
        error "Backup file not found: $BACKUP_FILE"
    fi

    # Check if GPG is available
    if ! command -v gpg >/dev/null 2>&1; then
        error "GPG not found. Please install gnupg: apt-get install gnupg"
    fi

    # Backup existing database if it exists
    if [[ -f "$OUTPUT_PATH" ]] && [[ "$BACKUP_EXISTING" == true ]]; then
        local backup_name="${OUTPUT_PATH}.restore_backup.$(date +%Y%m%d_%H%M%S)"
        log "Backing up existing database to: $backup_name" "$YELLOW"
        cp "$OUTPUT_PATH" "$backup_name" || error "Failed to backup existing database"
    fi

    # Decrypt backup
    log "Decrypting backup..." "$YELLOW"

    local temp_output="${OUTPUT_PATH}.restoring"

    if [[ -n "$GPG_KEY" ]]; then
        # Decrypt with private key
        gpg --decrypt --output "$temp_output" "$BACKUP_FILE" \
            || error "Failed to decrypt backup (check GPG key)"
    else
        # Symmetric decryption with passphrase
        if [[ -z "${BACKUP_GPG_PASSPHRASE:-}" ]]; then
            error "BACKUP_GPG_PASSPHRASE environment variable not set"
        fi

        echo "$BACKUP_GPG_PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 \
            --decrypt --output "$temp_output" "$BACKUP_FILE" \
            || error "Failed to decrypt backup (check passphrase)"
    fi

    log "Decryption successful" "$GREEN"

    # Verify database integrity if requested
    if [[ "$VERIFY" == true ]]; then
        log "Verifying database integrity..." "$YELLOW"

        if [[ -n "${DATABASE_ENCRYPTION_KEY:-}" ]]; then
            if command -v sqlcipher >/dev/null 2>&1; then
                sqlcipher "$temp_output" << EOF >/dev/null 2>&1 || error "Database integrity check failed"
PRAGMA key = '$DATABASE_ENCRYPTION_KEY';
PRAGMA integrity_check;
EOF
                log "Database integrity check passed (encrypted database)" "$GREEN"
            else
                log "Warning: sqlcipher not found, skipping integrity check" "$YELLOW"
            fi
        else
            if command -v sqlite3 >/dev/null 2>&1; then
                sqlite3 "$temp_output" "PRAGMA integrity_check;" >/dev/null 2>&1 \
                    || error "Database integrity check failed"
                log "Database integrity check passed" "$GREEN"
            else
                log "Warning: sqlite3 not found, skipping integrity check" "$YELLOW"
            fi
        fi
    fi

    # Move restored database to final location
    log "Moving restored database to final location..." "$YELLOW"
    mv "$temp_output" "$OUTPUT_PATH" || error "Failed to move restored database"
    chmod 600 "$OUTPUT_PATH"

    log "Database size: $(du -h "$OUTPUT_PATH" | cut -f1)"

    echo ""
    log "=== Restore Complete ===" "$GREEN"
    log "Database restored to: $OUTPUT_PATH"

    if [[ "$BACKUP_EXISTING" == true ]] && [[ -f "${OUTPUT_PATH}.restore_backup."* ]]; then
        echo ""
        log "Previous database backed up. Delete after verifying:" "$YELLOW"
        log "  rm ${OUTPUT_PATH}.restore_backup.*"
    fi

    echo ""
    log "Next steps:" "$YELLOW"
    log "1. Restart HeroForge service"
    log "2. Verify the application works correctly"
    log "3. Delete backup files after verification"
}

# Run main function
main
