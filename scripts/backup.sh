#!/bin/bash
#
# HeroForge Automated Backup Script
# Backs up the SQLite database with rotation
#
# Usage: ./backup.sh [backup_dir]
# Recommended: Add to crontab for daily execution
#
# Crontab entry (run at 4 AM daily):
# 0 4 * * * /root/Development/HeroForge/scripts/backup.sh >> /var/log/heroforge-backup.log 2>&1
#

set -e

# Configuration
HEROFORGE_DIR="${HEROFORGE_DIR:-/root/Development/HeroForge}"
BACKUP_DIR="${1:-/root/heroforge_backups}"
DB_FILE="${HEROFORGE_DIR}/heroforge.db"
MAX_BACKUPS=30  # Keep 30 days of backups

# Timestamp for this backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE_ONLY=$(date +%Y%m%d)

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "[$(date)] Starting HeroForge backup..."

# Check if database exists
if [ ! -f "$DB_FILE" ]; then
    echo "[$(date)] ERROR: Database file not found: $DB_FILE"
    exit 1
fi

# Get database size for logging
DB_SIZE=$(du -h "$DB_FILE" | cut -f1)
echo "[$(date)] Database size: $DB_SIZE"

# Create backup filename
BACKUP_FILE="${BACKUP_DIR}/heroforge_${TIMESTAMP}.db"

# SQLite online backup (safe for running databases)
if command -v sqlite3 &> /dev/null; then
    echo "[$(date)] Using SQLite online backup..."
    sqlite3 "$DB_FILE" ".backup '$BACKUP_FILE'"
else
    echo "[$(date)] Using file copy (ensure no writes during backup)..."
    cp "$DB_FILE" "$BACKUP_FILE"
fi

# Verify backup was created
if [ ! -f "$BACKUP_FILE" ]; then
    echo "[$(date)] ERROR: Backup file was not created"
    exit 1
fi

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "[$(date)] Backup created: $BACKUP_FILE ($BACKUP_SIZE)"

# Compress backup
echo "[$(date)] Compressing backup..."
gzip "$BACKUP_FILE"
COMPRESSED_FILE="${BACKUP_FILE}.gz"
COMPRESSED_SIZE=$(du -h "$COMPRESSED_FILE" | cut -f1)
echo "[$(date)] Compressed to: $COMPRESSED_FILE ($COMPRESSED_SIZE)"

# Calculate checksum
CHECKSUM=$(sha256sum "$COMPRESSED_FILE" | cut -d' ' -f1)
echo "[$(date)] SHA256: $CHECKSUM"

# Save checksum to file
echo "$CHECKSUM  heroforge_${TIMESTAMP}.db.gz" >> "${BACKUP_DIR}/checksums.txt"

# Rotate old backups (keep MAX_BACKUPS most recent)
echo "[$(date)] Checking backup rotation..."
BACKUP_COUNT=$(ls -1 "${BACKUP_DIR}"/heroforge_*.db.gz 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt "$MAX_BACKUPS" ]; then
    REMOVE_COUNT=$((BACKUP_COUNT - MAX_BACKUPS))
    echo "[$(date)] Removing $REMOVE_COUNT old backup(s)..."
    ls -1t "${BACKUP_DIR}"/heroforge_*.db.gz | tail -n "$REMOVE_COUNT" | xargs rm -f
fi

# Cleanup checksum file (keep only entries for existing files)
if [ -f "${BACKUP_DIR}/checksums.txt" ]; then
    TEMP_CHECKSUMS=$(mktemp)
    while IFS= read -r line; do
        FILENAME=$(echo "$line" | awk '{print $2}')
        if [ -f "${BACKUP_DIR}/${FILENAME}" ]; then
            echo "$line" >> "$TEMP_CHECKSUMS"
        fi
    done < "${BACKUP_DIR}/checksums.txt"
    mv "$TEMP_CHECKSUMS" "${BACKUP_DIR}/checksums.txt"
fi

# Summary
echo "[$(date)] Backup completed successfully"
echo "[$(date)] Backups in directory: $(ls -1 "${BACKUP_DIR}"/heroforge_*.db.gz 2>/dev/null | wc -l)"
echo "[$(date)] Total backup size: $(du -sh "$BACKUP_DIR" | cut -f1)"

# Optional: Verify backup integrity
echo "[$(date)] Verifying backup integrity..."
TEMP_DB=$(mktemp)
gunzip -c "$COMPRESSED_FILE" > "$TEMP_DB"
if sqlite3 "$TEMP_DB" "PRAGMA integrity_check;" | grep -q "ok"; then
    echo "[$(date)] Backup integrity verified: OK"
else
    echo "[$(date)] WARNING: Backup integrity check failed!"
fi
rm -f "$TEMP_DB"

echo "[$(date)] Done"
