# Database Encryption Quick Reference

## Enable Encryption (3 Steps)

```bash
# 1. Generate key
export DATABASE_ENCRYPTION_KEY=$(openssl rand -hex 32)

# 2. Add to environment (production)
echo "DATABASE_ENCRYPTION_KEY=$DATABASE_ENCRYPTION_KEY" >> /root/.env

# 3. Restart HeroForge
cd /root && docker compose restart heroforge
```

## Migrate Existing Database

```bash
# Backup first
cp heroforge.db heroforge.db.backup

# Migrate
export KEY="your-encryption-key"
sqlcipher heroforge.db.backup << EOF
ATTACH DATABASE 'heroforge.db.encrypted' AS encrypted KEY '$KEY';
SELECT sqlcipher_export('encrypted');
DETACH DATABASE encrypted;
EOF

# Replace
mv heroforge.db.encrypted heroforge.db
chmod 600 heroforge.db
```

## Verify Encryption

```bash
# Should FAIL (encrypted)
sqlite3 heroforge.db "SELECT * FROM users;"

# Should SUCCEED (with key)
sqlcipher heroforge.db << EOF
PRAGMA key = '$DATABASE_ENCRYPTION_KEY';
SELECT COUNT(*) FROM users;
EOF
```

## Backup & Restore

```bash
# Backup
export BACKUP_GPG_PASSPHRASE="your-passphrase"
./scripts/backup_encrypted_db.sh -v

# Restore
./scripts/restore_encrypted_db.sh backup_file.gpg -v
```

## Key Security Rules

1. **Never commit keys to git**
2. **Store keys in secrets manager** (Vault, AWS Secrets Manager)
3. **Backup keys separately** from database backups
4. **Use different keys** for dev/staging/prod
5. **Key loss = permanent data loss** (no recovery possible)

## Files

- `DATABASE_ENCRYPTION_MIGRATION.md` - Full migration guide
- `DATABASE_ENCRYPTION_IMPLEMENTATION.md` - Implementation details
- `scripts/backup_encrypted_db.sh` - Automated backups
- `scripts/restore_encrypted_db.sh` - Restore from backup

## Environment Variables

- `DATABASE_ENCRYPTION_KEY` - Required for encryption (256-bit hex)
- `BACKUP_GPG_PASSPHRASE` - Required for backup script

## Support

Check logs for encryption status:
```bash
docker logs heroforge -f | grep -i encrypt
```

Expected output:
```
Database encryption is ENABLED via DATABASE_ENCRYPTION_KEY
```
