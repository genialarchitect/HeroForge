# Database Encryption Migration Guide

This guide explains how to migrate an existing unencrypted HeroForge database to an encrypted SQLCipher database.

## Overview

HeroForge now supports transparent database encryption using SQLCipher, which provides AES-256 encryption of the entire SQLite database file. This ensures that all sensitive data (user credentials, scan results, vulnerabilities, etc.) is encrypted at rest.

## Security Features

When encryption is enabled, HeroForge uses:
- **AES-256 encryption** for all database pages
- **PBKDF2-HMAC-SHA512** key derivation with 256,000 iterations (FIPS 140-2 compliant)
- **4096-byte page size** for optimal security
- Encryption is transparent - no code changes required in application logic

## Prerequisites

Before migrating, ensure you have:
1. A backup of your existing database (see "Backup First" section)
2. The `sqlcipher` command-line tool installed (optional, but recommended)
3. A strong encryption key (see "Generating a Secure Key" section)

## Generating a Secure Encryption Key

Generate a cryptographically secure random key using one of these methods:

### Method 1: Using OpenSSL (Recommended)
```bash
# Generate a 256-bit (32-byte) hex key
openssl rand -hex 32

# Or generate a base64-encoded key
openssl rand -base64 32
```

### Method 2: Using /dev/urandom (Linux/macOS)
```bash
# Generate a 256-bit hex key
head -c 32 /dev/urandom | xxd -p -c 32

# Or base64-encoded
head -c 32 /dev/urandom | base64
```

### Method 3: Using Python
```python
import secrets
print(secrets.token_hex(32))  # Hex format
# or
print(secrets.token_urlsafe(32))  # URL-safe base64
```

**IMPORTANT:** Store this key securely! Anyone with access to this key can decrypt your database. Consider using:
- A secrets management service (HashiCorp Vault, AWS Secrets Manager, etc.)
- Environment variables (never commit to version control)
- Encrypted key files with restricted permissions

## Migration Methods

### Method 1: SQLCipher Command-Line Tool (Recommended)

This method uses the `sqlcipher` CLI to create an encrypted copy of your database.

#### Step 1: Install SQLCipher CLI

**Ubuntu/Debian:**
```bash
sudo apt-get install sqlcipher
```

**macOS (Homebrew):**
```bash
brew install sqlcipher
```

**Arch Linux:**
```bash
sudo pacman -S sqlcipher
```

#### Step 2: Backup Your Database
```bash
# Create a backup of your existing database
cp heroforge.db heroforge.db.backup.$(date +%Y%m%d_%H%M%S)
```

#### Step 3: Create Encrypted Database
```bash
# Set your encryption key
export DB_ENCRYPTION_KEY="your-secure-key-here"

# Create encrypted database from unencrypted one
sqlcipher heroforge.db.backup.* << EOF
PRAGMA key = '$DB_ENCRYPTION_KEY';
ATTACH DATABASE 'heroforge.db.encrypted' AS encrypted KEY '$DB_ENCRYPTION_KEY';
SELECT sqlcipher_export('encrypted');
DETACH DATABASE encrypted;
.quit
EOF

# Verify the encrypted database
sqlcipher heroforge.db.encrypted << EOF
PRAGMA key = '$DB_ENCRYPTION_KEY';
SELECT COUNT(*) FROM users;
.quit
EOF
```

#### Step 4: Replace Original Database
```bash
# Move the encrypted database into place
mv heroforge.db heroforge.db.unencrypted.backup
mv heroforge.db.encrypted heroforge.db

# Set appropriate permissions
chmod 600 heroforge.db
```

#### Step 5: Update Environment Variables
```bash
# Add to your .env file or environment
export DATABASE_ENCRYPTION_KEY="your-secure-key-here"

# For production (in /root/.env or docker-compose.yml):
echo "DATABASE_ENCRYPTION_KEY=your-secure-key-here" >> /root/.env
```

#### Step 6: Restart HeroForge
```bash
# If running via Docker
cd /root && docker compose restart heroforge

# If running directly
cargo run -- serve
```

### Method 2: Using Rust Migration Script

This method uses a Rust script to migrate the database programmatically.

#### Step 1: Create Migration Script

Save this as `migrate_to_encrypted.rs` in your project root:

```rust
// This is a standalone migration script
// Compile with: rustc migrate_to_encrypted.rs -o migrate_to_encrypted
// Or create a new binary in Cargo.toml

use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let old_db = env::args().nth(1).expect("Usage: migrate_to_encrypted <old.db> <new.db> <key>");
    let new_db = env::args().nth(2).expect("Usage: migrate_to_encrypted <old.db> <new.db> <key>");
    let key = env::args().nth(3).expect("Usage: migrate_to_encrypted <old.db> <new.db> <key>");

    println!("Migrating {} to encrypted database {}", old_db, new_db);

    // Open unencrypted database
    let old_conn = rusqlite::Connection::open(&old_db)?;

    // Create encrypted database
    let new_conn = rusqlite::Connection::open(&new_db)?;
    new_conn.pragma_update(None, "key", &key)?;
    new_conn.pragma_update(None, "cipher_page_size", &4096)?;
    new_conn.pragma_update(None, "kdf_iter", &256000)?;
    new_conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA512")?;
    new_conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")?;

    // Export schema and data
    old_conn.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS encrypted KEY '{}';
         SELECT sqlcipher_export('encrypted');
         DETACH DATABASE encrypted;",
        new_db, key
    ))?;

    println!("Migration complete! Encrypted database created at {}", new_db);
    Ok(())
}
```

Note: This is a conceptual script. For actual implementation, you'd need to add the `rusqlite` dependency with SQLCipher features.

### Method 3: In-Place Migration (Advanced)

This method migrates the database in-place by creating a new encrypted database and swapping it.

```bash
#!/bin/bash
set -e

# Configuration
OLD_DB="heroforge.db"
TEMP_DB="heroforge.db.migrating"
BACKUP_DB="heroforge.db.backup.$(date +%Y%m%d_%H%M%S)"
KEY="${DATABASE_ENCRYPTION_KEY}"

if [ -z "$KEY" ]; then
    echo "Error: DATABASE_ENCRYPTION_KEY environment variable not set"
    exit 1
fi

echo "=== HeroForge Database Encryption Migration ==="
echo "This will encrypt your database in-place."
echo "Original database: $OLD_DB"
echo "Backup will be created at: $BACKUP_DB"
echo ""
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Migration cancelled."
    exit 0
fi

# Step 1: Create backup
echo "Creating backup..."
cp "$OLD_DB" "$BACKUP_DB"
echo "Backup created at $BACKUP_DB"

# Step 2: Create encrypted copy
echo "Creating encrypted database..."
sqlcipher "$OLD_DB" << EOF
ATTACH DATABASE '$TEMP_DB' AS encrypted KEY '$KEY';
SELECT sqlcipher_export('encrypted');
DETACH DATABASE encrypted;
EOF

# Step 3: Verify encrypted database
echo "Verifying encrypted database..."
sqlcipher "$TEMP_DB" << EOF
PRAGMA key = '$KEY';
PRAGMA cipher_integrity_check;
EOF

# Step 4: Replace original
echo "Replacing original database with encrypted version..."
mv "$OLD_DB" "${OLD_DB}.old"
mv "$TEMP_DB" "$OLD_DB"
chmod 600 "$OLD_DB"

echo ""
echo "=== Migration Complete ==="
echo "Your database is now encrypted."
echo "Backup of original: $BACKUP_DB"
echo "Old unencrypted copy: ${OLD_DB}.old (delete after verifying)"
echo ""
echo "Next steps:"
echo "1. Set DATABASE_ENCRYPTION_KEY in your environment"
echo "2. Restart HeroForge"
echo "3. Verify the application works correctly"
echo "4. Delete the unencrypted backup files after verification"
```

## Verifying Encryption

After migration, verify that encryption is working:

### Check 1: File is Not Readable as SQLite
```bash
# This should fail or show gibberish
sqlite3 heroforge.db "SELECT * FROM users;" 2>&1 | head

# Expected output: "Error: file is not a database" or binary garbage
```

### Check 2: SQLCipher Can Read with Key
```bash
export KEY="your-encryption-key"
sqlcipher heroforge.db << EOF
PRAGMA key = '$KEY';
SELECT COUNT(*) FROM users;
EOF

# Should show the correct count of users
```

### Check 3: Application Logs
```bash
# Start HeroForge and check logs
cargo run -- serve 2>&1 | grep -i encrypt

# You should see:
# "Database encryption is ENABLED via DATABASE_ENCRYPTION_KEY"
```

### Check 4: Wrong Key Fails
```bash
# Try with wrong key - should fail
sqlcipher heroforge.db << EOF
PRAGMA key = 'wrong-key';
SELECT COUNT(*) FROM users;
EOF

# Expected: Error about file not being a database or decryption failure
```

## Backup Strategy with Encryption

### Manual Encrypted Backup
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/heroforge"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="heroforge_backup_${TIMESTAMP}.db"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Copy encrypted database
cp /root/Development/HeroForge/heroforge.db "$BACKUP_DIR/$BACKUP_FILE"

# Compress and encrypt again with GPG for extra security
gpg --symmetric --cipher-algo AES256 "$BACKUP_DIR/$BACKUP_FILE"
rm "$BACKUP_DIR/$BACKUP_FILE"  # Remove uncompressed copy

echo "Backup created: $BACKUP_DIR/${BACKUP_FILE}.gpg"
```

### Automated Backup Script
See `scripts/backup_encrypted_db.sh` for a complete automated backup solution with:
- Automatic timestamped backups
- GPG encryption for additional security layer
- Retention policy (keep last 7 daily, 4 weekly, 12 monthly)
- Integrity verification
- Email notifications on failure

## Rollback Procedure

If you need to rollback to the unencrypted database:

```bash
# Stop HeroForge
cd /root && docker compose stop heroforge

# Restore from backup
cp heroforge.db.backup.TIMESTAMP /root/Development/HeroForge/heroforge.db

# Remove encryption key from environment
# (edit /root/.env or docker-compose.yml)

# Restart HeroForge
cd /root && docker compose up -d heroforge
```

## Security Best Practices

1. **Key Management:**
   - Never commit encryption keys to version control
   - Use a secrets management service in production
   - Rotate keys periodically (requires re-encryption)
   - Use different keys for development, staging, and production

2. **Access Control:**
   - Set database file permissions to 600 (owner read/write only)
   - Restrict access to the server/container
   - Use file system encryption for additional security layer

3. **Backup Security:**
   - Encrypt backups with a different key/method (GPG)
   - Store backups in a secure, separate location
   - Test backup restoration regularly
   - Implement backup retention policies

4. **Monitoring:**
   - Monitor failed authentication attempts
   - Set up alerts for unauthorized database access attempts
   - Audit database file access logs
   - Track encryption key access/usage

5. **Disaster Recovery:**
   - Document the encryption key storage method
   - Include encryption keys in disaster recovery procedures
   - Test recovery procedures regularly
   - Maintain secure key escrow for emergency access

## Troubleshooting

### Error: "file is not a database"
This usually means:
1. The database is encrypted but no key was provided
2. The wrong encryption key was provided
3. The database file is corrupted

**Solution:** Verify the `DATABASE_ENCRYPTION_KEY` environment variable is set correctly.

### Error: "SQLite header does not match"
The SQLCipher library may not be properly installed or linked.

**Solution:** Rebuild HeroForge after installing SQLCipher:
```bash
cargo clean
cargo build --release
```

### Performance Degradation
Encryption adds a small performance overhead (typically 5-15%).

**Solutions:**
- Ensure `PRAGMA cipher_page_size=4096` is set
- Use `PRAGMA journal_mode=WAL` (already configured)
- Consider hardware AES acceleration if available

### Database Locked Errors
SQLCipher uses the same locking as SQLite.

**Solutions:**
- Ensure `PRAGMA busy_timeout=5000` is set
- Check that max_connections pool size is appropriate
- Close connections properly in application code

## FAQ

**Q: Can I migrate back to unencrypted?**
A: Yes, use the same process in reverse (export from encrypted to unencrypted). However, this defeats the security purpose.

**Q: Does encryption affect database size?**
A: No, encrypted databases are the same size as unencrypted ones.

**Q: Can I change the encryption key?**
A: Yes, but you need to export to a new database with the new key (same process as migration).

**Q: Is encryption FIPS 140-2 compliant?**
A: Yes, when using the PBKDF2-HMAC-SHA512 configuration (which is the default in HeroForge).

**Q: What happens if I lose the encryption key?**
A: The database becomes permanently inaccessible. There is no recovery mechanism. **Always backup your encryption key securely.**

**Q: Does this encrypt data in memory?**
A: No, SQLCipher encrypts data at rest (on disk). Data is decrypted when loaded into memory. For memory encryption, use full disk encryption or secure enclaves.

## References

- [SQLCipher Documentation](https://www.zetetic.net/sqlcipher/documentation/)
- [SQLCipher Design](https://www.zetetic.net/sqlcipher/design/)
- [FIPS 140-2 Compliance](https://www.zetetic.net/sqlcipher/sqlcipher-fips/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines
- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) - Recommendation for Password-Based Key Derivation
