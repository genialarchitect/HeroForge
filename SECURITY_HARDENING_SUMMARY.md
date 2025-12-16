# Security Hardening Implementation Summary

This document summarizes the security hardening features implemented for HeroForge.

## Implemented Features

### 1. SHA-256 Hashing for Refresh Tokens

**Location:** `src/db/mod.rs`

**Implementation:**
- Added `hash_token()` function that uses SHA-256 to hash tokens before storage
- Updated `store_refresh_token()` to hash tokens with SHA-256 before storing in database
- Updated `get_refresh_token()` to hash provided token before database lookup
- Updated `revoke_refresh_token()` to hash provided token before revoking

**Dependencies Added:**
- `sha2 = "0.10"` - SHA-256 hashing
- `hex = "0.4"` - Hex encoding for hash output

**Security Benefits:**
- Tokens are never stored in plaintext in the database
- If database is compromised, tokens cannot be used directly
- Follows NIST 800-63B guidelines for token storage

### 2. AES-256-GCM Encryption for TOTP Secrets

**Location:** `src/db/mod.rs`

**Implementation:**
- Added `get_totp_encryption_key()` to retrieve 32-byte key from environment
- Added `encrypt_totp_secret()` function using AES-256-GCM with random nonce
- Added `decrypt_totp_secret()` function to decrypt stored secrets
- Updated `store_totp_secret()` to encrypt before storing
- Updated `get_totp_secret()` to decrypt after retrieving

**Dependencies Added:**
- `aes-gcm = "0.10"` - AES-256-GCM encryption

**Environment Variables Required:**
```bash
# Generate encryption key with:
openssl rand -hex 32

# Set in environment:
export TOTP_ENCRYPTION_KEY="your_64_character_hex_key_here"
```

**Security Benefits:**
- TOTP secrets are encrypted at rest using industry-standard AES-256-GCM
- Random nonce generated for each encryption (stored with ciphertext)
- If database is compromised, TOTP secrets remain protected
- Key is stored separately from data (environment variable)

### 3. Password History (Prevent Reuse)

**Location:**
- `src/db/migrations.rs` - Table creation
- `src/db/mod.rs` - Database functions
- `src/web/api/auth.rs` - Endpoint integration

**Implementation:**
- Created `password_history` table with migration
- Added `check_password_history()` to check if password was used in last 5
- Added `add_password_to_history()` to store password hash and maintain limit
- Updated `change_password()` endpoint to:
  - Check password history before allowing change
  - Add new password to history after successful change
  - Return clear error if password was recently used

**Security Benefits:**
- Prevents password reuse (last 5 passwords)
- Follows NIST 800-63B recommendations
- Automatic cleanup of old history entries (keeps only last 5)
- Bcrypt hashes stored in history (secure comparison)

**User Experience:**
- Clear error message: "Password was recently used. Please choose a different password. Your last 5 passwords cannot be reused."

### 4. Improved Content Security Policy (CSP)

**Location:** `src/web/mod.rs`

**Implementation:**
- Removed `'unsafe-inline'` from `script-src` directive
- Changed from: `script-src 'self' 'unsafe-inline'`
- Changed to: `script-src 'self'`
- Added additional security directives:
  - `connect-src 'self' ws: wss:` - Allow WebSocket connections
  - `object-src 'none'` - Prevent plugin execution
  - `base-uri 'self'` - Restrict base URL
  - `form-action 'self'` - Restrict form submissions

**CSP Before:**
```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
```

**CSP After:**
```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self' ws: wss:;
object-src 'none';
base-uri 'self';
form-action 'self';
```

**Security Benefits:**
- Prevents inline JavaScript execution (XSS protection)
- Works with Vite-built SPAs (scripts are bundled, not inline)
- Maintains `'unsafe-inline'` for styles (Vite requirement)
- Allows WebSocket connections for real-time features
- Prevents various injection attacks

**Note:** Styles still use `'unsafe-inline'` because Vite uses inline styles for hot module replacement. For production builds, consider using style hashes or nonces.

## Environment Variables Summary

### Required for Production

**TOTP Encryption:**
```bash
# Generate with: openssl rand -hex 32
export TOTP_ENCRYPTION_KEY="64_character_hex_string"
```

**JWT Secret:**
```bash
# Generate with: openssl rand -base64 32
export JWT_SECRET="your_secret_here"
```

### Optional Configuration

**Database Encryption:**
```bash
# Generate with: openssl rand -hex 32
export DATABASE_ENCRYPTION_KEY="64_character_hex_string"
```

**Bcrypt Cost Factor:**
```bash
export BCRYPT_COST=12  # Range: 10-16, default: 12
```

## Testing the Implementation

### 1. Test Password History

```bash
# Change password multiple times
curl -X PUT http://localhost:8080/api/auth/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password": "old", "new_password": "new1"}'

# Try to reuse password (should fail)
curl -X PUT http://localhost:8080/api/auth/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password": "new1", "new_password": "old"}'
# Expected: 400 Bad Request with "Password was recently used" error
```

### 2. Test Refresh Token Hashing

```bash
# Check database - token_hash should be SHA-256 hash (64 hex characters)
sqlite3 heroforge.db "SELECT token_hash FROM refresh_tokens LIMIT 1;"
# Should output a 64-character hex string
```

### 3. Test TOTP Encryption

```bash
# Ensure TOTP_ENCRYPTION_KEY is set
# Check database - totp_secret should be base64-encoded encrypted data
sqlite3 heroforge.db "SELECT totp_secret FROM users WHERE totp_secret IS NOT NULL LIMIT 1;"
# Should output base64 string (not readable plaintext)
```

### 4. Test CSP Headers

```bash
# Check CSP header in response
curl -I https://heroforge.genialarchitect.io/
# Look for: Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

## Migration Notes

### Existing Installations

**Password History:**
- No migration needed for existing users
- History starts being tracked from next password change

**Refresh Tokens:**
- Existing refresh tokens in database will need to be re-issued
- Users will need to login again after deployment
- Old tokens (not hashed) will not match new hash lookups

**TOTP Secrets:**
- Existing TOTP secrets will need to be re-encrypted
- Users with MFA enabled may need to re-setup MFA
- Alternative: Write a migration script to re-encrypt existing secrets

### Deployment Checklist

1. ✅ Generate and set `TOTP_ENCRYPTION_KEY` environment variable
2. ✅ Verify `JWT_SECRET` is set
3. ✅ Run database migrations (automatic on startup)
4. ✅ Test password change flow
5. ✅ Test refresh token flow
6. ✅ Test MFA setup (if enabled)
7. ✅ Verify CSP headers in browser console
8. ⚠️ Notify users about re-login requirement (refresh token change)
9. ⚠️ Notify MFA users about re-setup requirement (if needed)

## Compliance and Standards

This implementation addresses the following security standards:

- **NIST 800-63B:** Password storage, token handling, MFA
- **OWASP Top 10:** A02 (Cryptographic Failures), A05 (Security Misconfiguration)
- **CIS Controls:** 16.11 (Account monitoring)
- **GDPR:** Data protection through encryption

## Files Modified

1. `/root/Development/HeroForge/Cargo.toml` - Added crypto dependencies
2. `/root/Development/HeroForge/src/db/mod.rs` - Token hashing, TOTP encryption, password history
3. `/root/Development/HeroForge/src/db/migrations.rs` - Password history table
4. `/root/Development/HeroForge/src/web/api/auth.rs` - Password history integration
5. `/root/Development/HeroForge/src/web/mod.rs` - CSP header improvements

## Known Limitations

1. **CSP Styles:** Still uses `'unsafe-inline'` for styles (Vite requirement)
2. **Refresh Token Migration:** Existing tokens will need re-issue
3. **TOTP Re-setup:** MFA users may need to re-configure if migrating existing secrets
4. **Key Rotation:** No automatic key rotation for TOTP encryption key

## Future Enhancements

1. Implement style hashes for production builds (remove `'unsafe-inline'` for styles)
2. Add key rotation mechanism for TOTP encryption
3. Add refresh token rotation (issue new token on each refresh)
4. Add session fingerprinting for refresh tokens
5. Implement automatic TOTP secret re-encryption migration script
