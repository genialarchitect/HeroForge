//! Hash Computation Module
//!
//! Computes various cryptographic hashes for binary files including
//! MD5, SHA1, SHA256, and import hash (imphash) for PE files.

use super::types::BinaryHashes;
use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::Sha256;
use goblin::pe::PE;

/// Compute all standard hashes for binary data
pub fn compute_hashes(data: &[u8], compute_imphash: bool) -> BinaryHashes {
    let md5 = compute_md5(data);
    let sha1 = compute_sha1(data);
    let sha256 = compute_sha256(data);

    // Try to compute imphash if this is a PE file
    let imphash = if compute_imphash {
        if let Ok(pe) = PE::parse(data) {
            compute_imphash_from_pe(&pe)
        } else {
            None
        }
    } else {
        None
    };

    // Compute fuzzy hashes
    let ssdeep = compute_ssdeep(data);
    let tlsh = compute_tlsh(data);

    BinaryHashes {
        md5,
        sha1,
        sha256,
        ssdeep,
        imphash,
        tlsh,
    }
}

/// Compute MD5 hash
pub fn compute_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA1 hash
pub fn compute_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA256 hash
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ==========================================================================
// SSDeep Fuzzy Hashing Implementation
// ==========================================================================

/// SSDeep constants
const SSDEEP_SPAMSUM_LENGTH: usize = 64;
const SSDEEP_MIN_BLOCKSIZE: u32 = 3;
const SSDEEP_HASH_INIT: u32 = 0x28021967;
const SSDEEP_HASH_PRIME: u32 = 0x01000193;

/// Compute SSDeep fuzzy hash
/// Based on the context-triggered piecewise hashing algorithm
pub fn compute_ssdeep(data: &[u8]) -> Option<String> {
    if data.len() < 4096 {
        // SSDeep needs minimum file size
        return None;
    }

    // Calculate block size based on file length
    let mut block_size = SSDEEP_MIN_BLOCKSIZE;
    while block_size * SSDEEP_SPAMSUM_LENGTH as u32 * 2 < data.len() as u32 {
        block_size *= 2;
    }

    // Generate hashes at two block sizes
    let hash1 = ssdeep_hash_block(data, block_size);
    let hash2 = ssdeep_hash_block(data, block_size * 2);

    // Ensure we have valid hashes
    if hash1.is_empty() || hash2.is_empty() {
        return None;
    }

    // Format: blocksize:hash1:hash2
    Some(format!("{}:{}:{}", block_size, hash1, hash2))
}

/// Hash a block of data for SSDeep
fn ssdeep_hash_block(data: &[u8], block_size: u32) -> String {
    let mut result = Vec::with_capacity(SSDEEP_SPAMSUM_LENGTH);
    let mut rolling_hash = RollingHash::new();
    let mut block_hash: u32 = SSDEEP_HASH_INIT;

    for &byte in data {
        block_hash = ssdeep_fnv_hash(block_hash, byte);
        rolling_hash.update(byte);

        if rolling_hash.sum() % block_size == (block_size - 1) {
            // Emit a character for this block
            let c = b64_char((block_hash & 0x3F) as usize);
            result.push(c);
            block_hash = SSDEEP_HASH_INIT;

            if result.len() >= SSDEEP_SPAMSUM_LENGTH {
                break;
            }
        }
    }

    // Emit final character if we have pending data
    if result.len() < SSDEEP_SPAMSUM_LENGTH {
        let c = b64_char((block_hash & 0x3F) as usize);
        result.push(c);
    }

    String::from_utf8(result).unwrap_or_default()
}

/// FNV-like hash for SSDeep
fn ssdeep_fnv_hash(h: u32, c: u8) -> u32 {
    (h.wrapping_mul(SSDEEP_HASH_PRIME)) ^ (c as u32)
}

/// Rolling hash for SSDeep (Adler-32 variant)
struct RollingHash {
    window: [u8; 7],
    idx: usize,
    h1: u32,
    h2: u32,
    h3: u32,
}

impl RollingHash {
    fn new() -> Self {
        Self {
            window: [0u8; 7],
            idx: 0,
            h1: 0,
            h2: 0,
            h3: 0,
        }
    }

    fn update(&mut self, byte: u8) {
        let old = self.window[self.idx] as u32;
        self.window[self.idx] = byte;
        self.idx = (self.idx + 1) % 7;

        let b = byte as u32;
        self.h1 = self.h1.wrapping_sub(old).wrapping_add(b);
        self.h2 = self.h2.wrapping_sub(old.wrapping_mul(7)).wrapping_add(self.h1);
        self.h3 = self.h3.wrapping_shl(5).wrapping_add(b) ^ self.h3;
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// Base64 character lookup for SSDeep
fn b64_char(idx: usize) -> u8 {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    B64[idx.min(63)]
}

/// Compare two SSDeep hashes and return similarity (0-100)
pub fn ssdeep_compare(hash1: &str, hash2: &str) -> Option<i32> {
    let parts1: Vec<&str> = hash1.split(':').collect();
    let parts2: Vec<&str> = hash2.split(':').collect();

    if parts1.len() != 3 || parts2.len() != 3 {
        return None;
    }

    let bs1: u32 = parts1[0].parse().ok()?;
    let bs2: u32 = parts2[0].parse().ok()?;

    // Block sizes must be compatible (same or double/half)
    if bs1 != bs2 && bs1 != bs2 * 2 && bs2 != bs1 * 2 {
        return Some(0);
    }

    // Compare the appropriate hash strings
    let score = if bs1 == bs2 {
        let s1 = edit_distance_score(parts1[1], parts2[1]);
        let s2 = edit_distance_score(parts1[2], parts2[2]);
        s1.max(s2)
    } else if bs1 == bs2 * 2 {
        edit_distance_score(parts1[1], parts2[2])
    } else {
        edit_distance_score(parts1[2], parts2[1])
    };

    Some(score)
}

/// Calculate similarity score based on edit distance
fn edit_distance_score(s1: &str, s2: &str) -> i32 {
    if s1.is_empty() || s2.is_empty() {
        return 0;
    }

    let len1 = s1.len();
    let len2 = s2.len();

    // Simple Levenshtein distance
    let mut matrix = vec![vec![0usize; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    let s1_bytes: Vec<u8> = s1.bytes().collect();
    let s2_bytes: Vec<u8> = s2.bytes().collect();

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_bytes[i - 1] == s2_bytes[j - 1] { 0 } else { 1 };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    let distance = matrix[len1][len2];
    let max_len = len1.max(len2);

    // Convert to similarity score (0-100)
    ((max_len - distance) * 100 / max_len) as i32
}

// ==========================================================================
// TLSH (Trend Micro Locality Sensitive Hash) Implementation
// ==========================================================================

/// TLSH constants
const TLSH_BUCKETS: usize = 256;
const TLSH_CODE_SIZE: usize = 32;
const TLSH_WINDOW_SIZE: usize = 5;
const TLSH_MIN_DATA_LENGTH: usize = 50;

/// Compute TLSH fuzzy hash
pub fn compute_tlsh(data: &[u8]) -> Option<String> {
    if data.len() < TLSH_MIN_DATA_LENGTH {
        return None;
    }

    // Step 1: Populate bucket counts using sliding window
    let mut buckets = [0u32; TLSH_BUCKETS];
    let mut checksum: u8 = 0;

    // Sliding window of 5 bytes
    for window in data.windows(TLSH_WINDOW_SIZE) {
        // Update checksum
        checksum = pearson_hash(checksum, window[0]);

        // Generate triplets and update buckets
        for i in 0..3 {
            for j in (i + 1)..4 {
                for k in (j + 1)..5 {
                    let bucket = tlsh_bucket(window[i], window[j], window[k], window[0]);
                    buckets[bucket as usize] += 1;
                }
            }
        }
    }

    // Step 2: Calculate quartile boundaries
    let total: u32 = buckets.iter().sum();
    let mut sorted: Vec<u32> = buckets.to_vec();
    sorted.sort_unstable();

    let q1 = tlsh_quartile(&sorted, 25);
    let q2 = tlsh_quartile(&sorted, 50);
    let q3 = tlsh_quartile(&sorted, 75);

    // Step 3: Generate body from bucket quartiles
    let mut body = [0u8; TLSH_CODE_SIZE];
    for i in 0..TLSH_BUCKETS {
        let bucket_val = buckets[i];
        let code = if bucket_val <= q1 {
            0
        } else if bucket_val <= q2 {
            1
        } else if bucket_val <= q3 {
            2
        } else {
            3
        };
        let byte_idx = i / 4;
        let bit_offset = (i % 4) * 2;
        body[byte_idx] |= code << bit_offset;
    }

    // Step 4: Calculate length and checksum components
    let log_len = tlsh_log_length(data.len());
    let q_ratios = tlsh_q_ratios(q1, q2, q3);

    // Step 5: Format as hex string
    let mut result = String::with_capacity(72);
    result.push_str(&format!("{:02X}", checksum));
    result.push_str(&format!("{:02X}", log_len));
    result.push_str(&format!("{:02X}", q_ratios));
    for &b in &body {
        result.push_str(&format!("{:02X}", b));
    }

    Some(result)
}

/// Pearson hash for TLSH checksum
fn pearson_hash(h: u8, c: u8) -> u8 {
    const PEARSON_TABLE: [u8; 256] = [
        98, 6, 85, 150, 36, 23, 112, 164, 135, 207, 169, 5, 26, 64, 165, 219,
        61, 20, 68, 89, 130, 63, 52, 102, 24, 229, 132, 245, 80, 216, 195, 115,
        90, 168, 156, 203, 177, 120, 2, 190, 188, 7, 100, 185, 174, 243, 162, 10,
        237, 18, 253, 225, 8, 208, 172, 244, 255, 126, 101, 79, 145, 235, 228, 121,
        123, 251, 67, 250, 161, 0, 107, 97, 241, 111, 181, 82, 249, 33, 69, 55,
        59, 153, 29, 9, 213, 167, 84, 93, 30, 46, 94, 75, 151, 114, 73, 222,
        197, 96, 210, 45, 16, 227, 248, 202, 51, 152, 252, 125, 81, 206, 215, 186,
        39, 158, 178, 187, 131, 136, 1, 49, 50, 17, 141, 91, 47, 129, 60, 99,
        154, 35, 86, 171, 105, 34, 38, 200, 147, 58, 77, 118, 173, 246, 76, 254,
        133, 232, 196, 144, 198, 124, 53, 4, 108, 74, 223, 234, 134, 230, 157, 139,
        189, 205, 199, 128, 176, 19, 211, 236, 127, 192, 231, 70, 233, 88, 146, 44,
        183, 201, 22, 83, 13, 214, 116, 109, 159, 32, 95, 226, 140, 220, 57, 12,
        221, 31, 209, 182, 143, 92, 149, 184, 148, 62, 113, 65, 37, 27, 106, 166,
        3, 14, 204, 72, 21, 41, 56, 66, 28, 193, 40, 217, 25, 54, 179, 117,
        238, 87, 240, 155, 180, 170, 242, 212, 191, 163, 78, 218, 137, 194, 175, 110,
        43, 119, 224, 71, 122, 142, 42, 160, 104, 48, 247, 103, 15, 11, 138, 239,
    ];
    PEARSON_TABLE[(h ^ c) as usize]
}

/// Calculate bucket index for TLSH
fn tlsh_bucket(a: u8, b: u8, c: u8, d: u8) -> u8 {
    // Simple hash combining the bytes
    let mut h: u32 = 0;
    h = h.wrapping_add(a as u32).wrapping_mul(3);
    h = h.wrapping_add(b as u32).wrapping_mul(5);
    h = h.wrapping_add(c as u32).wrapping_mul(7);
    h = h.wrapping_add(d as u32).wrapping_mul(11);
    (h % TLSH_BUCKETS as u32) as u8
}

/// Calculate quartile value
fn tlsh_quartile(sorted: &[u32], percentile: usize) -> u32 {
    let idx = (sorted.len() * percentile / 100).min(sorted.len() - 1);
    sorted[idx]
}

/// Encode length for TLSH
fn tlsh_log_length(len: usize) -> u8 {
    if len == 0 {
        return 0;
    }
    let log = (len as f64).log2().floor() as u8;
    log.min(255)
}

/// Encode quartile ratios for TLSH
fn tlsh_q_ratios(q1: u32, q2: u32, q3: u32) -> u8 {
    // Encode ratios as 4 bits each
    let r1 = if q2 > 0 { ((q1 * 16) / q2).min(15) } else { 0 } as u8;
    let r2 = if q3 > 0 { ((q2 * 16) / q3).min(15) } else { 0 } as u8;
    (r1 << 4) | r2
}

/// Compare two TLSH hashes and return distance (lower is more similar)
pub fn tlsh_compare(hash1: &str, hash2: &str) -> Option<i32> {
    if hash1.len() != hash2.len() || hash1.len() < 70 {
        return None;
    }

    let bytes1: Vec<u8> = (0..hash1.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hash1[i..i + 2], 16).ok())
        .collect();

    let bytes2: Vec<u8> = (0..hash2.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hash2[i..i + 2], 16).ok())
        .collect();

    if bytes1.len() != bytes2.len() {
        return None;
    }

    // Calculate Hamming distance on the body portion
    let mut distance = 0i32;
    for (b1, b2) in bytes1.iter().zip(bytes2.iter()) {
        distance += (b1 ^ b2).count_ones() as i32;
    }

    Some(distance)
}

/// Compute import hash (imphash) for PE files
/// This is the MD5 hash of the imported function names, useful for malware clustering
pub fn compute_imphash_from_pe(pe: &PE) -> Option<String> {
    let mut import_string = String::new();

    for import in &pe.imports {
        let dll_name = import.dll.to_lowercase();
        // Remove extension
        let dll_base = dll_name
            .strip_suffix(".dll")
            .or_else(|| dll_name.strip_suffix(".ocx"))
            .or_else(|| dll_name.strip_suffix(".sys"))
            .unwrap_or(&dll_name);

        let func_name = import.name.to_string();
        if !func_name.is_empty() {
            if !import_string.is_empty() {
                import_string.push(',');
            }
            import_string.push_str(dll_base);
            import_string.push('.');
            import_string.push_str(&func_name.to_lowercase());
        }
    }

    if import_string.is_empty() {
        return None;
    }

    let mut hasher = Md5::new();
    hasher.update(import_string.as_bytes());
    Some(hex::encode(hasher.finalize()))
}

/// Compute imphash from raw binary data
pub fn compute_imphash(data: &[u8]) -> Option<String> {
    PE::parse(data).ok().and_then(|pe| compute_imphash_from_pe(&pe))
}

/// Hash a file in chunks for large files
pub fn compute_hashes_streaming(data: &[u8]) -> BinaryHashes {
    const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks

    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    for chunk in data.chunks(CHUNK_SIZE) {
        md5_hasher.update(chunk);
        sha1_hasher.update(chunk);
        sha256_hasher.update(chunk);
    }

    BinaryHashes {
        md5: hex::encode(md5_hasher.finalize()),
        sha1: hex::encode(sha1_hasher.finalize()),
        sha256: hex::encode(sha256_hasher.finalize()),
        ssdeep: None,
        imphash: None,
        tlsh: None,
    }
}

/// Compute a quick hash for deduplication
pub fn compute_quick_hash(data: &[u8]) -> String {
    // Use first and last 4KB + file size for quick comparison
    let mut hasher = Sha256::new();

    // Add file size
    hasher.update(data.len().to_le_bytes());

    // Add first 4KB
    let first_chunk = &data[..data.len().min(4096)];
    hasher.update(first_chunk);

    // Add last 4KB if file is large enough
    if data.len() > 8192 {
        let last_chunk = &data[data.len() - 4096..];
        hasher.update(last_chunk);
    }

    hex::encode(hasher.finalize())
}

/// Compare two files by hash
pub fn files_match(data1: &[u8], data2: &[u8]) -> bool {
    if data1.len() != data2.len() {
        return false;
    }
    compute_sha256(data1) == compute_sha256(data2)
}

/// Compute section hashes for PE files
pub fn compute_section_hashes(data: &[u8]) -> Vec<SectionHash> {
    let Ok(pe) = PE::parse(data) else {
        return Vec::new();
    };

    pe.sections.iter().filter_map(|section| {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();

        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = (start + size).min(data.len());

        if start >= data.len() {
            return None;
        }

        let section_data = &data[start..end];
        let hash = compute_sha256(section_data);

        Some(SectionHash {
            name,
            offset: start as u64,
            size: size as u64,
            sha256: hash,
        })
    }).collect()
}

/// Section hash information
#[derive(Debug, Clone)]
pub struct SectionHash {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
}

/// Verify hash against expected value
pub fn verify_hash(data: &[u8], expected: &str, hash_type: HashType) -> bool {
    let computed = match hash_type {
        HashType::Md5 => compute_md5(data),
        HashType::Sha1 => compute_sha1(data),
        HashType::Sha256 => compute_sha256(data),
    };
    computed.to_lowercase() == expected.to_lowercase()
}

/// Hash algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
}

impl HashType {
    /// Parse hash type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "md5" => Some(HashType::Md5),
            "sha1" | "sha-1" => Some(HashType::Sha1),
            "sha256" | "sha-256" => Some(HashType::Sha256),
            _ => None,
        }
    }

    /// Detect hash type from hash length
    pub fn from_hash_length(len: usize) -> Option<Self> {
        match len {
            32 => Some(HashType::Md5),
            40 => Some(HashType::Sha1),
            64 => Some(HashType::Sha256),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let data = b"Hello, World!";
        let hash = compute_md5(data);
        assert_eq!(hash, "65a8e27d8879283831b664bd8b7f0ad4");
    }

    #[test]
    fn test_sha1() {
        let data = b"Hello, World!";
        let hash = compute_sha1(data);
        assert_eq!(hash, "0a0a9f2a6772942557ab5355d76af442f8f65e01");
    }

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = compute_sha256(data);
        assert_eq!(hash, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    }

    #[test]
    fn test_hash_type_detection() {
        assert_eq!(HashType::from_hash_length(32), Some(HashType::Md5));
        assert_eq!(HashType::from_hash_length(40), Some(HashType::Sha1));
        assert_eq!(HashType::from_hash_length(64), Some(HashType::Sha256));
        assert_eq!(HashType::from_hash_length(128), None);
    }

    #[test]
    fn test_verify_hash() {
        let data = b"test data";
        let expected_md5 = compute_md5(data);
        assert!(verify_hash(data, &expected_md5, HashType::Md5));
        assert!(!verify_hash(data, "wrong_hash", HashType::Md5));
    }
}
