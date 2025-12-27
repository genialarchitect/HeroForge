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

    BinaryHashes {
        md5,
        sha1,
        sha256,
        ssdeep: None, // SSDeep requires external library
        imphash,
        tlsh: None,   // TLSH requires external library
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
