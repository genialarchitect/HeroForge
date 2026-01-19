//! String Extraction Module
//!
//! Extracts strings from binary files with encoding detection and
//! categorization of interesting strings (URLs, IPs, paths, etc.)

use super::types::*;
use regex::Regex;
use once_cell::sync::Lazy;

/// Minimum default string length
pub const DEFAULT_MIN_LENGTH: usize = 4;

/// Maximum strings to extract by default
pub const DEFAULT_MAX_STRINGS: usize = 10000;

// Precompiled regex patterns for string categorization
static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^https?://[^\s]+$").unwrap()
});

static IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap()
});

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

static WINDOWS_PATH_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z]:\\").unwrap()
});

static UNIX_PATH_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^/[a-zA-Z0-9_./\-]+$").unwrap()
});

static REGISTRY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(HKEY_|HKLM|HKCU|HKU|HKCR|HKCC)").unwrap()
});

/// Extract all strings from binary data
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    // Extract ASCII strings
    strings.extend(extract_ascii_strings(data, min_length));

    // Extract UTF-16LE strings (common in Windows binaries)
    strings.extend(extract_utf16_strings(data, min_length, false));

    // Extract UTF-16BE strings (less common)
    strings.extend(extract_utf16_strings(data, min_length, true));

    // Sort by offset for consistent output
    strings.sort_by_key(|s| s.offset);

    // Deduplicate by value (keep first occurrence)
    let mut seen = std::collections::HashSet::new();
    strings.retain(|s| seen.insert(s.value.clone()));

    strings
}

/// Extract ASCII/UTF-8 strings
fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= min_length {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    let string_type = categorize_string(&s);
                    let is_interesting = string_type != StringType::Generic;

                    strings.push(ExtractedString {
                        value: s,
                        encoding: StringEncoding::Ascii,
                        offset: start_offset as u64,
                        section: None, // Would need section mapping
                        string_type,
                        is_interesting,
                    });
                }
            }
            current_string.clear();
        }
    }

    // Don't forget the last string
    if current_string.len() >= min_length {
        if let Ok(s) = String::from_utf8(current_string) {
            let string_type = categorize_string(&s);
            let is_interesting = string_type != StringType::Generic;

            strings.push(ExtractedString {
                value: s,
                encoding: StringEncoding::Ascii,
                offset: start_offset as u64,
                section: None,
                string_type,
                is_interesting,
            });
        }
    }

    strings
}

/// Extract UTF-16 strings (LE or BE)
fn extract_utf16_strings(data: &[u8], min_length: usize, big_endian: bool) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut current_chars = Vec::new();
    let mut start_offset = 0;

    let mut i = 0;
    while i + 1 < data.len() {
        let word = if big_endian {
            u16::from_be_bytes([data[i], data[i + 1]])
        } else {
            u16::from_le_bytes([data[i], data[i + 1]])
        };

        // Check if it's a printable character
        if is_printable_unicode(word) {
            if current_chars.is_empty() {
                start_offset = i;
            }
            current_chars.push(word);
        } else {
            if current_chars.len() >= min_length {
                if let Some(s) = decode_utf16(&current_chars) {
                    // Skip if it looks like ASCII (avoid duplicates)
                    if !s.chars().all(|c| c.is_ascii()) || s.len() > 4 {
                        let string_type = categorize_string(&s);
                        let is_interesting = string_type != StringType::Generic;

                        strings.push(ExtractedString {
                            value: s,
                            encoding: if big_endian {
                                StringEncoding::Utf16Be
                            } else {
                                StringEncoding::Utf16Le
                            },
                            offset: start_offset as u64,
                            section: None,
                            string_type,
                            is_interesting,
                        });
                    }
                }
            }
            current_chars.clear();
        }
        i += 2;
    }

    // Don't forget the last string
    if current_chars.len() >= min_length {
        if let Some(s) = decode_utf16(&current_chars) {
            if !s.chars().all(|c| c.is_ascii()) || s.len() > 4 {
                let string_type = categorize_string(&s);
                let is_interesting = string_type != StringType::Generic;

                strings.push(ExtractedString {
                    value: s,
                    encoding: if big_endian {
                        StringEncoding::Utf16Be
                    } else {
                        StringEncoding::Utf16Le
                    },
                    offset: start_offset as u64,
                    section: None,
                    string_type,
                    is_interesting,
                });
            }
        }
    }

    strings
}

/// Check if a byte is printable ASCII
fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

/// Check if a Unicode code point is printable
fn is_printable_unicode(cp: u16) -> bool {
    // Basic Latin (ASCII) + Latin Extended + some common ranges
    matches!(cp, 0x0020..=0x007E | 0x00A0..=0x00FF | 0x0100..=0x017F |
             0x0180..=0x024F | 0x0370..=0x03FF | 0x0400..=0x04FF |
             0x2000..=0x206F | 0x3000..=0x303F | 0x4E00..=0x9FFF)
}

/// Decode UTF-16 code units to a String
fn decode_utf16(chars: &[u16]) -> Option<String> {
    String::from_utf16(chars).ok()
}

/// Categorize a string based on its content
pub fn categorize_string(s: &str) -> StringType {
    let s_lower = s.to_lowercase();

    // Check URL
    if URL_REGEX.is_match(s) {
        return StringType::Url;
    }

    // Check IP address
    if IP_REGEX.is_match(s) {
        return StringType::Ip;
    }

    // Check email
    if EMAIL_REGEX.is_match(s) {
        return StringType::Email;
    }

    // Check file paths
    if WINDOWS_PATH_REGEX.is_match(s) || UNIX_PATH_REGEX.is_match(s) {
        return StringType::FilePath;
    }

    // Check registry keys
    if REGISTRY_REGEX.is_match(s) {
        return StringType::RegistryKey;
    }

    // Check for command-related strings
    if is_command_string(&s_lower) {
        return StringType::Command;
    }

    // Check for crypto-related strings
    if is_crypto_string(&s_lower) {
        return StringType::Crypto;
    }

    // Check for network-related strings
    if is_network_string(&s_lower) {
        return StringType::Network;
    }

    // Check for debug strings
    if is_debug_string(&s_lower) {
        return StringType::Debug;
    }

    // Check for other interesting patterns
    if is_interesting_string(s) {
        return StringType::Interesting;
    }

    StringType::Generic
}

/// Check if string looks like a command
fn is_command_string(s: &str) -> bool {
    let command_indicators = [
        "cmd.exe", "powershell", "bash", "sh -c", "/bin/",
        "exec", "system(", "popen", "subprocess", "shell",
        "wget ", "curl ", "net user", "net localgroup",
        "reg add", "reg delete", "schtasks", "wmic",
        "netsh", "sc create", "sc start", "sc stop",
    ];

    command_indicators.iter().any(|cmd| s.contains(cmd))
}

/// Check if string is crypto-related
fn is_crypto_string(s: &str) -> bool {
    let crypto_indicators = [
        "aes", "des", "rsa", "sha1", "sha256", "md5",
        "encrypt", "decrypt", "cipher", "crypto",
        "public key", "private key", "certificate",
        "pkcs", "openssl", "bcrypt", "scrypt",
        "-----begin", "-----end", "base64",
    ];

    crypto_indicators.iter().any(|c| s.contains(c))
}

/// Check if string is network-related
fn is_network_string(s: &str) -> bool {
    let network_indicators = [
        "socket", "connect", "send", "recv", "listen",
        "bind", "accept", "http", "https", "ftp",
        "smtp", "imap", "pop3", "dns", "tcp", "udp",
        "port ", "proxy", "tunnel", "vpn", "ssl",
        "tls", "user-agent", "cookie", "header",
    ];

    network_indicators.iter().any(|n| s.contains(n))
}

/// Check if string is debug-related
fn is_debug_string(s: &str) -> bool {
    let debug_indicators = [
        "error", "warning", "debug", "fatal", "exception",
        "failed", "success", "assert", "panic", "crash",
        "trace", "log", "info", "verbose", "[-]", "[+]",
        "[*]", "[!]", "stack trace", "backtrace",
    ];

    debug_indicators.iter().any(|d| s.contains(d))
}

/// Check for other interesting patterns
fn is_interesting_string(s: &str) -> bool {
    // Very long strings might be interesting (encoded data, configs)
    if s.len() > 100 {
        return true;
    }

    // Strings with unusual character patterns
    let lower = s.to_lowercase();

    let interesting_patterns = [
        "password", "passwd", "secret", "credential", "token",
        "api_key", "apikey", "auth", "login", "admin",
        "root", "backdoor", "trojan", "malware", "payload",
        "inject", "exploit", "shellcode", "obfuscate",
        "mutex", "pipe\\", "\\device\\", "\\registry\\",
        "ntdll", "kernel32", "advapi32", "ws2_32",
        "virtualalloc", "createprocess", "writeprocessmemory",
        "loadlibrary", "getprocaddress", "createremotethread",
    ];

    interesting_patterns.iter().any(|p| lower.contains(p))
}

/// Extract only interesting strings (URLs, IPs, commands, etc.)
pub fn extract_interesting_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    extract_strings(data, min_length)
        .into_iter()
        .filter(|s| s.is_interesting)
        .collect()
}

/// Get string statistics
pub fn get_string_stats(strings: &[ExtractedString]) -> StringStats {
    let mut url_count = 0;
    let mut ip_count = 0;
    let mut email_count = 0;
    let mut path_count = 0;
    let mut registry_count = 0;
    let mut command_count = 0;
    let mut crypto_count = 0;
    let mut network_count = 0;
    let mut debug_count = 0;
    let mut interesting_count = 0;

    for s in strings {
        match s.string_type {
            StringType::Url => url_count += 1,
            StringType::Ip => ip_count += 1,
            StringType::Email => email_count += 1,
            StringType::FilePath => path_count += 1,
            StringType::RegistryKey => registry_count += 1,
            StringType::Command => command_count += 1,
            StringType::Crypto => crypto_count += 1,
            StringType::Network => network_count += 1,
            StringType::Debug => debug_count += 1,
            StringType::Interesting => interesting_count += 1,
            StringType::Generic => {}
        }
    }

    StringStats {
        total: strings.len(),
        url_count,
        ip_count,
        email_count,
        path_count,
        registry_count,
        command_count,
        crypto_count,
        network_count,
        debug_count,
        interesting_count,
    }
}

/// String statistics
#[derive(Debug, Clone, Default)]
pub struct StringStats {
    pub total: usize,
    pub url_count: usize,
    pub ip_count: usize,
    pub email_count: usize,
    pub path_count: usize,
    pub registry_count: usize,
    pub command_count: usize,
    pub crypto_count: usize,
    pub network_count: usize,
    pub debug_count: usize,
    pub interesting_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_string() {
        let data = b"Hello\x00World\x00Test";
        // extract_strings extracts ASCII and UTF-16 strings, then deduplicates
        // We only test that ASCII extraction works correctly
        // With min_length=4, all three strings (Hello, World, Test) meet the requirement
        let strings = extract_ascii_strings(data, 4);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
        assert_eq!(strings[2].value, "Test");
    }

    #[test]
    fn test_categorize_url() {
        assert_eq!(categorize_string("http://example.com"), StringType::Url);
        assert_eq!(categorize_string("https://malware.com/payload"), StringType::Url);
    }

    #[test]
    fn test_categorize_ip() {
        assert_eq!(categorize_string("192.168.1.1"), StringType::Ip);
        assert_eq!(categorize_string("10.0.0.1"), StringType::Ip);
    }

    #[test]
    fn test_categorize_path() {
        assert_eq!(categorize_string("C:\\Windows\\System32"), StringType::FilePath);
        assert_eq!(categorize_string("/etc/passwd"), StringType::FilePath);
    }

    #[test]
    fn test_categorize_registry() {
        assert_eq!(categorize_string("HKEY_LOCAL_MACHINE\\SOFTWARE"), StringType::RegistryKey);
        assert_eq!(categorize_string("HKLM\\SYSTEM"), StringType::RegistryKey);
    }
}
