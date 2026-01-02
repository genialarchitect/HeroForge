//! Browser artifact extraction from memory
//!
//! Extract browser history, cookies, and other artifacts from memory dumps.

use anyhow::Result;

use super::{BrowserArtifact, BrowserArtifactType};
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::ProcessInfo;

/// Extract all browser data from memory
pub fn extract_browser_data(
    dump: &ParsedDump,
    processes: &[ProcessInfo],
) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // Extract from browser processes
    for process in processes {
        let name_lower = process.name.to_lowercase();

        if name_lower.contains("chrome") || name_lower.contains("msedge") {
            let chromium = extract_chromium_artifacts(dump, process)?;
            artifacts.extend(chromium);
        }

        if name_lower.contains("firefox") {
            let firefox = extract_firefox_artifacts(dump, process)?;
            artifacts.extend(firefox);
        }

        if name_lower.contains("iexplore") || name_lower.contains("edge") && !name_lower.contains("msedge") {
            let ie = extract_ie_artifacts(dump, process)?;
            artifacts.extend(ie);
        }
    }

    // Generic URL extraction
    let urls = extract_urls_from_memory(dump)?;
    artifacts.extend(urls);

    Ok(artifacts)
}

/// Extract artifacts from Chromium-based browsers
fn extract_chromium_artifacts(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // Chromium stores browsing data in memory during sessions
    // Look for URL patterns

    // HTTP/HTTPS URL pattern
    let url_patterns: &[&[u8]] = &[
        b"https://",
        b"http://",
    ];

    for pattern in url_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(1000) {
            if let Some(data) = dump.read_bytes(offset, 2048) {
                // Extract the URL
                let end = data.iter()
                    .position(|&b| b == 0 || b == b'"' || b == b'\'' || b == b' ' || b == b'\n')
                    .unwrap_or(2048);

                let url = String::from_utf8_lossy(&data[..end]);

                // Validate URL
                if is_valid_url(&url) {
                    artifacts.push(BrowserArtifact {
                        browser: process.name.clone(),
                        artifact_type: BrowserArtifactType::History,
                        url: Some(url.to_string()),
                        title: None,
                        username: None,
                        password: None,
                        data: None,
                    });
                }
            }
        }
    }

    // Look for cookie data
    let cookie_patterns: &[&[u8]] = &[
        b"Set-Cookie:",
        b"Cookie:",
        b"cookie=",
    ];

    for pattern in cookie_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(100) {
            if let Some(data) = dump.read_bytes(offset, 512) {
                let end = data.iter()
                    .position(|&b| b == 0 || b == b'\n' || b == b'\r')
                    .unwrap_or(512);

                let cookie = String::from_utf8_lossy(&data[..end]);

                artifacts.push(BrowserArtifact {
                    browser: process.name.clone(),
                    artifact_type: BrowserArtifactType::Cookie,
                    url: None,
                    title: None,
                    username: None,
                    password: None,
                    data: Some(cookie.to_string()),
                });
            }
        }
    }

    // Deduplicate URLs
    artifacts.sort_by(|a, b| a.url.cmp(&b.url));
    artifacts.dedup_by(|a, b| a.url == b.url && a.artifact_type == b.artifact_type);

    Ok(artifacts)
}

/// Extract artifacts from Firefox
fn extract_firefox_artifacts(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // Firefox stores places.sqlite in memory
    // Look for SQLite database patterns

    // SQLite header
    let sqlite_header = b"SQLite format 3";
    let matches = dump.search_pattern(sqlite_header);

    for &offset in matches.iter().take(10) {
        artifacts.push(BrowserArtifact {
            browser: process.name.clone(),
            artifact_type: BrowserArtifactType::History,
            url: None,
            title: None,
            username: None,
            password: None,
            data: Some(format!("SQLite database at offset {:#x}", offset)),
        });
    }

    // Look for moz_places URL patterns
    let moz_patterns: &[&[u8]] = &[
        b"moz_places",
        b"moz_historyvisits",
        b"moz_cookies",
    ];

    for pattern in moz_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(20) {
            artifacts.push(BrowserArtifact {
                browser: "Firefox".to_string(),
                artifact_type: BrowserArtifactType::History,
                url: None,
                title: None,
                username: None,
                password: None,
                data: Some(format!("Firefox DB table reference at {:#x}", offset)),
            });
        }
    }

    Ok(artifacts)
}

/// Extract artifacts from Internet Explorer / Legacy Edge
fn extract_ie_artifacts(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // IE uses WebCacheV01.dat and History folders
    // Look for specific patterns

    let ie_patterns: &[&[u8]] = &[
        b"Visited:",        // IE history prefix
        b"Cookie:",         // IE cookie entry
        b"ieHTTP",          // IE HTTP marker
        b"MSHISTORY",       // MS History marker
    ];

    for pattern in ie_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(50) {
            if let Some(data) = dump.read_bytes(offset, 512) {
                let text = String::from_utf8_lossy(&data[..256.min(data.len())]);

                artifacts.push(BrowserArtifact {
                    browser: process.name.clone(),
                    artifact_type: BrowserArtifactType::History,
                    url: None,
                    title: None,
                    username: None,
                    password: None,
                    data: Some(text.to_string()),
                });
            }
        }
    }

    Ok(artifacts)
}

/// Extract URLs from memory generically
fn extract_urls_from_memory(dump: &ParsedDump) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // Common URL patterns in memory
    let patterns = [
        (b"https://".as_slice(), "HTTPS"),
        (b"http://".as_slice(), "HTTP"),
        (b"ftp://".as_slice(), "FTP"),
        (b"file:///".as_slice(), "File"),
    ];

    for (pattern, proto) in &patterns {
        let matches = dump.search_pattern(*pattern);

        for &offset in matches.iter().take(500) {
            if let Some(data) = dump.read_bytes(offset, 1024) {
                // Find URL end
                let end = data.iter()
                    .position(|&b| {
                        b == 0 || b == b'"' || b == b'\'' || b == b' ' ||
                        b == b'\n' || b == b'\r' || b == b'>' || b == b'<'
                    })
                    .unwrap_or(1024);

                let url = String::from_utf8_lossy(&data[..end]);

                if is_valid_url(&url) && url.len() < 500 {
                    artifacts.push(BrowserArtifact {
                        browser: "Unknown".to_string(),
                        artifact_type: BrowserArtifactType::History,
                        url: Some(url.to_string()),
                        title: None,
                        username: None,
                        password: None,
                        data: Some(proto.to_string()),
                    });
                }
            }
        }
    }

    // Deduplicate
    artifacts.sort_by(|a, b| a.url.cmp(&b.url));
    artifacts.dedup_by(|a, b| a.url == b.url);

    Ok(artifacts)
}

/// Validate if a string looks like a valid URL
fn is_valid_url(url: &str) -> bool {
    if url.len() < 10 || url.len() > 2000 {
        return false;
    }

    // Must start with protocol
    if !url.starts_with("http://") && !url.starts_with("https://") &&
       !url.starts_with("ftp://") && !url.starts_with("file:///") {
        return false;
    }

    // Must have a domain-like structure
    let after_protocol = if url.starts_with("https://") {
        &url[8..]
    } else if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("file:///") {
        return true; // File URLs don't need domain validation
    } else {
        &url[6..]
    };

    // Check for domain
    let domain_end = after_protocol.find('/').unwrap_or(after_protocol.len());
    let domain = &after_protocol[..domain_end];

    // Domain should have at least one dot (except localhost)
    if !domain.contains('.') && !domain.starts_with("localhost") {
        return false;
    }

    // Domain should be printable
    if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':') {
        return false;
    }

    true
}

/// Extract download references
pub fn extract_downloads(dump: &ParsedDump) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // Common download patterns
    let patterns: &[&[u8]] = &[
        b"Content-Disposition:",
        b"filename=",
        b"attachment;",
        b"download=",
    ];

    for pattern in patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(100) {
            if let Some(data) = dump.read_bytes(offset, 256) {
                let text = String::from_utf8_lossy(&data);

                // Extract filename
                let filename = if let Some(pos) = text.find("filename=") {
                    let start = pos + 9;
                    let name_data = &text[start..];
                    let end = name_data.find(|c: char| c == '"' || c == '\'' || c == ';' || c == '\n')
                        .unwrap_or(name_data.len().min(100));
                    Some(name_data[..end].trim_matches('"').to_string())
                } else {
                    None
                };

                if let Some(fname) = filename {
                    artifacts.push(BrowserArtifact {
                        browser: "Unknown".to_string(),
                        artifact_type: BrowserArtifactType::Download,
                        url: None,
                        title: Some(fname),
                        username: None,
                        password: None,
                        data: None,
                    });
                }
            }
        }
    }

    Ok(artifacts)
}

/// Extract session/authentication tokens
pub fn extract_session_tokens(dump: &ParsedDump) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    // Session token patterns
    let patterns = [
        (b"session_id=".as_slice(), "Session ID"),
        (b"PHPSESSID=".as_slice(), "PHP Session"),
        (b"JSESSIONID=".as_slice(), "Java Session"),
        (b"ASP.NET_SessionId=".as_slice(), "ASP.NET Session"),
        (b"_ga=".as_slice(), "Google Analytics"),
        (b"csrf_token=".as_slice(), "CSRF Token"),
        (b"access_token=".as_slice(), "Access Token"),
    ];

    for (pattern, token_type) in &patterns {
        let matches = dump.search_pattern(*pattern);

        for &offset in matches.iter().take(100) {
            if let Some(data) = dump.read_bytes(offset, 256) {
                let start = pattern.len();
                let end = data[start..].iter()
                    .position(|&b| b == 0 || b == b';' || b == b'&' || b == b'\n')
                    .unwrap_or(data.len() - start);

                let token = String::from_utf8_lossy(&data[start..start + end]);

                if token.len() >= 8 && token.len() <= 256 {
                    artifacts.push(BrowserArtifact {
                        browser: "Unknown".to_string(),
                        artifact_type: BrowserArtifactType::Session,
                        url: None,
                        title: Some(token_type.to_string()),
                        username: None,
                        password: None,
                        data: Some(token.to_string()),
                    });
                }
            }
        }
    }

    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_validation() {
        assert!(is_valid_url("https://example.com"));
        assert!(is_valid_url("https://example.com/path/to/page"));
        assert!(is_valid_url("http://localhost:8080/api"));
        assert!(!is_valid_url("not a url"));
        assert!(!is_valid_url("ftp://"));
        assert!(!is_valid_url("https://")); // Too short after protocol
    }
}
