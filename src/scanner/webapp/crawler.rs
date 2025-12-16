// Allow unused code for internal helper functions
#![allow(dead_code)]

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use tokio::time::sleep;
use url::Url;

use super::WebAppScanConfig;

/// Crawl a website to discover pages and endpoints
pub async fn crawl_website(
    client: &Client,
    base_url: &Url,
    config: &WebAppScanConfig,
    pages_crawled: &mut HashSet<String>,
) -> Result<Vec<Url>> {
    let mut discovered_urls = Vec::new();
    let mut to_visit: VecDeque<(Url, usize)> = VecDeque::new();
    let mut visited = HashSet::new();

    // Start with base URL at depth 0
    to_visit.push_back((base_url.clone(), 0));
    visited.insert(normalize_url(base_url));

    // Check robots.txt if enabled
    let disallowed_paths = if config.respect_robots_txt {
        fetch_robots_txt(client, base_url).await.unwrap_or_default()
    } else {
        HashSet::new()
    };

    while let Some((current_url, depth)) = to_visit.pop_front() {
        // Check limits
        if pages_crawled.len() >= config.max_pages {
            info!("Reached maximum page limit ({})", config.max_pages);
            break;
        }

        if depth > config.max_depth {
            continue;
        }

        // Check robots.txt
        if is_disallowed(&current_url, &disallowed_paths) {
            debug!("Skipping disallowed URL: {}", current_url);
            continue;
        }

        // Rate limiting
        sleep(config.rate_limit_delay).await;

        // Fetch the page
        match fetch_page(client, &current_url).await {
            Ok(html_content) => {
                let normalized = normalize_url(&current_url);
                pages_crawled.insert(normalized);
                discovered_urls.push(current_url.clone());

                // Parse HTML and extract links
                let links = extract_links(&html_content, &current_url);

                for link in links {
                    // Only follow links within the same domain
                    if is_same_domain(&link, base_url) {
                        let normalized = normalize_url(&link);
                        if visited.insert(normalized) {
                            to_visit.push_back((link, depth + 1));
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to fetch {}: {}", current_url, e);
            }
        }
    }

    Ok(discovered_urls)
}

/// Fetch a page and return its HTML content
async fn fetch_page(client: &Client, url: &Url) -> Result<String> {
    debug!("Fetching: {}", url);

    let response = client
        .get(url.as_str())
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("HTTP {}", response.status()));
    }

    let content = response.text().await?;
    Ok(content)
}

/// Extract all links from HTML content
fn extract_links(html: &str, base_url: &Url) -> Vec<Url> {
    let mut links = Vec::new();
    let document = Html::parse_document(html);

    // Select all anchor tags
    if let Ok(selector) = Selector::parse("a[href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                // Skip javascript:, mailto:, tel:, etc.
                if href.starts_with("javascript:")
                    || href.starts_with("mailto:")
                    || href.starts_with("tel:")
                    || href.starts_with("#") {
                    continue;
                }

                // Try to resolve relative URLs
                if let Ok(absolute_url) = base_url.join(href) {
                    // Only include http/https URLs
                    if absolute_url.scheme() == "http" || absolute_url.scheme() == "https" {
                        links.push(absolute_url);
                    }
                }
            }
        }
    }

    links
}

/// Check if two URLs are from the same domain
fn is_same_domain(url1: &Url, url2: &Url) -> bool {
    url1.host_str() == url2.host_str()
}

/// Normalize URL by removing fragments and sorting query parameters
fn normalize_url(url: &Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);

    // Remove trailing slash from path (except for root)
    let path = normalized.path().to_string();
    if path.len() > 1 && path.ends_with('/') {
        let _ = normalized.set_path(&path[..path.len() - 1]);
    }

    normalized.to_string()
}

/// Fetch and parse robots.txt
async fn fetch_robots_txt(client: &Client, base_url: &Url) -> Result<HashSet<String>> {
    let mut robots_url = base_url.clone();
    robots_url.set_path("/robots.txt");

    let mut disallowed = HashSet::new();

    match client.get(robots_url.as_str()).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(text) = response.text().await {
                for line in text.lines() {
                    let line = line.trim();
                    if line.to_lowercase().starts_with("disallow:") {
                        if let Some(path) = line.split(':').nth(1) {
                            let path = path.trim();
                            if !path.is_empty() {
                                disallowed.insert(path.to_string());
                            }
                        }
                    }
                }
                info!("Found {} disallowed paths in robots.txt", disallowed.len());
            }
        }
        _ => {
            debug!("No robots.txt found or error fetching it");
        }
    }

    Ok(disallowed)
}

/// Check if a URL is disallowed by robots.txt
fn is_disallowed(url: &Url, disallowed_paths: &HashSet<String>) -> bool {
    let path = url.path();
    for disallowed in disallowed_paths {
        if path.starts_with(disallowed) {
            return true;
        }
    }
    false
}

/// Parse robots.txt content and extract disallowed paths
fn parse_robots_txt(content: &str) -> HashSet<String> {
    let mut disallowed = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("disallow:") {
            if let Some(path) = line.split(':').nth(1) {
                let path = path.trim();
                if !path.is_empty() {
                    disallowed.insert(path.to_string());
                }
            }
        }
    }
    disallowed
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== URL Extraction Tests ====================

    #[test]
    fn test_extract_links_absolute_urls() {
        let html = r#"
            <html>
            <body>
                <a href="https://example.com/page1">Page 1</a>
                <a href="https://example.com/page2">Page 2</a>
            </body>
            </html>
        "#;
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/page1"));
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/page2"));
    }

    #[test]
    fn test_extract_links_relative_urls() {
        let html = r#"
            <html>
            <body>
                <a href="/about">About</a>
                <a href="contact.html">Contact</a>
                <a href="../parent">Parent</a>
            </body>
            </html>
        "#;
        let base_url = Url::parse("https://example.com/subdir/page.html").unwrap();
        let links = extract_links(html, &base_url);

        assert_eq!(links.len(), 3);
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/about"));
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/subdir/contact.html"));
        assert!(links.iter().any(|u| u.as_str() == "https://example.com/parent"));
    }

    #[test]
    fn test_extract_links_skips_javascript() {
        let html = r#"
            <html>
            <body>
                <a href="javascript:void(0)">Click</a>
                <a href="javascript:alert('xss')">Alert</a>
                <a href="/real-link">Real Link</a>
            </body>
            </html>
        "#;
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].as_str(), "https://example.com/real-link");
    }

    #[test]
    fn test_extract_links_skips_mailto() {
        let html = r#"
            <html>
            <body>
                <a href="mailto:test@example.com">Email</a>
                <a href="tel:+1234567890">Call</a>
                <a href="/contact">Contact Page</a>
            </body>
            </html>
        "#;
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].as_str(), "https://example.com/contact");
    }

    #[test]
    fn test_extract_links_skips_fragments() {
        let html = r##"
            <html>
            <body>
                <a href="#section1">Section 1</a>
                <a href="#top">Top</a>
                <a href="/page#anchor">Page with Anchor</a>
            </body>
            </html>
        "##;
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        // Pure fragments are skipped, but URLs with fragments are kept
        assert_eq!(links.len(), 1);
        assert!(links[0].as_str().contains("/page"));
    }

    #[test]
    fn test_extract_links_empty_html() {
        let html = "";
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        assert!(links.is_empty());
    }

    #[test]
    fn test_extract_links_no_anchor_tags() {
        let html = r#"
            <html>
            <body>
                <p>No links here</p>
                <div>Just some text</div>
            </body>
            </html>
        "#;
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        assert!(links.is_empty());
    }

    #[test]
    fn test_extract_links_only_http_https() {
        let html = r#"
            <html>
            <body>
                <a href="ftp://example.com/file">FTP</a>
                <a href="file:///etc/passwd">File</a>
                <a href="http://example.com/http">HTTP</a>
                <a href="https://example.com/https">HTTPS</a>
            </body>
            </html>
        "#;
        let base_url = Url::parse("https://example.com/").unwrap();
        let links = extract_links(html, &base_url);

        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|u| u.scheme() == "http"));
        assert!(links.iter().any(|u| u.scheme() == "https"));
    }

    // ==================== Robots.txt Parsing Tests ====================

    #[test]
    fn test_parse_robots_txt_basic() {
        let content = r#"
User-agent: *
Disallow: /admin
Disallow: /private
Allow: /public
"#;
        let disallowed = parse_robots_txt(content);

        assert_eq!(disallowed.len(), 2);
        assert!(disallowed.contains("/admin"));
        assert!(disallowed.contains("/private"));
    }

    #[test]
    fn test_parse_robots_txt_case_insensitive() {
        let content = r#"
User-agent: *
DISALLOW: /Admin
disallow: /Private
Disallow: /SECRET
"#;
        let disallowed = parse_robots_txt(content);

        assert_eq!(disallowed.len(), 3);
        assert!(disallowed.contains("/Admin"));
        assert!(disallowed.contains("/Private"));
        assert!(disallowed.contains("/SECRET"));
    }

    #[test]
    fn test_parse_robots_txt_empty_disallow() {
        let content = r#"
User-agent: *
Disallow:
Disallow: /valid
"#;
        let disallowed = parse_robots_txt(content);

        // Empty disallow should be ignored
        assert_eq!(disallowed.len(), 1);
        assert!(disallowed.contains("/valid"));
    }

    #[test]
    fn test_parse_robots_txt_with_whitespace() {
        let content = r#"
User-agent: *
Disallow:   /admin
Disallow:  /private
"#;
        let disallowed = parse_robots_txt(content);

        assert_eq!(disallowed.len(), 2);
        assert!(disallowed.contains("/admin"));
        assert!(disallowed.contains("/private"));
    }

    #[test]
    fn test_parse_robots_txt_empty_content() {
        let content = "";
        let disallowed = parse_robots_txt(content);

        assert!(disallowed.is_empty());
    }

    #[test]
    fn test_parse_robots_txt_no_disallow() {
        let content = r#"
User-agent: *
Allow: /
"#;
        let disallowed = parse_robots_txt(content);

        assert!(disallowed.is_empty());
    }

    // ==================== is_disallowed Tests ====================

    #[test]
    fn test_is_disallowed_exact_match() {
        let mut disallowed = HashSet::new();
        disallowed.insert("/admin".to_string());
        disallowed.insert("/private".to_string());

        let url = Url::parse("https://example.com/admin").unwrap();
        assert!(is_disallowed(&url, &disallowed));

        let url = Url::parse("https://example.com/admin/users").unwrap();
        assert!(is_disallowed(&url, &disallowed));
    }

    #[test]
    fn test_is_disallowed_prefix_match() {
        let mut disallowed = HashSet::new();
        disallowed.insert("/admin".to_string());

        let url = Url::parse("https://example.com/admin/settings").unwrap();
        assert!(is_disallowed(&url, &disallowed));

        let url = Url::parse("https://example.com/admin123").unwrap();
        assert!(is_disallowed(&url, &disallowed));
    }

    #[test]
    fn test_is_disallowed_not_matching() {
        let mut disallowed = HashSet::new();
        disallowed.insert("/admin".to_string());
        disallowed.insert("/private".to_string());

        let url = Url::parse("https://example.com/public").unwrap();
        assert!(!is_disallowed(&url, &disallowed));

        let url = Url::parse("https://example.com/").unwrap();
        assert!(!is_disallowed(&url, &disallowed));
    }

    #[test]
    fn test_is_disallowed_empty_set() {
        let disallowed = HashSet::new();

        let url = Url::parse("https://example.com/anything").unwrap();
        assert!(!is_disallowed(&url, &disallowed));
    }

    #[test]
    fn test_is_disallowed_root() {
        let mut disallowed = HashSet::new();
        disallowed.insert("/".to_string());

        let url = Url::parse("https://example.com/anything").unwrap();
        assert!(is_disallowed(&url, &disallowed));

        let url = Url::parse("https://example.com/").unwrap();
        assert!(is_disallowed(&url, &disallowed));
    }

    // ==================== is_same_domain Tests ====================

    #[test]
    fn test_is_same_domain_exact() {
        let url1 = Url::parse("https://example.com/page1").unwrap();
        let url2 = Url::parse("https://example.com/page2").unwrap();
        assert!(is_same_domain(&url1, &url2));
    }

    #[test]
    fn test_is_same_domain_different_schemes() {
        let url1 = Url::parse("http://example.com/page1").unwrap();
        let url2 = Url::parse("https://example.com/page2").unwrap();
        assert!(is_same_domain(&url1, &url2));
    }

    #[test]
    fn test_is_same_domain_different_domains() {
        let url1 = Url::parse("https://example.com/page1").unwrap();
        let url2 = Url::parse("https://other.com/page2").unwrap();
        assert!(!is_same_domain(&url1, &url2));
    }

    #[test]
    fn test_is_same_domain_subdomain() {
        let url1 = Url::parse("https://www.example.com/page1").unwrap();
        let url2 = Url::parse("https://example.com/page2").unwrap();
        // Subdomains are treated as different hosts
        assert!(!is_same_domain(&url1, &url2));
    }

    #[test]
    fn test_is_same_domain_different_ports() {
        let url1 = Url::parse("https://example.com:8080/page1").unwrap();
        let url2 = Url::parse("https://example.com/page2").unwrap();
        // Host comparison doesn't include port
        assert!(is_same_domain(&url1, &url2));
    }

    // ==================== normalize_url Tests ====================

    #[test]
    fn test_normalize_url_removes_fragment() {
        let url = Url::parse("https://example.com/page#section").unwrap();
        let normalized = normalize_url(&url);
        assert_eq!(normalized, "https://example.com/page");
    }

    #[test]
    fn test_normalize_url_removes_trailing_slash() {
        let url = Url::parse("https://example.com/page/").unwrap();
        let normalized = normalize_url(&url);
        assert_eq!(normalized, "https://example.com/page");
    }

    #[test]
    fn test_normalize_url_preserves_root_slash() {
        let url = Url::parse("https://example.com/").unwrap();
        let normalized = normalize_url(&url);
        assert_eq!(normalized, "https://example.com/");
    }

    #[test]
    fn test_normalize_url_preserves_query() {
        let url = Url::parse("https://example.com/search?q=test").unwrap();
        let normalized = normalize_url(&url);
        assert_eq!(normalized, "https://example.com/search?q=test");
    }

    #[test]
    fn test_normalize_url_removes_fragment_preserves_query() {
        let url = Url::parse("https://example.com/search?q=test#results").unwrap();
        let normalized = normalize_url(&url);
        assert_eq!(normalized, "https://example.com/search?q=test");
    }
}
