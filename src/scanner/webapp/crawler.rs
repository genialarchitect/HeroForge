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
