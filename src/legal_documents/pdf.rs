//! PDF Generation for Legal Documents
//!
//! This module handles generating PDF versions of legal documents,
//! including embedding signatures and creating the final signed document.

use anyhow::Result;
use chrono::Utc;
use log::{debug, info, warn};
use std::path::Path;
use tokio::fs;
use tokio::process::Command;

use super::types::{LegalDocument, LegalDocumentSignature};

/// Generate a PDF from a legal document
pub async fn generate_document_pdf(
    document: &LegalDocument,
    signatures: &[LegalDocumentSignature],
    output_dir: &str,
) -> Result<String> {
    // Ensure output directory exists
    fs::create_dir_all(output_dir).await?;

    // Build the complete HTML with signatures embedded
    let html_content = build_signed_html(document, signatures);

    // Write temporary HTML file
    let temp_html_path = Path::new(output_dir).join(format!("{}_temp.html", document.id));
    fs::write(&temp_html_path, &html_content).await?;

    // Output PDF path
    let pdf_filename = format!("legal_doc_{}.pdf", document.id);
    let pdf_path = Path::new(output_dir).join(&pdf_filename);

    // Try wkhtmltopdf first, fall back to chromium
    let result = try_wkhtmltopdf(&temp_html_path, &pdf_path).await;

    if result.is_err() {
        warn!("wkhtmltopdf failed, trying chromium...");
        try_chromium(&temp_html_path, &pdf_path).await?;
    }

    // Clean up temp HTML
    let _ = fs::remove_file(&temp_html_path).await;

    let path_str = pdf_path.to_string_lossy().to_string();
    info!("Legal document PDF generated: {}", path_str);

    Ok(path_str)
}

/// Build HTML document with embedded signatures
fn build_signed_html(document: &LegalDocument, signatures: &[LegalDocumentSignature]) -> String {
    let mut html = String::new();

    // HTML header with styling
    html.push_str(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>"#);
    html.push_str(&html_escape(&document.name));
    html.push_str(r#"</title>
    <style>
        @page {
            size: A4;
            margin: 2cm;
        }
        body {
            font-family: 'Times New Roman', Times, serif;
            font-size: 12pt;
            line-height: 1.6;
            color: #333;
            max-width: 21cm;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            font-size: 18pt;
            text-align: center;
            margin-bottom: 30px;
            color: #1a1a1a;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        h2 {
            font-size: 14pt;
            margin-top: 25px;
            margin-bottom: 15px;
            color: #2c3e50;
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 5px;
        }
        h3 {
            font-size: 12pt;
            margin-top: 20px;
            margin-bottom: 10px;
            color: #34495e;
        }
        p {
            margin-bottom: 12px;
            text-align: justify;
        }
        ul, ol {
            margin-bottom: 15px;
            padding-left: 30px;
        }
        li {
            margin-bottom: 8px;
        }
        .signature-section {
            margin-top: 60px;
            page-break-inside: avoid;
        }
        .signature-block {
            display: inline-block;
            width: 45%;
            vertical-align: top;
            margin-bottom: 40px;
        }
        .signature-block:nth-child(odd) {
            margin-right: 8%;
        }
        .signature-line {
            border-bottom: 1px solid #333;
            height: 60px;
            margin-bottom: 5px;
            position: relative;
        }
        .signature-image {
            max-height: 50px;
            max-width: 200px;
            position: absolute;
            bottom: 5px;
            left: 10px;
        }
        .signature-info {
            font-size: 10pt;
            color: #666;
        }
        .signature-name {
            font-weight: bold;
            margin-top: 10px;
        }
        .signature-date {
            font-style: italic;
        }
        .signature-status-pending {
            color: #f39c12;
            font-style: italic;
        }
        .signature-status-signed {
            color: #27ae60;
        }
        .signature-status-declined {
            color: #e74c3c;
        }
        .document-footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            font-size: 9pt;
            color: #999;
            text-align: center;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
    </style>
</head>
<body>
"#);

    // Document content (already HTML)
    html.push_str(&document.content_html);

    // Signature section
    if !signatures.is_empty() {
        html.push_str(r#"
<div class="signature-section">
    <h2>Signatures</h2>
    <div class="signature-blocks">
"#);

        // Sort signatures by order
        let mut sorted_signatures = signatures.to_vec();
        sorted_signatures.sort_by_key(|s| s.signature_order);

        for sig in &sorted_signatures {
            html.push_str(&format!(r#"
        <div class="signature-block">
            <div class="signature-line">
"#));

            // Embed signature image if signed
            if sig.status == "signed" {
                if let Some(ref img) = sig.signature_image {
                    html.push_str(&format!(
                        r#"                <img class="signature-image" src="{}" alt="Signature" />"#,
                        img
                    ));
                }
            }

            html.push_str(r#"
            </div>
            <div class="signature-info">
"#);

            // Signer name
            if let Some(ref name) = sig.signer_name {
                html.push_str(&format!(
                    r#"                <div class="signature-name">{}</div>"#,
                    html_escape(name)
                ));
            }

            // Role
            html.push_str(&format!(
                r#"                <div>{} ({})</div>"#,
                html_escape(&sig.signer_role),
                if sig.signer_type == "client" { "Client" } else { "Provider" }
            ));

            // Status and date
            match sig.status.as_str() {
                "signed" => {
                    let date = sig.signed_at.as_ref()
                        .map(|d| format_signature_date(d))
                        .unwrap_or_else(|| "Date not recorded".to_string());
                    html.push_str(&format!(
                        r#"                <div class="signature-status-signed signature-date">Signed: {}</div>"#,
                        date
                    ));
                }
                "declined" => {
                    html.push_str(r#"                <div class="signature-status-declined">Declined</div>"#);
                }
                _ => {
                    html.push_str(r#"                <div class="signature-status-pending">Pending signature</div>"#);
                }
            }

            html.push_str(r#"
            </div>
        </div>
"#);
        }

        html.push_str(r#"
    </div>
</div>
"#);
    }

    // Document footer
    let generated_at = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    html.push_str(&format!(r#"
<div class="document-footer">
    Document ID: {} | Generated: {} | HeroForge Legal Document System
</div>
</body>
</html>
"#, document.id, generated_at));

    html
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Format signature date for display
fn format_signature_date(date_str: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(date_str) {
        dt.format("%B %d, %Y at %H:%M UTC").to_string()
    } else {
        date_str.to_string()
    }
}

/// Try generating PDF using wkhtmltopdf
async fn try_wkhtmltopdf(html_path: &Path, pdf_path: &Path) -> Result<()> {
    debug!("Attempting PDF generation with wkhtmltopdf for legal document");

    let status = Command::new("wkhtmltopdf")
        .args([
            "--enable-local-file-access",
            "--page-size", "A4",
            "--margin-top", "20mm",
            "--margin-bottom", "20mm",
            "--margin-left", "20mm",
            "--margin-right", "20mm",
            "--footer-center", "Page [page] of [topage]",
            "--footer-font-size", "9",
            "--footer-spacing", "5",
            "--quiet",
        ])
        .arg(html_path.to_str().unwrap())
        .arg(pdf_path.to_str().unwrap())
        .status()
        .await?;

    if !status.success() {
        return Err(anyhow::anyhow!("wkhtmltopdf failed with status: {}", status));
    }

    Ok(())
}

/// Try generating PDF using chromium headless
async fn try_chromium(html_path: &Path, pdf_path: &Path) -> Result<()> {
    debug!("Attempting PDF generation with chromium for legal document");

    // Try different chromium binary names
    let chromium_binaries = ["chromium", "chromium-browser", "google-chrome", "chrome"];

    for binary in &chromium_binaries {
        let result = Command::new(binary)
            .args([
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-software-rasterizer",
                &format!("--print-to-pdf={}", pdf_path.to_str().unwrap()),
            ])
            .arg(format!("file://{}", html_path.to_str().unwrap()))
            .status()
            .await;

        if let Ok(status) = result {
            if status.success() {
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!(
        "PDF generation failed. Please install wkhtmltopdf or chromium."
    ))
}

/// Check if a signature image is valid base64 PNG
pub fn validate_signature_image(data: &str) -> Result<()> {
    // Check for data URL format
    if data.starts_with("data:image/png;base64,") {
        let base64_data = &data[22..];
        // Validate base64
        if base64::decode(base64_data).is_ok() {
            return Ok(());
        }
    }
    // Also accept raw base64
    if base64::decode(data).is_ok() {
        return Ok(());
    }

    Err(anyhow::anyhow!("Invalid signature image format. Expected base64-encoded PNG."))
}
