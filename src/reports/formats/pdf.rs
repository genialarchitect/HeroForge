use anyhow::Result;
use log::{debug, info, warn};
use std::path::Path;
use tokio::fs;
use tokio::process::Command;

use crate::reports::types::ReportData;

/// Generate a PDF report using HTML-to-PDF conversion
pub async fn generate(data: &ReportData, reports_dir: &str) -> Result<(String, i64)> {
    // Ensure reports directory exists
    fs::create_dir_all(reports_dir).await?;

    // First generate HTML using the html module's generator
    let html_content = super::html::generate_html(data);

    // Write temporary HTML file
    let temp_html_path = Path::new(reports_dir).join(format!("{}_temp.html", data.id));
    fs::write(&temp_html_path, &html_content).await?;

    // Output PDF path
    let pdf_filename = format!("{}.pdf", data.id);
    let pdf_path = Path::new(reports_dir).join(&pdf_filename);

    // Try wkhtmltopdf first, fall back to chromium
    let result = try_wkhtmltopdf(&temp_html_path, &pdf_path).await;

    if result.is_err() {
        warn!("wkhtmltopdf failed, trying chromium...");
        try_chromium(&temp_html_path, &pdf_path).await?;
    }

    // Clean up temp HTML
    let _ = fs::remove_file(&temp_html_path).await;

    // Get file size
    let metadata = fs::metadata(&pdf_path).await?;
    let file_size = metadata.len() as i64;

    let path_str = pdf_path.to_string_lossy().to_string();
    info!("PDF report generated: {} ({} bytes)", path_str, file_size);

    Ok((path_str, file_size))
}

/// Try generating PDF using wkhtmltopdf
async fn try_wkhtmltopdf(html_path: &Path, pdf_path: &Path) -> Result<()> {
    debug!("Attempting PDF generation with wkhtmltopdf");

    let status = Command::new("wkhtmltopdf")
        .args([
            "--enable-local-file-access",
            "--page-size", "A4",
            "--margin-top", "20mm",
            "--margin-bottom", "20mm",
            "--margin-left", "15mm",
            "--margin-right", "15mm",
            "--footer-center", "[page] of [topage]",
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
    debug!("Attempting PDF generation with chromium");

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
