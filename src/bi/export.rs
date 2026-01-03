//! Data export (Excel, CSV, PDF)

use anyhow::Result;
use std::io::Write;
use tempfile::NamedTempFile;
use tokio::fs;
use tokio::process::Command;

pub struct DataExporter {}

impl DataExporter {
    pub fn new() -> Self {
        Self {}
    }

    /// Export data to Excel format (XML Spreadsheet 2003 format)
    /// This format is widely supported and doesn't require external dependencies
    pub async fn export_to_excel(&self, data: &serde_json::Value) -> Result<Vec<u8>> {
        let mut excel_content = String::new();

        // XML Spreadsheet 2003 header
        excel_content.push_str(r##"<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
<Styles>
<Style ss:ID="Header">
<Font ss:Bold="1"/>
<Interior ss:Color="#CCCCCC" ss:Pattern="Solid"/>
</Style>
<Style ss:ID="Normal"/>
</Styles>
<Worksheet ss:Name="Data">
<Table>
"##);

        match data {
            serde_json::Value::Array(arr) => {
                // Extract headers from first object if array of objects
                if let Some(first) = arr.first() {
                    if let serde_json::Value::Object(obj) = first {
                        // Write header row
                        excel_content.push_str("<Row>\n");
                        for key in obj.keys() {
                            excel_content.push_str(&format!(
                                r#"<Cell ss:StyleID="Header"><Data ss:Type="String">{}</Data></Cell>"#,
                                escape_xml(key)
                            ));
                            excel_content.push('\n');
                        }
                        excel_content.push_str("</Row>\n");

                        // Write data rows
                        for item in arr {
                            if let serde_json::Value::Object(row_obj) = item {
                                excel_content.push_str("<Row>\n");
                                for key in obj.keys() {
                                    let value = row_obj.get(key).unwrap_or(&serde_json::Value::Null);
                                    let (data_type, data_value) = json_value_to_excel_cell(value);
                                    excel_content.push_str(&format!(
                                        r#"<Cell><Data ss:Type="{}">{}</Data></Cell>"#,
                                        data_type,
                                        escape_xml(&data_value)
                                    ));
                                    excel_content.push('\n');
                                }
                                excel_content.push_str("</Row>\n");
                            }
                        }
                    } else {
                        // Array of primitives
                        excel_content.push_str("<Row>\n");
                        excel_content.push_str(r#"<Cell ss:StyleID="Header"><Data ss:Type="String">Value</Data></Cell>"#);
                        excel_content.push_str("\n</Row>\n");
                        for item in arr {
                            let (data_type, data_value) = json_value_to_excel_cell(item);
                            excel_content.push_str(&format!(
                                r#"<Row><Cell><Data ss:Type="{}">{}</Data></Cell></Row>"#,
                                data_type,
                                escape_xml(&data_value)
                            ));
                            excel_content.push('\n');
                        }
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                // Single object - render as key-value pairs
                excel_content.push_str("<Row>\n");
                excel_content.push_str(r#"<Cell ss:StyleID="Header"><Data ss:Type="String">Property</Data></Cell>"#);
                excel_content.push_str(r#"<Cell ss:StyleID="Header"><Data ss:Type="String">Value</Data></Cell>"#);
                excel_content.push_str("\n</Row>\n");

                for (key, value) in obj {
                    let (data_type, data_value) = json_value_to_excel_cell(value);
                    excel_content.push_str(&format!(
                        r#"<Row><Cell><Data ss:Type="String">{}</Data></Cell><Cell><Data ss:Type="{}">{}</Data></Cell></Row>"#,
                        escape_xml(key),
                        data_type,
                        escape_xml(&data_value)
                    ));
                    excel_content.push('\n');
                }
            }
            _ => {
                // Single primitive value
                let (data_type, data_value) = json_value_to_excel_cell(data);
                excel_content.push_str(&format!(
                    r#"<Row><Cell><Data ss:Type="{}">{}</Data></Cell></Row>"#,
                    data_type,
                    escape_xml(&data_value)
                ));
            }
        }

        // Close XML elements
        excel_content.push_str("</Table>\n</Worksheet>\n</Workbook>");

        Ok(excel_content.into_bytes())
    }

    /// Export data to CSV format
    pub async fn export_to_csv(&self, data: &serde_json::Value) -> Result<String> {
        let mut csv_output = String::new();

        match data {
            serde_json::Value::Array(arr) => {
                if let Some(first) = arr.first() {
                    if let serde_json::Value::Object(obj) = first {
                        // Write header row
                        let headers: Vec<&String> = obj.keys().collect();
                        csv_output.push_str(&headers.iter()
                            .map(|h| escape_csv(h))
                            .collect::<Vec<_>>()
                            .join(","));
                        csv_output.push('\n');

                        // Write data rows
                        for item in arr {
                            if let serde_json::Value::Object(row_obj) = item {
                                let values: Vec<String> = headers.iter()
                                    .map(|key| {
                                        row_obj.get(*key)
                                            .map(json_value_to_csv_string)
                                            .unwrap_or_default()
                                    })
                                    .collect();
                                csv_output.push_str(&values.join(","));
                                csv_output.push('\n');
                            }
                        }
                    } else {
                        // Array of primitives
                        csv_output.push_str("value\n");
                        for item in arr {
                            csv_output.push_str(&json_value_to_csv_string(item));
                            csv_output.push('\n');
                        }
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                // Single object - render as key-value pairs
                csv_output.push_str("property,value\n");
                for (key, value) in obj {
                    csv_output.push_str(&format!(
                        "{},{}\n",
                        escape_csv(key),
                        json_value_to_csv_string(value)
                    ));
                }
            }
            _ => {
                // Single primitive
                csv_output.push_str("value\n");
                csv_output.push_str(&json_value_to_csv_string(data));
                csv_output.push('\n');
            }
        }

        Ok(csv_output)
    }

    /// Export data to PDF format via HTML conversion
    pub async fn export_to_pdf(&self, data: &serde_json::Value) -> Result<Vec<u8>> {
        // Generate HTML representation of data
        let html_content = generate_html_for_pdf(data);

        // Write HTML to temp file
        let mut temp_html = NamedTempFile::new()?;
        temp_html.write_all(html_content.as_bytes())?;
        let html_path = temp_html.path().to_path_buf();

        // Create temp file for PDF output
        let temp_pdf = NamedTempFile::new()?;
        let pdf_path = temp_pdf.path().to_path_buf();

        // Try wkhtmltopdf first
        let wkhtmltopdf_result = Command::new("wkhtmltopdf")
            .args([
                "--enable-local-file-access",
                "--page-size", "A4",
                "--margin-top", "15mm",
                "--margin-bottom", "15mm",
                "--margin-left", "10mm",
                "--margin-right", "10mm",
                "--quiet",
            ])
            .arg(html_path.to_str().unwrap())
            .arg(pdf_path.to_str().unwrap())
            .status()
            .await;

        let pdf_generated = match wkhtmltopdf_result {
            Ok(status) if status.success() => true,
            _ => {
                // Try chromium as fallback
                let chromium_binaries = ["chromium", "chromium-browser", "google-chrome", "chrome"];
                let mut success = false;

                for binary in chromium_binaries {
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
                            success = true;
                            break;
                        }
                    }
                }
                success
            }
        };

        if !pdf_generated {
            return Err(anyhow::anyhow!(
                "PDF generation failed. Please install wkhtmltopdf or chromium."
            ));
        }

        // Read the generated PDF
        let pdf_bytes = fs::read(&pdf_path).await?;
        Ok(pdf_bytes)
    }
}

impl Default for DataExporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape special XML characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Escape CSV field values
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Convert JSON value to Excel cell data type and value
fn json_value_to_excel_cell(value: &serde_json::Value) -> (&'static str, String) {
    match value {
        serde_json::Value::Null => ("String", String::new()),
        serde_json::Value::Bool(b) => ("Boolean", if *b { "1".to_string() } else { "0".to_string() }),
        serde_json::Value::Number(n) => ("Number", n.to_string()),
        serde_json::Value::String(s) => ("String", s.clone()),
        serde_json::Value::Array(arr) => ("String", serde_json::to_string(arr).unwrap_or_default()),
        serde_json::Value::Object(obj) => ("String", serde_json::to_string(obj).unwrap_or_default()),
    }
}

/// Convert JSON value to CSV string
fn json_value_to_csv_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => escape_csv(s),
        serde_json::Value::Array(arr) => escape_csv(&serde_json::to_string(arr).unwrap_or_default()),
        serde_json::Value::Object(obj) => escape_csv(&serde_json::to_string(obj).unwrap_or_default()),
    }
}

/// Generate HTML representation of data for PDF export
fn generate_html_for_pdf(data: &serde_json::Value) -> String {
    let mut html = String::from(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Data Export</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; font-size: 12px; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #4a5568; color: white; }
tr:nth-child(even) { background-color: #f9f9f9; }
h1 { color: #2d3748; font-size: 18px; }
.property { font-weight: bold; background-color: #edf2f7; }
</style>
</head>
<body>
<h1>Data Export Report</h1>
"#);

    match data {
        serde_json::Value::Array(arr) => {
            if let Some(first) = arr.first() {
                if let serde_json::Value::Object(obj) = first {
                    html.push_str("<table>\n<thead><tr>\n");
                    for key in obj.keys() {
                        html.push_str(&format!("<th>{}</th>\n", escape_html(key)));
                    }
                    html.push_str("</tr></thead>\n<tbody>\n");

                    for item in arr {
                        if let serde_json::Value::Object(row_obj) = item {
                            html.push_str("<tr>\n");
                            for key in obj.keys() {
                                let value = row_obj.get(key).unwrap_or(&serde_json::Value::Null);
                                html.push_str(&format!("<td>{}</td>\n", escape_html(&value_to_string(value))));
                            }
                            html.push_str("</tr>\n");
                        }
                    }
                    html.push_str("</tbody></table>\n");
                } else {
                    html.push_str("<table>\n<thead><tr><th>Value</th></tr></thead>\n<tbody>\n");
                    for item in arr {
                        html.push_str(&format!("<tr><td>{}</td></tr>\n", escape_html(&value_to_string(item))));
                    }
                    html.push_str("</tbody></table>\n");
                }
            }
        }
        serde_json::Value::Object(obj) => {
            html.push_str("<table>\n<thead><tr><th>Property</th><th>Value</th></tr></thead>\n<tbody>\n");
            for (key, value) in obj {
                html.push_str(&format!(
                    "<tr><td class=\"property\">{}</td><td>{}</td></tr>\n",
                    escape_html(key),
                    escape_html(&value_to_string(value))
                ));
            }
            html.push_str("</tbody></table>\n");
        }
        _ => {
            html.push_str(&format!("<p>{}</p>\n", escape_html(&value_to_string(data))));
        }
    }

    html.push_str("</body></html>");
    html
}

/// Escape HTML special characters
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Convert JSON value to display string
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string_pretty(value).unwrap_or_default()
        }
    }
}
