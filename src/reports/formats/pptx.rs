//! PPTX Report Export
//!
//! Generates Microsoft PowerPoint presentations from scan reports.
//! Uses Open XML format (PPTX) for cross-platform compatibility.

use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::reports::types::{FindingDetail, ReportData, ReportSummary};
use crate::types::Severity;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Generate a PPTX report and save to file
pub async fn generate(data: &ReportData, reports_dir: &str) -> Result<(String, i64)> {
    // Ensure reports directory exists
    fs::create_dir_all(reports_dir).await?;

    // Generate filename
    let filename = format!("{}.pptx", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    // Generate PPTX bytes
    let pptx_bytes = generate_pptx(data)?;
    let file_size = pptx_bytes.len() as i64;

    // Write to file
    fs::write(&file_path, &pptx_bytes).await?;

    let path_str = file_path.to_string_lossy().to_string();
    Ok((path_str, file_size))
}

/// Generate a PPTX report from scan data (returns raw bytes)
pub fn generate_pptx(data: &ReportData) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut buffer);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Count slides we'll create
    let slide_count = calculate_slide_count(data);

    // Add required PPTX structure files
    add_content_types(&mut zip, options, slide_count)?;
    add_rels(&mut zip, options)?;
    add_presentation_xml(&mut zip, options, slide_count)?;
    add_presentation_rels(&mut zip, options, slide_count)?;
    add_slide_layouts(&mut zip, options)?;
    add_slide_masters(&mut zip, options)?;
    add_theme(&mut zip, options)?;

    // Add slides
    add_title_slide(&mut zip, options, data)?;
    add_summary_slide(&mut zip, options, &data.summary)?;
    add_risk_overview_slide(&mut zip, options, &data.summary)?;

    let mut slide_num = 4;
    for finding in data.findings.iter().take(10) {
        // Limit to top 10 findings
        add_finding_slide(&mut zip, options, slide_num, finding)?;
        slide_num += 1;
    }

    add_recommendations_slide(&mut zip, options, slide_num, data)?;

    zip.finish()?;
    Ok(buffer.into_inner())
}

fn calculate_slide_count(data: &ReportData) -> usize {
    3 + data.findings.len().min(10) + 1 // Title + Summary + Risk + Findings + Recommendations
}

fn add_content_types<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    slide_count: usize,
) -> anyhow::Result<()> {
    zip.start_file("[Content_Types].xml", options)?;

    let mut content = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>"#,
    );

    for i in 1..=slide_count {
        content.push_str(&format!(
            r#"
  <Override PartName="/ppt/slides/slide{}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>"#,
            i
        ));
    }

    content.push_str("\n</Types>");
    zip.write_all(content.as_bytes())?;
    Ok(())
}

fn add_rels<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("_rels/.rels", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>"#,
    )?;
    Ok(())
}

fn add_presentation_xml<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    slide_count: usize,
) -> anyhow::Result<()> {
    zip.start_file("ppt/presentation.xml", options)?;

    let mut content = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
                xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>"#,
    );

    for i in 1..=slide_count {
        content.push_str(&format!(
            r#"
    <p:sldId id="{}" r:id="rId{}"/>"#,
            255 + i,
            i + 2
        ));
    }

    content.push_str(
        r#"
  </p:sldIdLst>
  <p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>"#,
    );

    zip.write_all(content.as_bytes())?;
    Ok(())
}

fn add_presentation_rels<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    slide_count: usize,
) -> anyhow::Result<()> {
    zip.start_file("ppt/_rels/presentation.xml.rels", options)?;

    let mut content = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>"#,
    );

    for i in 1..=slide_count {
        content.push_str(&format!(
            r#"
  <Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{}.xml"/>"#,
            i + 2,
            i
        ));
    }

    content.push_str("\n</Relationships>");
    zip.write_all(content.as_bytes())?;
    Ok(())
}

fn add_slide_layouts<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("ppt/slideLayouts/slideLayout1.xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
             type="blank">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
    </p:spTree>
  </p:cSld>
</p:sldLayout>"#,
    )?;

    zip.start_file("ppt/slideLayouts/_rels/slideLayout1.xml.rels", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>"#,
    )?;
    Ok(())
}

fn add_slide_masters<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("ppt/slideMasters/slideMaster1.xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
              xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
              xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg>
      <p:bgPr>
        <a:solidFill><a:schemeClr val="bg1"/></a:solidFill>
      </p:bgPr>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="2147483649" r:id="rId1"/>
  </p:sldLayoutIdLst>
</p:sldMaster>"#,
    )?;

    zip.start_file("ppt/slideMasters/_rels/slideMaster1.xml.rels", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>"#,
    )?;
    Ok(())
}

fn add_theme<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
) -> anyhow::Result<()> {
    zip.start_file("ppt/theme/theme1.xml", options)?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Security Theme">
  <a:themeElements>
    <a:clrScheme name="Security">
      <a:dk1><a:srgbClr val="1F4E79"/></a:dk1>
      <a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>
      <a:dk2><a:srgbClr val="2E75B6"/></a:dk2>
      <a:lt2><a:srgbClr val="F2F2F2"/></a:lt2>
      <a:accent1><a:srgbClr val="5B9BD5"/></a:accent1>
      <a:accent2><a:srgbClr val="ED7D31"/></a:accent2>
      <a:accent3><a:srgbClr val="A5A5A5"/></a:accent3>
      <a:accent4><a:srgbClr val="FFC000"/></a:accent4>
      <a:accent5><a:srgbClr val="4472C4"/></a:accent5>
      <a:accent6><a:srgbClr val="70AD47"/></a:accent6>
      <a:hlink><a:srgbClr val="0563C1"/></a:hlink>
      <a:folHlink><a:srgbClr val="954F72"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="Office">
      <a:majorFont><a:latin typeface="Calibri Light"/></a:majorFont>
      <a:minorFont><a:latin typeface="Calibri"/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="Office">
      <a:fillStyleLst>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
      </a:fillStyleLst>
      <a:lnStyleLst>
        <a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
        <a:ln w="25400"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
        <a:ln w="38100"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
      </a:lnStyleLst>
      <a:effectStyleLst>
        <a:effectStyle><a:effectLst/></a:effectStyle>
        <a:effectStyle><a:effectLst/></a:effectStyle>
        <a:effectStyle><a:effectLst/></a:effectStyle>
      </a:effectStyleLst>
      <a:bgFillStyleLst>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
      </a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
</a:theme>"#,
    )?;
    Ok(())
}

fn add_title_slide<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    data: &ReportData,
) -> anyhow::Result<()> {
    zip.start_file("ppt/slides/slide1.xml", options)?;

    let company = data.options.company_name.clone().unwrap_or_else(|| "Security Assessment".to_string());
    let date = data.created_at.format("%Y-%m-%d").to_string();

    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg>
      <p:bgPr>
        <a:solidFill><a:srgbClr val="1F4E79"/></a:solidFill>
      </p:bgPr>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="2" name="Title"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="2286000"/>
            <a:ext cx="8229600" cy="1143000"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr anchor="ctr"/>
          <a:p>
            <a:pPr algn="ctr"/>
            <a:r>
              <a:rPr lang="en-US" sz="4400" b="1">
                <a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>
              </a:rPr>
              <a:t>{}</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="3" name="Subtitle"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="3657600"/>
            <a:ext cx="8229600" cy="914400"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr anchor="ctr"/>
          <a:p>
            <a:pPr algn="ctr"/>
            <a:r>
              <a:rPr lang="en-US" sz="2400">
                <a:solidFill><a:srgbClr val="CCCCCC"/></a:solidFill>
              </a:rPr>
              <a:t>{} | {}</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#,
        escape_xml(&data.name),
        escape_xml(&company),
        date
    );

    zip.write_all(content.as_bytes())?;
    add_slide_rels(zip, options, 1)?;
    Ok(())
}

fn add_summary_slide<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    summary: &ReportSummary,
) -> anyhow::Result<()> {
    zip.start_file("ppt/slides/slide2.xml", options)?;

    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="2" name="Title"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="274638"/>
            <a:ext cx="8229600" cy="857250"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="3600" b="1">
                <a:solidFill><a:srgbClr val="1F4E79"/></a:solidFill>
              </a:rPr>
              <a:t>Executive Summary</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="3" name="Content"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="1371600"/>
            <a:ext cx="8229600" cy="4572000"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2400"/>
              <a:t>• {} total vulnerabilities identified across {} hosts</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2400"/>
              <a:t>• Overall Risk Level: {} (Score: {}/100)</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2400"/>
              <a:t>• {} open ports detected</a:t>
            </a:r>
          </a:p>
          <a:p><a:endParaRPr/></a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2000" b="1"/>
              <a:t>Vulnerability Breakdown:</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2000">
                <a:solidFill><a:srgbClr val="8B0000"/></a:solidFill>
              </a:rPr>
              <a:t>  • Critical: {}</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2000">
                <a:solidFill><a:srgbClr val="FF4500"/></a:solidFill>
              </a:rPr>
              <a:t>  • High: {}</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2000">
                <a:solidFill><a:srgbClr val="FFA500"/></a:solidFill>
              </a:rPr>
              <a:t>  • Medium: {}</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2000">
                <a:solidFill><a:srgbClr val="228B22"/></a:solidFill>
              </a:rPr>
              <a:t>  • Low: {}</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#,
        summary.total_vulnerabilities,
        summary.live_hosts,
        summary.overall_risk_level,
        summary.overall_risk_score,
        summary.open_ports,
        summary.critical_count,
        summary.high_count,
        summary.medium_count,
        summary.low_count
    );

    zip.write_all(content.as_bytes())?;
    add_slide_rels(zip, options, 2)?;
    Ok(())
}

fn add_risk_overview_slide<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    summary: &ReportSummary,
) -> anyhow::Result<()> {
    zip.start_file("ppt/slides/slide3.xml", options)?;

    // Calculate bar widths based on counts (max width ~7000000 EMUs)
    let max_count = [summary.critical_count, summary.high_count, summary.medium_count, summary.low_count]
        .iter()
        .max()
        .copied()
        .unwrap_or(1)
        .max(1);

    let scale = 6000000.0 / max_count as f64;
    let crit_width = ((summary.critical_count as f64 * scale) as i64).max(100000);
    let high_width = ((summary.high_count as f64 * scale) as i64).max(100000);
    let med_width = ((summary.medium_count as f64 * scale) as i64).max(100000);
    let low_width = ((summary.low_count as f64 * scale) as i64).max(100000);

    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="2" name="Title"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="274638"/>
            <a:ext cx="8229600" cy="857250"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="3600" b="1">
                <a:solidFill><a:srgbClr val="1F4E79"/></a:solidFill>
              </a:rPr>
              <a:t>Risk Overview</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
      <!-- Critical bar -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="10" name="CritBar"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="2000000" y="1600000"/><a:ext cx="{}" cy="400000"/></a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
          <a:solidFill><a:srgbClr val="8B0000"/></a:solidFill>
        </p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="11" name="CritLbl"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="500000" y="1650000"/><a:ext cx="1400000" cy="300000"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr lang="en-US" sz="1800"/><a:t>Critical: {}</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <!-- High bar -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="12" name="HighBar"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="2000000" y="2200000"/><a:ext cx="{}" cy="400000"/></a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
          <a:solidFill><a:srgbClr val="FF4500"/></a:solidFill>
        </p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="13" name="HighLbl"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="500000" y="2250000"/><a:ext cx="1400000" cy="300000"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr lang="en-US" sz="1800"/><a:t>High: {}</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <!-- Medium bar -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="14" name="MedBar"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="2000000" y="2800000"/><a:ext cx="{}" cy="400000"/></a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
          <a:solidFill><a:srgbClr val="FFA500"/></a:solidFill>
        </p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="15" name="MedLbl"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="500000" y="2850000"/><a:ext cx="1400000" cy="300000"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr lang="en-US" sz="1800"/><a:t>Medium: {}</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <!-- Low bar -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="16" name="LowBar"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="2000000" y="3400000"/><a:ext cx="{}" cy="400000"/></a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
          <a:solidFill><a:srgbClr val="228B22"/></a:solidFill>
        </p:spPr>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="17" name="LowLbl"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="500000" y="3450000"/><a:ext cx="1400000" cy="300000"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr lang="en-US" sz="1800"/><a:t>Low: {}</a:t></a:r></a:p></p:txBody>
      </p:sp>
      <!-- Risk Score -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="20" name="RiskScore"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="500000" y="4500000"/><a:ext cx="8000000" cy="600000"/></a:xfrm></p:spPr>
        <p:txBody><a:bodyPr/><a:p><a:r><a:rPr lang="en-US" sz="2800" b="1"/><a:t>Overall Risk: {} ({}/100)</a:t></a:r></a:p></p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#,
        crit_width, summary.critical_count,
        high_width, summary.high_count,
        med_width, summary.medium_count,
        low_width, summary.low_count,
        summary.overall_risk_level, summary.overall_risk_score
    );

    zip.write_all(content.as_bytes())?;
    add_slide_rels(zip, options, 3)?;
    Ok(())
}

fn add_finding_slide<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    slide_num: usize,
    finding: &FindingDetail,
) -> anyhow::Result<()> {
    zip.start_file(&format!("ppt/slides/slide{}.xml", slide_num), options)?;

    let severity_color = match finding.severity {
        Severity::Critical => "8B0000",
        Severity::High => "FF4500",
        Severity::Medium => "FFA500",
        Severity::Low => "228B22",
    };

    let cve_text = finding
        .cve_id
        .as_ref()
        .map(|c| format!(" ({})", c))
        .unwrap_or_default();

    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="2" name="Title"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="274638"/>
            <a:ext cx="8229600" cy="857250"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="2800" b="1">
                <a:solidFill><a:srgbClr val="1F4E79"/></a:solidFill>
              </a:rPr>
              <a:t>{}{}</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="3" name="Severity"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="1200000"/>
            <a:ext cx="2000000" cy="400000"/>
          </a:xfrm>
          <a:solidFill><a:srgbClr val="{}"/></a:solidFill>
        </p:spPr>
        <p:txBody>
          <a:bodyPr anchor="ctr"/>
          <a:p>
            <a:pPr algn="ctr"/>
            <a:r>
              <a:rPr lang="en-US" sz="1800" b="1">
                <a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>
              </a:rPr>
              <a:t>{:?}</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="4" name="Content"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="1800000"/>
            <a:ext cx="8229600" cy="4500000"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="1600" b="1"/>
              <a:t>Description:</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="1400"/>
              <a:t>{}</a:t>
            </a:r>
          </a:p>
          <a:p><a:endParaRPr/></a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="1600" b="1"/>
              <a:t>Affected Hosts:</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="1400"/>
              <a:t>{}</a:t>
            </a:r>
          </a:p>
          <a:p><a:endParaRPr/></a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="1600" b="1"/>
              <a:t>Remediation:</a:t>
            </a:r>
          </a:p>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="1400"/>
              <a:t>{}</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#,
        escape_xml(&finding.title),
        cve_text,
        severity_color,
        finding.severity,
        escape_xml(&truncate_text(&finding.description, 300)),
        finding.affected_hosts.join(", "),
        escape_xml(&truncate_text(&finding.remediation, 300))
    );

    zip.write_all(content.as_bytes())?;
    add_slide_rels(zip, options, slide_num)?;
    Ok(())
}

fn add_recommendations_slide<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    slide_num: usize,
    data: &ReportData,
) -> anyhow::Result<()> {
    zip.start_file(&format!("ppt/slides/slide{}.xml", slide_num), options)?;

    let mut rec_text = String::new();
    for (i, rec) in data.remediation.iter().take(5).enumerate() {
        rec_text.push_str(&format!(
            r#"<a:p><a:r><a:rPr lang="en-US" sz="1800"/><a:t>{}. {} - {}</a:t></a:r></a:p>"#,
            i + 1,
            escape_xml(&rec.title),
            rec.timeline_suggestion
        ));
    }

    if rec_text.is_empty() {
        rec_text = r#"<a:p><a:r><a:rPr lang="en-US" sz="1800"/><a:t>No specific recommendations at this time.</a:t></a:r></a:p>"#.to_string();
    }

    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="2" name="Title"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="274638"/>
            <a:ext cx="8229600" cy="857250"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p>
            <a:r>
              <a:rPr lang="en-US" sz="3600" b="1">
                <a:solidFill><a:srgbClr val="1F4E79"/></a:solidFill>
              </a:rPr>
              <a:t>Remediation Priorities</a:t>
            </a:r>
          </a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr>
          <p:cNvPr id="3" name="Content"/>
          <p:cNvSpPr txBox="1"/>
          <p:nvPr/>
        </p:nvSpPr>
        <p:spPr>
          <a:xfrm>
            <a:off x="457200" y="1371600"/>
            <a:ext cx="8229600" cy="4572000"/>
          </a:xfrm>
        </p:spPr>
        <p:txBody>
          <a:bodyPr/>
          {}
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"#,
        rec_text
    );

    zip.write_all(content.as_bytes())?;
    add_slide_rels(zip, options, slide_num)?;
    Ok(())
}

fn add_slide_rels<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    slide_num: usize,
) -> anyhow::Result<()> {
    zip.start_file(
        &format!("ppt/slides/_rels/slide{}.xml.rels", slide_num),
        options,
    )?;
    zip.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>"#,
    )?;
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn truncate_text(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::types::{ReportOptions, ReportTemplate};
    use chrono::Utc;

    #[test]
    fn test_generate_pptx() {
        let data = ReportData {
            id: "test-report".to_string(),
            name: "Test Security Report".to_string(),
            description: Some("Test report".to_string()),
            scan_id: "scan-123".to_string(),
            scan_name: "Test Scan".to_string(),
            created_at: Utc::now(),
            scan_date: Utc::now(),
            template: ReportTemplate::executive(),
            sections: vec![],
            options: ReportOptions::default(),
            hosts: vec![],
            summary: crate::reports::types::ReportSummary {
                total_hosts: 10,
                live_hosts: 8,
                total_ports: 100,
                open_ports: 45,
                total_vulnerabilities: 25,
                critical_count: 2,
                high_count: 5,
                medium_count: 10,
                low_count: 8,
                overall_risk_score: 65,
                overall_risk_level: "High".to_string(),
                top_findings: vec![],
                affected_services: vec![],
            },
            findings: vec![],
            secrets: vec![],
            remediation: vec![],
            screenshots: vec![],
            operator_notes: None,
            finding_notes: std::collections::HashMap::new(),
        };

        let result = generate_pptx(&data);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        // PPTX files start with ZIP signature
        assert!(bytes.len() > 100);
        assert_eq!(&bytes[0..4], &[0x50, 0x4B, 0x03, 0x04]);
    }
}
