// Nuclei Scanner Module
// Integration with ProjectDiscovery's Nuclei vulnerability scanner

pub mod parser;
pub mod runner;
pub mod templates;
pub mod types;

pub use parser::{parse_nuclei_output, parse_nuclei_results, result_to_vulnerability};
pub use runner::{
    check_nuclei_available, get_nuclei_version, get_templates_path, run_nuclei_scan,
    update_templates, CancellationToken,
};
pub use templates::{
    get_template, get_template_content, get_template_stats, get_templates_for_cve, list_tags,
    list_templates, search_templates,
};
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nuclei_availability_check() {
        // Just verify the function doesn't panic
        let _ = check_nuclei_available();
    }

    #[test]
    fn test_templates_path() {
        let path = get_templates_path();
        // Should be a valid path (may or may not exist)
        assert!(!path.to_string_lossy().is_empty());
    }
}
