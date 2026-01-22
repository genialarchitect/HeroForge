use super::types::EnumDepth;
use std::path::Path;

pub struct WordlistManager {
    http_dirs_light: Vec<String>,
    http_dirs_aggressive: Vec<String>,
    http_files_light: Vec<String>,
    http_files_aggressive: Vec<String>,
    subdomains_light: Vec<String>,
    subdomains_aggressive: Vec<String>,
    db_users_light: Vec<String>,
    db_users_aggressive: Vec<String>,
    db_passwords_light: Vec<String>,
    db_passwords_aggressive: Vec<String>,
}

impl WordlistManager {
    pub fn new() -> Self {
        Self {
            http_dirs_light: parse_embedded_wordlist(include_str!("../../../wordlists/http_dirs_light.txt")),
            http_dirs_aggressive: parse_embedded_wordlist(include_str!("../../../wordlists/http_dirs_aggressive.txt")),
            http_files_light: parse_embedded_wordlist(include_str!("../../../wordlists/http_files_light.txt")),
            http_files_aggressive: parse_embedded_wordlist(include_str!("../../../wordlists/http_files_aggressive.txt")),
            subdomains_light: parse_embedded_wordlist(include_str!("../../../wordlists/subdomains_light.txt")),
            subdomains_aggressive: parse_embedded_wordlist(include_str!("../../../wordlists/subdomains_aggressive.txt")),
            db_users_light: parse_embedded_wordlist(include_str!("../../../wordlists/db_users_light.txt")),
            db_users_aggressive: parse_embedded_wordlist(include_str!("../../../wordlists/db_users_aggressive.txt")),
            db_passwords_light: parse_embedded_wordlist(include_str!("../../../wordlists/db_passwords_light.txt")),
            db_passwords_aggressive: parse_embedded_wordlist(include_str!("../../../wordlists/db_passwords_aggressive.txt")),
        }
    }

    pub fn get_http_dir_wordlist(&self, depth: EnumDepth) -> &[String] {
        match depth {
            EnumDepth::Passive => &[],
            EnumDepth::Light => &self.http_dirs_light,
            EnumDepth::Aggressive => &self.http_dirs_aggressive,
        }
    }

    pub fn get_http_file_wordlist(&self, depth: EnumDepth) -> &[String] {
        match depth {
            EnumDepth::Passive => &[],
            EnumDepth::Light => &self.http_files_light,
            EnumDepth::Aggressive => &self.http_files_aggressive,
        }
    }

    pub fn get_subdomain_wordlist(&self, depth: EnumDepth) -> &[String] {
        match depth {
            EnumDepth::Passive => &[],
            EnumDepth::Light => &self.subdomains_light,
            EnumDepth::Aggressive => &self.subdomains_aggressive,
        }
    }

    /// Get database username wordlist based on scan depth
    pub fn get_db_user_wordlist(&self, depth: EnumDepth) -> &[String] {
        match depth {
            EnumDepth::Passive => &[],
            EnumDepth::Light => &self.db_users_light,
            EnumDepth::Aggressive => &self.db_users_aggressive,
        }
    }

    /// Get database password wordlist based on scan depth
    pub fn get_db_password_wordlist(&self, depth: EnumDepth) -> &[String] {
        match depth {
            EnumDepth::Passive => &[],
            EnumDepth::Light => &self.db_passwords_light,
            EnumDepth::Aggressive => &self.db_passwords_aggressive,
        }
    }

    /// Generate credential pairs from username and password wordlists
    /// Always includes empty password as first attempt for each user
    pub fn get_db_credentials(&self, depth: EnumDepth) -> Vec<(String, String)> {
        let users = self.get_db_user_wordlist(depth);
        let passwords = self.get_db_password_wordlist(depth);

        let mut credentials = Vec::new();

        for user in users {
            // Always try empty password first
            credentials.push((user.clone(), String::new()));

            // Then try each password from the wordlist
            for password in passwords {
                credentials.push((user.clone(), password.clone()));
            }
        }

        credentials
    }

    pub fn load_custom_wordlist(path: &Path) -> anyhow::Result<Vec<String>> {
        let content = std::fs::read_to_string(path)?;
        Ok(parse_wordlist(&content))
    }
}

impl Default for WordlistManager {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_embedded_wordlist(content: &str) -> Vec<String> {
    parse_wordlist(content)
}

fn parse_wordlist(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| line.trim().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wordlist() {
        let content = "admin\n# comment\nlogin\n\napi\n";
        let wordlist = parse_wordlist(content);
        assert_eq!(wordlist, vec!["admin", "login", "api"]);
    }
}
