#![allow(dead_code)]
//! Suricata/Snort Rule Parser
//!
//! This module parses IDS rules in Suricata/Snort format. It supports:
//! - Standard rule header (action, protocol, addresses, ports, direction)
//! - Common options (msg, content, sid, rev, classtype, priority, reference)
//! - Content modifiers (nocase, depth, offset, distance, within)
//! - PCRE patterns
//! - Byte tests and byte jumps
//! - Flowbits
//! - Metadata

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use std::sync::LazyLock;

use super::{
    ByteJump, ByteOrder, ByteTest, ByteTestOperator, ContentMatch, Flowbits, FlowbitsOp,
    IdsAddress, IdsDirection, IdsPort, IdsProtocol, IdsRule, IdsRuleAction, NumberBase,
    PcreMatch, RuleClasstype, RuleMetadata, RuleReference, ThresholdConfig, ThresholdType,
};

// =============================================================================
// Static Regex Patterns
// =============================================================================

static RULE_HEADER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^
        \s*
        (\w+)           # Action (alert, drop, pass, etc.)
        \s+
        (\w+)           # Protocol (tcp, udp, icmp, etc.)
        \s+
        ([^\s]+)        # Source address
        \s+
        ([^\s]+)        # Source port
        \s+
        (->|<>)         # Direction
        \s+
        ([^\s]+)        # Destination address
        \s+
        ([^\s]+)        # Destination port
        \s*
        \(              # Start of options
        (.*)            # Options
        \)\s*$          # End of options
        "
    ).expect("Failed to compile rule header regex")
});

static CONTENT_HEX_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\|([0-9a-fA-F\s]+)\|").expect("Failed to compile content hex regex")
});

static OPTION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*:\s*"?([^";]*)"?\s*;"#).expect("Failed to compile option regex")
});

// =============================================================================
// Parser Implementation
// =============================================================================

/// Rule parser with configuration
#[derive(Debug, Clone, Default)]
pub struct RuleParser {
    /// Custom variables for address/port substitution
    pub variables: std::collections::HashMap<String, String>,
    /// Whether to be strict about unknown options
    pub strict: bool,
    /// Default classtype priorities
    pub classtype_priorities: std::collections::HashMap<String, u8>,
}

impl RuleParser {
    /// Create a new rule parser with default settings
    pub fn new() -> Self {
        let mut classtype_priorities = std::collections::HashMap::new();

        // Default classtype priorities (1 = highest, 4 = lowest)
        classtype_priorities.insert("attempted-admin".to_string(), 1);
        classtype_priorities.insert("successful-admin".to_string(), 1);
        classtype_priorities.insert("attempted-user".to_string(), 1);
        classtype_priorities.insert("successful-user".to_string(), 1);
        classtype_priorities.insert("attempted-recon".to_string(), 2);
        classtype_priorities.insert("successful-recon-limited".to_string(), 2);
        classtype_priorities.insert("trojan-activity".to_string(), 1);
        classtype_priorities.insert("malware-cnc".to_string(), 1);
        classtype_priorities.insert("exploit-attempt".to_string(), 1);
        classtype_priorities.insert("policy-violation".to_string(), 2);
        classtype_priorities.insert("web-application-attack".to_string(), 1);
        classtype_priorities.insert("misc-attack".to_string(), 2);
        classtype_priorities.insert("denial-of-service".to_string(), 2);
        classtype_priorities.insert("suspicious-activity".to_string(), 2);
        classtype_priorities.insert("bad-unknown".to_string(), 2);
        classtype_priorities.insert("not-suspicious".to_string(), 3);
        classtype_priorities.insert("protocol-command-decode".to_string(), 3);
        classtype_priorities.insert("misc-activity".to_string(), 3);
        classtype_priorities.insert("default-login-attempt".to_string(), 2);
        classtype_priorities.insert("credential-theft".to_string(), 1);
        classtype_priorities.insert("shellcode-detect".to_string(), 1);

        Self {
            variables: std::collections::HashMap::new(),
            strict: false,
            classtype_priorities,
        }
    }

    /// Add a variable substitution
    pub fn add_variable(&mut self, name: &str, value: &str) {
        self.variables.insert(name.to_string(), value.to_string());
    }

    /// Parse a single rule
    pub fn parse(&self, rule_text: &str) -> Result<IdsRule> {
        let rule_text = rule_text.trim();

        // Skip comments and empty lines
        if rule_text.is_empty() || rule_text.starts_with('#') {
            bail!("Empty or comment line");
        }

        // Match rule header
        let captures = RULE_HEADER_REGEX.captures(rule_text)
            .ok_or_else(|| anyhow!("Failed to parse rule header: {}", rule_text))?;

        let action = captures.get(1).unwrap().as_str().parse::<IdsRuleAction>()?;
        let protocol = captures.get(2).unwrap().as_str().parse::<IdsProtocol>()?;
        let src_addr = self.parse_address(captures.get(3).unwrap().as_str())?;
        let src_port = self.parse_port(captures.get(4).unwrap().as_str())?;
        let direction = match captures.get(5).unwrap().as_str() {
            "->" => IdsDirection::Unidirectional,
            "<>" => IdsDirection::Bidirectional,
            d => bail!("Unknown direction: {}", d),
        };
        let dst_addr = self.parse_address(captures.get(6).unwrap().as_str())?;
        let dst_port = self.parse_port(captures.get(7).unwrap().as_str())?;
        let options_str = captures.get(8).unwrap().as_str();

        // Parse options
        let mut rule = IdsRule {
            action,
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            direction,
            raw_rule: rule_text.to_string(),
            ..Default::default()
        };

        self.parse_options(&mut rule, options_str)?;

        Ok(rule)
    }

    /// Parse address specification
    fn parse_address(&self, addr_str: &str) -> Result<IdsAddress> {
        let addr_str = addr_str.trim();

        // Check for negation
        if addr_str.starts_with('!') {
            let inner = self.parse_address(&addr_str[1..])?;
            return Ok(IdsAddress::Negated(Box::new(inner)));
        }

        // Check for group
        if addr_str.starts_with('[') && addr_str.ends_with(']') {
            let inner = &addr_str[1..addr_str.len() - 1];
            let addrs: Result<Vec<_>> = inner
                .split(',')
                .map(|s| self.parse_address(s.trim()))
                .collect();
            return Ok(IdsAddress::Group(addrs?));
        }

        // Check for variable
        if addr_str.starts_with('$') {
            return Ok(IdsAddress::Variable(addr_str.to_string()));
        }

        // Check for "any"
        if addr_str.eq_ignore_ascii_case("any") {
            return Ok(IdsAddress::Any);
        }

        // Check for CIDR notation
        if addr_str.contains('/') {
            return Ok(IdsAddress::Cidr(addr_str.to_string()));
        }

        // Try to parse as IP address
        if let Ok(ip) = addr_str.parse() {
            return Ok(IdsAddress::Ip(ip));
        }

        // Treat as CIDR or hostname
        Ok(IdsAddress::Cidr(addr_str.to_string()))
    }

    /// Parse port specification
    fn parse_port(&self, port_str: &str) -> Result<IdsPort> {
        let port_str = port_str.trim();

        // Check for negation
        if port_str.starts_with('!') {
            let inner = self.parse_port(&port_str[1..])?;
            return Ok(IdsPort::Negated(Box::new(inner)));
        }

        // Check for group
        if port_str.starts_with('[') && port_str.ends_with(']') {
            let inner = &port_str[1..port_str.len() - 1];
            let ports: Result<Vec<_>> = inner
                .split(',')
                .map(|s| self.parse_port(s.trim()))
                .collect();
            return Ok(IdsPort::Group(ports?));
        }

        // Check for variable
        if port_str.starts_with('$') {
            return Ok(IdsPort::Variable(port_str.to_string()));
        }

        // Check for "any"
        if port_str.eq_ignore_ascii_case("any") {
            return Ok(IdsPort::Any);
        }

        // Check for range
        if port_str.contains(':') {
            let parts: Vec<&str> = port_str.split(':').collect();
            if parts.len() == 2 {
                let start = if parts[0].is_empty() { 0 } else { parts[0].parse()? };
                let end = if parts[1].is_empty() { 65535 } else { parts[1].parse()? };
                return Ok(IdsPort::Range(start, end));
            }
        }

        // Parse as single port
        let port: u16 = port_str.parse()
            .context(format!("Failed to parse port: {}", port_str))?;
        Ok(IdsPort::Single(port))
    }

    /// Parse rule options
    fn parse_options(&self, rule: &mut IdsRule, options_str: &str) -> Result<()> {
        // We need to handle the complex option parsing with proper state tracking
        let mut current_content: Option<ContentMatch> = None;
        let mut i = 0;
        let chars: Vec<char> = options_str.chars().collect();

        while i < chars.len() {
            // Skip whitespace
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }

            if i >= chars.len() {
                break;
            }

            // Parse option name
            let name_start = i;
            while i < chars.len() && chars[i] != ':' && chars[i] != ';' && !chars[i].is_whitespace() {
                i += 1;
            }
            let name = options_str[name_start..i].trim().to_lowercase();

            // Skip whitespace and colon
            while i < chars.len() && (chars[i].is_whitespace() || chars[i] == ':') {
                i += 1;
            }

            // Parse value (may be quoted, may contain semicolons in quotes)
            let value = if i < chars.len() && chars[i] != ';' {
                let value_start = i;
                let mut in_quotes = false;
                let mut escape_next = false;

                while i < chars.len() {
                    if escape_next {
                        escape_next = false;
                        i += 1;
                        continue;
                    }

                    if chars[i] == '\\' {
                        escape_next = true;
                        i += 1;
                        continue;
                    }

                    if chars[i] == '"' {
                        in_quotes = !in_quotes;
                        i += 1;
                        continue;
                    }

                    if !in_quotes && chars[i] == ';' {
                        break;
                    }

                    i += 1;
                }

                let value = options_str[value_start..i].trim();
                // Remove surrounding quotes if present
                if value.starts_with('"') && value.ends_with('"') && value.len() > 1 {
                    value[1..value.len() - 1].to_string()
                } else {
                    value.to_string()
                }
            } else {
                String::new()
            };

            // Skip the semicolon
            if i < chars.len() && chars[i] == ';' {
                i += 1;
            }

            // Process the option
            if !name.is_empty() {
                self.process_option(rule, &name, &value, &mut current_content)?;
            }
        }

        // Add any remaining content match
        if let Some(content) = current_content {
            rule.content_matches.push(content);
        }

        Ok(())
    }

    /// Process a single option
    fn process_option(
        &self,
        rule: &mut IdsRule,
        name: &str,
        value: &str,
        current_content: &mut Option<ContentMatch>,
    ) -> Result<()> {
        match name {
            "msg" => {
                rule.msg = value.to_string();
            }
            "sid" => {
                rule.sid = value.parse().context("Failed to parse SID")?;
            }
            "rev" => {
                rule.rev = value.parse().context("Failed to parse revision")?;
            }
            "classtype" => {
                let priority = self.classtype_priorities.get(value).copied().unwrap_or(3);
                rule.classtype = Some(RuleClasstype {
                    name: value.to_string(),
                    priority,
                });
            }
            "priority" => {
                rule.priority = Some(value.parse().context("Failed to parse priority")?);
            }
            "reference" => {
                if let Some((ref_type, ref_value)) = value.split_once(',') {
                    rule.references.push(RuleReference {
                        ref_type: ref_type.trim().to_string(),
                        value: ref_value.trim().to_string(),
                    });
                }
            }
            "content" => {
                // Save previous content if any
                if let Some(content) = current_content.take() {
                    rule.content_matches.push(content);
                }

                // Parse new content
                let pattern = self.parse_content_pattern(value)?;
                let negated = value.starts_with('!');

                *current_content = Some(ContentMatch {
                    pattern,
                    negated,
                    ..Default::default()
                });
            }
            "nocase" => {
                if let Some(ref mut content) = current_content {
                    content.nocase = true;
                }
            }
            "depth" => {
                if let Some(ref mut content) = current_content {
                    content.depth = Some(value.parse()?);
                }
            }
            "offset" => {
                if let Some(ref mut content) = current_content {
                    content.offset = Some(value.parse()?);
                }
            }
            "distance" => {
                if let Some(ref mut content) = current_content {
                    content.distance = Some(value.parse()?);
                }
            }
            "within" => {
                if let Some(ref mut content) = current_content {
                    content.within = Some(value.parse()?);
                }
            }
            "fast_pattern" => {
                if let Some(ref mut content) = current_content {
                    content.fast_pattern = true;
                }
            }
            "pcre" => {
                // Save any pending content
                if let Some(content) = current_content.take() {
                    rule.content_matches.push(content);
                }

                let pcre = self.parse_pcre(value)?;
                rule.pcre_matches.push(pcre);
            }
            "byte_test" => {
                let byte_test = self.parse_byte_test(value)?;
                rule.byte_tests.push(byte_test);
            }
            "byte_jump" => {
                let byte_jump = self.parse_byte_jump(value)?;
                rule.byte_jumps.push(byte_jump);
            }
            "flowbits" => {
                let flowbits = self.parse_flowbits(value)?;
                rule.flowbits.push(flowbits);
            }
            "flow" => {
                rule.flow = Some(value.to_string());
            }
            "threshold" | "detection_filter" => {
                rule.threshold = Some(self.parse_threshold(value)?);
            }
            "metadata" => {
                self.parse_metadata(rule, value)?;
            }
            "tag" => {
                rule.tags.push(value.to_string());
            }
            "target" => {
                rule.target = Some(value.to_string());
            }
            // Ignore unknown options in non-strict mode
            _ => {
                if self.strict {
                    bail!("Unknown option: {}", name);
                }
            }
        }

        Ok(())
    }

    /// Parse content pattern (handles hex encoding)
    fn parse_content_pattern(&self, value: &str) -> Result<Vec<u8>> {
        let value = value.trim();
        let value = if value.starts_with('!') {
            &value[1..]
        } else {
            value
        };
        let value = value.trim().trim_matches('"');

        let mut result = Vec::new();
        let mut i = 0;
        let chars: Vec<char> = value.chars().collect();

        while i < chars.len() {
            if chars[i] == '|' {
                // Hex-encoded section
                i += 1;
                let mut hex_str = String::new();
                while i < chars.len() && chars[i] != '|' {
                    if !chars[i].is_whitespace() {
                        hex_str.push(chars[i]);
                    }
                    i += 1;
                }
                if i < chars.len() {
                    i += 1; // Skip closing |
                }

                // Decode hex
                let bytes = hex::decode(&hex_str)
                    .context(format!("Failed to decode hex: {}", hex_str))?;
                result.extend(bytes);
            } else if chars[i] == '\\' {
                // Escape sequence
                i += 1;
                if i < chars.len() {
                    match chars[i] {
                        'n' => result.push(b'\n'),
                        'r' => result.push(b'\r'),
                        't' => result.push(b'\t'),
                        '\\' => result.push(b'\\'),
                        '"' => result.push(b'"'),
                        ';' => result.push(b';'),
                        'x' => {
                            // \xNN hex escape
                            if i + 2 < chars.len() {
                                let hex: String = chars[i + 1..i + 3].iter().collect();
                                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                    result.push(byte);
                                    i += 2;
                                }
                            }
                        }
                        _ => {
                            result.push(b'\\');
                            result.push(chars[i] as u8);
                        }
                    }
                    i += 1;
                }
            } else {
                result.push(chars[i] as u8);
                i += 1;
            }
        }

        Ok(result)
    }

    /// Parse PCRE pattern
    fn parse_pcre(&self, value: &str) -> Result<PcreMatch> {
        let value = value.trim().trim_matches('"');

        // Format: /pattern/flags or !/pattern/flags for negated
        let negated = value.starts_with('!');
        let value = if negated { &value[1..] } else { value };

        // Find the pattern delimiters
        if !value.starts_with('/') {
            bail!("PCRE must start with /");
        }

        // Find the closing delimiter (handle escaped /)
        let mut end_idx = None;
        let chars: Vec<char> = value.chars().collect();
        let mut i = 1;
        let mut escape_next = false;

        while i < chars.len() {
            if escape_next {
                escape_next = false;
                i += 1;
                continue;
            }
            if chars[i] == '\\' {
                escape_next = true;
                i += 1;
                continue;
            }
            if chars[i] == '/' {
                end_idx = Some(i);
                break;
            }
            i += 1;
        }

        let end_idx = end_idx.ok_or_else(|| anyhow!("PCRE missing closing /"))?;
        let pattern = value[1..end_idx].to_string();
        let flags = value[end_idx + 1..].to_string();

        let relative = flags.contains('R');

        Ok(PcreMatch {
            pattern,
            flags: flags.replace('R', ""), // Remove relative flag
            negated,
            relative,
        })
    }

    /// Parse byte_test option
    fn parse_byte_test(&self, value: &str) -> Result<ByteTest> {
        let parts: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
        if parts.len() < 4 {
            bail!("byte_test requires at least 4 arguments");
        }

        let bytes: u32 = parts[0].parse()?;
        let operator = match parts[1] {
            "=" | "==" => ByteTestOperator::Equal,
            "!=" | "!" => ByteTestOperator::NotEqual,
            "<" => ByteTestOperator::Less,
            "<=" => ByteTestOperator::LessOrEqual,
            ">" => ByteTestOperator::Greater,
            ">=" => ByteTestOperator::GreaterOrEqual,
            "&" => ByteTestOperator::And,
            "|" | "^" => ByteTestOperator::Or,
            _ => bail!("Unknown byte_test operator: {}", parts[1]),
        };
        let value_num: u64 = if parts[2].starts_with("0x") {
            u64::from_str_radix(&parts[2][2..], 16)?
        } else {
            parts[2].parse()?
        };
        let offset: i32 = parts[3].parse()?;

        let mut byte_test = ByteTest {
            bytes,
            operator,
            value: value_num,
            offset,
            relative: false,
            endian: ByteOrder::Big,
            base: NumberBase::Decimal,
            bitmask: None,
        };

        // Parse optional flags
        for part in &parts[4..] {
            match *part {
                "relative" => byte_test.relative = true,
                "big" => byte_test.endian = ByteOrder::Big,
                "little" => byte_test.endian = ByteOrder::Little,
                "string" | "dec" => byte_test.base = NumberBase::Decimal,
                "hex" => byte_test.base = NumberBase::Hexadecimal,
                "oct" => byte_test.base = NumberBase::Octal,
                s if s.starts_with("bitmask ") => {
                    let mask_str = s.strip_prefix("bitmask ").unwrap();
                    byte_test.bitmask = Some(mask_str.parse()?);
                }
                _ => {}
            }
        }

        Ok(byte_test)
    }

    /// Parse byte_jump option
    fn parse_byte_jump(&self, value: &str) -> Result<ByteJump> {
        let parts: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
        if parts.len() < 2 {
            bail!("byte_jump requires at least 2 arguments");
        }

        let bytes: u32 = parts[0].parse()?;
        let offset: i32 = parts[1].parse()?;

        let mut byte_jump = ByteJump {
            bytes,
            offset,
            relative: false,
            multiplier: 1,
            endian: ByteOrder::Big,
            base: NumberBase::Decimal,
            from_beginning: false,
            align: false,
            bitmask: None,
        };

        // Parse optional flags
        for part in &parts[2..] {
            match *part {
                "relative" => byte_jump.relative = true,
                "from_beginning" => byte_jump.from_beginning = true,
                "align" => byte_jump.align = true,
                "big" => byte_jump.endian = ByteOrder::Big,
                "little" => byte_jump.endian = ByteOrder::Little,
                "string" | "dec" => byte_jump.base = NumberBase::Decimal,
                "hex" => byte_jump.base = NumberBase::Hexadecimal,
                "oct" => byte_jump.base = NumberBase::Octal,
                s if s.starts_with("multiplier ") => {
                    let mult_str = s.strip_prefix("multiplier ").unwrap();
                    byte_jump.multiplier = mult_str.parse()?;
                }
                s if s.starts_with("bitmask ") => {
                    let mask_str = s.strip_prefix("bitmask ").unwrap();
                    byte_jump.bitmask = Some(mask_str.parse()?);
                }
                _ => {}
            }
        }

        Ok(byte_jump)
    }

    /// Parse flowbits option
    fn parse_flowbits(&self, value: &str) -> Result<Flowbits> {
        let parts: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
        if parts.is_empty() {
            bail!("flowbits requires at least an operation");
        }

        let operation = match parts[0].to_lowercase().as_str() {
            "set" => FlowbitsOp::Set,
            "unset" => FlowbitsOp::Unset,
            "toggle" => FlowbitsOp::Toggle,
            "isset" => FlowbitsOp::IsSet,
            "isnotset" => FlowbitsOp::IsNotSet,
            "noalert" => FlowbitsOp::NoAlert,
            _ => bail!("Unknown flowbits operation: {}", parts[0]),
        };

        let names = if parts.len() > 1 {
            parts[1..].iter().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        };

        Ok(Flowbits {
            operation,
            names,
            group: None,
        })
    }

    /// Parse threshold/detection_filter
    fn parse_threshold(&self, value: &str) -> Result<ThresholdConfig> {
        let mut threshold_type = ThresholdType::Threshold;
        let mut track = "by_src".to_string();
        let mut count = 1;
        let mut seconds = 60;

        for part in value.split(',').map(|s| s.trim()) {
            if let Some((key, val)) = part.split_once(' ') {
                match key.trim() {
                    "type" => {
                        threshold_type = match val.trim() {
                            "limit" => ThresholdType::Limit,
                            "threshold" => ThresholdType::Threshold,
                            "both" => ThresholdType::Both,
                            _ => ThresholdType::Threshold,
                        };
                    }
                    "track" => {
                        track = val.trim().to_string();
                    }
                    "count" => {
                        count = val.trim().parse()?;
                    }
                    "seconds" => {
                        seconds = val.trim().parse()?;
                    }
                    _ => {}
                }
            }
        }

        Ok(ThresholdConfig {
            threshold_type,
            track,
            count,
            seconds,
        })
    }

    /// Parse metadata options
    fn parse_metadata(&self, rule: &mut IdsRule, value: &str) -> Result<()> {
        for part in value.split(',').map(|s| s.trim()) {
            if let Some((key, val)) = part.split_once(' ') {
                let key = key.trim().to_string();
                let val = val.trim().to_string();

                match key.as_str() {
                    "mitre_tactic_id" => {
                        rule.mitre_tactics.push(val);
                    }
                    "mitre_technique_id" => {
                        rule.mitre_techniques.push(val);
                    }
                    _ => {
                        rule.metadata.push(RuleMetadata { key, value: val });
                    }
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// Public Parsing Functions
// =============================================================================

/// Parse a single IDS rule from text
pub fn parse_rule(rule_text: &str) -> Result<IdsRule> {
    let parser = RuleParser::new();
    parser.parse(rule_text)
}

/// Parse multiple IDS rules from text (one rule per line)
pub fn parse_ruleset(rules_text: &str) -> Result<Vec<IdsRule>> {
    let parser = RuleParser::new();
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    for (line_num, line) in rules_text.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parser.parse(line) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(format!("Line {}: {}", line_num + 1, e)),
        }
    }

    if rules.is_empty() && !errors.is_empty() {
        bail!("Failed to parse any rules:\n{}", errors.join("\n"));
    }

    Ok(rules)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let rule_text = r#"alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1000001; rev:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.action, IdsRuleAction::Alert);
        assert_eq!(rule.protocol, IdsProtocol::Tcp);
        assert_eq!(rule.src_addr, IdsAddress::Any);
        assert_eq!(rule.src_port, IdsPort::Any);
        assert_eq!(rule.dst_port, IdsPort::Single(80));
        assert_eq!(rule.msg, "HTTP GET Request");
        assert_eq!(rule.sid, 1000001);
        assert_eq!(rule.rev, 1);
        assert_eq!(rule.content_matches.len(), 1);
        assert_eq!(rule.content_matches[0].pattern, b"GET".to_vec());
    }

    #[test]
    fn test_parse_complex_rule() {
        let rule_text = r#"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware C2 Beacon"; flow:established,to_server; content:"POST"; http_method; content:"/beacon"; http_uri; pcre:"/[a-f0-9]{32}/i"; sid:2000001; rev:1; classtype:trojan-activity; reference:cve,2021-1234; priority:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.action, IdsRuleAction::Alert);
        assert_eq!(rule.protocol, IdsProtocol::Http);
        assert_eq!(rule.msg, "Malware C2 Beacon");
        assert_eq!(rule.sid, 2000001);
        assert_eq!(rule.priority, Some(1));
        assert!(rule.classtype.is_some());
        assert_eq!(rule.classtype.as_ref().unwrap().name, "trojan-activity");
        assert_eq!(rule.references.len(), 1);
        assert_eq!(rule.references[0].ref_type, "cve");
        assert_eq!(rule.references[0].value, "2021-1234");
    }

    #[test]
    fn test_parse_hex_content() {
        let rule_text = r#"alert tcp any any -> any any (msg:"Hex Test"; content:"|90 90 90 90|"; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.content_matches[0].pattern, vec![0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_parse_mixed_content() {
        // "GET|20|/" means "GET" + hex space (0x20) + "/" = "GET /"
        let rule_text = r#"alert tcp any any -> any any (msg:"Mixed Test"; content:"GET|20|/"; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.content_matches[0].pattern, b"GET /".to_vec());
    }

    #[test]
    fn test_parse_content_modifiers() {
        let rule_text = r#"alert tcp any any -> any any (msg:"Modifier Test"; content:"test"; nocase; depth:100; offset:10; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        let content = &rule.content_matches[0];
        assert!(content.nocase);
        assert_eq!(content.depth, Some(100));
        assert_eq!(content.offset, Some(10));
    }

    #[test]
    fn test_parse_pcre() {
        let rule_text = r#"alert tcp any any -> any any (msg:"PCRE Test"; pcre:"/user[0-9]+/i"; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.pcre_matches.len(), 1);
        assert_eq!(rule.pcre_matches[0].pattern, "user[0-9]+");
        assert_eq!(rule.pcre_matches[0].flags, "i");
    }

    #[test]
    fn test_parse_address() {
        let parser = RuleParser::new();

        assert_eq!(parser.parse_address("any").unwrap(), IdsAddress::Any);
        assert_eq!(
            parser.parse_address("192.168.1.0/24").unwrap(),
            IdsAddress::Cidr("192.168.1.0/24".to_string())
        );
        assert_eq!(
            parser.parse_address("$HOME_NET").unwrap(),
            IdsAddress::Variable("$HOME_NET".to_string())
        );

        if let IdsAddress::Negated(inner) = parser.parse_address("!192.168.1.0/24").unwrap() {
            assert_eq!(*inner, IdsAddress::Cidr("192.168.1.0/24".to_string()));
        } else {
            panic!("Expected negated address");
        }
    }

    #[test]
    fn test_parse_port() {
        let parser = RuleParser::new();

        assert_eq!(parser.parse_port("any").unwrap(), IdsPort::Any);
        assert_eq!(parser.parse_port("80").unwrap(), IdsPort::Single(80));
        assert_eq!(parser.parse_port("1:1024").unwrap(), IdsPort::Range(1, 1024));
        assert_eq!(
            parser.parse_port("$HTTP_PORTS").unwrap(),
            IdsPort::Variable("$HTTP_PORTS".to_string())
        );
    }

    #[test]
    fn test_parse_ruleset() {
        let rules_text = r#"
# Comment line
alert tcp any any -> any 80 (msg:"Rule 1"; sid:1; rev:1;)

# Another comment
alert tcp any any -> any 443 (msg:"Rule 2"; sid:2; rev:1;)
"#;

        let rules = parse_ruleset(rules_text).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].sid, 1);
        assert_eq!(rules[1].sid, 2);
    }

    #[test]
    fn test_parse_flowbits() {
        let rule_text = r#"alert tcp any any -> any any (msg:"Flowbits Test"; flowbits:set,test.flag; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.flowbits.len(), 1);
        assert_eq!(rule.flowbits[0].operation, FlowbitsOp::Set);
        assert_eq!(rule.flowbits[0].names, vec!["test.flag"]);
    }

    #[test]
    fn test_parse_byte_test() {
        let rule_text = r#"alert tcp any any -> any any (msg:"Byte Test"; byte_test:4,>,1000,0,relative; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert_eq!(rule.byte_tests.len(), 1);
        assert_eq!(rule.byte_tests[0].bytes, 4);
        assert_eq!(rule.byte_tests[0].operator, ByteTestOperator::Greater);
        assert_eq!(rule.byte_tests[0].value, 1000);
        assert!(rule.byte_tests[0].relative);
    }

    #[test]
    fn test_parse_metadata() {
        let rule_text = r#"alert tcp any any -> any any (msg:"Metadata Test"; metadata:mitre_tactic_id TA0001, mitre_technique_id T1190, created_at 2024-01-01; sid:1;)"#;
        let rule = parse_rule(rule_text).unwrap();

        assert!(rule.mitre_tactics.contains(&"TA0001".to_string()));
        assert!(rule.mitre_techniques.contains(&"T1190".to_string()));
        assert!(rule.metadata.iter().any(|m| m.key == "created_at"));
    }
}
