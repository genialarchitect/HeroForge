//! Matcher Engine
//!
//! Implements various matching strategies for template responses.

use super::types::*;
use log::debug;
use regex::Regex;
use std::collections::HashMap;

/// Response data for matching
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub raw: String,
    pub content_length: usize,
}

impl ResponseData {
    pub fn new(status: u16, headers: HashMap<String, String>, body: String) -> Self {
        let raw = format!(
            "HTTP/1.1 {} OK\r\n{}\r\n\r\n{}",
            status,
            headers
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\r\n"),
            body
        );
        let content_length = body.len();

        Self {
            status_code: Some(status),
            headers,
            body,
            raw,
            content_length,
        }
    }

    /// Get the part of response to match against
    pub fn get_part(&self, part: &MatchPart) -> &str {
        match part {
            MatchPart::Body => &self.body,
            MatchPart::Header => {
                // Return headers as string
                &self.raw // Simplified - in real impl would extract headers only
            }
            MatchPart::All => &self.raw,
            _ => &self.raw,
        }
    }
}

/// Match result
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub matched: bool,
    pub matcher_name: Option<String>,
    pub matched_values: Vec<String>,
}

impl MatchResult {
    pub fn success(name: Option<String>, values: Vec<String>) -> Self {
        Self {
            matched: true,
            matcher_name: name,
            matched_values: values,
        }
    }

    pub fn failure() -> Self {
        Self {
            matched: false,
            matcher_name: None,
            matched_values: Vec::new(),
        }
    }
}

/// Execute a single matcher against response data
pub fn execute_matcher(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    let result = match matcher.matcher_type {
        MatcherType::Word => match_words(matcher, response),
        MatcherType::Regex => match_regex(matcher, response),
        MatcherType::Binary => match_binary(matcher, response),
        MatcherType::Status => match_status(matcher, response),
        MatcherType::Size => match_size(matcher, response),
        MatcherType::Dsl => match_dsl(matcher, response),
    };

    // Handle negative matching
    if matcher.negative {
        MatchResult {
            matched: !result.matched,
            ..result
        }
    } else {
        result
    }
}

/// Execute multiple matchers with condition
pub fn execute_matchers(
    matchers: &[Matcher],
    condition: MatcherCondition,
    response: &ResponseData,
) -> MatchResult {
    if matchers.is_empty() {
        return MatchResult::failure();
    }

    let mut matched_any = false;
    let mut matched_all = true;
    let mut matched_values = Vec::new();
    let mut last_matcher_name = None;

    for matcher in matchers {
        // Skip internal matchers in final result
        if matcher.internal {
            continue;
        }

        let result = execute_matcher(matcher, response);

        if result.matched {
            matched_any = true;
            matched_values.extend(result.matched_values);
            last_matcher_name = matcher.name.clone().or(result.matcher_name);
        } else {
            matched_all = false;
        }

        // Short-circuit evaluation
        match condition {
            MatcherCondition::Or if matched_any => {
                return MatchResult::success(last_matcher_name, matched_values);
            }
            MatcherCondition::And if !matched_all => {
                return MatchResult::failure();
            }
            _ => {}
        }
    }

    match condition {
        MatcherCondition::Or => {
            if matched_any {
                MatchResult::success(last_matcher_name, matched_values)
            } else {
                MatchResult::failure()
            }
        }
        MatcherCondition::And => {
            if matched_all {
                MatchResult::success(last_matcher_name, matched_values)
            } else {
                MatchResult::failure()
            }
        }
    }
}

/// Match words in response
fn match_words(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    let content = response.get_part(&matcher.part);
    let content = if matcher.case_insensitive {
        content.to_lowercase()
    } else {
        content.to_string()
    };

    let mut matched_values = Vec::new();
    let mut matched = false;

    for word in &matcher.words {
        let word = if matcher.case_insensitive {
            word.to_lowercase()
        } else {
            word.clone()
        };

        if content.contains(&word) {
            matched_values.push(word);
            matched = true;

            if matcher.condition == MatcherCondition::Or {
                break;
            }
        } else if matcher.condition == MatcherCondition::And {
            return MatchResult::failure();
        }
    }

    if matched {
        MatchResult::success(matcher.name.clone(), matched_values)
    } else {
        MatchResult::failure()
    }
}

/// Match regex patterns in response
fn match_regex(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    let content = response.get_part(&matcher.part);
    let mut matched_values = Vec::new();
    let mut matched = false;

    for pattern in &matcher.regex {
        let regex = if matcher.case_insensitive {
            Regex::new(&format!("(?i){}", pattern))
        } else {
            Regex::new(pattern)
        };

        match regex {
            Ok(re) => {
                if let Some(captures) = re.captures(content) {
                    matched = true;

                    // Extract captured groups
                    for cap in captures.iter().skip(1).flatten() {
                        matched_values.push(cap.as_str().to_string());
                    }

                    // If no groups, add the full match
                    if matched_values.is_empty() {
                        if let Some(m) = captures.get(0) {
                            matched_values.push(m.as_str().to_string());
                        }
                    }

                    if matcher.condition == MatcherCondition::Or {
                        break;
                    }
                } else if matcher.condition == MatcherCondition::And {
                    return MatchResult::failure();
                }
            }
            Err(e) => {
                debug!("Invalid regex pattern '{}': {}", pattern, e);
                if matcher.condition == MatcherCondition::And {
                    return MatchResult::failure();
                }
            }
        }
    }

    if matched {
        MatchResult::success(matcher.name.clone(), matched_values)
    } else {
        MatchResult::failure()
    }
}

/// Match binary patterns in response
fn match_binary(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    let content = response.body.as_bytes();
    let mut matched = false;

    for hex_pattern in &matcher.binary {
        if let Ok(pattern_bytes) = hex::decode(hex_pattern.replace(" ", "")) {
            if contains_bytes(content, &pattern_bytes) {
                matched = true;
                if matcher.condition == MatcherCondition::Or {
                    break;
                }
            } else if matcher.condition == MatcherCondition::And {
                return MatchResult::failure();
            }
        }
    }

    if matched {
        MatchResult::success(matcher.name.clone(), vec![])
    } else {
        MatchResult::failure()
    }
}

/// Check if haystack contains needle bytes
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }

    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Match HTTP status codes
fn match_status(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    if let Some(status) = response.status_code {
        let matched = match matcher.condition {
            MatcherCondition::Or => matcher.status.contains(&status),
            MatcherCondition::And => matcher.status.iter().all(|&s| s == status),
        };

        if matched {
            MatchResult::success(matcher.name.clone(), vec![status.to_string()])
        } else {
            MatchResult::failure()
        }
    } else {
        MatchResult::failure()
    }
}

/// Match response size
fn match_size(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    let size = response.content_length;

    let matched = match matcher.condition {
        MatcherCondition::Or => matcher.size.contains(&size),
        MatcherCondition::And => matcher.size.iter().all(|&s| s == size),
    };

    if matched {
        MatchResult::success(matcher.name.clone(), vec![size.to_string()])
    } else {
        MatchResult::failure()
    }
}

/// Match DSL expressions
fn match_dsl(matcher: &Matcher, response: &ResponseData) -> MatchResult {
    // Create DSL context
    let mut context = DslContext::new();
    context.set("status_code", response.status_code.unwrap_or(0) as i64);
    context.set("content_length", response.content_length as i64);
    context.set_string("body", &response.body);
    context.set_string("all", &response.raw);

    // Add header values
    for (key, value) in &response.headers {
        context.set_string(&format!("header_{}", key.to_lowercase().replace("-", "_")), value);
    }

    let mut matched = false;

    for expr in &matcher.dsl {
        match evaluate_dsl(expr, &context) {
            Ok(result) => {
                if result {
                    matched = true;
                    if matcher.condition == MatcherCondition::Or {
                        break;
                    }
                } else if matcher.condition == MatcherCondition::And {
                    return MatchResult::failure();
                }
            }
            Err(e) => {
                debug!("DSL evaluation error for '{}': {}", expr, e);
                if matcher.condition == MatcherCondition::And {
                    return MatchResult::failure();
                }
            }
        }
    }

    if matched {
        MatchResult::success(matcher.name.clone(), vec![])
    } else {
        MatchResult::failure()
    }
}

/// DSL context for expression evaluation
#[derive(Debug, Default)]
pub struct DslContext {
    numbers: HashMap<String, i64>,
    strings: HashMap<String, String>,
}

impl DslContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: &str, value: i64) {
        self.numbers.insert(key.to_string(), value);
    }

    pub fn set_string(&mut self, key: &str, value: &str) {
        self.strings.insert(key.to_string(), value.to_string());
    }

    pub fn get_number(&self, key: &str) -> Option<i64> {
        self.numbers.get(key).copied()
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.strings.get(key).map(|s| s.as_str())
    }
}

/// Evaluate a DSL expression
pub fn evaluate_dsl(expr: &str, context: &DslContext) -> Result<bool, String> {
    let expr = expr.trim();

    // Handle common DSL patterns

    // contains(body, "string")
    if expr.starts_with("contains(") && expr.ends_with(")") {
        let inner = &expr[9..expr.len() - 1];
        let parts: Vec<&str> = inner.splitn(2, ',').collect();
        if parts.len() == 2 {
            let var = parts[0].trim();
            let needle = parts[1].trim().trim_matches('"');

            if let Some(haystack) = context.get_string(var) {
                return Ok(haystack.contains(needle));
            }
        }
        return Err(format!("Invalid contains expression: {}", expr));
    }

    // status_code == 200
    if let Some((left, right)) = expr.split_once("==") {
        let left = left.trim();
        let right = right.trim();

        if let Some(left_val) = context.get_number(left) {
            if let Ok(right_val) = right.parse::<i64>() {
                return Ok(left_val == right_val);
            }
        }

        if let Some(left_str) = context.get_string(left) {
            let right_str = right.trim_matches('"');
            return Ok(left_str == right_str);
        }
    }

    // status_code != 200
    if let Some((left, right)) = expr.split_once("!=") {
        let left = left.trim();
        let right = right.trim();

        if let Some(left_val) = context.get_number(left) {
            if let Ok(right_val) = right.parse::<i64>() {
                return Ok(left_val != right_val);
            }
        }
    }

    // status_code > 200
    if let Some((left, right)) = expr.split_once(">") {
        if !right.starts_with("=") {
            let left = left.trim();
            let right = right.trim();

            if let Some(left_val) = context.get_number(left) {
                if let Ok(right_val) = right.parse::<i64>() {
                    return Ok(left_val > right_val);
                }
            }
        }
    }

    // status_code >= 200
    if let Some((left, right)) = expr.split_once(">=") {
        let left = left.trim();
        let right = right.trim();

        if let Some(left_val) = context.get_number(left) {
            if let Ok(right_val) = right.parse::<i64>() {
                return Ok(left_val >= right_val);
            }
        }
    }

    // status_code < 400
    if let Some((left, right)) = expr.split_once("<") {
        if !right.starts_with("=") {
            let left = left.trim();
            let right = right.trim();

            if let Some(left_val) = context.get_number(left) {
                if let Ok(right_val) = right.parse::<i64>() {
                    return Ok(left_val < right_val);
                }
            }
        }
    }

    // status_code <= 400
    if let Some((left, right)) = expr.split_once("<=") {
        let left = left.trim();
        let right = right.trim();

        if let Some(left_val) = context.get_number(left) {
            if let Ok(right_val) = right.parse::<i64>() {
                return Ok(left_val <= right_val);
            }
        }
    }

    // len(body) > 100
    if expr.starts_with("len(") {
        if let Some(rest) = expr.strip_prefix("len(") {
            if let Some((var, comparison)) = rest.split_once(")") {
                let var = var.trim();
                let comparison = comparison.trim();

                let len = if let Some(s) = context.get_string(var) {
                    s.len() as i64
                } else {
                    return Err(format!("Unknown variable: {}", var));
                };

                // Parse comparison
                if let Some(right) = comparison.strip_prefix(">") {
                    let right = right.trim();
                    if let Some(right) = right.strip_prefix("=") {
                        if let Ok(val) = right.trim().parse::<i64>() {
                            return Ok(len >= val);
                        }
                    } else if let Ok(val) = right.parse::<i64>() {
                        return Ok(len > val);
                    }
                }
                if let Some(right) = comparison.strip_prefix("<") {
                    let right = right.trim();
                    if let Some(right) = right.strip_prefix("=") {
                        if let Ok(val) = right.trim().parse::<i64>() {
                            return Ok(len <= val);
                        }
                    } else if let Ok(val) = right.parse::<i64>() {
                        return Ok(len < val);
                    }
                }
                if let Some(right) = comparison.strip_prefix("==") {
                    if let Ok(val) = right.trim().parse::<i64>() {
                        return Ok(len == val);
                    }
                }
            }
        }
    }

    // Fallback: try to evaluate as boolean
    match expr.to_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("Unknown DSL expression: {}", expr)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_matcher() {
        let response = ResponseData::new(
            200,
            HashMap::new(),
            "Hello World, this is a test".to_string(),
        );

        let matcher = Matcher {
            matcher_type: MatcherType::Word,
            words: vec!["Hello".to_string(), "World".to_string()],
            condition: MatcherCondition::And,
            ..Default::default()
        };

        let result = execute_matcher(&matcher, &response);
        assert!(result.matched);
    }

    #[test]
    fn test_regex_matcher() {
        let response = ResponseData::new(
            200,
            HashMap::new(),
            "Version: 1.2.3".to_string(),
        );

        let matcher = Matcher {
            matcher_type: MatcherType::Regex,
            regex: vec![r"Version:\s+(\d+\.\d+\.\d+)".to_string()],
            ..Default::default()
        };

        let result = execute_matcher(&matcher, &response);
        assert!(result.matched);
        assert!(result.matched_values.contains(&"1.2.3".to_string()));
    }

    #[test]
    fn test_status_matcher() {
        let response = ResponseData::new(200, HashMap::new(), "OK".to_string());

        let matcher = Matcher {
            matcher_type: MatcherType::Status,
            status: vec![200, 201],
            condition: MatcherCondition::Or,
            ..Default::default()
        };

        let result = execute_matcher(&matcher, &response);
        assert!(result.matched);
    }

    #[test]
    fn test_dsl_contains() {
        let response = ResponseData::new(
            200,
            HashMap::new(),
            "admin panel access".to_string(),
        );

        let matcher = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["contains(body, \"admin\")".to_string()],
            ..Default::default()
        };

        let result = execute_matcher(&matcher, &response);
        assert!(result.matched);
    }

    #[test]
    fn test_negative_matcher() {
        let response = ResponseData::new(404, HashMap::new(), "Not Found".to_string());

        let matcher = Matcher {
            matcher_type: MatcherType::Status,
            status: vec![200],
            negative: true,
            ..Default::default()
        };

        let result = execute_matcher(&matcher, &response);
        assert!(result.matched); // 404 != 200, so negative match succeeds
    }

    #[test]
    fn test_case_insensitive() {
        let response = ResponseData::new(
            200,
            HashMap::new(),
            "HELLO WORLD".to_string(),
        );

        let matcher = Matcher {
            matcher_type: MatcherType::Word,
            words: vec!["hello".to_string()],
            case_insensitive: true,
            ..Default::default()
        };

        let result = execute_matcher(&matcher, &response);
        assert!(result.matched);
    }
}
