use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Query AST node types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum QueryNode {
    /// Field comparison: field:value
    FieldMatch {
        field: String,
        value: String,
        operator: MatchOperator,
    },
    /// Range query: field:[start TO end]
    Range {
        field: String,
        start: String,
        end: String,
    },
    /// Boolean AND operation
    And {
        left: Box<QueryNode>,
        right: Box<QueryNode>,
    },
    /// Boolean OR operation
    Or {
        left: Box<QueryNode>,
        right: Box<QueryNode>,
    },
    /// Boolean NOT operation
    Not {
        operand: Box<QueryNode>,
    },
    /// Grouped expression
    Group {
        expression: Box<QueryNode>,
    },
}

/// Match operators for field comparisons
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MatchOperator {
    Equals,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Contains,
    Regex,
}

/// Query DSL parser
pub struct QueryParser {
    input: String,
    position: usize,
}

impl QueryParser {
    /// Create a new parser for the given query string
    pub fn new(input: String) -> Self {
        Self { input, position: 0 }
    }

    /// Parse the query into an AST
    pub fn parse(&mut self) -> Result<QueryNode> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<QueryNode> {
        let mut left = self.parse_and()?;

        while self.peek_token() == Some("OR") {
            self.consume_token("OR")?;
            let right = self.parse_and()?;
            left = QueryNode::Or {
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<QueryNode> {
        let mut left = self.parse_not()?;

        while self.peek_token() == Some("AND") {
            self.consume_token("AND")?;
            let right = self.parse_not()?;
            left = QueryNode::And {
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    fn parse_not(&mut self) -> Result<QueryNode> {
        if self.peek_token() == Some("NOT") {
            self.consume_token("NOT")?;
            let operand = self.parse_primary()?;
            Ok(QueryNode::Not {
                operand: Box::new(operand),
            })
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<QueryNode> {
        self.skip_whitespace();

        // Check for grouped expression
        if self.peek_char() == Some('(') {
            self.consume_char('(')?;
            let expr = self.parse_or()?;
            self.consume_char(')')?;
            return Ok(QueryNode::Group {
                expression: Box::new(expr),
            });
        }

        // Parse field:value or field:[start TO end]
        let field = self.parse_identifier()?;
        self.consume_char(':')?;

        // Check for range query
        if self.peek_char() == Some('[') {
            self.consume_char('[')?;
            let start = self.parse_value()?;
            self.skip_whitespace();
            self.consume_token("TO")?;
            self.skip_whitespace();
            let end = self.parse_value()?;
            self.consume_char(']')?;
            return Ok(QueryNode::Range { field, start, end });
        }

        // Check for comparison operators
        let operator = if self.peek_char() == Some('>') {
            self.position += 1;
            if self.peek_char() == Some('=') {
                self.position += 1;
                MatchOperator::GreaterThanOrEqual
            } else {
                MatchOperator::GreaterThan
            }
        } else if self.peek_char() == Some('<') {
            self.position += 1;
            if self.peek_char() == Some('=') {
                self.position += 1;
                MatchOperator::LessThanOrEqual
            } else {
                MatchOperator::LessThan
            }
        } else {
            MatchOperator::Equals
        };

        let value = self.parse_value()?;

        Ok(QueryNode::FieldMatch {
            field,
            value,
            operator,
        })
    }

    fn parse_identifier(&mut self) -> Result<String> {
        self.skip_whitespace();
        let start = self.position;

        while let Some(ch) = self.peek_char() {
            if ch.is_alphanumeric() || ch == '_' || ch == '.' {
                self.position += 1;
            } else {
                break;
            }
        }

        if start == self.position {
            return Err(anyhow::anyhow!("Expected identifier at position {}", start));
        }

        Ok(self.input[start..self.position].to_string())
    }

    fn parse_value(&mut self) -> Result<String> {
        self.skip_whitespace();

        // Handle quoted strings
        if self.peek_char() == Some('"') {
            self.consume_char('"')?;
            let start = self.position;
            while let Some(ch) = self.peek_char() {
                if ch == '"' {
                    break;
                }
                self.position += 1;
            }
            let value = self.input[start..self.position].to_string();
            self.consume_char('"')?;
            return Ok(value);
        }

        // Handle unquoted values
        let start = self.position;
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() || ch == ')' || ch == ']' {
                break;
            }
            self.position += 1;
        }

        if start == self.position {
            return Err(anyhow::anyhow!("Expected value at position {}", start));
        }

        Ok(self.input[start..self.position].to_string())
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    fn consume_char(&mut self, expected: char) -> Result<()> {
        self.skip_whitespace();
        if self.peek_char() == Some(expected) {
            self.position += 1;
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Expected '{}' at position {}",
                expected,
                self.position
            ))
        }
    }

    fn peek_token(&self) -> Option<&str> {
        let start = self.position;
        let input = &self.input[start..];

        if input.starts_with("AND") {
            Some("AND")
        } else if input.starts_with("OR") {
            Some("OR")
        } else if input.starts_with("NOT") {
            Some("NOT")
        } else if input.starts_with("TO") {
            Some("TO")
        } else {
            None
        }
    }

    fn consume_token(&mut self, expected: &str) -> Result<()> {
        self.skip_whitespace();
        if self.peek_token() == Some(expected) {
            self.position += expected.len();
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Expected '{}' at position {}",
                expected,
                self.position
            ))
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.position += 1;
            } else {
                break;
            }
        }
    }
}

/// Query executor (stub implementation)
#[allow(dead_code)]
pub struct QueryExecutor {
    // TODO: Add data lake connection
}

impl QueryExecutor {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {}
    }

    /// Execute a parsed query against the data lake
    #[allow(dead_code)]
    pub async fn execute(&self, _ast: &QueryNode) -> Result<Vec<serde_json::Value>> {
        // TODO: Implement actual query execution
        // This would translate the AST to SQL/NoSQL queries against the data lake
        Ok(Vec::new())
    }
}

/// Query templates for common hunts
#[allow(dead_code)]
pub fn get_query_templates() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Failed Login Attempts", "source:auth AND event:login_failed AND count:>5"),
        ("Privilege Escalation", "source:security AND event:privilege_change AND (new_role:admin OR new_role:root)"),
        ("Suspicious PowerShell", "source:process AND process_name:powershell.exe AND (command_line:*encoded* OR command_line:*bypass*)"),
        ("Lateral Movement", "source:network AND (port:445 OR port:3389 OR port:22) AND src:internal AND dst:internal"),
        ("Data Exfiltration", "source:network AND bytes_out:>10000000 AND destination:external"),
        ("Beaconing", "source:network AND destination:external AND connection_count:>100"),
        ("Credential Dumping", "source:process AND (process_name:mimikatz.exe OR process_name:procdump.exe OR command_line:*lsass*)"),
        ("Unusual Parent-Child Process", "source:process AND parent_process:explorer.exe AND (child_process:cmd.exe OR child_process:powershell.exe)"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let mut parser = QueryParser::new("source:auth".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::FieldMatch { field, value, .. } => {
                assert_eq!(field, "source");
                assert_eq!(value, "auth");
            }
            _ => panic!("Expected FieldMatch"),
        }
    }

    #[test]
    fn test_parse_and_query() {
        let mut parser = QueryParser::new("source:auth AND event:login".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::And { .. } => {}
            _ => panic!("Expected And node"),
        }
    }

    #[test]
    fn test_parse_range_query() {
        let mut parser = QueryParser::new("time:[08:00 TO 18:00]".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::Range { field, start, end } => {
                assert_eq!(field, "time");
                assert_eq!(start, "08:00");
                assert_eq!(end, "18:00");
            }
            _ => panic!("Expected Range"),
        }
    }
}
