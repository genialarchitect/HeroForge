use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use chrono::{DateTime, Utc, Duration};
use regex::Regex;
use std::collections::HashMap;

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
    /// Wildcard match
    Wildcard {
        field: String,
        pattern: String,
    },
    /// In-list query: field:(val1 OR val2 OR val3)
    InList {
        field: String,
        values: Vec<String>,
    },
    /// Exists check
    Exists {
        field: String,
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
    StartsWith,
    EndsWith,
}

/// Query execution context with time bounds
#[derive(Debug, Clone)]
pub struct QueryContext {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub source_filter: Option<Vec<String>>,
    pub max_results: i64,
    pub offset: i64,
}

impl Default for QueryContext {
    fn default() -> Self {
        Self {
            start_time: Utc::now() - Duration::days(7),
            end_time: Utc::now(),
            source_filter: None,
            max_results: 1000,
            offset: 0,
        }
    }
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
        self.skip_whitespace();
        if self.is_at_end() {
            return Err(anyhow::anyhow!("Empty query"));
        }
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<QueryNode> {
        let mut left = self.parse_and()?;

        self.skip_whitespace();
        while self.peek_keyword("OR") {
            self.consume_keyword("OR")?;
            self.skip_whitespace();
            let right = self.parse_and()?;
            left = QueryNode::Or {
                left: Box::new(left),
                right: Box::new(right),
            };
            self.skip_whitespace();
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<QueryNode> {
        let mut left = self.parse_not()?;

        self.skip_whitespace();
        while self.peek_keyword("AND") {
            self.consume_keyword("AND")?;
            self.skip_whitespace();
            let right = self.parse_not()?;
            left = QueryNode::And {
                left: Box::new(left),
                right: Box::new(right),
            };
            self.skip_whitespace();
        }

        Ok(left)
    }

    fn parse_not(&mut self) -> Result<QueryNode> {
        self.skip_whitespace();
        if self.peek_keyword("NOT") {
            self.consume_keyword("NOT")?;
            self.skip_whitespace();
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
            self.skip_whitespace();
            self.consume_char(')')?;
            return Ok(QueryNode::Group {
                expression: Box::new(expr),
            });
        }

        // Check for _exists_:field
        if self.peek_keyword("_exists_") {
            self.consume_keyword("_exists_")?;
            self.consume_char(':')?;
            let field = self.parse_identifier()?;
            return Ok(QueryNode::Exists { field });
        }

        // Parse field:value or field:[start TO end]
        let field = self.parse_identifier()?;
        self.consume_char(':')?;

        // Check for in-list query: field:(val1 OR val2)
        if self.peek_char() == Some('(') {
            self.consume_char('(')?;
            let mut values = vec![self.parse_value()?];
            self.skip_whitespace();
            while self.peek_keyword("OR") {
                self.consume_keyword("OR")?;
                self.skip_whitespace();
                values.push(self.parse_value()?);
                self.skip_whitespace();
            }
            self.consume_char(')')?;
            return Ok(QueryNode::InList { field, values });
        }

        // Check for range query
        if self.peek_char() == Some('[') {
            self.consume_char('[')?;
            self.skip_whitespace();
            let start = self.parse_range_value()?;
            self.skip_whitespace();
            self.consume_keyword("TO")?;
            self.skip_whitespace();
            let end = self.parse_range_value()?;
            self.skip_whitespace();
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

        // Check for wildcard
        if value.contains('*') {
            return Ok(QueryNode::Wildcard {
                field,
                pattern: value,
            });
        }

        // Check for regex (starts with /)
        if value.starts_with('/') && value.ends_with('/') && value.len() > 2 {
            return Ok(QueryNode::FieldMatch {
                field,
                value: value[1..value.len()-1].to_string(),
                operator: MatchOperator::Regex,
            });
        }

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
            if ch.is_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
                self.position += ch.len_utf8();
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
                if ch == '\\' {
                    self.position += 1;
                    if self.peek_char().is_some() {
                        self.position += 1;
                    }
                } else {
                    self.position += ch.len_utf8();
                }
            }
            let value = self.input[start..self.position].to_string();
            self.consume_char('"')?;
            return Ok(value);
        }

        // Handle regex patterns
        if self.peek_char() == Some('/') {
            let start = self.position;
            self.position += 1;
            while let Some(ch) = self.peek_char() {
                self.position += ch.len_utf8();
                if ch == '/' {
                    break;
                }
            }
            return Ok(self.input[start..self.position].to_string());
        }

        // Handle unquoted values
        let start = self.position;
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() || ch == ')' || ch == ']' || ch == '(' {
                break;
            }
            self.position += ch.len_utf8();
        }

        if start == self.position {
            return Err(anyhow::anyhow!("Expected value at position {}", start));
        }

        Ok(self.input[start..self.position].to_string())
    }

    fn parse_range_value(&mut self) -> Result<String> {
        self.skip_whitespace();

        // Handle special values
        if self.peek_char() == Some('*') {
            self.position += 1;
            return Ok("*".to_string());
        }

        // Parse until TO or ]
        let start = self.position;
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() || ch == ']' {
                break;
            }
            // Stop if we see "TO"
            if &self.input[self.position..] == "TO" || self.input[self.position..].starts_with("TO ") {
                break;
            }
            self.position += ch.len_utf8();
        }

        if start == self.position {
            return Err(anyhow::anyhow!("Expected range value at position {}", start));
        }

        Ok(self.input[start..self.position].to_string())
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    fn is_at_end(&self) -> bool {
        self.position >= self.input.len()
    }

    fn consume_char(&mut self, expected: char) -> Result<()> {
        self.skip_whitespace();
        if self.peek_char() == Some(expected) {
            self.position += expected.len_utf8();
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Expected '{}' at position {}, found {:?}",
                expected,
                self.position,
                self.peek_char()
            ))
        }
    }

    fn peek_keyword(&self, keyword: &str) -> bool {
        let remaining = &self.input[self.position..];
        if remaining.starts_with(keyword) {
            // Make sure it's a complete keyword (followed by whitespace, paren, or end)
            let next_pos = self.position + keyword.len();
            if next_pos >= self.input.len() {
                return true;
            }
            let next_char = self.input[next_pos..].chars().next();
            matches!(next_char, Some(c) if c.is_whitespace() || c == '(' || c == ')')
        } else {
            false
        }
    }

    fn consume_keyword(&mut self, expected: &str) -> Result<()> {
        self.skip_whitespace();
        if self.peek_keyword(expected) {
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
                self.position += ch.len_utf8();
            } else {
                break;
            }
        }
    }
}

/// SQL query builder for translating AST to SQL
struct SqlQueryBuilder {
    params: Vec<String>,
    param_index: usize,
}

impl SqlQueryBuilder {
    fn new() -> Self {
        Self {
            params: Vec::new(),
            param_index: 0,
        }
    }

    fn build_where_clause(&mut self, node: &QueryNode) -> String {
        match node {
            QueryNode::FieldMatch { field, value, operator } => {
                self.param_index += 1;
                self.params.push(value.clone());

                let json_path = format!("json_extract(data, '$.{}')", field);

                match operator {
                    MatchOperator::Equals => format!("{} = ?{}", json_path, self.param_index),
                    MatchOperator::GreaterThan => format!("CAST({} AS REAL) > ?{}", json_path, self.param_index),
                    MatchOperator::LessThan => format!("CAST({} AS REAL) < ?{}", json_path, self.param_index),
                    MatchOperator::GreaterThanOrEqual => format!("CAST({} AS REAL) >= ?{}", json_path, self.param_index),
                    MatchOperator::LessThanOrEqual => format!("CAST({} AS REAL) <= ?{}", json_path, self.param_index),
                    MatchOperator::Contains => {
                        self.params[self.param_index - 1] = format!("%{}%", value);
                        format!("{} LIKE ?{}", json_path, self.param_index)
                    }
                    MatchOperator::Regex => format!("{} REGEXP ?{}", json_path, self.param_index),
                    MatchOperator::StartsWith => {
                        self.params[self.param_index - 1] = format!("{}%", value);
                        format!("{} LIKE ?{}", json_path, self.param_index)
                    }
                    MatchOperator::EndsWith => {
                        self.params[self.param_index - 1] = format!("%{}", value);
                        format!("{} LIKE ?{}", json_path, self.param_index)
                    }
                }
            }
            QueryNode::Range { field, start, end } => {
                let json_path = format!("json_extract(data, '$.{}')", field);
                let mut conditions = Vec::new();

                if start != "*" {
                    self.param_index += 1;
                    self.params.push(start.clone());
                    conditions.push(format!("{} >= ?{}", json_path, self.param_index));
                }

                if end != "*" {
                    self.param_index += 1;
                    self.params.push(end.clone());
                    conditions.push(format!("{} <= ?{}", json_path, self.param_index));
                }

                if conditions.is_empty() {
                    "1=1".to_string()
                } else {
                    format!("({})", conditions.join(" AND "))
                }
            }
            QueryNode::And { left, right } => {
                let left_clause = self.build_where_clause(left);
                let right_clause = self.build_where_clause(right);
                format!("({} AND {})", left_clause, right_clause)
            }
            QueryNode::Or { left, right } => {
                let left_clause = self.build_where_clause(left);
                let right_clause = self.build_where_clause(right);
                format!("({} OR {})", left_clause, right_clause)
            }
            QueryNode::Not { operand } => {
                let clause = self.build_where_clause(operand);
                format!("NOT ({})", clause)
            }
            QueryNode::Group { expression } => {
                let clause = self.build_where_clause(expression);
                format!("({})", clause)
            }
            QueryNode::Wildcard { field, pattern } => {
                self.param_index += 1;
                let sql_pattern = pattern.replace('*', "%").replace('?', "_");
                self.params.push(sql_pattern);
                let json_path = format!("json_extract(data, '$.{}')", field);
                format!("{} LIKE ?{}", json_path, self.param_index)
            }
            QueryNode::InList { field, values } => {
                let json_path = format!("json_extract(data, '$.{}')", field);
                let placeholders: Vec<String> = values
                    .iter()
                    .map(|v| {
                        self.param_index += 1;
                        self.params.push(v.clone());
                        format!("?{}", self.param_index)
                    })
                    .collect();
                format!("{} IN ({})", json_path, placeholders.join(", "))
            }
            QueryNode::Exists { field } => {
                let json_path = format!("json_extract(data, '$.{}')", field);
                format!("{} IS NOT NULL", json_path)
            }
        }
    }

    fn get_params(&self) -> &[String] {
        &self.params
    }
}

/// Query execution result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub records: Vec<serde_json::Value>,
    pub total_count: i64,
    pub execution_time_ms: i64,
    pub query_plan: Option<String>,
}

/// Query executor for the threat hunting data lake
pub struct QueryExecutor {
    pool: SqlitePool,
    compiled_regex_cache: HashMap<String, Regex>,
}

impl QueryExecutor {
    /// Create a new query executor with database connection
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            compiled_regex_cache: HashMap::new(),
        }
    }

    /// Execute a parsed query against the data lake
    pub async fn execute(&mut self, ast: &QueryNode) -> Result<Vec<serde_json::Value>> {
        let context = QueryContext::default();
        self.execute_with_context(ast, &context).await
    }

    /// Execute query with custom context (time range, filters, etc.)
    pub async fn execute_with_context(
        &mut self,
        ast: &QueryNode,
        context: &QueryContext,
    ) -> Result<Vec<serde_json::Value>> {
        let start_time = std::time::Instant::now();

        // Build SQL query from AST
        let mut builder = SqlQueryBuilder::new();
        let where_clause = builder.build_where_clause(ast);

        // Build the full query
        let mut sql = format!(
            "SELECT id, source_id, timestamp, data, metadata
             FROM data_lake_records
             WHERE timestamp >= ? AND timestamp <= ?
             AND ({})",
            where_clause
        );

        // Add source filter if specified
        if let Some(ref sources) = context.source_filter {
            if !sources.is_empty() {
                let placeholders: Vec<&str> = sources.iter().map(|_| "?").collect();
                sql.push_str(&format!(" AND source_id IN ({})", placeholders.join(", ")));
            }
        }

        sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        // Execute query
        let mut query = sqlx::query_as::<_, (String, String, String, String, String)>(&sql);

        // Bind time range
        query = query.bind(context.start_time.to_rfc3339());
        query = query.bind(context.end_time.to_rfc3339());

        // Bind WHERE clause params
        for param in builder.get_params() {
            query = query.bind(param);
        }

        // Bind source filter if present
        if let Some(ref sources) = context.source_filter {
            for source in sources {
                query = query.bind(source);
            }
        }

        // Bind limit and offset
        query = query.bind(context.max_results);
        query = query.bind(context.offset);

        let rows = query.fetch_all(&self.pool).await.unwrap_or_else(|e| {
            log::warn!("Query execution failed: {}", e);
            Vec::new()
        });

        // Transform results
        let mut results = Vec::with_capacity(rows.len());
        for (id, source_id, timestamp, data, metadata) in rows {
            let mut record = serde_json::json!({
                "id": id,
                "source_id": source_id,
                "timestamp": timestamp,
            });

            // Parse and merge data
            if let Ok(data_value) = serde_json::from_str::<serde_json::Value>(&data) {
                record["data"] = data_value;
            }

            // Parse and merge metadata
            if let Ok(meta_value) = serde_json::from_str::<serde_json::Value>(&metadata) {
                record["metadata"] = meta_value;
            }

            results.push(record);
        }

        let execution_time = start_time.elapsed();
        log::debug!(
            "Query executed in {}ms, returned {} results",
            execution_time.as_millis(),
            results.len()
        );

        Ok(results)
    }

    /// Execute a raw query string (parses and executes)
    pub async fn execute_raw(&mut self, query_str: &str) -> Result<Vec<serde_json::Value>> {
        let mut parser = QueryParser::new(query_str.to_string());
        let ast = parser.parse()?;
        self.execute(&ast).await
    }

    /// Execute with full result metadata
    pub async fn execute_full(
        &mut self,
        ast: &QueryNode,
        context: &QueryContext,
    ) -> Result<QueryResult> {
        let start_time = std::time::Instant::now();

        // Get total count first
        let total_count = self.count_matches(ast, context).await?;

        // Execute main query
        let records = self.execute_with_context(ast, context).await?;

        let execution_time = start_time.elapsed();

        Ok(QueryResult {
            records,
            total_count,
            execution_time_ms: execution_time.as_millis() as i64,
            query_plan: None,
        })
    }

    /// Count matching records without fetching data
    async fn count_matches(
        &self,
        ast: &QueryNode,
        context: &QueryContext,
    ) -> Result<i64> {
        let mut builder = SqlQueryBuilder::new();
        let where_clause = builder.build_where_clause(ast);

        let mut sql = format!(
            "SELECT COUNT(*)
             FROM data_lake_records
             WHERE timestamp >= ? AND timestamp <= ?
             AND ({})",
            where_clause
        );

        if let Some(ref sources) = context.source_filter {
            if !sources.is_empty() {
                let placeholders: Vec<&str> = sources.iter().map(|_| "?").collect();
                sql.push_str(&format!(" AND source_id IN ({})", placeholders.join(", ")));
            }
        }

        let mut query = sqlx::query_scalar(&sql);

        query = query.bind(context.start_time.to_rfc3339());
        query = query.bind(context.end_time.to_rfc3339());

        for param in builder.get_params() {
            query = query.bind(param);
        }

        if let Some(ref sources) = context.source_filter {
            for source in sources {
                query = query.bind(source);
            }
        }

        let count: i64 = query.fetch_one(&self.pool).await.unwrap_or(0);
        Ok(count)
    }

    /// Validate a query without executing it
    pub fn validate_query(&self, query_str: &str) -> Result<QueryNode> {
        let mut parser = QueryParser::new(query_str.to_string());
        parser.parse()
    }

    /// Check if a single record matches the query (for in-memory filtering)
    pub fn matches_record(&mut self, ast: &QueryNode, record: &serde_json::Value) -> bool {
        match ast {
            QueryNode::FieldMatch { field, value, operator } => {
                let field_value = self.get_field_value(record, field);
                match field_value {
                    Some(v) => self.compare_values(&v, value, operator),
                    None => false,
                }
            }
            QueryNode::Range { field, start, end } => {
                let field_value = self.get_field_value(record, field);
                match field_value {
                    Some(v) => {
                        let v_str = v.to_string();
                        let in_start = start == "*" || v_str >= *start;
                        let in_end = end == "*" || v_str <= *end;
                        in_start && in_end
                    }
                    None => false,
                }
            }
            QueryNode::And { left, right } => {
                self.matches_record(left, record) && self.matches_record(right, record)
            }
            QueryNode::Or { left, right } => {
                self.matches_record(left, record) || self.matches_record(right, record)
            }
            QueryNode::Not { operand } => !self.matches_record(operand, record),
            QueryNode::Group { expression } => self.matches_record(expression, record),
            QueryNode::Wildcard { field, pattern } => {
                let field_value = self.get_field_value(record, field);
                match field_value {
                    Some(v) => {
                        let regex_pattern = pattern.replace('*', ".*").replace('?', ".");
                        self.match_regex(&v.to_string(), &regex_pattern)
                    }
                    None => false,
                }
            }
            QueryNode::InList { field, values } => {
                let field_value = self.get_field_value(record, field);
                match field_value {
                    Some(v) => {
                        let v_str = v.to_string().trim_matches('"').to_string();
                        values.iter().any(|val| *val == v_str)
                    }
                    None => false,
                }
            }
            QueryNode::Exists { field } => {
                self.get_field_value(record, field).is_some()
            }
        }
    }

    fn get_field_value<'a>(&self, record: &'a serde_json::Value, field: &str) -> Option<&'a serde_json::Value> {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = record;

        for part in parts {
            match current.get(part) {
                Some(v) => current = v,
                None => {
                    // Try looking in "data" subobject
                    if let Some(data) = record.get("data") {
                        if let Some(v) = data.get(part) {
                            current = v;
                            continue;
                        }
                    }
                    return None;
                }
            }
        }

        Some(current)
    }

    fn compare_values(&mut self, field_val: &serde_json::Value, target: &str, op: &MatchOperator) -> bool {
        let field_str = match field_val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => field_val.to_string(),
        };

        match op {
            MatchOperator::Equals => field_str == target,
            MatchOperator::GreaterThan => {
                if let (Ok(a), Ok(b)) = (field_str.parse::<f64>(), target.parse::<f64>()) {
                    a > b
                } else {
                    field_str > target.to_string()
                }
            }
            MatchOperator::LessThan => {
                if let (Ok(a), Ok(b)) = (field_str.parse::<f64>(), target.parse::<f64>()) {
                    a < b
                } else {
                    field_str < target.to_string()
                }
            }
            MatchOperator::GreaterThanOrEqual => {
                if let (Ok(a), Ok(b)) = (field_str.parse::<f64>(), target.parse::<f64>()) {
                    a >= b
                } else {
                    field_str >= target.to_string()
                }
            }
            MatchOperator::LessThanOrEqual => {
                if let (Ok(a), Ok(b)) = (field_str.parse::<f64>(), target.parse::<f64>()) {
                    a <= b
                } else {
                    field_str <= target.to_string()
                }
            }
            MatchOperator::Contains => field_str.contains(target),
            MatchOperator::Regex => self.match_regex(&field_str, target),
            MatchOperator::StartsWith => field_str.starts_with(target),
            MatchOperator::EndsWith => field_str.ends_with(target),
        }
    }

    fn match_regex(&mut self, text: &str, pattern: &str) -> bool {
        if let Some(re) = self.compiled_regex_cache.get(pattern) {
            return re.is_match(text);
        }

        match Regex::new(pattern) {
            Ok(re) => {
                let result = re.is_match(text);
                self.compiled_regex_cache.insert(pattern.to_string(), re);
                result
            }
            Err(_) => false,
        }
    }
}

/// Query templates for common hunts
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
        ("DNS Tunneling", "source:dns AND query_length:>100 AND query_type:TXT"),
        ("Malware Persistence", "source:registry AND key_path:*Run* AND _exists_:value"),
        ("Kerberoasting", "source:kerberos AND event:TGS_REQ AND service_name:*$ NOT"),
        ("Pass-the-Hash", "source:auth AND logon_type:9 AND process_name:NOT lsass.exe"),
        ("Webshell Activity", "source:web AND (uri:*cmd* OR uri:*shell* OR uri:*exec*) AND method:POST"),
        ("Suspicious Scheduled Tasks", "source:scheduled_task AND (command:*powershell* OR command:*cmd* OR command:*wscript*)"),
        ("LOLBIN Usage", "source:process AND (process_name:certutil.exe OR process_name:bitsadmin.exe OR process_name:mshta.exe)"),
    ]
}

/// Get categorized query templates
pub fn get_query_templates_by_category() -> HashMap<&'static str, Vec<(&'static str, &'static str)>> {
    let mut categories = HashMap::new();

    categories.insert("Authentication", vec![
        ("Failed Login Attempts", "source:auth AND event:login_failed AND count:>5"),
        ("Brute Force Detection", "source:auth AND event:login_failed AND source_ip:* GROUP BY source_ip HAVING count:>10"),
        ("Pass-the-Hash", "source:auth AND logon_type:9 AND process_name:NOT lsass.exe"),
    ]);

    categories.insert("Privilege Escalation", vec![
        ("Privilege Escalation", "source:security AND event:privilege_change AND (new_role:admin OR new_role:root)"),
        ("Token Manipulation", "source:security AND event:token_manipulation"),
        ("UAC Bypass", "source:process AND integrity:high AND parent_integrity:medium"),
    ]);

    categories.insert("Lateral Movement", vec![
        ("Lateral Movement", "source:network AND (port:445 OR port:3389 OR port:22) AND src:internal AND dst:internal"),
        ("PsExec Usage", "source:process AND (process_name:psexec.exe OR parent_name:psexesvc.exe)"),
        ("WMI Lateral Movement", "source:wmi AND event:remote_process_creation"),
    ]);

    categories.insert("Data Exfiltration", vec![
        ("Data Exfiltration", "source:network AND bytes_out:>10000000 AND destination:external"),
        ("DNS Tunneling", "source:dns AND query_length:>100 AND query_type:TXT"),
        ("Cloud Storage Upload", "source:network AND (destination:*s3.amazonaws.com OR destination:*blob.core.windows.net)"),
    ]);

    categories.insert("Malware", vec![
        ("Beaconing", "source:network AND destination:external AND connection_count:>100"),
        ("Credential Dumping", "source:process AND (process_name:mimikatz.exe OR process_name:procdump.exe OR command_line:*lsass*)"),
        ("Suspicious PowerShell", "source:process AND process_name:powershell.exe AND (command_line:*encoded* OR command_line:*bypass*)"),
    ]);

    categories.insert("Persistence", vec![
        ("Malware Persistence", "source:registry AND key_path:*Run* AND _exists_:value"),
        ("Suspicious Scheduled Tasks", "source:scheduled_task AND (command:*powershell* OR command:*cmd* OR command:*wscript*)"),
        ("Service Installation", "source:service AND event:install AND service_type:kernel_driver"),
    ]);

    categories
}

/// Parse a time expression like "now-7d" or "2024-01-01"
pub fn parse_time_expression(expr: &str) -> Result<DateTime<Utc>> {
    if expr == "now" {
        return Ok(Utc::now());
    }

    if expr.starts_with("now-") {
        let duration_str = &expr[4..];
        let duration = parse_duration(duration_str)?;
        return Ok(Utc::now() - duration);
    }

    if expr.starts_with("now+") {
        let duration_str = &expr[4..];
        let duration = parse_duration(duration_str)?;
        return Ok(Utc::now() + duration);
    }

    // Try parsing as RFC3339
    if let Ok(dt) = expr.parse::<DateTime<Utc>>() {
        return Ok(dt);
    }

    // Try parsing as date only
    if let Ok(dt) = chrono::NaiveDate::parse_from_str(expr, "%Y-%m-%d") {
        return Ok(dt.and_hms_opt(0, 0, 0).unwrap().and_utc());
    }

    Err(anyhow::anyhow!("Invalid time expression: {}", expr))
}

fn parse_duration(s: &str) -> Result<Duration> {
    let len = s.len();
    if len < 2 {
        return Err(anyhow::anyhow!("Invalid duration: {}", s));
    }

    let (num_str, unit) = s.split_at(len - 1);
    let num: i64 = num_str.parse()?;

    match unit {
        "s" => Ok(Duration::seconds(num)),
        "m" => Ok(Duration::minutes(num)),
        "h" => Ok(Duration::hours(num)),
        "d" => Ok(Duration::days(num)),
        "w" => Ok(Duration::weeks(num)),
        _ => Err(anyhow::anyhow!("Invalid duration unit: {}", unit)),
    }
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
    fn test_parse_or_query() {
        let mut parser = QueryParser::new("port:22 OR port:3389".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::Or { .. } => {}
            _ => panic!("Expected Or node"),
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

    #[test]
    fn test_parse_not_query() {
        let mut parser = QueryParser::new("NOT source:internal".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::Not { operand } => {
                match *operand {
                    QueryNode::FieldMatch { field, value, .. } => {
                        assert_eq!(field, "source");
                        assert_eq!(value, "internal");
                    }
                    _ => panic!("Expected FieldMatch in Not"),
                }
            }
            _ => panic!("Expected Not node"),
        }
    }

    #[test]
    fn test_parse_grouped_query() {
        let mut parser = QueryParser::new("source:auth AND (event:login OR event:logout)".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::And { left, right } => {
                match *left {
                    QueryNode::FieldMatch { ref field, .. } => {
                        assert_eq!(field, "source");
                    }
                    _ => panic!("Expected FieldMatch on left"),
                }
                match *right {
                    QueryNode::Group { .. } => {}
                    _ => panic!("Expected Group on right"),
                }
            }
            _ => panic!("Expected And node"),
        }
    }

    #[test]
    fn test_parse_wildcard_query() {
        let mut parser = QueryParser::new("filename:*.exe".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::Wildcard { field, pattern } => {
                assert_eq!(field, "filename");
                assert_eq!(pattern, "*.exe");
            }
            _ => panic!("Expected Wildcard"),
        }
    }

    #[test]
    fn test_parse_in_list_query() {
        let mut parser = QueryParser::new("port:(22 OR 80 OR 443)".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::InList { field, values } => {
                assert_eq!(field, "port");
                assert_eq!(values, vec!["22", "80", "443"]);
            }
            _ => panic!("Expected InList"),
        }
    }

    #[test]
    fn test_parse_comparison_operators() {
        let mut parser = QueryParser::new("bytes_out:>10000".to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::FieldMatch { field, value, operator } => {
                assert_eq!(field, "bytes_out");
                assert_eq!(value, "10000");
                assert_eq!(operator, MatchOperator::GreaterThan);
            }
            _ => panic!("Expected FieldMatch with GreaterThan"),
        }
    }

    #[test]
    fn test_parse_quoted_value() {
        let mut parser = QueryParser::new(r#"message:"login failed""#.to_string());
        let ast = parser.parse().unwrap();

        match ast {
            QueryNode::FieldMatch { field, value, .. } => {
                assert_eq!(field, "message");
                assert_eq!(value, "login failed");
            }
            _ => panic!("Expected FieldMatch"),
        }
    }

    #[test]
    fn test_sql_builder() {
        let mut builder = SqlQueryBuilder::new();
        let ast = QueryNode::FieldMatch {
            field: "source".to_string(),
            value: "auth".to_string(),
            operator: MatchOperator::Equals,
        };

        let where_clause = builder.build_where_clause(&ast);
        assert!(where_clause.contains("json_extract"));
        assert_eq!(builder.get_params(), &["auth"]);
    }

    #[test]
    fn test_time_expression_parsing() {
        assert!(parse_time_expression("now").is_ok());
        assert!(parse_time_expression("now-7d").is_ok());
        assert!(parse_time_expression("now-1h").is_ok());
        assert!(parse_time_expression("2024-01-01").is_ok());
    }

    #[test]
    fn test_query_templates() {
        let templates = get_query_templates();
        assert!(!templates.is_empty());

        // Verify all templates are parseable
        for (name, query) in &templates {
            let mut parser = QueryParser::new(query.to_string());
            assert!(parser.parse().is_ok(), "Failed to parse template: {}", name);
        }
    }

    #[test]
    fn test_categorized_templates() {
        let categories = get_query_templates_by_category();
        assert!(categories.contains_key("Authentication"));
        assert!(categories.contains_key("Lateral Movement"));
        assert!(categories.contains_key("Malware"));
    }
}
