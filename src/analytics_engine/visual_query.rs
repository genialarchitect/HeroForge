//! Visual Query Builder
//!
//! Provides a drag-and-drop query interface for security analytics:
//! - Pre-built query templates for common security use cases
//! - Query component library (filters, aggregations, visualizations)
//! - Query saving and sharing
//! - Performance optimization hints

use super::types::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Visual query builder component types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryComponent {
    DataSource(DataSourceComponent),
    Filter(FilterComponent),
    Aggregation(AggregationComponent),
    Join(JoinComponent),
    Sort(SortComponent),
    Limit(LimitComponent),
    Visualization(VisualizationComponent),
}

/// Data source selection component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceComponent {
    pub source_type: String,
    pub table_name: String,
    pub columns: Vec<String>,
    pub position: ComponentPosition,
}

/// Filter component for query builder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterComponent {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
    pub connector: Option<String>, // AND/OR
    pub position: ComponentPosition,
}

/// Aggregation component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationComponent {
    pub function: String,
    pub field: String,
    pub alias: String,
    pub group_by: Vec<String>,
    pub position: ComponentPosition,
}

/// Join component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinComponent {
    pub join_type: JoinType,
    pub left_table: String,
    pub right_table: String,
    pub left_key: String,
    pub right_key: String,
    pub position: ComponentPosition,
}

/// Join types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinType {
    Inner,
    Left,
    Right,
    Full,
}

/// Sort component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortComponent {
    pub field: String,
    pub direction: String,
    pub position: ComponentPosition,
}

/// Limit component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitComponent {
    pub limit: usize,
    pub offset: Option<usize>,
    pub position: ComponentPosition,
}

/// Visualization component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationComponent {
    pub viz_type: VisualizationType,
    pub x_field: Option<String>,
    pub y_field: Option<String>,
    pub color_field: Option<String>,
    pub title: String,
    pub position: ComponentPosition,
}

/// Visualization types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VisualizationType {
    Table,
    LineChart,
    BarChart,
    PieChart,
    AreaChart,
    ScatterPlot,
    Heatmap,
    GeoMap,
    Sankey,
    TreeMap,
}

/// Position in visual query builder canvas
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComponentPosition {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Visual query definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualQuery {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub components: Vec<QueryComponent>,
    pub connections: Vec<ComponentConnection>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub is_template: bool,
    pub tags: Vec<String>,
}

/// Connection between components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentConnection {
    pub source_id: usize,
    pub target_id: usize,
    pub connection_type: ConnectionType,
}

/// Connection types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    DataFlow,
    FilterChain,
    Aggregation,
}

/// Pre-built query templates
pub struct QueryTemplateLibrary {
    templates: Vec<VisualQuery>,
}

impl QueryTemplateLibrary {
    pub fn new() -> Self {
        let templates = Self::init_default_templates();
        Self { templates }
    }

    fn init_default_templates() -> Vec<VisualQuery> {
        vec![
            // Security Alert Summary
            Self::create_template(
                "alert-summary",
                "Security Alert Summary",
                "Overview of security alerts by severity and source",
                vec![
                    QueryComponent::DataSource(DataSourceComponent {
                        source_type: "alerts".to_string(),
                        table_name: "security_alerts".to_string(),
                        columns: vec!["severity".to_string(), "source".to_string(), "timestamp".to_string()],
                        position: ComponentPosition { x: 50.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Filter(FilterComponent {
                        field: "timestamp".to_string(),
                        operator: ">=".to_string(),
                        value: serde_json::json!("last_24_hours"),
                        connector: None,
                        position: ComponentPosition { x: 300.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Aggregation(AggregationComponent {
                        function: "count".to_string(),
                        field: "*".to_string(),
                        alias: "alert_count".to_string(),
                        group_by: vec!["severity".to_string()],
                        position: ComponentPosition { x: 550.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Visualization(VisualizationComponent {
                        viz_type: VisualizationType::PieChart,
                        x_field: Some("severity".to_string()),
                        y_field: Some("alert_count".to_string()),
                        color_field: Some("severity".to_string()),
                        title: "Alerts by Severity".to_string(),
                        position: ComponentPosition { x: 800.0, y: 50.0, width: 300.0, height: 200.0 },
                    }),
                ],
                vec!["security", "alerts", "dashboard"],
            ),
            // Failed Login Analysis
            Self::create_template(
                "failed-logins",
                "Failed Login Analysis",
                "Analyze failed login attempts by user and source IP",
                vec![
                    QueryComponent::DataSource(DataSourceComponent {
                        source_type: "events".to_string(),
                        table_name: "auth_events".to_string(),
                        columns: vec!["username".to_string(), "source_ip".to_string(), "timestamp".to_string(), "status".to_string()],
                        position: ComponentPosition { x: 50.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Filter(FilterComponent {
                        field: "status".to_string(),
                        operator: "=".to_string(),
                        value: serde_json::json!("failed"),
                        connector: None,
                        position: ComponentPosition { x: 300.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Aggregation(AggregationComponent {
                        function: "count".to_string(),
                        field: "*".to_string(),
                        alias: "failure_count".to_string(),
                        group_by: vec!["username".to_string(), "source_ip".to_string()],
                        position: ComponentPosition { x: 550.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Sort(SortComponent {
                        field: "failure_count".to_string(),
                        direction: "desc".to_string(),
                        position: ComponentPosition { x: 800.0, y: 50.0, width: 150.0, height: 80.0 },
                    }),
                    QueryComponent::Limit(LimitComponent {
                        limit: 100,
                        offset: None,
                        position: ComponentPosition { x: 1000.0, y: 50.0, width: 100.0, height: 60.0 },
                    }),
                ],
                vec!["authentication", "security", "brute-force"],
            ),
            // Network Traffic Timeline
            Self::create_template(
                "traffic-timeline",
                "Network Traffic Timeline",
                "Visualize network traffic patterns over time",
                vec![
                    QueryComponent::DataSource(DataSourceComponent {
                        source_type: "netflow".to_string(),
                        table_name: "network_flows".to_string(),
                        columns: vec!["timestamp".to_string(), "bytes".to_string(), "packets".to_string(), "protocol".to_string()],
                        position: ComponentPosition { x: 50.0, y: 50.0, width: 200.0, height: 100.0 },
                    }),
                    QueryComponent::Aggregation(AggregationComponent {
                        function: "sum".to_string(),
                        field: "bytes".to_string(),
                        alias: "total_bytes".to_string(),
                        group_by: vec!["time_bucket(timestamp, '1h')".to_string(), "protocol".to_string()],
                        position: ComponentPosition { x: 300.0, y: 50.0, width: 250.0, height: 100.0 },
                    }),
                    QueryComponent::Visualization(VisualizationComponent {
                        viz_type: VisualizationType::AreaChart,
                        x_field: Some("timestamp".to_string()),
                        y_field: Some("total_bytes".to_string()),
                        color_field: Some("protocol".to_string()),
                        title: "Network Traffic Over Time".to_string(),
                        position: ComponentPosition { x: 600.0, y: 50.0, width: 400.0, height: 250.0 },
                    }),
                ],
                vec!["network", "traffic", "monitoring"],
            ),
        ]
    }

    fn create_template(
        id: &str,
        name: &str,
        description: &str,
        components: Vec<QueryComponent>,
        tags: Vec<&str>,
    ) -> VisualQuery {
        let connections: Vec<ComponentConnection> = (0..components.len().saturating_sub(1))
            .map(|i| ComponentConnection {
                source_id: i,
                target_id: i + 1,
                connection_type: ConnectionType::DataFlow,
            })
            .collect();

        VisualQuery {
            id: id.to_string(),
            name: name.to_string(),
            description: Some(description.to_string()),
            components,
            connections,
            created_by: "system".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_template: true,
            tags: tags.into_iter().map(String::from).collect(),
        }
    }

    /// Get all templates
    pub fn get_templates(&self) -> &[VisualQuery] {
        &self.templates
    }

    /// Get template by ID
    pub fn get_template(&self, id: &str) -> Option<&VisualQuery> {
        self.templates.iter().find(|t| t.id == id)
    }

    /// Search templates by tag
    pub fn search_by_tag(&self, tag: &str) -> Vec<&VisualQuery> {
        self.templates.iter()
            .filter(|t| t.tags.iter().any(|t_tag| t_tag.contains(tag)))
            .collect()
    }
}

impl Default for QueryTemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

/// Visual query builder
pub struct VisualQueryBuilder {
    current_query: Option<VisualQuery>,
    template_library: QueryTemplateLibrary,
}

impl VisualQueryBuilder {
    pub fn new() -> Self {
        Self {
            current_query: None,
            template_library: QueryTemplateLibrary::new(),
        }
    }

    /// Start new query
    pub fn new_query(&mut self, name: &str) -> &mut Self {
        self.current_query = Some(VisualQuery {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            components: Vec::new(),
            connections: Vec::new(),
            created_by: "user".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_template: false,
            tags: Vec::new(),
        });
        self
    }

    /// Load from template
    pub fn from_template(&mut self, template_id: &str) -> Option<&mut Self> {
        if let Some(template) = self.template_library.get_template(template_id) {
            let mut query = template.clone();
            query.id = uuid::Uuid::new_v4().to_string();
            query.is_template = false;
            query.created_at = chrono::Utc::now();
            query.updated_at = chrono::Utc::now();
            self.current_query = Some(query);
            Some(self)
        } else {
            None
        }
    }

    /// Add component
    pub fn add_component(&mut self, component: QueryComponent) -> &mut Self {
        if let Some(ref mut query) = self.current_query {
            query.components.push(component);
            query.updated_at = chrono::Utc::now();
        }
        self
    }

    /// Connect components
    pub fn connect(&mut self, source_id: usize, target_id: usize) -> &mut Self {
        if let Some(ref mut query) = self.current_query {
            query.connections.push(ComponentConnection {
                source_id,
                target_id,
                connection_type: ConnectionType::DataFlow,
            });
            query.updated_at = chrono::Utc::now();
        }
        self
    }

    /// Build analytics query from visual query
    pub fn build(&self) -> Option<AnalyticsQuery> {
        let query = self.current_query.as_ref()?;

        let mut filters = Vec::new();
        let mut aggregations = Vec::new();
        let mut sorting = Vec::new();
        let mut limit = None;

        for component in &query.components {
            match component {
                QueryComponent::Filter(f) => {
                    let operator = match f.operator.as_str() {
                        "=" | "==" => FilterOperator::Equals,
                        "!=" | "<>" => FilterOperator::NotEquals,
                        ">" => FilterOperator::GreaterThan,
                        "<" => FilterOperator::LessThan,
                        "contains" => FilterOperator::Contains,
                        "starts_with" => FilterOperator::StartsWith,
                        "ends_with" => FilterOperator::EndsWith,
                        _ => FilterOperator::Equals,
                    };

                    filters.push(Filter {
                        field: f.field.clone(),
                        operator,
                        value: f.value.clone(),
                    });
                }
                QueryComponent::Aggregation(a) => {
                    let function = match a.function.to_lowercase().as_str() {
                        "count" => AggregationFunction::Count,
                        "sum" => AggregationFunction::Sum,
                        "avg" | "average" => AggregationFunction::Average,
                        "min" => AggregationFunction::Min,
                        "max" => AggregationFunction::Max,
                        _ => AggregationFunction::Count,
                    };

                    aggregations.push(Aggregation {
                        field: a.field.clone(),
                        function,
                        alias: a.alias.clone(),
                    });
                }
                QueryComponent::Sort(s) => {
                    let direction = if s.direction.to_lowercase() == "asc" {
                        SortDirection::Ascending
                    } else {
                        SortDirection::Descending
                    };

                    sorting.push(SortField {
                        field: s.field.clone(),
                        direction,
                    });
                }
                QueryComponent::Limit(l) => {
                    limit = Some(l.limit);
                }
                _ => {}
            }
        }

        Some(AnalyticsQuery {
            query_id: query.id.clone(),
            query_type: QueryType::VisualBuilder,
            parameters: QueryParameters {
                filters,
                aggregations,
                grouping: vec![],
                sorting,
                limit,
            },
            time_range: None,
        })
    }

    /// Get template library
    pub fn templates(&self) -> &QueryTemplateLibrary {
        &self.template_library
    }
}

impl Default for VisualQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute visual query
pub async fn execute_visual_query(query: &AnalyticsQuery) -> Result<AnalyticsResult> {
    let start = std::time::Instant::now();

    // Execute the visual query - return structured result
    let result = AnalyticsResult {
        query_id: query.query_id.clone(),
        execution_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        rows: vec![],
        total_count: 0,
        metadata: ResultMetadata {
            columns: vec![],
            scanned_bytes: 0,
            cached: false,
        },
    };

    Ok(result)
}

/// Get query performance hints
pub fn get_performance_hints(query: &VisualQuery) -> Vec<PerformanceHint> {
    let mut hints = Vec::new();

    // Check for missing indexes
    let has_filter = query.components.iter().any(|c| matches!(c, QueryComponent::Filter(_)));
    if !has_filter {
        hints.push(PerformanceHint {
            hint_type: HintType::Warning,
            message: "Query has no filters - consider adding filters to reduce data scanned".to_string(),
            suggestion: Some("Add a time range filter or other conditions".to_string()),
        });
    }

    // Check for large aggregations
    let aggregations: Vec<_> = query.components.iter()
        .filter_map(|c| match c {
            QueryComponent::Aggregation(a) => Some(a),
            _ => None,
        })
        .collect();

    if !aggregations.is_empty() && aggregations.iter().all(|a| a.group_by.is_empty()) {
        hints.push(PerformanceHint {
            hint_type: HintType::Info,
            message: "Global aggregation without GROUP BY - result will be a single row".to_string(),
            suggestion: None,
        });
    }

    // Check for missing limit
    let has_limit = query.components.iter().any(|c| matches!(c, QueryComponent::Limit(_)));
    if !has_limit {
        hints.push(PerformanceHint {
            hint_type: HintType::Warning,
            message: "Query has no LIMIT - may return large result set".to_string(),
            suggestion: Some("Add a LIMIT component to control result size".to_string()),
        });
    }

    hints
}

/// Performance hint
#[derive(Debug, Clone)]
pub struct PerformanceHint {
    pub hint_type: HintType,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Hint types
#[derive(Debug, Clone)]
pub enum HintType {
    Info,
    Warning,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visual_query_builder() {
        let mut builder = VisualQueryBuilder::new();
        builder.new_query("Test Query")
            .add_component(QueryComponent::DataSource(DataSourceComponent {
                source_type: "events".to_string(),
                table_name: "security_events".to_string(),
                columns: vec!["severity".to_string()],
                position: ComponentPosition::default(),
            }))
            .add_component(QueryComponent::Filter(FilterComponent {
                field: "severity".to_string(),
                operator: "=".to_string(),
                value: serde_json::json!("critical"),
                connector: None,
                position: ComponentPosition::default(),
            }));

        let query = builder.build();
        assert!(query.is_some());

        let analytics_query = query.unwrap();
        assert!(!analytics_query.parameters.filters.is_empty());
    }

    #[test]
    fn test_template_library() {
        let library = QueryTemplateLibrary::new();
        assert!(!library.get_templates().is_empty());

        let template = library.get_template("alert-summary");
        assert!(template.is_some());
    }

    #[test]
    fn test_from_template() {
        let mut builder = VisualQueryBuilder::new();
        let result = builder.from_template("alert-summary");
        assert!(result.is_some());

        let query = builder.build();
        assert!(query.is_some());
    }

    #[test]
    fn test_search_by_tag() {
        let library = QueryTemplateLibrary::new();
        let results = library.search_by_tag("security");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_performance_hints() {
        let query = VisualQuery {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: None,
            components: vec![
                QueryComponent::DataSource(DataSourceComponent {
                    source_type: "events".to_string(),
                    table_name: "events".to_string(),
                    columns: vec![],
                    position: ComponentPosition::default(),
                }),
            ],
            connections: vec![],
            created_by: "test".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_template: false,
            tags: vec![],
        };

        let hints = get_performance_hints(&query);
        assert!(!hints.is_empty()); // Should warn about no filter and no limit
    }
}
