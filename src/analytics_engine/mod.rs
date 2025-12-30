//! Advanced Analytics Engine (Phase 4 Sprint 17)
//!
//! Best-in-class security analytics with real-time and batch processing

pub mod stream;
pub mod correlation;
pub mod batch;
pub mod warehouse;
pub mod nlp;
pub mod visual_query;
pub mod types;

pub use types::*;
use anyhow::Result;

/// Run comprehensive analytics query
pub async fn run_analytics_query(query: &AnalyticsQuery) -> Result<AnalyticsResult> {
    match &query.query_type {
        QueryType::RealTimeStream => stream::process_stream_query(query).await,
        QueryType::BatchProcessing => batch::process_batch_query(query).await,
        QueryType::EventCorrelation => correlation::correlate_events(query).await,
        QueryType::NaturalLanguage => nlp::process_nl_query(query).await,
        QueryType::VisualBuilder => visual_query::execute_visual_query(query).await,
    }
}
