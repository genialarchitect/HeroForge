//! Permission system module
//!
//! This module provides a comprehensive ABAC (Attribute-Based Access Control)
//! system with hierarchical organization support.
//!
//! # Architecture
//!
//! - **Organizations**: Top-level tenants
//! - **Departments**: Subdivisions within organizations
//! - **Teams**: Working groups within departments
//! - **Role Templates**: Predefined permission bundles
//! - **Custom Roles**: Organization-specific roles
//! - **Policies**: ABAC rules with conditions
//!
//! # Permission Evaluation Order
//!
//! 1. User permission overrides (highest priority)
//! 2. Team-scoped role assignments
//! 3. Department-scoped role assignments
//! 4. Organization-wide role assignments
//! 5. Role template defaults (lowest priority)
//!
//! Explicit denies always override allows at the same level.

pub mod types;
pub mod organizations;
pub mod roles;
pub mod evaluation;
pub mod cache;

pub use types::*;
pub use organizations::*;
pub use roles::*;
pub use evaluation::*;
pub use cache::*;
