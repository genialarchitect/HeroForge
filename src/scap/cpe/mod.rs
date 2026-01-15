//! CPE - Common Platform Enumeration
//!
//! Implements CPE 2.3 naming and matching for platform identification.

mod types;
mod parser;
mod matcher;
mod dictionary;

pub use types::*;
pub use parser::CpeParser;
pub use matcher::CpeMatcher;
pub use dictionary::CpeDictionary;
