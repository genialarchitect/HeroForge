//! OVAL - Open Vulnerability and Assessment Language
//!
//! Implements OVAL 5.11 for technical security checks.

pub mod types;
pub mod parser;
pub mod interpreter;
pub mod collectors;
pub mod remote;

pub use types::*;
pub use parser::OvalParser;
pub use interpreter::OvalEngine;

use std::collections::HashMap;

/// Collection of OVAL definitions
#[derive(Debug, Clone, Default)]
pub struct OvalDefinitions {
    pub definitions: HashMap<String, OvalDefinition>,
    pub tests: HashMap<String, OvalTest>,
    pub objects: HashMap<String, OvalObject>,
    pub states: HashMap<String, OvalState>,
    pub variables: HashMap<String, OvalVariable>,
}

impl OvalDefinitions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, id: &str) -> Option<&OvalDefinition> {
        self.definitions.get(id)
    }

    pub fn get_test(&self, id: &str) -> Option<&OvalTest> {
        self.tests.get(id)
    }

    pub fn get_object(&self, id: &str) -> Option<&OvalObject> {
        self.objects.get(id)
    }

    pub fn get_state(&self, id: &str) -> Option<&OvalState> {
        self.states.get(id)
    }
}
