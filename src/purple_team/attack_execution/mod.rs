//! Attack Execution Module
//!
//! Provides execution engines for various attack frameworks:
//! - Atomic Red Team (ART)
//! - CALDERA integration
//! - Custom attack scripts

#![allow(dead_code)]

pub mod atomic_red_team;

pub use atomic_red_team::*;
