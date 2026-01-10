//! Subscription management module for tiered registration system
//!
//! This module handles:
//! - Subscription tier definitions and lookups
//! - Stripe payment integration
//! - Email verification for registration
//! - Organization quota mapping based on tier

pub mod stripe;
pub mod tiers;
pub mod verification;

