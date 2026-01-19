//! Subscription tier definitions and database operations

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Subscription tier with quota limits and feature flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionTier {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub monthly_price_cents: Option<i32>,
    pub yearly_price_cents: Option<i32>,
    pub stripe_monthly_price_id: Option<String>,
    pub stripe_yearly_price_id: Option<String>,
    pub max_users: i32,
    pub max_scans_per_day: i32,
    pub max_assets: i32,
    pub max_reports_per_month: i32,
    pub max_customer_portals: i32,
    pub feature_flags: TierFeatures,
    pub is_active: bool,
    pub sort_order: i32,
}

/// Feature flags for subscription tiers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierFeatures {
    pub scanning: bool,
    pub reporting: bool,
    pub scheduling: bool,
    pub team_management: bool,
    pub crm: bool,
    pub api_access: bool,
    pub custom_branding: bool,
    #[serde(default)]
    pub sso: bool,
    #[serde(default)]
    pub dedicated_support: bool,
    #[serde(default)]
    pub on_premise: bool,
}

/// Get all active subscription tiers
pub async fn get_all_tiers(pool: &SqlitePool) -> Result<Vec<SubscriptionTier>> {
    let rows = sqlx::query_as::<_, TierRow>(
        r#"
        SELECT id, name, display_name, description,
               monthly_price_cents, yearly_price_cents,
               stripe_monthly_price_id, stripe_yearly_price_id,
               max_users, max_scans_per_day, max_assets,
               max_reports_per_month, max_customer_portals,
               feature_flags, is_active, sort_order
        FROM subscription_tiers
        WHERE is_active = 1
        ORDER BY sort_order ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let tiers: Vec<SubscriptionTier> = rows.into_iter().map(|r| r.into()).collect();
    Ok(tiers)
}

/// Get a specific tier by ID
pub async fn get_tier_by_id(pool: &SqlitePool, tier_id: &str) -> Result<Option<SubscriptionTier>> {
    let row = sqlx::query_as::<_, TierRow>(
        r#"
        SELECT id, name, display_name, description,
               monthly_price_cents, yearly_price_cents,
               stripe_monthly_price_id, stripe_yearly_price_id,
               max_users, max_scans_per_day, max_assets,
               max_reports_per_month, max_customer_portals,
               feature_flags, is_active, sort_order
        FROM subscription_tiers
        WHERE id = ?
        "#,
    )
    .bind(tier_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into()))
}

/// Get a tier by name (solo, professional, team, enterprise)
pub async fn get_tier_by_name(pool: &SqlitePool, name: &str) -> Result<Option<SubscriptionTier>> {
    let row = sqlx::query_as::<_, TierRow>(
        r#"
        SELECT id, name, display_name, description,
               monthly_price_cents, yearly_price_cents,
               stripe_monthly_price_id, stripe_yearly_price_id,
               max_users, max_scans_per_day, max_assets,
               max_reports_per_month, max_customer_portals,
               feature_flags, is_active, sort_order
        FROM subscription_tiers
        WHERE name = ?
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into()))
}

/// Get the role name for a given tier
pub fn get_role_for_tier(tier_name: &str) -> &'static str {
    match tier_name {
        "free" => "free_user",
        "solo" => "solo_user",
        "professional" => "professional_user",
        "team" => "team_user",
        "enterprise" => "enterprise_user",
        _ => "free_user", // Default fallback to free tier
    }
}

/// Update Stripe price IDs for a tier
pub async fn update_stripe_price_ids(
    pool: &SqlitePool,
    tier_id: &str,
    monthly_price_id: Option<&str>,
    yearly_price_id: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE subscription_tiers
        SET stripe_monthly_price_id = ?, stripe_yearly_price_id = ?
        WHERE id = ?
        "#,
    )
    .bind(monthly_price_id)
    .bind(yearly_price_id)
    .bind(tier_id)
    .execute(pool)
    .await?;

    Ok(())
}

// Internal row type for database mapping
#[derive(sqlx::FromRow)]
struct TierRow {
    id: String,
    name: String,
    display_name: String,
    description: Option<String>,
    monthly_price_cents: Option<i32>,
    yearly_price_cents: Option<i32>,
    stripe_monthly_price_id: Option<String>,
    stripe_yearly_price_id: Option<String>,
    max_users: i32,
    max_scans_per_day: i32,
    max_assets: i32,
    max_reports_per_month: i32,
    max_customer_portals: i32,
    feature_flags: String,
    is_active: i32,
    sort_order: i32,
}

impl From<TierRow> for SubscriptionTier {
    fn from(row: TierRow) -> Self {
        let features: TierFeatures =
            serde_json::from_str(&row.feature_flags).unwrap_or_default();

        Self {
            id: row.id,
            name: row.name,
            display_name: row.display_name,
            description: row.description,
            monthly_price_cents: row.monthly_price_cents,
            yearly_price_cents: row.yearly_price_cents,
            stripe_monthly_price_id: row.stripe_monthly_price_id,
            stripe_yearly_price_id: row.stripe_yearly_price_id,
            max_users: row.max_users,
            max_scans_per_day: row.max_scans_per_day,
            max_assets: row.max_assets,
            max_reports_per_month: row.max_reports_per_month,
            max_customer_portals: row.max_customer_portals,
            feature_flags: features,
            is_active: row.is_active == 1,
            sort_order: row.sort_order,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_for_tier() {
        assert_eq!(get_role_for_tier("free"), "free_user");
        assert_eq!(get_role_for_tier("solo"), "solo_user");
        assert_eq!(get_role_for_tier("professional"), "professional_user");
        assert_eq!(get_role_for_tier("team"), "team_user");
        assert_eq!(get_role_for_tier("enterprise"), "enterprise_user");
        assert_eq!(get_role_for_tier("unknown"), "free_user");
    }

    #[test]
    fn test_tier_features_default() {
        let features = TierFeatures::default();
        assert!(!features.scanning);
        assert!(!features.sso);
    }
}
