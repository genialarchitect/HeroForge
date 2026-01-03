//! Intelligence marketplace
//!
//! Provides access to threat intelligence feeds with:
//! - Premium and free feed discovery
//! - Ratings and reviews system
//! - Subscription management
//! - Feed comparison and evaluation
//! - Free trial support

use super::types::*;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use log::info;

/// Connect to intelligence marketplace
pub async fn connect_marketplace(config: &MarketplaceConfig) -> Result<Marketplace> {
    info!("Connecting to intelligence marketplace at {}", config.endpoint);

    // Initialize with available feeds from marketplace
    let available_feeds = fetch_available_feeds(config).await?;

    // Load existing subscriptions
    let subscriptions = load_subscriptions(config).await?;

    info!(
        "Marketplace connected: {} feeds available, {} active subscriptions",
        available_feeds.len(),
        subscriptions.iter().filter(|s| matches!(s.status, SubscriptionStatus::Active)).count()
    );

    Ok(Marketplace {
        available_feeds,
        subscriptions,
    })
}

/// Fetch available feeds from marketplace
async fn fetch_available_feeds(config: &MarketplaceConfig) -> Result<Vec<FeedListing>> {
    // In real implementation, would fetch from marketplace API
    // Return curated list of common threat intelligence feeds

    Ok(vec![
        FeedListing {
            feed_id: "alienvault-otx".to_string(),
            name: "AlienVault OTX".to_string(),
            provider: "AT&T Cybersecurity".to_string(),
            description: "Open Threat Exchange - Community-driven threat intelligence".to_string(),
            category: "OSINT".to_string(),
            pricing: PricingModel::Free,
            rating: 4.2,
            reviews: 1250,
        },
        FeedListing {
            feed_id: "abuse-ch-urlhaus".to_string(),
            name: "URLhaus".to_string(),
            provider: "abuse.ch".to_string(),
            description: "Database of malicious URLs used for malware distribution".to_string(),
            category: "Malware".to_string(),
            pricing: PricingModel::Free,
            rating: 4.5,
            reviews: 890,
        },
        FeedListing {
            feed_id: "crowdstrike-falcon".to_string(),
            name: "CrowdStrike Falcon Intelligence".to_string(),
            provider: "CrowdStrike".to_string(),
            description: "Premium threat intelligence with adversary tracking".to_string(),
            category: "Premium".to_string(),
            pricing: PricingModel::Enterprise,
            rating: 4.8,
            reviews: 456,
        },
        FeedListing {
            feed_id: "recorded-future".to_string(),
            name: "Recorded Future".to_string(),
            provider: "Recorded Future".to_string(),
            description: "AI-powered threat intelligence platform".to_string(),
            category: "Premium".to_string(),
            pricing: PricingModel::Monthly(2500.0),
            rating: 4.7,
            reviews: 678,
        },
        FeedListing {
            feed_id: "threatconnect-tc".to_string(),
            name: "ThreatConnect".to_string(),
            provider: "ThreatConnect".to_string(),
            description: "Intelligence-driven security operations".to_string(),
            category: "Premium".to_string(),
            pricing: PricingModel::Monthly(1500.0),
            rating: 4.4,
            reviews: 345,
        },
        FeedListing {
            feed_id: "misp-default".to_string(),
            name: "MISP Default Feeds".to_string(),
            provider: "CIRCL".to_string(),
            description: "Open source threat intelligence sharing platform feeds".to_string(),
            category: "OSINT".to_string(),
            pricing: PricingModel::Free,
            rating: 4.3,
            reviews: 567,
        },
    ])
}

/// Load existing subscriptions
async fn load_subscriptions(_config: &MarketplaceConfig) -> Result<Vec<Subscription>> {
    // In real implementation, would load from database
    Ok(vec![])
}

/// Subscribe to a feed
pub async fn subscribe_to_feed(
    marketplace: &mut Marketplace,
    feed_id: &str,
    trial: bool,
) -> Result<Subscription> {
    // Find the feed
    let feed = marketplace.available_feeds.iter()
        .find(|f| f.feed_id == feed_id)
        .ok_or_else(|| anyhow!("Feed not found: {}", feed_id))?;

    // Check if already subscribed
    if marketplace.subscriptions.iter().any(|s| s.feed_id == feed_id && matches!(s.status, SubscriptionStatus::Active)) {
        return Err(anyhow!("Already subscribed to feed: {}", feed_id));
    }

    let now = chrono::Utc::now();
    let expires_at = if trial {
        Some(now + chrono::Duration::days(14)) // 14-day trial
    } else {
        match &feed.pricing {
            PricingModel::Free => None, // No expiration
            PricingModel::Monthly(_) => Some(now + chrono::Duration::days(30)),
            PricingModel::PerIndicator(_) => None, // Usage-based
            PricingModel::Enterprise => Some(now + chrono::Duration::days(365)),
        }
    };

    let subscription = Subscription {
        subscription_id: uuid::Uuid::new_v4().to_string(),
        feed_id: feed_id.to_string(),
        status: SubscriptionStatus::Active,
        started_at: now,
        expires_at,
    };

    marketplace.subscriptions.push(subscription.clone());
    info!("Subscribed to feed: {} (trial: {})", feed_id, trial);

    Ok(subscription)
}

/// Cancel a subscription
pub async fn cancel_subscription(
    marketplace: &mut Marketplace,
    subscription_id: &str,
) -> Result<()> {
    let subscription = marketplace.subscriptions.iter_mut()
        .find(|s| s.subscription_id == subscription_id)
        .ok_or_else(|| anyhow!("Subscription not found: {}", subscription_id))?;

    subscription.status = SubscriptionStatus::Cancelled;
    info!("Cancelled subscription: {}", subscription_id);

    Ok(())
}

/// Check subscription status and handle expirations
pub async fn check_subscriptions(marketplace: &mut Marketplace) -> Vec<SubscriptionAlert> {
    let mut alerts = Vec::new();
    let now = chrono::Utc::now();

    for subscription in marketplace.subscriptions.iter_mut() {
        if let Some(expires_at) = subscription.expires_at {
            if expires_at <= now && matches!(subscription.status, SubscriptionStatus::Active) {
                subscription.status = SubscriptionStatus::Expired;
                alerts.push(SubscriptionAlert {
                    subscription_id: subscription.subscription_id.clone(),
                    feed_id: subscription.feed_id.clone(),
                    alert_type: AlertType::Expired,
                    message: format!("Subscription to {} has expired", subscription.feed_id),
                });
            } else if expires_at <= now + chrono::Duration::days(7) && matches!(subscription.status, SubscriptionStatus::Active) {
                alerts.push(SubscriptionAlert {
                    subscription_id: subscription.subscription_id.clone(),
                    feed_id: subscription.feed_id.clone(),
                    alert_type: AlertType::ExpiringSoon,
                    message: format!("Subscription to {} expires in {} days",
                        subscription.feed_id,
                        (expires_at - now).num_days()
                    ),
                });
            }
        }
    }

    alerts
}

/// Search feeds by criteria
pub fn search_feeds<'a>(
    marketplace: &'a Marketplace,
    query: &FeedSearchQuery,
) -> Vec<&'a FeedListing> {
    marketplace.available_feeds.iter()
        .filter(|feed| {
            // Filter by category
            if let Some(ref category) = query.category {
                if &feed.category != category {
                    return false;
                }
            }

            // Filter by minimum rating
            if let Some(min_rating) = query.min_rating {
                if feed.rating < min_rating {
                    return false;
                }
            }

            // Filter by pricing type
            if let Some(ref pricing) = query.pricing_type {
                let matches = match (pricing.as_str(), &feed.pricing) {
                    ("free", PricingModel::Free) => true,
                    ("monthly", PricingModel::Monthly(_)) => true,
                    ("enterprise", PricingModel::Enterprise) => true,
                    ("usage", PricingModel::PerIndicator(_)) => true,
                    _ => false,
                };
                if !matches {
                    return false;
                }
            }

            // Filter by text search
            if let Some(ref text) = query.text {
                let lower_text = text.to_lowercase();
                if !feed.name.to_lowercase().contains(&lower_text)
                    && !feed.description.to_lowercase().contains(&lower_text)
                    && !feed.provider.to_lowercase().contains(&lower_text)
                {
                    return false;
                }
            }

            true
        })
        .collect()
}

/// Compare feeds
pub fn compare_feeds(
    marketplace: &Marketplace,
    feed_ids: &[String],
) -> Result<FeedComparison> {
    let feeds: Vec<&FeedListing> = feed_ids.iter()
        .filter_map(|id| marketplace.available_feeds.iter().find(|f| &f.feed_id == id))
        .collect();

    if feeds.len() != feed_ids.len() {
        return Err(anyhow!("One or more feeds not found"));
    }

    let avg_rating = feeds.iter().map(|f| f.rating).sum::<f64>() / feeds.len() as f64;
    let total_reviews: usize = feeds.iter().map(|f| f.reviews).sum();

    let mut pricing_comparison = HashMap::new();
    for feed in &feeds {
        let price_str = match &feed.pricing {
            PricingModel::Free => "Free".to_string(),
            PricingModel::Monthly(price) => format!("${}/month", price),
            PricingModel::PerIndicator(price) => format!("${}/indicator", price),
            PricingModel::Enterprise => "Enterprise (contact sales)".to_string(),
        };
        pricing_comparison.insert(feed.feed_id.clone(), price_str);
    }

    Ok(FeedComparison {
        feed_ids: feed_ids.to_vec(),
        average_rating: avg_rating,
        total_reviews,
        pricing_comparison,
        categories: feeds.iter().map(|f| f.category.clone()).collect(),
    })
}

/// Get marketplace statistics
pub fn get_marketplace_stats(marketplace: &Marketplace) -> MarketplaceStats {
    let active_subscriptions = marketplace.subscriptions.iter()
        .filter(|s| matches!(s.status, SubscriptionStatus::Active))
        .count();

    let free_feeds = marketplace.available_feeds.iter()
        .filter(|f| matches!(f.pricing, PricingModel::Free))
        .count();

    let premium_feeds = marketplace.available_feeds.len() - free_feeds;

    MarketplaceStats {
        total_feeds: marketplace.available_feeds.len(),
        free_feeds,
        premium_feeds,
        active_subscriptions,
        categories: marketplace.available_feeds.iter()
            .map(|f| f.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect(),
    }
}

// Additional types for marketplace operations

#[derive(Debug, Clone)]
pub struct SubscriptionAlert {
    pub subscription_id: String,
    pub feed_id: String,
    pub alert_type: AlertType,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum AlertType {
    ExpiringSoon,
    Expired,
    PaymentFailed,
    NewVersion,
}

#[derive(Debug, Clone, Default)]
pub struct FeedSearchQuery {
    pub category: Option<String>,
    pub min_rating: Option<f64>,
    pub pricing_type: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FeedComparison {
    pub feed_ids: Vec<String>,
    pub average_rating: f64,
    pub total_reviews: usize,
    pub pricing_comparison: HashMap<String, String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MarketplaceStats {
    pub total_feeds: usize,
    pub free_feeds: usize,
    pub premium_feeds: usize,
    pub active_subscriptions: usize,
    pub categories: Vec<String>,
}
