//! Frontend performance optimization

use super::types::*;
use anyhow::Result;

/// Frontend optimization recommendation
#[derive(Debug, Clone)]
pub struct FrontendOptimization {
    pub category: OptimizationCategory,
    pub description: String,
    pub impact: Impact,
    pub estimated_improvement_ms: f64,
}

/// Optimization category
#[derive(Debug, Clone)]
pub enum OptimizationCategory {
    PWA,
    CodeSplitting,
    ImageOptimization,
    CSSOptimization,
    BundleSize,
    Caching,
}

/// Impact level
#[derive(Debug, Clone)]
pub enum Impact {
    High,
    Medium,
    Low,
}

/// Analyze bundle and generate optimization recommendations
fn analyze_bundle(config: &FrontendConfig) -> Vec<FrontendOptimization> {
    let mut optimizations = Vec::new();

    // PWA recommendations
    if config.enable_pwa {
        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::PWA,
            description: "Enable app manifest for installability".to_string(),
            impact: Impact::Medium,
            estimated_improvement_ms: 0.0, // Installability, not speed
        });
    }

    if config.enable_service_worker {
        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::PWA,
            description: "Service worker for offline caching and faster repeat visits".to_string(),
            impact: Impact::High,
            estimated_improvement_ms: 500.0,
        });
    }

    // Code splitting recommendations
    if config.enable_code_splitting {
        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::CodeSplitting,
            description: "Route-based code splitting with dynamic imports".to_string(),
            impact: Impact::High,
            estimated_improvement_ms: 300.0,
        });

        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::CodeSplitting,
            description: "Lazy load heavy components (charts, tables, modals)".to_string(),
            impact: Impact::Medium,
            estimated_improvement_ms: 150.0,
        });
    }

    // Image optimization recommendations
    if config.enable_image_optimization {
        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::ImageOptimization,
            description: "Convert images to WebP/AVIF format".to_string(),
            impact: Impact::High,
            estimated_improvement_ms: 200.0,
        });

        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::ImageOptimization,
            description: "Implement responsive images with srcset".to_string(),
            impact: Impact::Medium,
            estimated_improvement_ms: 100.0,
        });
    }

    if config.enable_lazy_loading {
        optimizations.push(FrontendOptimization {
            category: OptimizationCategory::ImageOptimization,
            description: "Lazy load images and iframes below the fold".to_string(),
            impact: Impact::Medium,
            estimated_improvement_ms: 150.0,
        });
    }

    // CSS optimizations
    optimizations.push(FrontendOptimization {
        category: OptimizationCategory::CSSOptimization,
        description: "Extract and inline critical CSS".to_string(),
        impact: Impact::High,
        estimated_improvement_ms: 200.0,
    });

    optimizations.push(FrontendOptimization {
        category: OptimizationCategory::CSSOptimization,
        description: "Purge unused CSS (Tailwind PurgeCSS)".to_string(),
        impact: Impact::Medium,
        estimated_improvement_ms: 50.0,
    });

    // Bundle size optimizations
    optimizations.push(FrontendOptimization {
        category: OptimizationCategory::BundleSize,
        description: "Enable tree shaking for dead code elimination".to_string(),
        impact: Impact::High,
        estimated_improvement_ms: 100.0,
    });

    optimizations.push(FrontendOptimization {
        category: OptimizationCategory::BundleSize,
        description: "Use smaller alternatives (date-fns vs moment, preact vs react)".to_string(),
        impact: Impact::Medium,
        estimated_improvement_ms: 80.0,
    });

    // Caching recommendations
    optimizations.push(FrontendOptimization {
        category: OptimizationCategory::Caching,
        description: "Add content hash to filenames for cache busting".to_string(),
        impact: Impact::Medium,
        estimated_improvement_ms: 0.0, // Caching, not initial load
    });

    optimizations
}

/// Estimate bundle size based on config
fn estimate_bundle_size(config: &FrontendConfig) -> f64 {
    let mut bundle_size = 800.0; // Base bundle size in KB

    // Code splitting reduces initial bundle
    if config.enable_code_splitting {
        bundle_size *= 0.6;
    }

    // Image optimization (affects asset size)
    if config.enable_image_optimization {
        bundle_size *= 0.85;
    }

    // Service worker adds overhead but enables caching
    if config.enable_service_worker {
        bundle_size += 10.0;
    }

    bundle_size
}

/// Calculate Lighthouse score based on metrics
fn calculate_lighthouse_score(fcp: f64, tti: f64, lcp: f64, bundle_kb: f64) -> f64 {
    // Simplified Lighthouse scoring model
    // Real Lighthouse uses more complex weighted metrics

    let mut score = 100.0;

    // FCP scoring (good: <1.8s, needs improvement: 1.8-3s, poor: >3s)
    if fcp > 3000.0 {
        score -= 25.0;
    } else if fcp > 1800.0 {
        score -= 15.0;
    } else if fcp > 1000.0 {
        score -= 5.0;
    }

    // TTI scoring (good: <3.8s, needs improvement: 3.8-7.3s, poor: >7.3s)
    if tti > 7300.0 {
        score -= 25.0;
    } else if tti > 3800.0 {
        score -= 15.0;
    } else if tti > 2000.0 {
        score -= 5.0;
    }

    // LCP scoring (good: <2.5s, needs improvement: 2.5-4s, poor: >4s)
    if lcp > 4000.0 {
        score -= 25.0;
    } else if lcp > 2500.0 {
        score -= 15.0;
    } else if lcp > 1500.0 {
        score -= 5.0;
    }

    // Bundle size penalty
    if bundle_kb > 1000.0 {
        score -= 10.0;
    } else if bundle_kb > 500.0 {
        score -= 5.0;
    }

    f64::max(score, 0.0)
}

/// Estimate Core Web Vitals based on optimizations
fn estimate_metrics(config: &FrontendConfig, optimizations: &[FrontendOptimization]) -> (f64, f64, f64) {
    // Base metrics (unoptimized)
    let mut fcp = 2500.0;  // First Contentful Paint
    let mut tti = 5000.0;  // Time to Interactive
    let mut lcp = 3500.0;  // Largest Contentful Paint

    // Apply improvements from optimizations
    for opt in optimizations {
        let improvement = opt.estimated_improvement_ms;
        match opt.category {
            OptimizationCategory::PWA => {
                tti -= improvement * 0.5;
            }
            OptimizationCategory::CodeSplitting => {
                fcp -= improvement * 0.3;
                tti -= improvement * 0.7;
            }
            OptimizationCategory::ImageOptimization => {
                lcp -= improvement * 0.8;
                fcp -= improvement * 0.2;
            }
            OptimizationCategory::CSSOptimization => {
                fcp -= improvement * 0.8;
                lcp -= improvement * 0.2;
            }
            OptimizationCategory::BundleSize => {
                fcp -= improvement * 0.4;
                tti -= improvement * 0.6;
            }
            OptimizationCategory::Caching => {
                // Caching helps repeat visits, not initial load
            }
        }
    }

    // Service worker improves repeat visit performance
    if config.enable_service_worker {
        fcp = fcp.min(fcp * 0.3); // Dramatic improvement on cached visits
    }

    (fcp.max(200.0), tti.max(500.0), lcp.max(300.0))
}

/// Optimize frontend performance
pub async fn optimize_frontend(config: &FrontendConfig) -> Result<FrontendMetrics> {
    log::info!("Analyzing frontend performance configuration");

    // Generate optimization recommendations
    let optimizations = analyze_bundle(config);

    for opt in &optimizations {
        log::info!(
            "Frontend optimization ({:?}): {} - {:?} impact, {:.0}ms improvement",
            opt.category,
            opt.description,
            opt.impact,
            opt.estimated_improvement_ms
        );
    }

    // Estimate bundle size
    let bundle_size_kb = estimate_bundle_size(config);
    log::info!("Estimated bundle size: {:.1} KB", bundle_size_kb);

    // Estimate Core Web Vitals
    let (fcp, tti, lcp) = estimate_metrics(config, &optimizations);

    // Calculate Lighthouse score
    let lighthouse_score = calculate_lighthouse_score(fcp, tti, lcp, bundle_size_kb);

    log::info!(
        "Core Web Vitals - FCP: {:.0}ms, TTI: {:.0}ms, LCP: {:.0}ms",
        fcp, tti, lcp
    );
    log::info!("Estimated Lighthouse score: {:.0}", lighthouse_score);

    // Provide specific recommendations based on scores
    if lighthouse_score < 90.0 {
        if fcp > 1800.0 {
            log::warn!("FCP needs improvement. Consider inlining critical CSS and reducing render-blocking resources.");
        }
        if tti > 3800.0 {
            log::warn!("TTI needs improvement. Consider code splitting and reducing JavaScript execution time.");
        }
        if lcp > 2500.0 {
            log::warn!("LCP needs improvement. Consider optimizing images and preloading critical assets.");
        }
    }

    Ok(FrontendMetrics {
        first_contentful_paint_ms: fcp,
        time_to_interactive_ms: tti,
        largest_contentful_paint_ms: lcp,
        bundle_size_kb,
        lighthouse_score,
    })
}
