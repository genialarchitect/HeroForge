//! Entropy Analysis Module
//!
//! Calculates Shannon entropy for binary data to detect packed,
//! encrypted, or compressed content.

/// Calculate Shannon entropy for a byte slice
/// Returns a value between 0.0 (no randomness) and 8.0 (maximum randomness)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate entropy for chunks of data
/// Returns a vector of (offset, entropy) pairs
pub fn calculate_chunk_entropy(data: &[u8], chunk_size: usize) -> Vec<(u64, f64)> {
    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| {
            ((i * chunk_size) as u64, calculate_entropy(chunk))
        })
        .collect()
}

/// Entropy thresholds for classification
pub mod thresholds {
    /// Text/code typically has low entropy
    pub const LOW_ENTROPY: f64 = 4.0;

    /// Normal binary code
    pub const NORMAL_ENTROPY: f64 = 6.0;

    /// High entropy suggests compression/encryption
    pub const HIGH_ENTROPY: f64 = 7.0;

    /// Very high entropy strongly suggests encryption
    pub const VERY_HIGH_ENTROPY: f64 = 7.5;
}

/// Entropy classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyLevel {
    /// Low entropy (< 4.0) - likely plaintext, sparse data
    Low,
    /// Normal entropy (4.0 - 6.0) - typical binary code
    Normal,
    /// High entropy (6.0 - 7.5) - possibly compressed
    High,
    /// Very high entropy (> 7.5) - likely encrypted or packed
    VeryHigh,
}

impl EntropyLevel {
    /// Classify entropy value
    pub fn from_entropy(entropy: f64) -> Self {
        if entropy < thresholds::LOW_ENTROPY {
            EntropyLevel::Low
        } else if entropy < thresholds::NORMAL_ENTROPY {
            EntropyLevel::Normal
        } else if entropy < thresholds::VERY_HIGH_ENTROPY {
            EntropyLevel::High
        } else {
            EntropyLevel::VeryHigh
        }
    }

    /// Check if entropy suggests packing/encryption
    pub fn is_suspicious(&self) -> bool {
        matches!(self, EntropyLevel::High | EntropyLevel::VeryHigh)
    }
}

/// Analyze entropy distribution across a binary
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    /// Overall file entropy
    pub overall_entropy: f64,

    /// Overall entropy classification
    pub classification: EntropyLevel,

    /// Entropy by section (offset, size, entropy)
    pub sections: Vec<SectionEntropy>,

    /// High entropy regions (offset, size, entropy)
    pub high_entropy_regions: Vec<EntropyRegion>,

    /// Whether the binary appears to be packed
    pub appears_packed: bool,

    /// Confidence score for packing detection (0.0 - 1.0)
    pub packing_confidence: f64,
}

/// Section entropy information
#[derive(Debug, Clone)]
pub struct SectionEntropy {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub classification: EntropyLevel,
}

/// High entropy region
#[derive(Debug, Clone)]
pub struct EntropyRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
}

/// Perform full entropy analysis on binary data
pub fn analyze_entropy(data: &[u8], chunk_size: usize) -> EntropyAnalysis {
    let overall_entropy = calculate_entropy(data);
    let classification = EntropyLevel::from_entropy(overall_entropy);

    // Calculate chunk entropies
    let chunk_entropies = calculate_chunk_entropy(data, chunk_size);

    // Find high entropy regions
    let mut high_entropy_regions = Vec::new();
    let mut region_start: Option<u64> = None;
    let mut region_chunks = 0;

    for (offset, entropy) in &chunk_entropies {
        if *entropy >= thresholds::HIGH_ENTROPY {
            if region_start.is_none() {
                region_start = Some(*offset);
            }
            region_chunks += 1;
        } else if let Some(start) = region_start {
            // End of high entropy region
            let size = region_chunks * chunk_size;
            let region_data = &data[start as usize..(start as usize + size).min(data.len())];
            let region_entropy = calculate_entropy(region_data);

            high_entropy_regions.push(EntropyRegion {
                offset: start,
                size: size as u64,
                entropy: region_entropy,
            });

            region_start = None;
            region_chunks = 0;
        }
    }

    // Handle trailing high entropy region
    if let Some(start) = region_start {
        let size = region_chunks * chunk_size;
        let region_data = &data[start as usize..(start as usize + size).min(data.len())];
        let region_entropy = calculate_entropy(region_data);

        high_entropy_regions.push(EntropyRegion {
            offset: start,
            size: size as u64,
            entropy: region_entropy,
        });
    }

    // Calculate packing indicators
    let (appears_packed, packing_confidence) = detect_packing_from_entropy(
        overall_entropy,
        &chunk_entropies,
        &high_entropy_regions,
        data.len(),
    );

    EntropyAnalysis {
        overall_entropy,
        classification,
        sections: Vec::new(), // Filled in by caller with section info
        high_entropy_regions,
        appears_packed,
        packing_confidence,
    }
}

/// Detect packing based on entropy patterns
fn detect_packing_from_entropy(
    overall_entropy: f64,
    chunk_entropies: &[(u64, f64)],
    high_entropy_regions: &[EntropyRegion],
    file_size: usize,
) -> (bool, f64) {
    let mut confidence: f64 = 0.0;

    // Factor 1: High overall entropy
    if overall_entropy >= thresholds::VERY_HIGH_ENTROPY {
        confidence += 0.4;
    } else if overall_entropy >= thresholds::HIGH_ENTROPY {
        confidence += 0.2;
    }

    // Factor 2: Large high-entropy regions
    let high_entropy_bytes: u64 = high_entropy_regions.iter().map(|r| r.size).sum();
    let high_entropy_ratio = high_entropy_bytes as f64 / file_size as f64;

    if high_entropy_ratio > 0.8 {
        confidence += 0.4;
    } else if high_entropy_ratio > 0.5 {
        confidence += 0.2;
    }

    // Factor 3: Consistent high entropy (low variance)
    if !chunk_entropies.is_empty() {
        let entropies: Vec<f64> = chunk_entropies.iter().map(|(_, e)| *e).collect();
        let mean: f64 = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let variance: f64 = entropies.iter()
            .map(|e| (e - mean).powi(2))
            .sum::<f64>() / entropies.len() as f64;

        // Low variance with high mean suggests uniform encryption/compression
        if variance < 0.5 && mean > thresholds::HIGH_ENTROPY {
            confidence += 0.2;
        }
    }

    // Factor 4: Entry point in high entropy region (would need PE/ELF parsing)
    // This is handled by the packer_detection module

    let appears_packed = confidence >= 0.5;
    (appears_packed, confidence.min(1.0))
}

/// Get entropy histogram (256 bins for byte frequency)
pub fn get_entropy_histogram(data: &[u8]) -> [u64; 256] {
    let mut histogram = [0u64; 256];
    for &byte in data {
        histogram[byte as usize] += 1;
    }
    histogram
}

/// Calculate chi-square statistic for randomness test
/// Lower values suggest less random (more structured) data
pub fn chi_square_test(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let histogram = get_entropy_histogram(data);
    let expected = data.len() as f64 / 256.0;

    let mut chi_square = 0.0;
    for &count in &histogram {
        let diff = count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    chi_square
}

/// Monte Carlo Pi estimation test for randomness
/// Values close to Pi suggest random data
pub fn monte_carlo_pi(data: &[u8]) -> f64 {
    if data.len() < 8 {
        return 0.0;
    }

    let mut inside_circle = 0u64;
    let mut total_points = 0u64;

    // Use pairs of bytes as x,y coordinates
    for chunk in data.chunks(4) {
        if chunk.len() >= 4 {
            let x = u16::from_le_bytes([chunk[0], chunk[1]]) as f64 / 65535.0;
            let y = u16::from_le_bytes([chunk[2], chunk[3]]) as f64 / 65535.0;

            // Check if point is inside unit circle
            if x * x + y * y <= 1.0 {
                inside_circle += 1;
            }
            total_points += 1;
        }
    }

    if total_points == 0 {
        return 0.0;
    }

    4.0 * inside_circle as f64 / total_points as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.1, "Entropy of all zeros should be ~0");
    }

    #[test]
    fn test_entropy_random() {
        // Simulate random data
        let data: Vec<u8> = (0..1000).map(|i| (i * 17 + 13) as u8).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0, "Entropy of varied data should be high");
    }

    #[test]
    fn test_entropy_text() {
        let text = b"Hello World! This is some sample text with normal distribution.";
        let entropy = calculate_entropy(text);
        assert!(entropy > 3.0 && entropy < 5.0, "Text entropy should be moderate");
    }

    #[test]
    fn test_entropy_level_classification() {
        assert_eq!(EntropyLevel::from_entropy(2.0), EntropyLevel::Low);
        assert_eq!(EntropyLevel::from_entropy(5.0), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_entropy(7.0), EntropyLevel::High);
        assert_eq!(EntropyLevel::from_entropy(7.8), EntropyLevel::VeryHigh);
    }
}
