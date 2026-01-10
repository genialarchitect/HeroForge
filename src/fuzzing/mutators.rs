//! Fuzzing Mutators
//!
//! Various mutation strategies for fuzzing inputs.

use rand::prelude::*;
use crate::fuzzing::types::{FuzzerConfig, MutationStrategy};

/// Interesting values for mutation
const INTERESTING_8: [u8; 9] = [
    0x00, 0x01, 0x7f, 0x80, 0xff,
    0x10, 0x20, 0x40, 0xfe,
];

const INTERESTING_16: [u16; 10] = [
    0x0000, 0x0001, 0x007f, 0x0080, 0x00ff,
    0x0100, 0x7fff, 0x8000, 0xfffe, 0xffff,
];

const INTERESTING_32: [u32; 12] = [
    0x00000000, 0x00000001, 0x0000007f, 0x00000080,
    0x000000ff, 0x00007fff, 0x00008000, 0x0000ffff,
    0x7fffffff, 0x80000000, 0xffffff80, 0xffffffff,
];

/// Input mutator
pub struct Mutator {
    rng: rand::rngs::ThreadRng,
}

impl Mutator {
    /// Create a new mutator
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    /// Mutate an input based on configuration
    pub fn mutate(&self, input: &[u8], config: &FuzzerConfig) -> Vec<u8> {
        let strategies = config.mutation_strategies.clone().unwrap_or_else(|| {
            vec![
                MutationStrategy::BitFlip,
                MutationStrategy::ByteFlip,
                MutationStrategy::ArithmeticAdd,
                MutationStrategy::InterestingValues,
                MutationStrategy::BlockDuplication,
                MutationStrategy::BlockDeletion,
            ]
        });

        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();

        // Apply 1-3 mutations
        let num_mutations = rng.gen_range(1..=3);

        for _ in 0..num_mutations {
            let strategy = strategies.choose(&mut rng).unwrap_or(&MutationStrategy::BitFlip);
            result = self.apply_mutation(&result, strategy, config);
        }

        result
    }

    /// Apply a specific mutation strategy
    fn apply_mutation(&self, input: &[u8], strategy: &MutationStrategy, config: &FuzzerConfig) -> Vec<u8> {
        let rng = rand::thread_rng();

        match strategy {
            MutationStrategy::BitFlip => self.bit_flip(input),
            MutationStrategy::ByteFlip => self.byte_flip(input),
            MutationStrategy::ArithmeticAdd => self.arithmetic_add(input),
            MutationStrategy::ArithmeticSub => self.arithmetic_sub(input),
            MutationStrategy::InterestingValues => self.interesting_values(input),
            MutationStrategy::BlockDuplication => self.block_duplication(input, config),
            MutationStrategy::BlockDeletion => self.block_deletion(input),
            MutationStrategy::BlockInsertion => self.block_insertion(input, config),
            MutationStrategy::BlockSwap => self.block_swap(input),
            MutationStrategy::Havoc => self.havoc(input, config),
            MutationStrategy::Splice => self.splice(input, config),
            MutationStrategy::Dictionary => self.dictionary_insert(input, config),
            MutationStrategy::Custom => input.to_vec(),
        }
    }

    /// Flip a random bit
    fn bit_flip(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }

        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();
        let byte_pos = rng.gen_range(0..result.len());
        let bit_pos = rng.gen_range(0..8);
        result[byte_pos] ^= 1 << bit_pos;
        result
    }

    /// Flip a random byte
    fn byte_flip(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }

        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();
        let pos = rng.gen_range(0..result.len());
        result[pos] = rng.gen();
        result
    }

    /// Add a small value to a random byte/word/dword
    fn arithmetic_add(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }

        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();
        let pos = rng.gen_range(0..result.len());
        let delta: u8 = rng.gen_range(1..=35);

        match rng.gen_range(0..3) {
            0 => {
                // 8-bit
                result[pos] = result[pos].wrapping_add(delta);
            }
            1 if pos + 2 <= result.len() => {
                // 16-bit
                let val = u16::from_le_bytes([result[pos], result[pos + 1]]);
                let new_val = val.wrapping_add(delta as u16);
                let bytes = new_val.to_le_bytes();
                result[pos] = bytes[0];
                result[pos + 1] = bytes[1];
            }
            2 if pos + 4 <= result.len() => {
                // 32-bit
                let val = u32::from_le_bytes([
                    result[pos], result[pos + 1], result[pos + 2], result[pos + 3]
                ]);
                let new_val = val.wrapping_add(delta as u32);
                let bytes = new_val.to_le_bytes();
                result[pos..pos + 4].copy_from_slice(&bytes);
            }
            _ => {
                result[pos] = result[pos].wrapping_add(delta);
            }
        }

        result
    }

    /// Subtract a small value from a random byte/word/dword
    fn arithmetic_sub(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }

        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();
        let pos = rng.gen_range(0..result.len());
        let delta: u8 = rng.gen_range(1..=35);

        match rng.gen_range(0..3) {
            0 => {
                result[pos] = result[pos].wrapping_sub(delta);
            }
            1 if pos + 2 <= result.len() => {
                let val = u16::from_le_bytes([result[pos], result[pos + 1]]);
                let new_val = val.wrapping_sub(delta as u16);
                let bytes = new_val.to_le_bytes();
                result[pos] = bytes[0];
                result[pos + 1] = bytes[1];
            }
            2 if pos + 4 <= result.len() => {
                let val = u32::from_le_bytes([
                    result[pos], result[pos + 1], result[pos + 2], result[pos + 3]
                ]);
                let new_val = val.wrapping_sub(delta as u32);
                let bytes = new_val.to_le_bytes();
                result[pos..pos + 4].copy_from_slice(&bytes);
            }
            _ => {
                result[pos] = result[pos].wrapping_sub(delta);
            }
        }

        result
    }

    /// Replace with interesting values
    fn interesting_values(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }

        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();
        let pos = rng.gen_range(0..result.len());

        match rng.gen_range(0..3) {
            0 => {
                // 8-bit
                result[pos] = *INTERESTING_8.choose(&mut rng).unwrap();
            }
            1 if pos + 2 <= result.len() => {
                // 16-bit
                let val = INTERESTING_16.choose(&mut rng).unwrap();
                let bytes = if rng.gen_bool(0.5) {
                    val.to_le_bytes()
                } else {
                    val.to_be_bytes()
                };
                result[pos] = bytes[0];
                result[pos + 1] = bytes[1];
            }
            2 if pos + 4 <= result.len() => {
                // 32-bit
                let val = INTERESTING_32.choose(&mut rng).unwrap();
                let bytes = if rng.gen_bool(0.5) {
                    val.to_le_bytes()
                } else {
                    val.to_be_bytes()
                };
                result[pos..pos + 4].copy_from_slice(&bytes);
            }
            _ => {
                result[pos] = *INTERESTING_8.choose(&mut rng).unwrap();
            }
        }

        result
    }

    /// Duplicate a random block
    fn block_duplication(&self, input: &[u8], config: &FuzzerConfig) -> Vec<u8> {
        if input.len() < 2 {
            return input.to_vec();
        }

        let max_size = config.max_input_size.unwrap_or(1024 * 1024);
        let mut rng = rand::thread_rng();

        let block_size = rng.gen_range(1..=input.len().min(64));
        let src_pos = rng.gen_range(0..input.len() - block_size + 1);
        let dst_pos = rng.gen_range(0..=input.len());

        let mut result = Vec::with_capacity(input.len() + block_size);
        result.extend_from_slice(&input[..dst_pos]);
        result.extend_from_slice(&input[src_pos..src_pos + block_size]);
        result.extend_from_slice(&input[dst_pos..]);

        // Truncate if too large
        if result.len() > max_size {
            result.truncate(max_size);
        }

        result
    }

    /// Delete a random block
    fn block_deletion(&self, input: &[u8]) -> Vec<u8> {
        if input.len() < 2 {
            return input.to_vec();
        }

        let mut rng = rand::thread_rng();
        let block_size = rng.gen_range(1..=input.len() / 2);
        let pos = rng.gen_range(0..input.len() - block_size + 1);

        let mut result = Vec::with_capacity(input.len() - block_size);
        result.extend_from_slice(&input[..pos]);
        result.extend_from_slice(&input[pos + block_size..]);

        result
    }

    /// Insert a random block
    fn block_insertion(&self, input: &[u8], config: &FuzzerConfig) -> Vec<u8> {
        let max_size = config.max_input_size.unwrap_or(1024 * 1024);
        let mut rng = rand::thread_rng();

        let block_size = rng.gen_range(1..=64);
        let pos = if input.is_empty() {
            0
        } else {
            rng.gen_range(0..=input.len())
        };

        let mut result = Vec::with_capacity(input.len() + block_size);
        result.extend_from_slice(&input[..pos]);

        // Generate random bytes or repeat existing bytes
        if !input.is_empty() && rng.gen_bool(0.5) {
            // Repeat bytes from input
            let src_pos = rng.gen_range(0..input.len());
            for i in 0..block_size {
                result.push(input[(src_pos + i) % input.len()]);
            }
        } else {
            // Random bytes
            for _ in 0..block_size {
                result.push(rng.gen());
            }
        }

        result.extend_from_slice(&input[pos..]);

        if result.len() > max_size {
            result.truncate(max_size);
        }

        result
    }

    /// Swap two random blocks
    fn block_swap(&self, input: &[u8]) -> Vec<u8> {
        if input.len() < 4 {
            return input.to_vec();
        }

        let mut rng = rand::thread_rng();
        let block_size = rng.gen_range(1..=input.len() / 4);

        let pos1 = rng.gen_range(0..input.len() / 2 - block_size);
        let pos2 = rng.gen_range(input.len() / 2..input.len() - block_size);

        let mut result = input.to_vec();
        for i in 0..block_size {
            result.swap(pos1 + i, pos2 + i);
        }

        result
    }

    /// Havoc mode: apply multiple random mutations
    fn havoc(&self, input: &[u8], config: &FuzzerConfig) -> Vec<u8> {
        let mut result = input.to_vec();
        let mut rng = rand::thread_rng();
        let num_mutations = rng.gen_range(2..=16);

        let strategies = vec![
            MutationStrategy::BitFlip,
            MutationStrategy::ByteFlip,
            MutationStrategy::ArithmeticAdd,
            MutationStrategy::ArithmeticSub,
            MutationStrategy::InterestingValues,
            MutationStrategy::BlockDuplication,
            MutationStrategy::BlockDeletion,
            MutationStrategy::BlockInsertion,
            MutationStrategy::BlockSwap,
        ];

        for _ in 0..num_mutations {
            let strategy = strategies.choose(&mut rng).unwrap();
            result = self.apply_mutation(&result, strategy, config);
        }

        result
    }

    /// Splice two inputs together
    fn splice(&self, input: &[u8], _config: &FuzzerConfig) -> Vec<u8> {
        // Without a corpus, we just duplicate and mutate
        if input.len() < 2 {
            return input.to_vec();
        }

        let mut rng = rand::thread_rng();
        let split_point = rng.gen_range(1..input.len());

        let mut result = input[..split_point].to_vec();
        // Reverse second half as simple splice variant
        let mut second_half: Vec<u8> = input[split_point..].to_vec();
        second_half.reverse();
        result.extend_from_slice(&second_half);

        result
    }

    /// Insert dictionary words
    fn dictionary_insert(&self, input: &[u8], config: &FuzzerConfig) -> Vec<u8> {
        let dictionary = config.dictionary.clone().unwrap_or_else(|| {
            // Default dictionary for common fuzzing scenarios
            vec![
                // SQL injection
                "' OR '1'='1".to_string(),
                "'; DROP TABLE".to_string(),
                "1; SELECT *".to_string(),
                // XSS
                "<script>".to_string(),
                "javascript:".to_string(),
                "onerror=".to_string(),
                // Command injection
                "; ls".to_string(),
                "| cat /etc/passwd".to_string(),
                "`id`".to_string(),
                "$(whoami)".to_string(),
                // Path traversal
                "../".to_string(),
                "..\\".to_string(),
                "%2e%2e%2f".to_string(),
                // Format strings
                "%n%n%n%n".to_string(),
                "%s%s%s%s".to_string(),
                "%x%x%x%x".to_string(),
                // Buffer overflow triggers
                "A".repeat(256),
                "A".repeat(1024),
                "\x00\x00\x00\x00".to_string(),
            ]
        });

        if dictionary.is_empty() {
            return input.to_vec();
        }

        let mut rng = rand::thread_rng();
        let word = dictionary.choose(&mut rng).unwrap();
        let pos = if input.is_empty() {
            0
        } else {
            rng.gen_range(0..=input.len())
        };

        let mut result = Vec::with_capacity(input.len() + word.len());
        result.extend_from_slice(&input[..pos]);
        result.extend_from_slice(word.as_bytes());
        result.extend_from_slice(&input[pos..]);

        result
    }
}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_flip() {
        let mutator = Mutator::new();
        let input = vec![0x00, 0x00, 0x00, 0x00];
        let result = mutator.bit_flip(&input);

        // At least one bit should be different
        let diff: u32 = input.iter().zip(result.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert_eq!(diff, 1);
    }

    #[test]
    fn test_block_deletion() {
        let mutator = Mutator::new();
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let result = mutator.block_deletion(&input);
        assert!(result.len() < input.len());
    }

    #[test]
    fn test_block_duplication() {
        let mutator = Mutator::new();
        let input = vec![1, 2, 3, 4];
        let config = FuzzerConfig {
            mutation_strategies: None,
            grammar: None,
            template: None,
            dictionary: None,
            seeds: None,
            max_input_size: Some(1024),
            min_input_size: None,
            max_iterations: None,
            max_runtime_secs: None,
            enable_coverage: None,
            workers: None,
        };
        let result = mutator.block_duplication(&input, &config);
        assert!(result.len() >= input.len());
    }
}
