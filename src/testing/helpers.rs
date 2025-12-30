//! Testing helper functions

use anyhow::Result;

/// Assert that a result is an error with a specific message
pub fn assert_error_contains(result: &Result<()>, expected_msg: &str) {
    match result {
        Ok(_) => panic!("Expected error but got Ok"),
        Err(e) => {
            let error_msg = format!("{}", e);
            assert!(
                error_msg.contains(expected_msg),
                "Expected error message to contain '{}', but got: '{}'",
                expected_msg,
                error_msg
            );
        }
    }
}

/// Generate random test data
pub mod generators {
    use rand::Rng;

    pub fn random_ip() -> String {
        let mut rng = rand::thread_rng();
        format!(
            "{}.{}.{}.{}",
            rng.gen_range(1..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(1..255)
        )
    }

    pub fn random_port() -> u16 {
        let mut rng = rand::thread_rng();
        rng.gen_range(1..65535)
    }

    pub fn random_cidr() -> String {
        let mut rng = rand::thread_rng();
        format!(
            "{}.{}.{}.0/{}",
            rng.gen_range(1..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(24..29)
        )
    }

    pub fn random_string(length: usize) -> String {
        use rand::distributions::Alphanumeric;
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
}

/// Timing helpers for performance tests
pub mod timing {
    use std::time::{Duration, Instant};

    pub struct Timer {
        start: Instant,
    }

    impl Timer {
        pub fn start() -> Self {
            Self {
                start: Instant::now(),
            }
        }

        pub fn elapsed(&self) -> Duration {
            self.start.elapsed()
        }

        pub fn elapsed_ms(&self) -> u128 {
            self.elapsed().as_millis()
        }

        pub fn assert_completed_within(&self, max_duration: Duration) {
            let elapsed = self.elapsed();
            assert!(
                elapsed <= max_duration,
                "Operation took {:?}, expected to complete within {:?}",
                elapsed,
                max_duration
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generators::*;

    #[test]
    fn test_random_generators() {
        let ip = random_ip();
        assert!(ip.contains('.'));

        let port = random_port();
        assert!(port > 0 && port < 65535);

        let cidr = random_cidr();
        assert!(cidr.contains('/'));

        let s = random_string(10);
        assert_eq!(s.len(), 10);
    }

    #[test]
    fn test_timer() {
        use std::thread;
        use std::time::Duration;

        let timer = timing::Timer::start();
        thread::sleep(Duration::from_millis(100));

        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 100);
    }
}
