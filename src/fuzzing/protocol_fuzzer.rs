//! Protocol Fuzzer
//!
//! Template-based fuzzing for network protocols.

use std::collections::HashMap;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};
use chrono::Utc;
use rand::prelude::*;

use crate::fuzzing::types::*;
use crate::fuzzing::mutators::Mutator;
use crate::fuzzing::generators::InputGenerator;

/// Protocol fuzzer for network services
pub struct ProtocolFuzzer {
    mutator: Mutator,
    generator: InputGenerator,
}

impl ProtocolFuzzer {
    /// Create a new protocol fuzzer
    pub fn new() -> Self {
        Self {
            mutator: Mutator::new(),
            generator: InputGenerator::new(),
        }
    }

    /// Fuzz a TCP service
    pub async fn fuzz_tcp(
        &self,
        target: &str,
        port: u16,
        template: Option<&FuzzTemplate>,
        config: &FuzzerConfig,
        iterations: u64,
    ) -> Vec<FuzzingCrash> {
        let mut crashes = Vec::new();
        let addr = format!("{}:{}", target, port);
        let timeout_duration = Duration::from_secs(5);

        for i in 0..iterations {
            // Generate input
            let input = if let Some(tmpl) = template {
                self.generator.generate_from_template(tmpl)
            } else {
                let base = config.seeds.as_ref()
                    .and_then(|s| s.first())
                    .cloned()
                    .unwrap_or_else(|| self.generator.generate_random(config));
                self.mutator.mutate(&base, config)
            };

            // Connect and send
            let result = timeout(timeout_duration, async {
                match TcpStream::connect(&addr).await {
                    Ok(mut stream) => {
                        if let Err(e) = stream.write_all(&input).await {
                            return Some(self.create_crash_from_error(&e.to_string(), &input, "tcp"));
                        }

                        // Try to read response
                        let mut buf = vec![0u8; 4096];
                        match stream.read(&mut buf).await {
                            Ok(0) => {
                                // Connection closed - might be crash
                                return Some(self.create_crash_from_error(
                                    "Connection closed by server",
                                    &input,
                                    "tcp",
                                ));
                            }
                            Ok(_n) => None,
                            Err(e) => {
                                Some(self.create_crash_from_error(&e.to_string(), &input, "tcp"))
                            }
                        }
                    }
                    Err(e) => {
                        // Connection refused might mean service crashed
                        if e.to_string().contains("Connection refused") {
                            Some(self.create_crash_from_error(&e.to_string(), &input, "tcp"))
                        } else {
                            None
                        }
                    }
                }
            }).await;

            match result {
                Ok(Some(crash)) => crashes.push(crash),
                Err(_) => {
                    // Timeout
                    crashes.push(FuzzingCrash {
                        id: uuid::Uuid::new_v4().to_string(),
                        campaign_id: String::new(),
                        crash_type: CrashType::Hang,
                        crash_hash: self.hash_input(&input),
                        exploitability: Exploitability::Unknown,
                        input_data: input,
                        input_size: 0,
                        stack_trace: None,
                        registers: None,
                        signal: None,
                        exit_code: None,
                        stderr_output: Some("TCP timeout".to_string()),
                        reproduced: false,
                        reproduction_count: 1,
                        minimized_input: None,
                        notes: None,
                        created_at: Utc::now(),
                    });
                }
                Ok(None) => {}
            }

            // Small delay between iterations
            if i % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        crashes
    }

    /// Fuzz a UDP service
    pub async fn fuzz_udp(
        &self,
        target: &str,
        port: u16,
        template: Option<&FuzzTemplate>,
        config: &FuzzerConfig,
        iterations: u64,
    ) -> Vec<FuzzingCrash> {
        let mut crashes = Vec::new();
        let addr = format!("{}:{}", target, port);
        let timeout_duration = Duration::from_secs(2);

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return crashes,
        };

        for i in 0..iterations {
            // Generate input
            let input = if let Some(tmpl) = template {
                self.generator.generate_from_template(tmpl)
            } else {
                let base = config.seeds.as_ref()
                    .and_then(|s| s.first())
                    .cloned()
                    .unwrap_or_else(|| self.generator.generate_random(config));
                self.mutator.mutate(&base, config)
            };

            // Send packet
            if let Err(e) = socket.send_to(&input, &addr).await {
                crashes.push(self.create_crash_from_error(&e.to_string(), &input, "udp"));
                continue;
            }

            // Try to receive response (UDP is connectionless)
            let mut buf = vec![0u8; 4096];
            let result = timeout(timeout_duration, socket.recv_from(&mut buf)).await;

            match result {
                Ok(Ok((_n, _src))) => {
                    // Got response, service is still alive
                }
                Ok(Err(e)) => {
                    crashes.push(self.create_crash_from_error(&e.to_string(), &input, "udp"));
                }
                Err(_) => {
                    // Timeout - this is normal for UDP, don't count as crash
                }
            }

            if i % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        crashes
    }

    /// Create a common protocol template
    pub fn create_protocol_template(&self, protocol: &str) -> Option<FuzzTemplate> {
        match protocol.to_lowercase().as_str() {
            "http" => Some(FuzzTemplate {
                name: "HTTP Request".to_string(),
                content: "{{METHOD}} {{PATH}} HTTP/1.1\r\nHost: {{HOST}}\r\nContent-Length: {{LENGTH}}\r\n\r\n{{BODY}}".to_string(),
                fuzz_points: vec![
                    FuzzPoint {
                        name: "METHOD".to_string(),
                        data_type: FuzzDataType::String,
                        min_length: Some(3),
                        max_length: Some(10),
                        values: Some(vec![
                            "GET".to_string(), "POST".to_string(), "PUT".to_string(),
                            "DELETE".to_string(), "PATCH".to_string(), "OPTIONS".to_string(),
                        ]),
                    },
                    FuzzPoint {
                        name: "PATH".to_string(),
                        data_type: FuzzDataType::Path,
                        min_length: Some(1),
                        max_length: Some(1024),
                        values: None,
                    },
                    FuzzPoint {
                        name: "HOST".to_string(),
                        data_type: FuzzDataType::String,
                        min_length: Some(1),
                        max_length: Some(256),
                        values: None,
                    },
                    FuzzPoint {
                        name: "LENGTH".to_string(),
                        data_type: FuzzDataType::Integer,
                        min_length: None,
                        max_length: None,
                        values: None,
                    },
                    FuzzPoint {
                        name: "BODY".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(0),
                        max_length: Some(10240),
                        values: None,
                    },
                ],
            }),
            "smtp" => Some(FuzzTemplate {
                name: "SMTP Commands".to_string(),
                content: "{{COMMAND}} {{ARG}}\r\n".to_string(),
                fuzz_points: vec![
                    FuzzPoint {
                        name: "COMMAND".to_string(),
                        data_type: FuzzDataType::String,
                        min_length: Some(4),
                        max_length: Some(10),
                        values: Some(vec![
                            "HELO".to_string(), "EHLO".to_string(), "MAIL FROM:".to_string(),
                            "RCPT TO:".to_string(), "DATA".to_string(), "QUIT".to_string(),
                            "VRFY".to_string(), "EXPN".to_string(), "RSET".to_string(),
                        ]),
                    },
                    FuzzPoint {
                        name: "ARG".to_string(),
                        data_type: FuzzDataType::String,
                        min_length: Some(0),
                        max_length: Some(512),
                        values: None,
                    },
                ],
            }),
            "ftp" => Some(FuzzTemplate {
                name: "FTP Commands".to_string(),
                content: "{{COMMAND}} {{ARG}}\r\n".to_string(),
                fuzz_points: vec![
                    FuzzPoint {
                        name: "COMMAND".to_string(),
                        data_type: FuzzDataType::String,
                        min_length: Some(3),
                        max_length: Some(10),
                        values: Some(vec![
                            "USER".to_string(), "PASS".to_string(), "LIST".to_string(),
                            "RETR".to_string(), "STOR".to_string(), "CWD".to_string(),
                            "PWD".to_string(), "QUIT".to_string(), "PORT".to_string(),
                            "PASV".to_string(), "TYPE".to_string(), "SIZE".to_string(),
                        ]),
                    },
                    FuzzPoint {
                        name: "ARG".to_string(),
                        data_type: FuzzDataType::String,
                        min_length: Some(0),
                        max_length: Some(256),
                        values: None,
                    },
                ],
            }),
            "dns" => Some(FuzzTemplate {
                name: "DNS Query".to_string(),
                content: "{{TXID}}{{FLAGS}}{{QUESTIONS}}{{ANSWERS}}{{AUTHORITY}}{{ADDITIONAL}}{{QUERY}}".to_string(),
                fuzz_points: vec![
                    FuzzPoint {
                        name: "TXID".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(2),
                        max_length: Some(2),
                        values: None,
                    },
                    FuzzPoint {
                        name: "FLAGS".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(2),
                        max_length: Some(2),
                        values: None,
                    },
                    FuzzPoint {
                        name: "QUESTIONS".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(2),
                        max_length: Some(2),
                        values: None,
                    },
                    FuzzPoint {
                        name: "ANSWERS".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(2),
                        max_length: Some(2),
                        values: None,
                    },
                    FuzzPoint {
                        name: "AUTHORITY".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(2),
                        max_length: Some(2),
                        values: None,
                    },
                    FuzzPoint {
                        name: "ADDITIONAL".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(2),
                        max_length: Some(2),
                        values: None,
                    },
                    FuzzPoint {
                        name: "QUERY".to_string(),
                        data_type: FuzzDataType::Binary,
                        min_length: Some(5),
                        max_length: Some(255),
                        values: None,
                    },
                ],
            }),
            _ => None,
        }
    }

    /// Create crash from error
    fn create_crash_from_error(&self, error: &str, input: &[u8], protocol: &str) -> FuzzingCrash {
        FuzzingCrash {
            id: uuid::Uuid::new_v4().to_string(),
            campaign_id: String::new(),
            crash_type: CrashType::Unknown,
            crash_hash: self.hash_input(input),
            exploitability: Exploitability::Unknown,
            input_data: input.to_vec(),
            input_size: input.len(),
            stack_trace: None,
            registers: None,
            signal: None,
            exit_code: None,
            stderr_output: Some(format!("{} error: {}", protocol.to_uppercase(), error)),
            reproduced: false,
            reproduction_count: 1,
            minimized_input: None,
            notes: None,
            created_at: Utc::now(),
        }
    }

    /// Hash input for deduplication
    fn hash_input(&self, input: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for ProtocolFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
