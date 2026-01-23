//! Ethereum JSON-RPC Client
//!
//! Provides a simple client for interacting with Ethereum nodes via JSON-RPC.
//! Uses the `ETH_RPC_URL` environment variable for the RPC endpoint.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Ethereum RPC client
pub struct EthRpcClient {
    client: reqwest::Client,
    rpc_url: String,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: String,
    params: serde_json::Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl EthRpcClient {
    /// Create a new client from ETH_RPC_URL environment variable
    pub fn from_env() -> Result<Self> {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .map_err(|_| anyhow!("ETH_RPC_URL not configured"))?;

        if rpc_url.is_empty() {
            return Err(anyhow!("ETH_RPC_URL is empty"));
        }

        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            rpc_url,
        })
    }

    /// Send a JSON-RPC request
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
            id,
        };

        let response = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow!("RPC request failed: {}", e))?;

        let rpc_response: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse RPC response: {}", e))?;

        if let Some(error) = rpc_response.error {
            return Err(anyhow!("RPC error {}: {}", error.code, error.message));
        }

        rpc_response.result
            .ok_or_else(|| anyhow!("RPC response has no result"))
    }

    /// Get the balance of an address (in wei as hex string)
    pub async fn eth_get_balance(&self, address: &str) -> Result<String> {
        let result = self.call(
            "eth_getBalance",
            serde_json::json!([address, "latest"]),
        ).await?;

        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid balance response"))
    }

    /// Get the contract code at an address
    pub async fn eth_get_code(&self, address: &str) -> Result<String> {
        let result = self.call(
            "eth_getCode",
            serde_json::json!([address, "latest"]),
        ).await?;

        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid getCode response"))
    }

    /// Execute a read-only contract call
    pub async fn eth_call(&self, to: &str, data: &str) -> Result<String> {
        let result = self.call(
            "eth_call",
            serde_json::json!([{"to": to, "data": data}, "latest"]),
        ).await?;

        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid eth_call response"))
    }

    /// Get transaction by hash
    pub async fn eth_get_transaction_by_hash(&self, tx_hash: &str) -> Result<serde_json::Value> {
        self.call(
            "eth_getTransactionByHash",
            serde_json::json!([tx_hash]),
        ).await
    }

    /// Get transaction receipt
    pub async fn eth_get_transaction_receipt(&self, tx_hash: &str) -> Result<serde_json::Value> {
        self.call(
            "eth_getTransactionReceipt",
            serde_json::json!([tx_hash]),
        ).await
    }

    /// Get logs matching a filter
    pub async fn eth_get_logs(
        &self,
        address: &str,
        from_block: &str,
        to_block: &str,
        topics: Option<Vec<Option<String>>>,
    ) -> Result<Vec<serde_json::Value>> {
        let mut filter = serde_json::json!({
            "address": address,
            "fromBlock": from_block,
            "toBlock": to_block,
        });

        if let Some(t) = topics {
            filter["topics"] = serde_json::json!(t);
        }

        let result = self.call("eth_getLogs", serde_json::json!([filter])).await?;

        result.as_array()
            .cloned()
            .ok_or_else(|| anyhow!("Invalid getLogs response"))
    }

    /// Get the current block number
    pub async fn eth_block_number(&self) -> Result<u64> {
        let result = self.call("eth_blockNumber", serde_json::json!([])).await?;

        let hex_str = result.as_str()
            .ok_or_else(|| anyhow!("Invalid blockNumber response"))?;

        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| anyhow!("Failed to parse block number: {}", e))
    }

    /// Get transaction count for an address
    pub async fn eth_get_transaction_count(&self, address: &str) -> Result<u64> {
        let result = self.call(
            "eth_getTransactionCount",
            serde_json::json!([address, "latest"]),
        ).await?;

        let hex_str = result.as_str()
            .ok_or_else(|| anyhow!("Invalid transactionCount response"))?;

        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| anyhow!("Failed to parse transaction count: {}", e))
    }
}

/// Parse a hex balance string (wei) to ETH as f64
pub fn wei_hex_to_eth(hex_wei: &str) -> f64 {
    let hex = hex_wei.trim_start_matches("0x");
    let wei = u128::from_str_radix(hex, 16).unwrap_or(0);
    wei as f64 / 1e18
}

/// Encode a function selector (first 4 bytes of keccak256 hash)
/// This uses a pre-computed lookup for common selectors
pub fn function_selector(signature: &str) -> String {
    // Common ERC-20/721/1155 selectors
    match signature {
        "balanceOf(address)" => "0x70a08231".to_string(),
        "totalSupply()" => "0x18160ddd".to_string(),
        "owner()" => "0x8da5cb5b".to_string(),
        "name()" => "0x06fdde03".to_string(),
        "symbol()" => "0x95d89b41".to_string(),
        "decimals()" => "0x313ce567".to_string(),
        "tokenURI(uint256)" => "0xc87b56dd".to_string(),
        "uri(uint256)" => "0x0e89341c".to_string(),
        "supportsInterface(bytes4)" => "0x01ffc9a7".to_string(),
        "royaltyInfo(uint256,uint256)" => "0x2a55205a".to_string(),
        _ => {
            // Unknown selector - log warning and return placeholder
            log::warn!("Unknown function selector requested: {}", signature);
            "0x00000000".to_string()
        }
    }
}

/// Pad an address to 32 bytes for ABI encoding
pub fn abi_encode_address(address: &str) -> String {
    let addr = address.trim_start_matches("0x");
    format!("000000000000000000000000{}", addr)
}

/// Pad a uint256 to 32 bytes for ABI encoding
pub fn abi_encode_uint256(value: u64) -> String {
    format!("{:064x}", value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wei_hex_to_eth() {
        // 1 ETH = 1e18 wei = 0xDE0B6B3A7640000
        assert!((wei_hex_to_eth("0xDE0B6B3A7640000") - 1.0).abs() < 0.001);
        assert_eq!(wei_hex_to_eth("0x0"), 0.0);
    }

    #[test]
    fn test_function_selector() {
        assert_eq!(function_selector("balanceOf(address)"), "0x70a08231");
        assert_eq!(function_selector("totalSupply()"), "0x18160ddd");
        assert_eq!(function_selector("supportsInterface(bytes4)"), "0x01ffc9a7");
    }

    #[test]
    fn test_abi_encode_address() {
        let encoded = abi_encode_address("0x1234567890abcdef1234567890abcdef12345678");
        assert_eq!(encoded.len(), 64);
        assert!(encoded.ends_with("1234567890abcdef1234567890abcdef12345678"));
    }
}
