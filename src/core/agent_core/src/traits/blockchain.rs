//! Blockchain service trait for Agent integration
//!
//! This trait allows the Agent to interact with blockchain functionality
//! through an injected service (e.g., AjnaClient).

use async_trait::async_trait;

/// Error type for blockchain operations
#[derive(Debug, Clone)]
pub struct BlockchainError(pub String);

impl std::fmt::Display for BlockchainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BlockchainError {}

impl From<String> for BlockchainError {
    fn from(s: String) -> Self {
        BlockchainError(s)
    }
}

impl From<&str> for BlockchainError {
    fn from(s: &str) -> Self {
        BlockchainError(s.to_string())
    }
}

/// Result type for blockchain operations
pub type BlockchainResult<T> = std::result::Result<T, BlockchainError>;

/// Consensus status from the blockchain network
#[derive(Debug, Clone)]
pub struct ConsensusStatus {
    /// Current view/block number
    pub current_view: u64,
    /// Whether this validator is the current leader
    pub is_leader: bool,
    /// Number of pending transactions in mempool
    pub mempool_size: usize,
    /// Total number of validators
    pub validator_count: usize,
    /// Latest committed block number
    pub latest_block: u64,
    /// Latest committed block hash
    pub latest_block_hash: String,
}

/// Account state from the blockchain
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Account address
    pub address: String,
    /// Whether the account exists
    pub exists: bool,
    /// Account balance (decimal string for large numbers)
    pub balance: Option<String>,
    /// Account nonce (transaction count)
    pub nonce: Option<u64>,
    /// Associated DID (if registered)
    pub did: Option<String>,
}

/// Result of transaction submission
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// Transaction hash (hex encoded)
    pub tx_hash: String,
    /// Status: "pending", "included", "rejected"
    pub status: String,
    /// Block number if included
    pub block_number: Option<u64>,
    /// Error message if rejected
    pub error: Option<String>,
}

/// Result of faucet request
#[derive(Debug, Clone)]
pub struct FaucetResult {
    /// Whether the request was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Amount received (decimal string)
    pub amount: Option<String>,
    /// Transaction hash
    pub tx_hash: Option<String>,
}

/// Result of DID registration
#[derive(Debug, Clone)]
pub struct DidRegistrationResult {
    /// Whether registration was successful
    pub success: bool,
    /// The registered DID
    pub did: Option<String>,
    /// Transaction hash
    pub tx_hash: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Blockchain service trait for Agent integration
///
/// This trait allows the Agent to interact with blockchain functionality
/// through an injected service (e.g., AjnaClient).
///
/// # Example
///
/// ```ignore
/// use agent_core::traits::BlockchainService;
/// use ajna_client::AjnaClient;
///
/// // AjnaClient implements BlockchainService
/// let client = AjnaClient::new(config).await?;
///
/// // Inject into Agent
/// let agent = Agent::builder()
///     .storage(storage)
///     .wallet_provider(wallet)
///     .blockchain_service(Arc::new(client))
///     .build()?;
///
/// // Now Agent can do blockchain operations
/// let balance = agent.get_balance("0x1234...").await?;
/// ```
#[async_trait]
pub trait BlockchainService: Send + Sync {
    /// Get consensus status from the network
    async fn get_consensus_status(&self) -> BlockchainResult<ConsensusStatus>;

    /// Get account balance
    async fn get_balance(&self, address: &str) -> BlockchainResult<String>;

    /// Get account nonce
    async fn get_nonce(&self, address: &str) -> BlockchainResult<u64>;

    /// Get full account state
    async fn get_account(&self, address: &str) -> BlockchainResult<AccountState>;

    /// Get latest block number
    async fn get_latest_block_number(&self) -> BlockchainResult<u64>;

    /// Submit a signed transaction
    ///
    /// # Arguments
    /// * `tx_bytes` - The signed transaction bytes (SCALE encoded)
    ///
    /// # Returns
    /// Transaction result with hash and status
    async fn submit_transaction(&self, tx_bytes: &[u8]) -> BlockchainResult<TransactionResult>;

    /// Request tokens from faucet (devnet/testnet only)
    ///
    /// # Arguments
    /// * `recipient` - The recipient address (hex string)
    async fn request_faucet(&self, recipient: &str) -> BlockchainResult<FaucetResult>;

    /// Register a DID on-chain
    ///
    /// # Arguments
    /// * `sid_sanskrit` - The SID in Sanskrit encoding
    /// * `vm_root` - The verification method Merkle root (hex)
    /// * `did_document` - The DID document (JSON)
    async fn register_did(
        &self,
        sid_sanskrit: &str,
        vm_root: &str,
        did_document: serde_json::Value,
    ) -> BlockchainResult<DidRegistrationResult>;

    /// Resolve a handle to a DID document
    ///
    /// Queries the explorer for the handle index, fetches the DID document,
    /// decrypts the `encryptedConnection` section, and returns the full document.
    ///
    /// # Arguments
    /// * `handle` - The plaintext handle (e.g., "alice-karamada")
    ///
    /// # Returns
    /// The fully decrypted DID document, or None if not found
    async fn resolve_handle(&self, _handle: &str) -> BlockchainResult<Option<serde_json::Value>> {
        Err(BlockchainError("resolve_handle not implemented".into()))
    }

    /// Wait for balance to change (useful after faucet/transfer)
    ///
    /// Default implementation polls get_balance until it changes.
    async fn wait_for_balance_change(
        &self,
        address: &str,
        initial_balance: &str,
        timeout_secs: u64,
    ) -> BlockchainResult<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

        while std::time::Instant::now() < deadline {
            let current = self.get_balance(address).await?;
            if current != initial_balance {
                return Ok(current);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        Err(BlockchainError(format!(
            "Balance did not change within {} seconds",
            timeout_secs
        )))
    }
}
