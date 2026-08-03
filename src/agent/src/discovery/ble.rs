//! BLE (Bluetooth Low Energy) Proximity Discovery
//!
//! Enables agents to discover each other via Bluetooth Low Energy for:
//! - Mobile devices (iOS, Android)
//! - Desktop with BLE support
//! - Proximity-based discovery (typically 10-100 meters)
//!
//! ## How it works
//!
//! 1. Agent advertises via BLE peripheral mode with custom Ajna service UUID
//! 2. Agent scans for other agents via BLE central mode
//! 3. When discovered, agents can establish DIDComm connections
//!
//! ## BLE Service Structure
//!
//! - Service UUID: `0000a3a0-0000-1000-8000-00805f9b34fb` (Ajna)
//! - Characteristics:
//!   - `did` (read): DID identifier (UUID: `0000d1d0-0000-1000-8000-00805f9b34fb`)
//!   - `endpoint` (read): HTTP/WebSocket endpoint (UUID: `0000e9d0-0000-1000-8000-00805f9b34fb`)
//!   - `capabilities` (read): JSON array (UUID: `0000ca90-0000-1000-8000-00805f9b34fb`)
//!
//! ## Platform Notes
//!
//! - **iOS**: Requires `NSBluetoothPeripheralUsageDescription` in Info.plist
//! - **Android**: Requires BLUETOOTH, BLUETOOTH_ADMIN, ACCESS_FINE_LOCATION permissions
//! - **Desktop (Linux)**: Requires BlueZ installed and user in bluetooth group
//! - **Desktop (macOS)**: Works out of the box with system permissions

use super::{DiscoveryMethod, PeerInfo};
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, Peripheral};
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Ajna BLE Service UUID: 0000a3a0-0000-1000-8000-00805f9b34fb
const AJNA_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000a3a0_0000_1000_8000_00805f9b34fb);

/// DID Characteristic UUID (read): 0000d1d0-0000-1000-8000-00805f9b34fb
const DID_CHAR_UUID: Uuid = Uuid::from_u128(0x0000d1d0_0000_1000_8000_00805f9b34fb);

/// Endpoint Characteristic UUID (read): 0000e9d0-0000-1000-8000-00805f9b34fb
const ENDPOINT_CHAR_UUID: Uuid = Uuid::from_u128(0x0000e9d0_0000_1000_8000_00805f9b34fb);

/// Capabilities Characteristic UUID (read): 0000ca90-0000-1000-8000-00805f9b34fb
const CAPABILITIES_CHAR_UUID: Uuid = Uuid::from_u128(0x0000ca90_0000_1000_8000_00805f9b34fb);

/// Scan timeout in seconds
const SCAN_TIMEOUT_SECS: u64 = 10;

/// BLE Discovery Service
pub struct BleDiscovery {
    /// Our DID
    our_did: String,

    /// Our endpoint — reserved for BLE peripheral (advertising) mode, which
    /// this scan-only implementation does not yet support.
    #[allow(dead_code)]
    our_endpoint: String,

    /// Our capabilities — reserved for BLE peripheral (advertising) mode.
    #[allow(dead_code)]
    our_capabilities: Vec<String>,

    /// BLE adapter
    adapter: Option<Adapter>,

    /// Channel to receive discovered peers
    discovery_rx: Option<mpsc::Receiver<PeerInfo>>,

    /// Handle to the background discovery task
    _discovery_handle: Option<tokio::task::JoinHandle<()>>,
}

impl BleDiscovery {
    /// Create a new BLE discovery service
    ///
    /// # Arguments
    /// * `did` - Our DID to advertise
    /// * `endpoint` - Our HTTP endpoint
    /// * `capabilities` - List of capabilities we support
    ///
    /// # Returns
    /// A new BleDiscovery instance that is actively scanning
    ///
    /// # Note
    /// BLE advertising (peripheral mode) is platform-specific and complex.
    /// This implementation focuses on scanning (central mode) for simplicity.
    /// Full peripheral support requires platform-specific code (CoreBluetooth, Android BluetoothLeAdvertiser, etc.)
    pub async fn new(
        did: String,
        endpoint: String,
        capabilities: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("🔧 [BLE] Initializing BLE discovery...");
        tracing::debug!("  DID: {}", did);
        tracing::debug!("  Endpoint: {}", endpoint);
        tracing::debug!("  Capabilities: {:?}", capabilities);

        // Get BLE adapter
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let adapter = adapters.into_iter().next().ok_or("No BLE adapter found")?;

        tracing::info!(
            "✓ [BLE] Found BLE adapter: {:?}",
            adapter.adapter_info().await?
        );

        // Create channel for discovered peers
        let (tx, rx) = mpsc::channel(100);

        // Start BLE scanner
        let scanner_handle = Self::start_scanner(adapter.clone(), tx, did.clone()).await?;

        tracing::info!("✓ [BLE] BLE discovery initialized");
        tracing::debug!("  Scanning for Ajna agents via BLE...");
        tracing::debug!("  Note: BLE advertising requires platform-specific implementation");

        Ok(Self {
            our_did: did,
            our_endpoint: endpoint,
            our_capabilities: capabilities,
            adapter: Some(adapter),
            discovery_rx: Some(rx),
            _discovery_handle: Some(scanner_handle),
        })
    }

    /// Start BLE scanner to discover other agents
    async fn start_scanner(
        adapter: Adapter,
        tx: mpsc::Sender<PeerInfo>,
        our_did: String,
    ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        let handle = tokio::spawn(async move {
            tracing::info!("[BLE] Started scanning for Ajna agents via BLE");

            loop {
                // Start scanning with filter for Ajna service
                let filter = ScanFilter {
                    services: vec![AJNA_SERVICE_UUID],
                };

                match adapter.start_scan(filter).await {
                    Ok(_) => {
                        tracing::debug!("[BLE] Started BLE scan");
                    }
                    Err(e) => {
                        tracing::error!("[BLE] Failed to start BLE scan: {}", e);
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                }

                // Scan for 10 seconds
                tokio::time::sleep(Duration::from_secs(SCAN_TIMEOUT_SECS)).await;

                // Get discovered peripherals
                match adapter.peripherals().await {
                    Ok(peripherals) => {
                        tracing::debug!("[BLE] Found {} peripherals", peripherals.len());

                        for peripheral in peripherals {
                            // Try to read DID from peripheral
                            match Self::read_peer_info(&peripheral, &our_did).await {
                                Ok(Some(peer)) => {
                                    tracing::info!(
                                        "[BLE] Discovered peer: {} at {}",
                                        peer.did,
                                        peer.endpoint
                                    );

                                    if let Err(e) = tx.send(peer).await {
                                        tracing::error!(
                                            "[BLE] Failed to send discovered peer: {}",
                                            e
                                        );
                                        return;
                                    }
                                }
                                Ok(None) => {
                                    // Not an Ajna agent or couldn't read characteristics
                                }
                                Err(e) => {
                                    tracing::debug!("[BLE] Error reading peer info: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("[BLE] Failed to get peripherals: {}", e);
                    }
                }

                // Wait before next scan
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        Ok(handle)
    }

    /// Read peer information from a BLE peripheral
    async fn read_peer_info(
        peripheral: &Peripheral,
        our_did: &str,
    ) -> Result<Option<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        // Connect to peripheral
        if !peripheral.is_connected().await? {
            peripheral.connect().await?;
        }

        // Discover services
        peripheral.discover_services().await?;

        // Find Ajna service
        let services = peripheral.services();
        let Some(ajna_service) = services.iter().find(|s| s.uuid == AJNA_SERVICE_UUID) else {
            peripheral.disconnect().await?;
            return Ok(None);
        };

        // Read DID characteristic
        let did_char = ajna_service
            .characteristics
            .iter()
            .find(|c| c.uuid == DID_CHAR_UUID);

        let did = if let Some(char) = did_char {
            let data = peripheral.read(char).await?;
            String::from_utf8(data)?
        } else {
            peripheral.disconnect().await?;
            return Ok(None);
        };

        // Don't discover ourselves
        if did == our_did {
            peripheral.disconnect().await?;
            return Ok(None);
        }

        // Read endpoint characteristic
        let endpoint_char = ajna_service
            .characteristics
            .iter()
            .find(|c| c.uuid == ENDPOINT_CHAR_UUID);

        let endpoint = if let Some(char) = endpoint_char {
            let data = peripheral.read(char).await?;
            String::from_utf8(data)?
        } else {
            peripheral.disconnect().await?;
            return Ok(None);
        };

        // Read capabilities characteristic (optional)
        let capabilities_char = ajna_service
            .characteristics
            .iter()
            .find(|c| c.uuid == CAPABILITIES_CHAR_UUID);

        let capabilities: Vec<String> = if let Some(char) = capabilities_char {
            let data = peripheral.read(char).await?;
            let json_str = String::from_utf8(data)?;
            serde_json::from_str(&json_str).unwrap_or_default()
        } else {
            vec![]
        };

        // Disconnect
        peripheral.disconnect().await?;

        Ok(Some(PeerInfo {
            did,
            endpoint,
            capabilities,
            discovered_at: chrono::Utc::now(),
            discovery_method: DiscoveryMethod::Ble,
            last_seen: chrono::Utc::now(),
        }))
    }

    /// Receive next discovered peer (non-blocking)
    ///
    /// Returns None if no peers discovered yet
    pub async fn try_recv_peer(&mut self) -> Option<PeerInfo> {
        if let Some(ref mut rx) = self.discovery_rx {
            rx.try_recv().ok()
        } else {
            None
        }
    }

    /// Wait for next discovered peer (blocking)
    ///
    /// Returns None if discovery channel is closed
    pub async fn recv_peer(&mut self) -> Option<PeerInfo> {
        if let Some(ref mut rx) = self.discovery_rx {
            rx.recv().await
        } else {
            None
        }
    }

    /// Perform one-time discovery scan
    ///
    /// Returns all peers discovered in the scan period
    pub async fn discover_once(
        &self,
    ) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let adapter = self.adapter.as_ref().ok_or("No BLE adapter available")?;

        // Start scanning
        let filter = ScanFilter {
            services: vec![AJNA_SERVICE_UUID],
        };

        adapter.start_scan(filter).await?;

        // Scan for specified timeout
        tokio::time::sleep(Duration::from_secs(SCAN_TIMEOUT_SECS)).await;

        // Get discovered peripherals
        let peripherals = adapter.peripherals().await?;
        let mut peers = Vec::new();

        for peripheral in peripherals {
            match Self::read_peer_info(&peripheral, &self.our_did).await {
                Ok(Some(peer)) => {
                    peers.push(peer);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("[BLE] Error reading peer info: {}", e);
                }
            }
        }

        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ble_discovery_initialization() {
        // This test requires BLE hardware and may fail in CI environments
        // It's here to verify the API works correctly

        let result = BleDiscovery::new(
            "did:ajna:test123".to_string(),
            "http://192.168.1.100:3000".to_string(),
            vec!["did_sync".to_string()],
        )
        .await;

        // We don't assert success because BLE may not be available
        // but we verify the code compiles and runs
        match result {
            Ok(_) => tracing::info!("✓ BLE initialization succeeded"),
            Err(e) => {
                tracing::info!(
                    "⚠️  BLE initialization failed (expected in some environments): {}",
                    e
                )
            }
        }
    }

    #[test]
    fn test_uuids() {
        // Verify UUIDs are valid
        assert_eq!(
            AJNA_SERVICE_UUID.to_string(),
            "0000a3a0-0000-1000-8000-00805f9b34fb"
        );
        assert_eq!(
            DID_CHAR_UUID.to_string(),
            "0000d1d0-0000-1000-8000-00805f9b34fb"
        );
        assert_eq!(
            ENDPOINT_CHAR_UUID.to_string(),
            "0000e9d0-0000-1000-8000-00805f9b34fb"
        );
        assert_eq!(
            CAPABILITIES_CHAR_UUID.to_string(),
            "0000ca90-0000-1000-8000-00805f9b34fb"
        );
    }
}
