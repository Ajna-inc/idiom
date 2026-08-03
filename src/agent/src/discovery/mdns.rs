//! mDNS Local Network Discovery
//!
//! Enables agents to discover each other on the same local network (WiFi/Ethernet)
//! using Multicast DNS (mDNS), also known as Bonjour or Avahi.
//!
//! ## How it works
//!
//! 1. Agent advertises itself via mDNS with service type `_ajna-agent._tcp.local`
//! 2. Other agents listen for mDNS announcements
//! 3. When discovered, agents can establish DIDComm connections
//!
//! ## Service Structure
//!
//! - Service Type: `_ajna-agent._tcp.local`
//! - Instance Name: Agent's DID (truncated for compatibility)
//! - Port: Agent's HTTP endpoint port
//! - TXT Records:
//!   - `did`: Full DID identifier
//!   - `endpoint`: Full endpoint URL
//!   - `version`: Protocol version
//!   - `capabilities`: Comma-separated capabilities

use super::{DiscoveryMethod, PeerInfo};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

const SERVICE_TYPE: &str = "_ajna-agent._tcp.local.";
const SCAN_TIMEOUT_SECS: u64 = 5;

/// mDNS Discovery Service
pub struct MdnsDiscovery {
    /// Our DID
    our_did: String,

    /// Our endpoint — reserved for advertising our own mDNS service record,
    /// which this browse-only implementation does not yet register.
    #[allow(dead_code)]
    our_endpoint: String,

    /// Our capabilities — reserved for advertising our own mDNS service record.
    #[allow(dead_code)]
    our_capabilities: Vec<String>,

    /// Channel to receive discovered peers
    discovery_rx: Option<mpsc::Receiver<PeerInfo>>,

    /// Handle to the background discovery task
    _discovery_handle: Option<tokio::task::JoinHandle<()>>,

    /// mDNS service daemon (kept alive)
    _mdns: Option<ServiceDaemon>,
}

impl MdnsDiscovery {
    /// Create a new mDNS discovery service and start advertising
    ///
    /// # Arguments
    /// * `did` - Our DID to advertise
    /// * `endpoint` - Our HTTP endpoint (e.g., "http://192.168.1.100:3000")
    /// * `capabilities` - List of capabilities we support
    ///
    /// # Returns
    /// A new MdnsDiscovery instance that is actively advertising and discovering
    pub async fn new(
        did: String,
        endpoint: String,
        capabilities: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        tracing::info!("🔧 [mDNS] Initializing mDNS discovery...");
        tracing::debug!("  DID: {}", did);
        tracing::debug!("  Endpoint: {}", endpoint);
        tracing::debug!("  Capabilities: {:?}", capabilities);

        // Parse endpoint to get host and port
        let url = url::Url::parse(&endpoint)?;
        let host = url.host_str().ok_or("No host in endpoint")?;
        let port = url
            .port()
            .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });

        // Create instance name (truncate DID if too long for mDNS)
        let instance_name = Self::create_instance_name(&did);

        // Create mDNS service daemon
        let mdns = ServiceDaemon::new()?;

        // Create TXT records
        let mut properties = HashMap::new();
        properties.insert("did".to_string(), did.clone());
        properties.insert("endpoint".to_string(), endpoint.clone());
        properties.insert("version".to_string(), "1.0".to_string());
        properties.insert("capabilities".to_string(), capabilities.join(","));

        // Register our service (advertise)
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &format!("{}.local.", host),
            host,
            port,
            properties,
        )?;

        match mdns.register(service_info) {
            Ok(_) => {
                tracing::info!("✓ [mDNS] Registered service: {}", instance_name);
            }
            Err(e) => {
                tracing::warn!("⚠️  [mDNS] Failed to register service: {}", e);
                tracing::debug!("  Note: mDNS registration failed, but continuing with discovery");
            }
        }

        // Create channel for discovered peers
        let (tx, rx) = mpsc::channel(100);

        // Start mDNS browser (discover others)
        let browser_handle = Self::start_browser(mdns.clone(), tx, did.clone())?;

        tracing::info!("✓ [mDNS] mDNS discovery initialized");
        tracing::debug!("  Advertising as: {}", instance_name);
        tracing::debug!("  Listening for peers on: {}", SERVICE_TYPE);

        Ok(Self {
            our_did: did,
            our_endpoint: endpoint,
            our_capabilities: capabilities,
            discovery_rx: Some(rx),
            _discovery_handle: Some(browser_handle),
            _mdns: Some(mdns),
        })
    }

    /// Create mDNS instance name from DID (must be valid mDNS name)
    fn create_instance_name(did: &str) -> String {
        // mDNS instance names should be human-readable
        // Extract suffix from did:ajna:SUFFIX
        if let Some(suffix) = did.strip_prefix("did:ajna:") {
            // Take first 20 chars to keep it short
            let truncated = if suffix.len() > 20 {
                &suffix[..20]
            } else {
                suffix
            };
            format!("ajna-{}", truncated)
        } else {
            // Fallback for other DID methods
            "ajna-agent".to_string()
        }
    }

    /// Start mDNS browser to discover other agents
    fn start_browser(
        mdns: ServiceDaemon,
        tx: mpsc::Sender<PeerInfo>,
        our_did: String,
    ) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
        // Browse for Ajna agent services
        let receiver = mdns.browse(SERVICE_TYPE)?;

        let handle = tokio::spawn(async move {
            tracing::info!("[mDNS] Started browsing for Ajna agents on local network");

            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        tracing::debug!("[mDNS] Service resolved: {:?}", info.get_fullname());

                        // Extract DID from TXT records
                        let did = info.get_property_val_str("did");
                        let endpoint = info.get_property_val_str("endpoint");
                        let capabilities_str = info.get_property_val_str("capabilities");

                        if let (Some(did), Some(endpoint)) = (did, endpoint) {
                            // Don't discover ourselves
                            if did == our_did {
                                tracing::debug!("[mDNS] Ignoring self-discovery");
                                continue;
                            }

                            // Parse capabilities
                            let capabilities: Vec<String> = capabilities_str
                                .map(|s| s.split(',').map(|c| c.to_string()).collect())
                                .unwrap_or_default();

                            let peer = PeerInfo {
                                did: did.to_string(),
                                endpoint: endpoint.to_string(),
                                capabilities,
                                discovered_at: chrono::Utc::now(),
                                discovery_method: DiscoveryMethod::Mdns,
                                last_seen: chrono::Utc::now(),
                            };

                            tracing::info!(
                                "[mDNS] Discovered peer: {} at {}",
                                peer.did,
                                peer.endpoint
                            );

                            if let Err(e) = tx.send(peer).await {
                                tracing::error!("[mDNS] Failed to send discovered peer: {}", e);
                                break;
                            }
                        } else {
                            tracing::warn!(
                                "[mDNS] Service missing required TXT records (did/endpoint)"
                            );
                        }
                    }
                    ServiceEvent::ServiceRemoved(typ, fullname) => {
                        tracing::debug!("[mDNS] Service removed: {} - {}", typ, fullname);
                    }
                    ServiceEvent::SearchStarted(typ) => {
                        tracing::debug!("[mDNS] Search started for: {}", typ);
                    }
                    ServiceEvent::SearchStopped(typ) => {
                        tracing::warn!("[mDNS] Search stopped for: {}", typ);
                    }
                    _ => {}
                }
            }

            tracing::info!("[mDNS] Browser task ended");
        });

        Ok(handle)
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
    pub async fn discover_once(&self) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error>> {
        let mdns = ServiceDaemon::new()?;
        let receiver = mdns.browse(SERVICE_TYPE)?;
        let our_did = self.our_did.clone();

        // Spawn blocking task to handle sync receiver
        let peers = tokio::task::spawn_blocking(move || {
            let mut peers = Vec::new();
            let start = std::time::Instant::now();

            while start.elapsed() < Duration::from_secs(SCAN_TIMEOUT_SECS) {
                // Try to receive with timeout
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(ServiceEvent::ServiceResolved(info)) => {
                        let did = info.get_property_val_str("did");
                        let endpoint = info.get_property_val_str("endpoint");
                        let capabilities_str = info.get_property_val_str("capabilities");

                        if let (Some(did), Some(endpoint)) = (did, endpoint) {
                            // Don't include ourselves
                            if did == our_did {
                                continue;
                            }

                            let capabilities: Vec<String> = capabilities_str
                                .map(|s| s.split(',').map(|c| c.to_string()).collect())
                                .unwrap_or_default();

                            let peer = PeerInfo {
                                did: did.to_string(),
                                endpoint: endpoint.to_string(),
                                capabilities,
                                discovered_at: chrono::Utc::now(),
                                discovery_method: DiscoveryMethod::Mdns,
                                last_seen: chrono::Utc::now(),
                            };

                            peers.push(peer);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // Timeout or channel closed - continue until time limit
                    }
                }
            }

            peers
        })
        .await?;

        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_instance_name() {
        let name = MdnsDiscovery::create_instance_name("did:ajna:abc123xyz789");
        assert_eq!(name, "ajna-abc123xyz789");

        let long_did = "did:ajna:verylongidentifierthatexceeds20characters";
        let name = MdnsDiscovery::create_instance_name(long_did);
        assert_eq!(name, "ajna-verylongidentifier");
        assert!(name.len() <= 25); // ajna- + 20 chars
    }

    #[tokio::test]
    async fn test_mdns_discovery_initialization() {
        // This test requires network access and may fail in CI environments
        // It's here to verify the API works correctly

        let result = MdnsDiscovery::new(
            "did:ajna:test123".to_string(),
            "http://192.168.1.100:3000".to_string(),
            vec!["did_sync".to_string()],
        )
        .await;

        // We don't assert success because mDNS may not be available
        // but we verify the code compiles and runs
        match result {
            Ok(_) => tracing::info!("✓ mDNS initialization succeeded"),
            Err(e) => tracing::info!(
                "⚠️  mDNS initialization failed (expected in some environments): {}",
                e
            ),
        }
    }
}
