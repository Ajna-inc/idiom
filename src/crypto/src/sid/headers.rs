/// Header validation and parsing for SID structure
///
/// SID structure (18 digits in base-125, where d0 is MSB/first digit):
/// - d0: version (4 bits) + network (3 bits) - FIRST digit (MSB)
/// - d1: DID kind (7 bits)
/// - d2: Shard ID (0-15 for state sharding)
/// - d3-d16: random payload (14 digits ≈ 98 bits)
/// - d17: checksum (7 bits) - LAST digit (LSB)
use crate::sid::error::{Result, SIDError};

/// Extract a single digit from sid_int (base-125)
/// Digit 0 is the MSB (most significant), digit 17 is LSB
fn extract_digit(sid_int: u128, index: usize) -> u8 {
    assert!(index < 18, "Digit index must be 0-17");
    let mut n = sid_int;
    // Divide by 125^(17-index) to shift the desired digit to position 0
    for _ in 0..(17 - index) {
        n /= 125;
    }
    (n % 125) as u8
}

/// SID Version (4 bits, stored in upper 4 bits of digit 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum Version {
    /// Version 0: DID identifier
    #[default]
    V0 = 0,
    /// Version 1: Transaction ID (future)
    V1 = 1,
    /// Version 2: Asset ID (future)
    V2 = 2,
    /// Version 3: Contract ID (future)
    V3 = 3,
    // 4-15 reserved for future versions
}

impl Version {
    /// Parse from 4-bit value
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Version::V0),
            1 => Ok(Version::V1),
            2 => Ok(Version::V2),
            3 => Ok(Version::V3),
            v => Err(SIDError::InvalidVersion(v)),
        }
    }

    /// Convert to 4-bit value
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Network type (3 bits, stored in lower 3 bits of digit 0)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum Network {
    /// Mainnet (production)
    #[default]
    Mainnet = 0,
    /// Testnet (public testing)
    Testnet = 1,
    /// Devnet (development)
    Devnet = 2,
    /// Staging (pre-production)
    Staging = 3,
    // 4-7 reserved for future networks
}

impl Network {
    /// Parse from 3-bit value
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Network::Mainnet),
            1 => Ok(Network::Testnet),
            2 => Ok(Network::Devnet),
            3 => Ok(Network::Staging),
            v if v < 8 => Err(SIDError::InvalidFormat(format!(
                "Reserved network value: {}",
                v
            ))),
            v => Err(SIDError::InvalidFormat(format!(
                "Invalid network value: {}",
                v
            ))),
        }
    }

    /// Convert to 3-bit value
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// DID Kind (7 bits, stored in digit 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum DIDKind {
    /// Generic DID (default)
    #[default]
    Generic = 0,
    /// Person/Individual
    Person = 1,
    /// Organization
    Organization = 2,
    /// Device/IoT
    Device = 3,
    /// AI Agent
    Agent = 4,
    /// Service endpoint
    Service = 5,
    /// Faucet DID (for genesis/bootstrap)
    Faucet = 6,
    // 7-124 reserved for future kinds
}

impl DIDKind {
    /// Parse from 7-bit value (0-124, 125 is reserved)
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(DIDKind::Generic),
            1 => Ok(DIDKind::Person),
            2 => Ok(DIDKind::Organization),
            3 => Ok(DIDKind::Device),
            4 => Ok(DIDKind::Agent),
            5 => Ok(DIDKind::Service),
            6 => Ok(DIDKind::Faucet),
            v if v < 125 => Err(SIDError::InvalidFormat(format!("Reserved DID kind: {}", v))),
            v => Err(SIDError::InvalidFormat(format!("Invalid DID kind: {}", v))),
        }
    }

    /// Convert to 7-bit value
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Shard ID for state partitioning (stored in digit 2)
///
/// The shard ID determines which of the 16 state shards this DID belongs to.
/// This enables parallel transaction execution across shards.
///
/// Shard assignment: `shard_id() = d2 % 16`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShardId {
    value: u8,
}

impl ShardId {
    /// Number of shards in the system
    pub const NUM_SHARDS: u8 = 16;

    /// Create new ShardId from d2 digit value (0-124)
    pub fn new(value: u8) -> Result<Self> {
        if value >= 125 {
            return Err(SIDError::InvalidFormat(format!(
                "ShardId value too large: {}",
                value
            )));
        }
        Ok(Self { value })
    }

    /// Create ShardId for a specific shard (0-15)
    pub fn for_shard(shard: u8) -> Result<Self> {
        if shard >= Self::NUM_SHARDS {
            return Err(SIDError::InvalidFormat(format!(
                "Shard must be 0-15, got: {}",
                shard
            )));
        }
        Ok(Self { value: shard })
    }

    /// Get the raw d2 digit value (0-124)
    pub fn as_u8(self) -> u8 {
        self.value
    }

    /// Get the shard index (0-15)
    #[inline]
    pub fn shard(self) -> u8 {
        self.value % Self::NUM_SHARDS
    }
}

/// SID header structure (digits 0-2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SIDHeader {
    pub version: Version,
    pub network: Network,
    pub kind: DIDKind,
    pub shard_id: ShardId,
}

impl SIDHeader {
    /// Create new header
    pub fn new(version: Version, network: Network, kind: DIDKind, shard_id: ShardId) -> Self {
        Self {
            version,
            network,
            kind,
            shard_id,
        }
    }

    /// Create header with specific shard (convenience method)
    pub fn with_shard(
        version: Version,
        network: Network,
        kind: DIDKind,
        shard: u8,
    ) -> Result<Self> {
        Ok(Self {
            version,
            network,
            kind,
            shard_id: ShardId::for_shard(shard)?,
        })
    }

    /// Parse header from digits 0-2 (base-125)
    pub fn from_digits(d0: u8, d1: u8, d2: u8) -> Result<Self> {
        // d0 = (version << 3) | network
        let version = Version::from_u8(d0 >> 3)?;
        let network = Network::from_u8(d0 & 0x07)?;

        // d1 = kind
        let kind = DIDKind::from_u8(d1)?;

        // d2 = shard_id
        let shard_id = ShardId::new(d2)?;

        Ok(Self {
            version,
            network,
            kind,
            shard_id,
        })
    }

    /// Convert header to digits 0-2 (base-125)
    pub fn to_digits(self) -> (u8, u8, u8) {
        let d0 = (self.version.as_u8() << 3) | self.network.as_u8();
        let d1 = self.kind.as_u8();
        let d2 = self.shard_id.as_u8();
        (d0, d1, d2)
    }

    /// Get the shard index (0-15) for this header
    #[inline]
    pub fn shard(&self) -> u8 {
        self.shard_id.shard()
    }

    /// Extract header from sid_int (u128)
    pub fn from_sid_int(sid_int: u128) -> Result<Self> {
        // Extract digits 0-2 from MSB side
        // Digit extraction: for digit i, divide by 125^(17-i) and take mod 125
        let d0 = extract_digit(sid_int, 0);
        let d1 = extract_digit(sid_int, 1);
        let d2 = extract_digit(sid_int, 2);

        Self::from_digits(d0, d1, d2)
    }

    /// Encode header into the first 3 digits of sid_int
    /// This builds a partial sid_int with headers in d0-d2
    /// Caller should add payload (d3-d16) and checksum (d17)
    pub fn to_sid_bits(self) -> u128 {
        let (d0, d1, d2) = self.to_digits();

        // Build sid_int starting from d0 (MSB)
        // sid_int = d0*125^17 + d1*125^16 + d2*125^15 + ...
        let mut result = 0u128;
        result = result * 125 + (d0 as u128);
        result = result * 125 + (d1 as u128);
        result = result * 125 + (d2 as u128);

        // Multiply by 125^15 to shift to the MSB position (d0-d2 of 18 digits)
        result * 125_u128.pow(15)
    }

    /// Validate header (check for invalid combinations)
    pub fn validate(&self) -> Result<()> {
        // Shard ID is always valid (0-124 maps to shards 0-15)
        // No restrictions on shard selection
        Ok(())
    }
}

impl Default for SIDHeader {
    fn default() -> Self {
        Self {
            version: Version::V0,
            network: Network::Mainnet,
            kind: DIDKind::Generic,
            shard_id: ShardId::new(0).unwrap(), // Default to shard 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_roundtrip() {
        for i in 0..=3 {
            let version = Version::from_u8(i).unwrap();
            assert_eq!(version.as_u8(), i);
        }
    }

    #[test]
    fn test_network_roundtrip() {
        for i in 0..=3 {
            let network = Network::from_u8(i).unwrap();
            assert_eq!(network.as_u8(), i);
        }
    }

    #[test]
    fn test_did_kind_roundtrip() {
        for i in 0..=6 {
            let kind = DIDKind::from_u8(i).unwrap();
            assert_eq!(kind.as_u8(), i);
        }
    }

    #[test]
    fn test_shard_id_basic() {
        // Test shard creation and extraction
        for shard in 0..16 {
            let shard_id = ShardId::for_shard(shard).unwrap();
            assert_eq!(shard_id.shard(), shard);
        }

        // Test invalid shard
        assert!(ShardId::for_shard(16).is_err());
        assert!(ShardId::for_shard(100).is_err());
    }

    #[test]
    fn test_shard_id_modulo() {
        // Values 0-15 map directly
        for i in 0..16 {
            let shard_id = ShardId::new(i).unwrap();
            assert_eq!(shard_id.shard(), i);
        }

        // Values 16+ wrap around via modulo
        assert_eq!(ShardId::new(16).unwrap().shard(), 0);
        assert_eq!(ShardId::new(17).unwrap().shard(), 1);
        assert_eq!(ShardId::new(32).unwrap().shard(), 0);
        assert_eq!(ShardId::new(124).unwrap().shard(), 12); // 124 % 16 = 12
    }

    #[test]
    fn test_header_roundtrip() {
        let header = SIDHeader {
            version: Version::V0,
            network: Network::Testnet,
            kind: DIDKind::Person,
            shard_id: ShardId::for_shard(5).unwrap(),
        };

        let (d0, d1, d2) = header.to_digits();
        let decoded = SIDHeader::from_digits(d0, d1, d2).unwrap();

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_header_encoding() {
        let header = SIDHeader {
            version: Version::V0,
            network: Network::Mainnet,
            kind: DIDKind::Generic,
            shard_id: ShardId::for_shard(0).unwrap(),
        };

        let (d0, d1, d2) = header.to_digits();
        assert_eq!(d0, 0); // version=0, network=0
        assert_eq!(d1, 0); // kind=0
        assert_eq!(d2, 0); // shard=0
    }

    #[test]
    fn test_header_with_shard() {
        // Test with_shard convenience method
        let header =
            SIDHeader::with_shard(Version::V0, Network::Testnet, DIDKind::Agent, 7).unwrap();

        assert_eq!(header.shard(), 7);
        assert_eq!(header.network, Network::Testnet);
        assert_eq!(header.kind, DIDKind::Agent);

        let (d0, d1, d2) = header.to_digits();
        assert_eq!(d0, 1); // version=0, network=1
        assert_eq!(d1, 4); // kind=Agent=4
        assert_eq!(d2, 7); // shard=7
    }

    #[test]
    fn test_header_all_shards() {
        // Test that all 16 shards work correctly
        for shard in 0..16 {
            let header =
                SIDHeader::with_shard(Version::V0, Network::Mainnet, DIDKind::Person, shard)
                    .unwrap();

            assert_eq!(header.shard(), shard);

            // Roundtrip through digits
            let (d0, d1, d2) = header.to_digits();
            let decoded = SIDHeader::from_digits(d0, d1, d2).unwrap();
            assert_eq!(decoded.shard(), shard);
        }
    }

    #[test]
    fn test_header_validation() {
        // All headers are valid now (no restrictions on shard)
        let header = SIDHeader::default();
        assert!(header.validate().is_ok());

        // Headers with any shard are valid
        for shard in 0..16 {
            let header =
                SIDHeader::with_shard(Version::V0, Network::Mainnet, DIDKind::Generic, shard)
                    .unwrap();
            assert!(header.validate().is_ok());
        }
    }

    #[test]
    fn test_sid_int_roundtrip() {
        let header = SIDHeader {
            version: Version::V0,
            network: Network::Testnet,
            kind: DIDKind::Organization,
            shard_id: ShardId::for_shard(12).unwrap(),
        };

        let sid_bits = header.to_sid_bits();
        let decoded = SIDHeader::from_sid_int(sid_bits).unwrap();

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_default_header() {
        let header = SIDHeader::default();
        assert_eq!(header.version, Version::V0);
        assert_eq!(header.network, Network::Mainnet);
        assert_eq!(header.kind, DIDKind::Generic);
        assert_eq!(header.shard(), 0); // Default shard is 0
    }
}
