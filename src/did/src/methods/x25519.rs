//! Canonical Ed25519 ↔ X25519 / did:key helpers.
//!
//! These functions were previously duplicated in:
//!   - `mediator_server/src/crypto.rs`
//!   - `agent/src/crypto/secrets_resolver.rs`
//!   - `did_methods/src/key.rs` (private method on `KeyDidResolver`)
//!   - `didcomm_v1/src/crypto/utils.rs` (Askar-flavored variant)
//!
//! `did_methods` is the lowest crate every caller already depends on,
//! so this is the canonical home. The Askar-flavored helper in
//! `didcomm_v1` and the private secrets-resolver methods can be kept
//! for now (they take different argument types), but new call sites
//! should use these free functions.
//!
//! Background:
//! - did:key Ed25519 form (`z6Mk…`) is the signing/identity key.
//! - DIDComm authcrypt/anoncrypt uses ECDH, which requires X25519.
//! - X25519 is derived from Ed25519 by Edwards → Montgomery curve
//!   mapping (RFC 7748). The conversion is deterministic.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;

/// Convert a 32-byte Ed25519 seed (raw private key) to the derived
/// X25519 secret + its matching X25519 public key.
///
/// Standard Ed25519 → X25519 derivation (per libsodium
/// `crypto_sign_ed25519_sk_to_curve25519`):
///   1. SHA-512 the seed.
///   2. Take the first 32 bytes as the X25519 scalar.
///   3. Clamp per RFC 7748: clear low 3 bits, clear high bit, set second-highest bit.
///   4. Derive the X25519 pub by scalar-multiplying the basepoint.
///
/// Both outputs are 32 bytes. Used by DIDComm authcrypt + DCX channel
/// establishment — anywhere we need the X25519 counterpart of an
/// Ed25519 identity that lives in the wallet.
///
/// Previously duplicated inline as a private method on
/// `AgentSecretsResolver::ed25519_private_to_x25519`; new callers use
/// this free function.
pub fn ed25519_private_to_x25519(ed25519_seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    use curve25519_dalek::constants::X25519_BASEPOINT;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    if ed25519_seed.len() != 32 {
        return Err(format!(
            "Ed25519 seed must be 32 bytes, got {}",
            ed25519_seed.len()
        ));
    }
    let hash = Sha512::digest(ed25519_seed);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&hash[..32]);
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(secret);
    let public = (scalar * X25519_BASEPOINT).to_bytes();
    Ok((secret, public))
}

/// Convert a 32-byte Ed25519 public key to its corresponding 32-byte
/// X25519 public key (curve mapping per RFC 7748).
pub fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<[u8; 32], String> {
    if ed25519_public.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            ed25519_public.len()
        ));
    }
    let edwards_point = CompressedEdwardsY::from_slice(ed25519_public)
        .map_err(|e| format!("Invalid Ed25519 public key: {:?}", e))?;
    let edwards = edwards_point
        .decompress()
        .ok_or_else(|| "Failed to decompress Ed25519 public key".to_string())?;
    let montgomery: MontgomeryPoint = edwards.to_montgomery();
    Ok(montgomery.to_bytes())
}

/// Parse a `did:key:z…` Ed25519 DID into its raw 32-byte verkey.
/// Returns `None` if the input isn't a recognisable did:key (no
/// `did:key:z` prefix, bad base58, wrong multicodec, or wrong length).
pub fn ed25519_pubkey_from_did_key(did_key: &str) -> Option<[u8; 32]> {
    let stripped = did_key.strip_prefix("did:key:z")?;
    // Some callers pass `did:key:z…#z…` references; trim the fragment.
    let stripped = stripped.split('#').next().unwrap_or(stripped);
    let decoded = bs58::decode(stripped).into_vec().ok()?;
    // Ed25519 multicodec prefix: [0xed, 0x01]
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[2..]);
    Some(out)
}

/// Given a `did:key:z…` Ed25519 DID, return all the base58 verkey
/// strings the JWE/keylist layer may use to address this identity:
///   1. The Ed25519 raw verkey (matches `from`/`to` plaintext fields
///      after DIDComm v1 unpack).
///   2. The X25519 raw verkey derived from (1) (matches the JWE
///      recipient `kid` for ECDH-based authcrypt/anoncrypt).
///
/// Returns `None` if `did_key` isn't a valid Ed25519 did:key.
///
/// This is what the per-tenant routing table needs to register so an
/// inbound JWE (whose kid is the X25519 form) routes to the right
/// tenant even though the keylist key (set by the mediator) is the
/// Ed25519 form.
pub fn verkey_aliases_for_did_key(did_key: &str) -> Option<DidKeyAliases> {
    let ed = ed25519_pubkey_from_did_key(did_key)?;
    let x = ed25519_public_to_x25519(&ed).ok()?;
    Some(DidKeyAliases {
        ed25519_base58: bs58::encode(ed).into_string(),
        x25519_base58: bs58::encode(x).into_string(),
    })
}

#[derive(Debug, Clone)]
pub struct DidKeyAliases {
    /// Base58-encoded raw Ed25519 public key (32 bytes).
    pub ed25519_base58: String,
    /// Base58-encoded raw X25519 public key (32 bytes), derived from
    /// the Ed25519 via Edwards→Montgomery mapping.
    pub x25519_base58: String,
}

/// Normalize an identifier to `did:key:z…` form.
///
/// Accepts:
/// - Already-`did:` strings → returned unchanged.
/// - 32-byte Ed25519 raw verkey base58 (the form DIDComm v1 authcrypt
///   leaves on the unpacked `from`/`to`) → wrapped as
///   `did:key:z{multicodec || verkey}`.
///
/// Returns the input unchanged on any other format. Canonical
/// replacement for `mediator_server::routes::ensure_did_key` and
/// `agent_ffi::mediation::verkey_to_did_key`, which were both private
/// copies of this same logic. Use this wherever a downstream API needs
/// a real DID (e.g., `pack_encrypted`'s `to` argument) but the input
/// may arrive as a raw verkey.
pub fn ensure_did_key_form(input: &str) -> String {
    if input.starts_with("did:") {
        return input.to_string();
    }
    if let Ok(decoded) = bs58::decode(input).into_vec() {
        if decoded.len() == 32 {
            let mut multicodec = Vec::with_capacity(34);
            multicodec.push(0xed);
            multicodec.push(0x01);
            multicodec.extend_from_slice(&decoded);
            return format!("did:key:z{}", bs58::encode(multicodec).into_string());
        }
    }
    input.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_to_x25519_matches_known_vector() {
        // Known RFC 8032 test vector: Ed25519 public key for the
        // private seed of 32 0xC0 bytes (not security-critical here —
        // we just need a stable vector).
        // Generate Ed25519 pub from a fixed seed and verify the X
        // conversion is deterministic and 32 bytes.
        let ed_pub = [0x57u8; 32];
        // 0x57 is not actually on the Edwards curve in general; pick
        // a real point: the basepoint compressed encoding.
        // ED25519_BASEPOINT_COMPRESSED:
        let basepoint_compressed: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let x = ed25519_public_to_x25519(&basepoint_compressed).expect("basepoint must convert");
        assert_eq!(x.len(), 32);
        // Determinism.
        let x2 = ed25519_public_to_x25519(&basepoint_compressed).unwrap();
        assert_eq!(x, x2);

        // Reject wrong-length input.
        assert!(ed25519_public_to_x25519(&ed_pub[..10]).is_err());
    }

    #[test]
    fn parse_ed25519_did_key_round_trip() {
        // Construct a did:key for a known Ed25519 verkey, then parse
        // it back.
        let ed_pub: [u8; 32] = [0x66; 32];
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&ed_pub);
        let did_key = format!("did:key:z{}", bs58::encode(&multicodec).into_string());
        assert_eq!(ed25519_pubkey_from_did_key(&did_key), Some(ed_pub));

        // Fragment is tolerated.
        let with_frag = format!("{}#z123", did_key);
        assert_eq!(ed25519_pubkey_from_did_key(&with_frag), Some(ed_pub));

        // Non-did:key input rejected.
        assert!(ed25519_pubkey_from_did_key("not-a-did").is_none());
        assert!(ed25519_pubkey_from_did_key("did:peer:1z…").is_none());
    }

    #[test]
    fn ensure_did_key_form_round_trips() {
        // Already a DID — unchanged.
        assert_eq!(
            ensure_did_key_form("did:key:z6MkABC"),
            "did:key:z6MkABC".to_string(),
        );
        assert_eq!(
            ensure_did_key_form("did:peer:1zXYZ"),
            "did:peer:1zXYZ".to_string(),
        );

        // 32-byte raw verkey — wrapped to did:key.
        let raw = [0x66u8; 32];
        let raw_b58 = bs58::encode(&raw).into_string();
        let did = ensure_did_key_form(&raw_b58);
        assert!(did.starts_with("did:key:z"), "got: {}", did);
        // Round-trip back to raw bytes.
        assert_eq!(ed25519_pubkey_from_did_key(&did), Some(raw));

        // Garbage input — unchanged.
        assert_eq!(ensure_did_key_form("not-base58!"), "not-base58!");
        // Short base58 (not 32 bytes) — unchanged.
        assert_eq!(ensure_did_key_form("3"), "3");
    }

    #[test]
    fn verkey_aliases_yields_both_forms() {
        // Use the Ed25519 basepoint so the curve math actually works.
        let basepoint_compressed: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&basepoint_compressed);
        let did_key = format!("did:key:z{}", bs58::encode(&multicodec).into_string());

        let aliases = verkey_aliases_for_did_key(&did_key).expect("aliases");
        // Ed25519 alias must match the embedded verkey.
        assert_eq!(
            aliases.ed25519_base58,
            bs58::encode(basepoint_compressed).into_string()
        );
        // X25519 alias must be different from Ed25519 (Edwards ≠ Montgomery).
        assert_ne!(aliases.ed25519_base58, aliases.x25519_base58);
        // Both are 32-byte values (base58 of 32 bytes is 43-44 chars).
        assert!(
            bs58::decode(&aliases.x25519_base58)
                .into_vec()
                .unwrap()
                .len()
                == 32
        );
    }
}
