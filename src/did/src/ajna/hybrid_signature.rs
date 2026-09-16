//! Hybrid Ed25519 ‖ ML-DSA-65 signatures bound to a caller-supplied context.
//! Both components are mandatory; which contexts are accepted is the caller's policy.
use ::crypto::mldsa::{self, ValidatorPublicKey, ValidatorSignature};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(test)]
mod tests;

pub const PUBLIC_KEY_BYTES: usize = 32 + mldsa::PUBKEY_SIZE;
pub const SIGNATURE_BYTES: usize = 64 + mldsa::SIGNATURE_SIZE;

pub struct HybridPublicKey {
    classical: VerifyingKey,
    pq: ValidatorPublicKey,
}

impl HybridPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return None;
        }
        let classical = VerifyingKey::from_bytes(bytes[..32].try_into().ok()?).ok()?;
        if classical.is_weak() {
            return None;
        }
        Some(Self {
            classical,
            pq: ValidatorPublicKey::from_bytes(&bytes[32..]).ok()?,
        })
    }

    pub fn from_parts(classical: &[u8; 32], pq: &[u8]) -> Option<Self> {
        if pq.len() != mldsa::PUBKEY_SIZE {
            return None;
        }
        Self::from_bytes(&[classical.as_slice(), pq].concat())
    }

    /// `z` + base58btc of the concatenated key; not a did:key codec.
    pub fn from_multibase(value: &str) -> Option<Self> {
        if value.len() > PUBLIC_KEY_BYTES * 2 {
            return None;
        }
        let bytes = bs58::decode(value.strip_prefix('z')?).into_vec().ok()?;
        let key = Self::from_bytes(&bytes)?;
        (key.to_multibase() == value).then_some(key)
    }

    pub fn to_multibase(&self) -> String {
        let bytes = [self.classical.as_bytes().as_slice(), self.pq.to_bytes()].concat();
        format!("z{}", bs58::encode(bytes).into_string())
    }

    pub fn classical(&self) -> &VerifyingKey {
        &self.classical
    }

    pub fn pq_bytes(&self) -> &[u8] {
        self.pq.to_bytes()
    }

    /// Classical signs `context ‖ 0x00 ‖ message`; PQ uses `context` as its domain. Both must verify.
    pub fn verify_with_context(&self, message: &[u8], proof: &[u8], context: &[u8]) -> bool {
        if context.is_empty() || proof.len() != SIGNATURE_BYTES {
            return false;
        }
        let Ok(signature) = Signature::from_slice(&proof[..64]) else {
            return false;
        };
        let classical_message = [context, &[0], message].concat();
        if self
            .classical
            .verify_strict(&classical_message, &signature)
            .is_err()
        {
            return false;
        }
        let Ok(pq) = ValidatorSignature::from_bytes(&proof[64..]) else {
            return false;
        };
        mldsa::verify(message, &pq, &self.pq, context).unwrap_or(false)
    }
}
