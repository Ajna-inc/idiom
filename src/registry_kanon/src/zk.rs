//! Tier-2 (ZK / Mode B) provisioning — issuer BabyJubjub key, credential
//! preparation (leaf + EdDSA signature), active-leaf tracking, and revocation.
//!
//! Tier-2 credentials publish two Merkle roots on `MerkleStateRegistry`: a
//! keccak OZ-StandardMerkle root (Mode A / on-chain proof compatible) and a
//! depth-26 tagged-Poseidon root matching the `non_revocation.circom` circuit.
//! Revocation rotates both roots over the *remaining active leaves* and calls
//! `MerkleStateRegistry.batchUpdate`.
//!
//! [`ZkProvisioner`] is the injection point. [`NoZk`] keeps Tier-1-only builds
//! working (every hook returns `None`). [`PoseidonZk`] is the real
//! implementation, wiring the circom-byte-identical primitives (`poseidon`,
//! `leaf`, `merkle`, `babyjub`, `eddsa`, `blake512`), all KAT-validated against
//! the Python `did_kanon` reference.
//!
//! ## Issuer key derivation
//!
//! The BabyJubjub-EdDSA issuer private key is derived **deterministically** per
//! cred-def: `sk = keccak256("kanon-zk-issuer-key-v1" || credDefId)`. This lets
//! the synchronous [`ZkProvisioner::issuer_zk_pub_key`] hook (called at cred-def
//! registration, which publishes `(ax, ay)` on chain) and the async signing
//! path ([`PoseidonZk::prepare_mode_b`]) recover the identical key without a
//! storage round-trip or an RNG. The key is also persisted to agent storage
//! (best-effort) for auditability, mirroring the Python
//! `KanonZkIssuerKeyService` record.
//!
//! ## Active-leaf tracking
//!
//! Each `prepare_mode_b` (issuance) appends the credential's `(keccak,
//! poseidon)` leaf pair to a per-cred-def active-leaf checkpoint in agent
//! storage. `revoke_by_cred_ids` reads that checkpoint, recomputes both roots
//! over the leaves that REMAIN after removing the revoked ones, and publishes a
//! `batchUpdate` — so `/did/kanon/revoke` by `kanonCredId` needs no
//! caller-supplied active set. Mirrors the Python `KanonZkIssuerState.active`
//! map + `kanon/zk/sync-checkpoint` record.

use std::sync::Arc;

use ark_bn254::Fr;
use serde::{Deserialize, Serialize};

use crate::chain::{BatchUpdate, KanonChain};
use crate::eddsa;
use crate::error::{KanonError, Result};
use crate::ids::{keccak256, Bytes32};
use crate::leaf::{
    compute_zk_leaf, derive_leaf_hex, encode_attributes_canonical, pad_attrs_to_circuit,
};
use crate::merkle::{oz_keccak_root, poseidon_root_bytes32};
use crate::poseidon::{felt_from_be_bytes, felt_to_bytes32};

/// Domain separator for deterministic issuer-key derivation.
const ISSUER_KEY_DOMAIN: &[u8] = b"kanon-zk-issuer-key-v1";

/// Storage category for the per-cred-def active-leaf checkpoint.
const CAT_ZK_ACTIVE: &str = "kanon_zk_active";
/// Storage category for the persisted issuer key record (audit/parity).
const CAT_ZK_ISSUER_KEY: &str = "kanon_zk_issuer_key";

/// Provides the issuer's BabyJubjub public-key coordinates and computes
/// Poseidon Merkle leaves for Tier-2 cred-defs.
pub trait ZkProvisioner: Send + Sync {
    /// BabyJubjub `(ax, ay)` for a cred-def, provisioning if needed. `None`
    /// means Tier-2 is unavailable and the cred-def must downgrade to Tier-1.
    fn issuer_zk_pub_key(&self, cred_def_id: &Bytes32) -> Result<Option<(Bytes32, Bytes32)>>;

    /// Poseidon leaf for a credential (circom-compatible). `None` if unavailable.
    fn poseidon_leaf(&self, cred_def_id: &Bytes32, cred_id: &str) -> Result<Option<Bytes32>>;
}

/// No Tier-2 support — every hook returns `None`, so cred-defs register as
/// Tier-1 only.
pub struct NoZk;

impl ZkProvisioner for NoZk {
    fn issuer_zk_pub_key(&self, _cred_def_id: &Bytes32) -> Result<Option<(Bytes32, Bytes32)>> {
        Ok(None)
    }
    fn poseidon_leaf(&self, _cred_def_id: &Bytes32, _cred_id: &str) -> Result<Option<Bytes32>> {
        Ok(None)
    }
}

/// One active leaf pair: the keccak leaf (`deriveLeaf`) and its companion
/// Poseidon leaf, both as on-chain `bytes32`. Mirrors the `keccak -> poseidon`
/// map the Python `KanonZkIssuerState.active` maintains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveLeaf {
    pub keccak: Bytes32,
    pub poseidon: Bytes32,
}

/// Persisted per-cred-def active-leaf checkpoint. Serialised shape mirrors the
/// Python `KanonZkIssuerState.to_dict()` so the two stacks can (in principle)
/// interpret each other's checkpoints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ActiveCheckpoint {
    /// keccak leaf hex (no 0x), in on-chain add order.
    keccak: Vec<String>,
    /// companion poseidon leaf hex (no 0x), parallel to `keccak`.
    poseidon: Vec<String>,
}

impl ActiveCheckpoint {
    fn to_active(&self) -> Vec<ActiveLeaf> {
        self.keccak
            .iter()
            .zip(self.poseidon.iter())
            .filter_map(|(k, p)| {
                let kb = crate::ids::parse_bytes32(k).ok()?;
                let pb = crate::ids::parse_bytes32(p).ok()?;
                Some(ActiveLeaf {
                    keccak: kb,
                    poseidon: pb,
                })
            })
            .collect()
    }

    fn from_active(active: &[ActiveLeaf]) -> Self {
        Self {
            keccak: active.iter().map(|l| hex::encode(l.keccak)).collect(),
            poseidon: active.iter().map(|l| hex::encode(l.poseidon)).collect(),
        }
    }
}

/// Result of `prepare_mode_b`: the full attribute set the AnonCreds issuance
/// flow signs, plus the generated kanon identifiers.
#[derive(Debug, Clone)]
pub struct ModeBPrep {
    /// Domain attrs + `kanonCredId` + `kanonZkSig`.
    pub attributes: Vec<(String, String)>,
    /// Freshly-minted 32-byte bookkeeping id, `0x<64 hex>`.
    pub kanon_cred_id: String,
    /// BJJ-EdDSA signature over the Mode B leaf, base64.
    pub kanon_zk_sig: String,
}

/// Outcome of recomputing the two roots for a `batchUpdate`.
#[derive(Debug, Clone)]
pub struct RevokeRoots {
    /// Keccak leaves being revoked (the `deriveLeaf` values removed).
    pub revoked_keccak: Vec<Bytes32>,
    /// Companion Poseidon leaves being revoked.
    pub revoked_poseidon: Vec<Bytes32>,
    /// New keccak OZ-StandardMerkle root over the remaining active leaves.
    pub new_root_keccak: Bytes32,
    /// New depth-26 tagged-Poseidon root over the remaining active leaves.
    pub new_root_poseidon: Bytes32,
    /// The active set AFTER removing the revoked leaves (order preserved).
    pub remaining: Vec<ActiveLeaf>,
}

/// Real Tier-2 provisioner backed by the circom-byte-identical primitives.
///
/// Holds a `KanonChain` handle (to drive `batchUpdate`) and a
/// `StorageProvider` handle (to persist the per-cred-def active-leaf checkpoint
/// and the issuer-key audit record). The issuer BabyJubjub key is derived
/// deterministically from the cred-def id, so both the sync pubkey hook and the
/// async signing path recover it identically.
pub struct PoseidonZk {
    chain: Arc<dyn KanonChain>,
    storage: Arc<dyn agent_core::traits::StorageProvider>,
}

impl PoseidonZk {
    pub fn new(
        chain: Arc<dyn KanonChain>,
        storage: Arc<dyn agent_core::traits::StorageProvider>,
    ) -> Self {
        Self { chain, storage }
    }

    /// Deterministic issuer BJJ private key hex for a cred-def:
    /// `0x || keccak256(DOMAIN || credDefId)`.
    fn issuer_private_key_hex(cred_def_id: &Bytes32) -> String {
        let mut buf = Vec::with_capacity(ISSUER_KEY_DOMAIN.len() + 32);
        buf.extend_from_slice(ISSUER_KEY_DOMAIN);
        buf.extend_from_slice(cred_def_id);
        let sk = keccak256(&buf);
        format!("0x{}", hex::encode(sk))
    }

    /// Provision (get-or-derive) the issuer keypair for a cred-def and return
    /// the on-chain `(ax, ay)` coordinates as `bytes32`. Deterministic — no
    /// storage or RNG needed. This is the workhorse behind the sync
    /// [`ZkProvisioner::issuer_zk_pub_key`] hook.
    pub fn provision_issuer_pub_key(cred_def_id: &Bytes32) -> Result<(Bytes32, Bytes32)> {
        let priv_hex = Self::issuer_private_key_hex(cred_def_id);
        let key = eddsa::restore_issuer_key(&priv_hex)?;
        let ax = biguint_to_be32(&key.ax);
        let ay = biguint_to_be32(&key.ay);
        Ok((ax, ay))
    }

    /// Prepare a Mode B credential: mint a `kanonCredId`, felt-encode the domain
    /// attributes, compute the tagged-Poseidon leaf, sign it with the issuer's
    /// BJJ key, append the leaf to the active checkpoint, and return the merged
    /// attribute set. Mirrors the Python `prepare_mode_b_credential`.
    ///
    /// `cred_def_id` is the 32-byte credDefId (the on-chain key). `domain_attrs`
    /// are the caller's non-reserved attribute name→value pairs.
    pub async fn prepare_mode_b(
        &self,
        cred_def_id: &Bytes32,
        domain_attrs: &[(String, String)],
    ) -> Result<ModeBPrep> {
        // Reject reserved names — the issuer injects them, the caller must not.
        for (name, _) in domain_attrs {
            if crate::leaf::KANON_ZK_RESERVED_ATTRIBUTE_NAMES.contains(&name.as_str()) {
                return Err(KanonError::Invalid(format!(
                    "domain attributes must not include reserved name {name:?}; \
                     the issuer injects them"
                )));
            }
        }

        // Fresh 32-byte credId, hex-encoded (deterministic-from-nonce so we
        // don't need an OS RNG dep: keccak of a monotonic + credDef mix).
        let kanon_cred_id = mint_cred_id(cred_def_id);

        // Canonical (alphabetical-name) felt encoding of the domain values,
        // padded to the circuit's 16-attribute width.
        let attr_felts = encode_attributes_canonical(domain_attrs);
        let padded = pad_attrs_to_circuit(&attr_felts)?;

        // credId felt = uint256(keccak256(utf8(kanonCredId))) mod p — matches
        // the holder/verifier side. Feed compute_zk_leaf the keccak digest.
        let cred_id_keccak = keccak256(kanon_cred_id.as_bytes());
        let leaf = compute_zk_leaf(cred_def_id, &cred_id_keccak, &padded)?;

        // Sign the leaf with the issuer's BJJ key.
        let priv_hex = Self::issuer_private_key_hex(cred_def_id);
        let sig = eddsa::sign_poseidon(&priv_hex, &leaf)?;
        let kanon_zk_sig = eddsa::encode_zk_signature(&sig);

        // NOTE: the active leaf is NOT appended here. `prepare_mode_b` only
        // signs and returns; the on-chain leaf publish + checkpoint append
        // happen exactly once in [`Self::add_issued`], driven by the issuance
        // listener when the credential actually reaches `done`. This mirrors
        // the Python split: `prepare_mode_b_credential` signs, the issuance
        // listener calls `KanonZkIssuer.add_issued`. Appending in both places
        // would double-count the leaf.

        // Persist the issuer key record (best-effort, parity/audit).
        let _ = self.persist_issuer_key(cred_def_id, &priv_hex).await;

        // Final attribute set: domain attrs first, reserved at the tail.
        let mut attributes: Vec<(String, String)> = domain_attrs.to_vec();
        attributes.push((
            crate::leaf::KANON_CRED_ID_ATTRIBUTE.to_string(),
            kanon_cred_id.clone(),
        ));
        attributes.push((
            crate::leaf::KANON_ZK_SIG_ATTRIBUTE.to_string(),
            kanon_zk_sig.clone(),
        ));

        Ok(ModeBPrep {
            attributes,
            kanon_cred_id,
            kanon_zk_sig,
        })
    }

    /// Publish the Mode B issuance leaf for a newly-issued credential on chain.
    ///
    /// Mirrors the Python `KanonZkIssuer.add_issued` (single-credential form):
    /// compute the tagged-Poseidon leaf from `(cred_def_id, cred_id, attrs)` —
    /// byte-identical to the leaf `prepare_mode_b` signed for the same inputs —
    /// append it to the per-cred-def active checkpoint, recompute both roots over
    /// the full active set, and write `MerkleStateRegistry.batchUpdate` so
    /// `issuedCount` increments. Idempotent per credId: a leaf already in the
    /// checkpoint is skipped (returns `None`, no chain write).
    ///
    /// `cred_def_id` is the 32-byte credDefId. `cred_id` is the credential's
    /// `kanonCredId` (`0x<64 hex>` string). `domain_attrs` are the issued
    /// non-reserved attribute name→value pairs the issuer signed.
    ///
    /// Returns `Some(tx_hash)` on a publish, `None` if the leaf was already
    /// present (duplicate issuance).
    pub async fn add_issued(
        &self,
        cred_def_id: &Bytes32,
        cred_id: &str,
        domain_attrs: &[(String, String)],
    ) -> Result<Option<String>> {
        // Compute the leaf EXACTLY as prepare_mode_b did: canonical felt
        // encoding of the domain attrs padded to circuit width, credId felt =
        // keccak256(utf8(credId)) reduced mod p. `compute_poseidon_leaf`
        // encapsulates this and is the single source of truth shared with
        // prepare_mode_b's `compute_zk_leaf` call over the same inputs.
        let poseidon_leaf = self.compute_poseidon_leaf(cred_def_id, cred_id, domain_attrs)?;
        let keccak_leaf = derive_leaf_hex(cred_id)?;

        // Load the active set; skip if this leaf is already published (matches
        // the Python `if keccak_hex in state.active: continue`).
        let mut active = self.load_active(cred_def_id).await?;
        if active.iter().any(|l| l.keccak == keccak_leaf) {
            return Ok(None);
        }

        // First leaf for this cred-def → initialize the on-chain Merkle state
        // with the empty-tree genesis roots before the first `batchUpdate`.
        // The `MerkleStateRegistry` reverts a `batchUpdate` against an
        // uninitialized cred-def, so this mirrors the Python `add_issued`'s
        // one-time `initialize_cred_def_state`. Tolerate "already initialized"
        // (e.g. after a checkpoint loss) — the `batch_update` below surfaces
        // any real error.
        if active.is_empty() {
            let genesis_keccak = compute_keccak_root(&active);
            let genesis_poseidon = compute_poseidon_root(&active)?;
            if let Err(e) = self
                .chain
                .init_merkle_state(*cred_def_id, genesis_keccak, genesis_poseidon)
                .await
            {
                tracing::warn!(
                    error = %e,
                    "add_issued: init_merkle_state failed (continuing; may already be initialized)"
                );
            }
        }

        active.push(ActiveLeaf {
            keccak: keccak_leaf,
            poseidon: poseidon_leaf,
        });

        // Recompute both roots over the full active set and publish the leaf.
        let new_root_keccak = compute_keccak_root(&active);
        let new_root_poseidon = compute_poseidon_root(&active)?;
        let tx = self
            .chain
            .batch_update(BatchUpdate {
                cred_def_id: *cred_def_id,
                added_keccak: vec![keccak_leaf],
                added_poseidon: vec![poseidon_leaf],
                revoked_keccak: vec![],
                revoked_poseidon: vec![],
                new_root_keccak,
                new_root_poseidon,
            })
            .await?;

        // Only persist the checkpoint AFTER the chain accepted the leaf, so a
        // failed write doesn't leave the local set ahead of chain state.
        self.save_active(cred_def_id, &active).await?;
        Ok(Some(tx))
    }

    /// Verify a Mode B signature (`kanonZkSig` base64) over the leaf recomputed
    /// from the public attribute set + `kanonCredId`, using the issuer's
    /// on-chain BJJ key for this cred-def. Mirrors the pure-crypto layer the
    /// Python `test_mode_b` exercises (SNARK / on-chain root recency are out of
    /// scope here — this is the issuer-signature check).
    pub fn verify_mode_b_sig(
        &self,
        cred_def_id: &Bytes32,
        kanon_cred_id: &str,
        domain_attrs: &[(String, String)],
        kanon_zk_sig_b64: &str,
    ) -> Result<bool> {
        let attr_felts = encode_attributes_canonical(domain_attrs);
        let padded = pad_attrs_to_circuit(&attr_felts)?;
        let cred_id_keccak = keccak256(kanon_cred_id.as_bytes());
        let leaf = compute_zk_leaf(cred_def_id, &cred_id_keccak, &padded)?;

        let sig = eddsa::decode_zk_signature(kanon_zk_sig_b64)?;
        let priv_hex = Self::issuer_private_key_hex(cred_def_id);
        let key = eddsa::restore_issuer_key(&priv_hex)?;
        Ok(eddsa::verify_poseidon((&key.ax, &key.ay), &leaf, &sig))
    }

    /// Real Mode B credential leaf as on-chain `bytes32` (attribute-bound).
    pub fn compute_poseidon_leaf(
        &self,
        cred_def_bytes: &Bytes32,
        cred_id: &str,
        attributes: &[(String, String)],
    ) -> Result<Bytes32> {
        let attr_felts = encode_attributes_canonical(attributes);
        let padded = pad_attrs_to_circuit(&attr_felts)?;
        let cred_id_keccak = keccak256(cred_id.as_bytes());
        let leaf = compute_zk_leaf(cred_def_bytes, &cred_id_keccak, &padded)?;
        Ok(felt_to_bytes32(leaf))
    }

    /// Recompute both roots for a revocation without touching the chain.
    ///
    /// `active` is the current active leaf set (order = on-chain add order).
    /// `cred_ids` are the `kanonCredId` hex strings (`0x<64 hex>`) to revoke;
    /// each is resolved to its keccak `deriveLeaf` and matched against the
    /// active set. Every id MUST be present, else this errors *before* any
    /// chain write.
    pub fn plan_revoke(&self, active: &[ActiveLeaf], cred_ids: &[String]) -> Result<RevokeRoots> {
        let mut remaining: Vec<ActiveLeaf> = active.to_vec();
        let mut revoked_keccak: Vec<Bytes32> = Vec::with_capacity(cred_ids.len());
        let mut revoked_poseidon: Vec<Bytes32> = Vec::with_capacity(cred_ids.len());

        for cid in cred_ids {
            let keccak_leaf = derive_leaf_hex(cid)?;
            match remaining.iter().position(|l| l.keccak == keccak_leaf) {
                Some(pos) => {
                    let removed = remaining.remove(pos);
                    revoked_keccak.push(removed.keccak);
                    revoked_poseidon.push(removed.poseidon);
                }
                None => {
                    return Err(KanonError::Invalid(format!(
                        "credId not in active set: {cid} (leaf=0x{})",
                        hex::encode(keccak_leaf)
                    )));
                }
            }
        }

        let new_root_keccak = compute_keccak_root(&remaining);
        let new_root_poseidon = compute_poseidon_root(&remaining)?;

        Ok(RevokeRoots {
            revoked_keccak,
            revoked_poseidon,
            new_root_keccak,
            new_root_poseidon,
            remaining,
        })
    }

    /// Plan a revocation over an *explicitly supplied* active set and publish it
    /// via `MerkleStateRegistry.batchUpdate`. Returns the plan + tx hash. Kept
    /// for callers that track the active set themselves; the storage-backed
    /// [`Self::revoke_by_cred_ids`] is preferred.
    pub async fn revoke(
        &self,
        cred_def_id: Bytes32,
        active: &[ActiveLeaf],
        cred_ids: &[String],
    ) -> Result<(RevokeRoots, String)> {
        if cred_ids.is_empty() {
            return Err(KanonError::Invalid("revoke: no cred_ids".into()));
        }
        let plan = self.plan_revoke(active, cred_ids)?;
        let tx = self.publish_revoke(cred_def_id, &plan).await?;
        Ok((plan, tx))
    }

    /// Revoke by `kanonCredId`, reading the active set from the storage-backed
    /// checkpoint (no caller-supplied active set). Recomputes both roots over
    /// the remaining leaves, publishes `batchUpdate`, and rewrites the
    /// checkpoint to the remaining set. This is what `/did/kanon/revoke` calls.
    pub async fn revoke_by_cred_ids(
        &self,
        cred_def_id: Bytes32,
        cred_ids: &[String],
    ) -> Result<(RevokeRoots, String)> {
        if cred_ids.is_empty() {
            return Err(KanonError::Invalid("revoke: no cred_ids".into()));
        }
        let active = self.load_active(&cred_def_id).await?;
        let plan = self.plan_revoke(&active, cred_ids)?;
        let tx = self.publish_revoke(cred_def_id, &plan).await?;
        // Persist the remaining set so a subsequent revoke sees the reduced set.
        self.save_active(&cred_def_id, &plan.remaining).await?;
        Ok((plan, tx))
    }

    async fn publish_revoke(&self, cred_def_id: Bytes32, plan: &RevokeRoots) -> Result<String> {
        self.chain
            .batch_update(BatchUpdate {
                cred_def_id,
                added_keccak: vec![],
                added_poseidon: vec![],
                revoked_keccak: plan.revoked_keccak.clone(),
                revoked_poseidon: plan.revoked_poseidon.clone(),
                new_root_keccak: plan.new_root_keccak,
                new_root_poseidon: plan.new_root_poseidon,
            })
            .await
    }

    // ── Active-leaf checkpoint persistence ─────────────────────────────────

    fn active_record_name(cred_def_id: &Bytes32) -> String {
        hex::encode(cred_def_id)
    }

    async fn load_active(&self, cred_def_id: &Bytes32) -> Result<Vec<ActiveLeaf>> {
        let name = Self::active_record_name(cred_def_id);
        match self
            .storage
            .find(CAT_ZK_ACTIVE, &name)
            .await
            .map_err(|e| KanonError::Storage(format!("find active leaves: {e}")))?
        {
            Some(r) => {
                let cp: ActiveCheckpoint = serde_json::from_slice(&r.value)
                    .map_err(|e| KanonError::Storage(format!("decode active checkpoint: {e}")))?;
                Ok(cp.to_active())
            }
            None => Ok(vec![]),
        }
    }

    async fn save_active(&self, cred_def_id: &Bytes32, active: &[ActiveLeaf]) -> Result<()> {
        let name = Self::active_record_name(cred_def_id);
        let cp = ActiveCheckpoint::from_active(active);
        let bytes = serde_json::to_vec(&cp)
            .map_err(|e| KanonError::Storage(format!("serialize active checkpoint: {e}")))?;
        let record = agent_core::traits::Record::new(CAT_ZK_ACTIVE, &name, bytes);
        self.upsert(record).await
    }

    async fn persist_issuer_key(&self, cred_def_id: &Bytes32, priv_hex: &str) -> Result<()> {
        let name = hex::encode(cred_def_id);
        // Only write once — deterministic key, so an existing record matches.
        if self
            .storage
            .find(CAT_ZK_ISSUER_KEY, &name)
            .await
            .map_err(|e| KanonError::Storage(format!("find issuer key: {e}")))?
            .is_some()
        {
            return Ok(());
        }
        let key = eddsa::restore_issuer_key(priv_hex)?;
        let payload = serde_json::json!({
            "privateKeyHex": priv_hex,
            "ax": key.ax.to_str_radix(10),
            "ay": key.ay.to_str_radix(10),
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| KanonError::Storage(format!("serialize issuer key: {e}")))?;
        let record = agent_core::traits::Record::new(CAT_ZK_ISSUER_KEY, &name, bytes);
        self.upsert(record).await
    }

    async fn upsert(&self, record: agent_core::traits::Record) -> Result<()> {
        if self.storage.update(&record).await.is_err() {
            self.storage
                .save(&record)
                .await
                .map_err(|e| KanonError::Storage(format!("save {}: {e}", record.category)))?;
        }
        Ok(())
    }
}

/// Deterministic 32-byte credId minting without an OS RNG dep. Mixes the
/// cred-def id with a high-resolution timestamp so repeated `prepare` calls for
/// the same cred-def yield distinct ids (as the SDK's random `token_hex` does),
/// while staying dependency-free.
fn mint_cred_id(cred_def_id: &Bytes32) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut buf = Vec::with_capacity(32 + 16 + 8);
    buf.extend_from_slice(cred_def_id);
    buf.extend_from_slice(&nanos.to_be_bytes());
    // A per-process counter to break ties within the same nanosecond.
    let ctr = next_counter();
    buf.extend_from_slice(&ctr.to_be_bytes());
    format!("0x{}", hex::encode(keccak256(&buf)))
}

fn next_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// `num_bigint::BigUint` → 32 big-endian bytes (left-zero-padded).
fn biguint_to_be32(v: &num_bigint::BigUint) -> Bytes32 {
    let be = v.to_bytes_be();
    let mut out = [0u8; 32];
    let n = be.len().min(32);
    out[32 - n..].copy_from_slice(&be[be.len() - n..]);
    out
}

/// Keccak OZ root over the active keccak leaves, with the SDK empty-set
/// convention (a single zero leaf → the zero leaf).
fn compute_keccak_root(active: &[ActiveLeaf]) -> Bytes32 {
    if active.is_empty() {
        return oz_keccak_root(&[[0u8; 32]]);
    }
    let leaves: Vec<Bytes32> = active.iter().map(|l| l.keccak).collect();
    oz_keccak_root(&leaves)
}

/// Depth-26 tagged-Poseidon root over the active Poseidon leaves (read
/// big-endian into felts, mod p), returned as `bytes32`.
fn compute_poseidon_root(active: &[ActiveLeaf]) -> Result<Bytes32> {
    let felts: Vec<Fr> = active
        .iter()
        .map(|l| felt_from_be_bytes(&l.poseidon))
        .collect();
    poseidon_root_bytes32(&felts)
}

impl ZkProvisioner for PoseidonZk {
    /// Deterministic BabyJubjub key provisioning: derive `(ax, ay)` from the
    /// cred-def id and publish them via cred-def registration. Never `None` —
    /// Mode B is always available with the real provisioner.
    fn issuer_zk_pub_key(&self, cred_def_id: &Bytes32) -> Result<Option<(Bytes32, Bytes32)>> {
        Ok(Some(Self::provision_issuer_pub_key(cred_def_id)?))
    }

    /// A Poseidon leaf cannot be computed from `(cred_def_id, cred_id)` alone —
    /// the real leaf binds the credential's domain attributes. Use
    /// [`PoseidonZk::compute_poseidon_leaf`] / [`PoseidonZk::prepare_mode_b`].
    fn poseidon_leaf(&self, _cred_def_id: &Bytes32, _cred_id: &str) -> Result<Option<Bytes32>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mock::MockKanonChain;
    use crate::leaf::derive_leaf_hex;

    #[derive(Default)]
    struct MemStore(std::sync::Mutex<std::collections::HashMap<(String, String), Vec<u8>>>);

    #[async_trait::async_trait]
    impl agent_core::traits::StorageProvider for MemStore {
        async fn save(&self, r: &agent_core::traits::Record) -> agent_core::error::Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert((r.category.clone(), r.name.clone()), r.value.clone());
            Ok(())
        }
        async fn find(
            &self,
            category: &str,
            name: &str,
        ) -> agent_core::error::Result<Option<agent_core::traits::Record>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(&(category.to_string(), name.to_string()))
                .map(|v| agent_core::traits::Record::new(category, name, v.clone())))
        }
        async fn find_all(
            &self,
            _category: &str,
            _query: &agent_core::traits::Query,
        ) -> agent_core::error::Result<Vec<agent_core::traits::Record>> {
            Ok(vec![])
        }
        async fn update(&self, r: &agent_core::traits::Record) -> agent_core::error::Result<()> {
            // Emulate askar: update fails if the record doesn't exist.
            let mut g = self.0.lock().unwrap();
            let k = (r.category.clone(), r.name.clone());
            if let std::collections::hash_map::Entry::Occupied(mut e) = g.entry(k) {
                e.insert(r.value.clone());
                Ok(())
            } else {
                Err(agent_core::error::AgentError::Storage("not found".into()))
            }
        }
        async fn delete(&self, category: &str, name: &str) -> agent_core::error::Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(&(category.to_string(), name.to_string()));
            Ok(())
        }
        async fn delete_all(&self, _category: &str) -> agent_core::error::Result<()> {
            Ok(())
        }
    }

    fn hex32(s: &str) -> Bytes32 {
        crate::ids::parse_bytes32(s).unwrap()
    }

    fn mk() -> PoseidonZk {
        PoseidonZk::new(
            std::sync::Arc::new(MockKanonChain::new()),
            std::sync::Arc::new(MemStore::default()),
        )
    }

    /// The deterministic issuer key must be non-zero on both coords and stable.
    /// The `(ax, ay)` for credDef = 0xcd*32 is cross-checked against the
    /// reference Python `eddsa.restore_issuer_key(keccak256(DOMAIN||credDef))`
    /// so the on-chain-published key stays byte-identical to what a reference
    /// verifier expects.
    #[test]
    fn issuer_pub_key_deterministic_nonzero() {
        use std::str::FromStr;
        let cd = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let (ax, ay) = PoseidonZk::provision_issuer_pub_key(&cd).unwrap();
        assert_ne!(ax, [0u8; 32], "ax must be non-zero");
        assert_ne!(ay, [0u8; 32], "ay must be non-zero");
        // Cross-language KAT (reference Python, priv = keccak256(DOMAIN||credDef)).
        let ax_felt = felt_from_be_bytes(&ax);
        let ay_felt = felt_from_be_bytes(&ay);
        assert_eq!(
            ax_felt,
            Fr::from_str(
                "13389252574629738178774801511136641550766074332776282441651719971181176005290"
            )
            .unwrap()
        );
        assert_eq!(
            ay_felt,
            Fr::from_str(
                "5815042852524745320311019961817400786100732573873763212699960106103610983982"
            )
            .unwrap()
        );
        // Stable across calls.
        let (ax2, ay2) = PoseidonZk::provision_issuer_pub_key(&cd).unwrap();
        assert_eq!((ax, ay), (ax2, ay2));
        // Different cred-def → different key.
        let cd2 = hex32(&("0x".to_string() + &"ab".repeat(32)));
        let (ax3, _) = PoseidonZk::provision_issuer_pub_key(&cd2).unwrap();
        assert_ne!(ax, ax3);
    }

    /// prepare_mode_b: signature verifies under the on-chain issuer key, and the
    /// attribute set carries the reserved names at the tail.
    #[tokio::test]
    async fn prepare_mode_b_signs_and_tracks() {
        let zk = mk();
        let cd = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let attrs = vec![
            ("studentId".to_string(), "S-12345".to_string()),
            ("name".to_string(), "Alice".to_string()),
            ("gpa".to_string(), "3.9".to_string()),
        ];
        let prep = zk.prepare_mode_b(&cd, &attrs).await.unwrap();

        // credId shape 0x<64hex>.
        assert!(prep.kanon_cred_id.starts_with("0x"));
        assert_eq!(prep.kanon_cred_id.len(), 66);
        // sig is 96 bytes when decoded.
        let sig = eddsa::decode_zk_signature(&prep.kanon_zk_sig).unwrap();
        assert!(sig.s < crate::babyjub::sub_order());
        // reserved attrs at the tail.
        let names: Vec<&str> = prep.attributes.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(&names[names.len() - 2..], &["kanonCredId", "kanonZkSig"]);

        // Verify the signature via the issuer's on-chain key over the domain attrs.
        assert!(zk
            .verify_mode_b_sig(&cd, &prep.kanon_cred_id, &attrs, &prep.kanon_zk_sig)
            .unwrap());
    }

    /// prepare rejects reserved names in the domain attributes.
    #[tokio::test]
    async fn prepare_rejects_reserved() {
        let zk = mk();
        let cd = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let attrs = vec![
            ("name".to_string(), "Carol".to_string()),
            ("kanonCredId".to_string(), "0x12".to_string()),
        ];
        let err = zk.prepare_mode_b(&cd, &attrs).await.unwrap_err();
        assert!(format!("{err}").contains("reserved name"));
    }

    /// Two prepares → distinct credIds.
    #[tokio::test]
    async fn prepare_mints_distinct_cred_ids() {
        let zk = mk();
        let cd = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let attrs = vec![("name".to_string(), "Alice".to_string())];
        let a = zk.prepare_mode_b(&cd, &attrs).await.unwrap();
        let b = zk.prepare_mode_b(&cd, &attrs).await.unwrap();
        assert_ne!(a.kanon_cred_id, b.kanon_cred_id);
    }

    /// End-to-end storage-backed revoke: prepare two creds, revoke one by
    /// credId (no active_leaves passed), assert Merkle state advances and the
    /// remaining set persists.
    #[tokio::test]
    async fn revoke_by_cred_ids_uses_stored_active_set() {
        let chain = std::sync::Arc::new(MockKanonChain::new());
        let zk = PoseidonZk::new(chain.clone(), std::sync::Arc::new(MemStore::default()));
        let cd = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let attrs = vec![("name".to_string(), "Alice".to_string())];

        let a = zk.prepare_mode_b(&cd, &attrs).await.unwrap();
        let b = zk.prepare_mode_b(&cd, &attrs).await.unwrap();
        // prepare_mode_b only signs; the issuance listener publishes the leaf
        // + populates the active checkpoint via add_issued.
        zk.add_issued(&cd, &a.kanon_cred_id, &attrs).await.unwrap();
        zk.add_issued(&cd, &b.kanon_cred_id, &attrs).await.unwrap();

        // Revoke the first credential by id — no caller-supplied active set.
        let (plan, tx) = zk
            .revoke_by_cred_ids(cd, std::slice::from_ref(&a.kanon_cred_id))
            .await
            .unwrap();
        assert!(!tx.is_empty());
        assert_eq!(plan.remaining.len(), 1);
        assert_eq!(
            plan.revoked_keccak[0],
            derive_leaf_hex(&a.kanon_cred_id).unwrap()
        );

        // The mock chain recorded the rotated poseidon root + revoked count.
        let st = chain.get_merkle_state(cd).await.unwrap().unwrap();
        assert_eq!(st.root_poseidon, plan.new_root_poseidon);
        assert_eq!(st.revoked_count, 1);

        // Revoking the same id again fails — it's no longer active.
        let err = zk
            .revoke_by_cred_ids(cd, &[a.kanon_cred_id])
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("not in active set"));

        // The still-active credential can be revoked.
        let (plan2, _) = zk.revoke_by_cred_ids(cd, &[b.kanon_cred_id]).await.unwrap();
        assert!(plan2.remaining.is_empty());
    }

    #[test]
    fn plan_revoke_rejects_unknown_cred() {
        let zk = mk();
        let id_a = "0x".to_string() + &"a".repeat(64);
        let id_x = "0x".to_string() + &"f".repeat(64);
        let active = vec![ActiveLeaf {
            keccak: derive_leaf_hex(&id_a).unwrap(),
            poseidon: [0u8; 32],
        }];
        let err = zk.plan_revoke(&active, &[id_x]).unwrap_err();
        assert!(format!("{err}").contains("not in active set"));
    }

    #[test]
    fn plan_revoke_removes_and_recomputes() {
        let zk = mk();
        let id_a = "0x".to_string() + &"a".repeat(64);
        let id_b = "0x".to_string() + &"b".repeat(64);
        let id_c = "0x".to_string() + &"c".repeat(64);
        let p = |n: u64| felt_to_bytes32(Fr::from(n));
        let af = |id: &str, pv: Bytes32| ActiveLeaf {
            keccak: derive_leaf_hex(id).unwrap(),
            poseidon: pv,
        };
        let active = vec![af(&id_a, p(1000)), af(&id_b, p(2000)), af(&id_c, p(3000))];

        let plan = zk
            .plan_revoke(&active, std::slice::from_ref(&id_b))
            .unwrap();
        assert_eq!(plan.remaining.len(), 2);
        // New poseidon root MUST match the reference over remaining [1000, 3000].
        assert_eq!(
            hex::encode(plan.new_root_poseidon),
            "03cc0962f295e7bc4a8ae216b353ecdb996cf0ce5065369684755ba3809a4439"
        );
        let expect_keccak = oz_keccak_root(&[
            derive_leaf_hex(&id_a).unwrap(),
            derive_leaf_hex(&id_c).unwrap(),
        ]);
        assert_eq!(plan.new_root_keccak, expect_keccak);
    }

    #[tokio::test]
    async fn revoke_all_leaves_uses_empty_convention() {
        let zk = mk();
        let id_a = "0x".to_string() + &"a".repeat(64);
        let active = vec![ActiveLeaf {
            keccak: derive_leaf_hex(&id_a).unwrap(),
            poseidon: felt_to_bytes32(Fr::from(7u64)),
        }];
        let plan = zk.plan_revoke(&active, &[id_a]).unwrap();
        assert!(plan.remaining.is_empty());
        assert_eq!(plan.new_root_keccak, [0u8; 32]);
        assert_eq!(plan.new_root_poseidon, poseidon_root_bytes32(&[]).unwrap());
    }

    #[test]
    fn compute_poseidon_leaf_matches_sdk() {
        let zk = mk();
        let cred_def = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let attrs = vec![
            ("studentId".to_string(), "S-12345".to_string()),
            ("name".to_string(), "Alice".to_string()),
            ("gpa".to_string(), "3.9".to_string()),
        ];
        let kanon_cred_id = "0x".to_string() + &"7a".repeat(32);
        let leaf_b32 = zk
            .compute_poseidon_leaf(&cred_def, &kanon_cred_id, &attrs)
            .unwrap();
        let expected = felt_to_bytes32({
            use std::str::FromStr;
            Fr::from_str(
                "1393485080625247459900569500640157328168465545537288134804249149028564603699",
            )
            .unwrap()
        });
        assert_eq!(leaf_b32, expected);
    }

    /// The leaf `add_issued` publishes on chain MUST equal the leaf
    /// `prepare_mode_b` signed for the same (credDef, credId, attrs). This is
    /// the load-bearing reconciliation: the issuer signs one leaf and the
    /// listener must publish that exact leaf, or the SNARK side won't verify.
    #[tokio::test]
    async fn add_issued_leaf_equals_prepare_mode_b_leaf() {
        let chain = std::sync::Arc::new(MockKanonChain::new());
        let zk = PoseidonZk::new(chain.clone(), std::sync::Arc::new(MemStore::default()));
        let cd = hex32(&("0x".to_string() + &"cd".repeat(32)));
        let attrs = vec![
            ("studentId".to_string(), "S-12345".to_string()),
            ("name".to_string(), "Alice".to_string()),
            ("gpa".to_string(), "3.9".to_string()),
        ];

        // prepare_mode_b mints a credId and signs the leaf over these attrs.
        let prep = zk.prepare_mode_b(&cd, &attrs).await.unwrap();

        // The leaf prepare_mode_b signed (recomputed from the same inputs).
        let prep_leaf = zk
            .compute_poseidon_leaf(&cd, &prep.kanon_cred_id, &attrs)
            .unwrap();

        // add_issued publishes on chain and populates the checkpoint.
        let tx = zk
            .add_issued(&cd, &prep.kanon_cred_id, &attrs)
            .await
            .unwrap();
        assert!(tx.is_some(), "first add_issued must publish");

        // The published Poseidon leaf (from the stored active set) equals the
        // leaf prepare_mode_b signed.
        let active = zk.load_active(&cd).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].poseidon, prep_leaf);
        assert_eq!(
            active[0].keccak,
            derive_leaf_hex(&prep.kanon_cred_id).unwrap()
        );

        // The signature verifies over that same leaf.
        assert!(zk
            .verify_mode_b_sig(&cd, &prep.kanon_cred_id, &attrs, &prep.kanon_zk_sig)
            .unwrap());

        // The chain recorded issuedCount == 1 and the published Poseidon root
        // matches the root over the active set.
        let st = chain.get_merkle_state(cd).await.unwrap().unwrap();
        assert_eq!(st.issued_count, 1);
        assert_eq!(st.root_poseidon, compute_poseidon_root(&active).unwrap());

        // Idempotent: re-issuing the same credId is a no-op (no double count).
        let tx2 = zk
            .add_issued(&cd, &prep.kanon_cred_id, &attrs)
            .await
            .unwrap();
        assert!(tx2.is_none(), "duplicate add_issued must be a no-op");
        let st2 = chain.get_merkle_state(cd).await.unwrap().unwrap();
        assert_eq!(st2.issued_count, 1, "issuedCount must not double-count");
    }
}
