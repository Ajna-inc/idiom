//! Kanon Postgres storage backend.
//!
//! Implements [`agent_core::traits::StorageProvider`] over the **exact same
//! Postgres schema** the ACA-Py `kanon_storage` plugin creates
//! (`kanon_generic_record`). This lets the idiom agent and a vanilla ACA-Py
//! agent persist to the *same* database shape, so the credential benchmark can
//! hold storage constant and compare runtimes 1:1.
//!
//! Design notes (see `interop-tests/perf/credentials/DESIGN.md` §4):
//! - idiom `Record.category` ⇄ `record_type`, `Record.name` ⇄ `id`.
//! - idiom `Record.value: Vec<u8>` is stored in the `value` JSONB column. idiom
//!   records are serde-serialized JSON, so the common path stores real JSON
//!   (parity with ACA-Py); non-JSON blobs are wrapped as `{"$kanon_b64": …}`
//!   so read-back is lossless either way.
//! - `Query`'s tag-AND filter maps to a JSONB containment (`tags @> …`) served
//!   by the same GIN index the Python plugin defines.
//! - Single fixed `profile_id` (idiom is single-profile).

mod provider;
mod wallet;

pub use provider::{KanonStorageProvider, DEFAULT_PROFILE_ID};
pub use wallet::KanonWalletProvider;

/// DDL mirroring the `kanon_storage` plugin's `kanon_generic_record` table
/// (`db/models/generic_record_pg.py`). Idempotent so it is safe to run on every
/// connect; a DB already provisioned by ACA-Py's plugin satisfies it unchanged.
pub(crate) const GENERIC_RECORD_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS kanon_generic_record (
    row_pk      UUID PRIMARY KEY,
    id          TEXT NOT NULL,
    profile_id  TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value       JSONB NOT NULL,
    tags        JSONB,
    custom_tags JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_kanon_generic_profile_type_id UNIQUE (profile_id, record_type, id)
);
CREATE INDEX IF NOT EXISTS ix_kanon_generic_record_id          ON kanon_generic_record (id);
CREATE INDEX IF NOT EXISTS ix_kanon_generic_record_profile_id  ON kanon_generic_record (profile_id);
CREATE INDEX IF NOT EXISTS ix_kanon_generic_record_record_type ON kanon_generic_record (record_type);
CREATE INDEX IF NOT EXISTS ix_kanon_generic_tags_gin           ON kanon_generic_record USING gin (tags);
"#;

/// DDL mirroring the plugin's `kanon_key` table (`db/models/key_pg.py`).
/// Secrets are stored encrypted (`secret_ciphertext` + `nonce`); the row shape
/// matches ACA-Py's so the storage cost is comparable. idiom keys are keyed by
/// their internal id (uuid) rather than a verkey — cross-agent *wallet*
/// interchange is a non-goal (DESIGN §4.5), only the schema/cost is matched.
pub(crate) const KEY_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS kanon_key (
    id                TEXT PRIMARY KEY,
    profile_id        TEXT NOT NULL,
    custom_tags       JSONB,
    key_alg           TEXT NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    nonce             BYTEA NOT NULL,
    metadata_json     JSONB,
    kid               JSONB,
    multikey          TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_kanon_key_profile_verkey  ON kanon_key (profile_id, id);
CREATE INDEX        IF NOT EXISTS ix_kanon_key_key_alg         ON kanon_key (key_alg);
CREATE INDEX        IF NOT EXISTS ix_kanon_key_kid_gin         ON kanon_key USING gin (kid);
CREATE INDEX        IF NOT EXISTS ix_kanon_key_profile_multikey ON kanon_key (profile_id, multikey);
"#;
