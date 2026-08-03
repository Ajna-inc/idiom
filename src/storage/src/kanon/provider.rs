//! `KanonStorageProvider` — `StorageProvider` over the kanon Postgres schema.

use agent_core::traits::{Query, Record, StorageProvider, Tags};
use agent_core::{AgentError, Result};
use async_trait::async_trait;
use base64::Engine as _;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use std::collections::HashMap;

/// Default profile id. idiom is single-profile; all rows share this value.
pub const DEFAULT_PROFILE_ID: &str = "idiom";

/// Sentinel key for storing non-JSON record values as base64 inside JSONB.
const B64_KEY: &str = "$kanon_b64";

/// Fixed advisory-lock key used to serialize schema provisioning.
const KANON_DDL_LOCK_KEY: i64 = 0x6b616e6f6e5f31; // "kanon_1"

/// Storage provider backed by the kanon Postgres schema.
///
/// Behaves like [`crate::askar::AskarStorageProvider`] so the agent runs
/// unchanged on either backend: `save` inserts (fails on duplicate), `update`
/// replaces, `find_all` applies a tag-AND filter.
#[derive(Clone)]
pub struct KanonStorageProvider {
    pool: PgPool,
    profile_id: String,
}

impl KanonStorageProvider {
    /// Connect to Postgres, provision the schema (idempotent), and use the
    /// default profile.
    pub async fn connect(database_url: &str) -> Result<Self> {
        Self::connect_with_profile(database_url, DEFAULT_PROFILE_ID).await
    }

    /// Connect with an explicit profile id.
    pub async fn connect_with_profile(database_url: &str, profile_id: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(database_url)
            .await
            .map_err(map_sqlx)?;
        Self::from_pool(pool, profile_id).await
    }

    /// Build from an existing pool (e.g. shared with other components) and
    /// ensure the schema exists.
    pub async fn from_pool(pool: PgPool, profile_id: &str) -> Result<Self> {
        provision(&pool, super::GENERIC_RECORD_DDL).await?;
        Ok(Self {
            pool,
            profile_id: profile_id.to_string(),
        })
    }

    /// The underlying pool (for the wallet backend / benchmarks to share).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Encode an idiom record value (opaque bytes) into a JSONB value. idiom
/// records are serde JSON, so the common path stores real JSON (parity with
/// ACA-Py); anything else is wrapped losslessly as base64.
fn value_to_json(bytes: &[u8]) -> serde_json::Value {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) => v,
        Err(_) => {
            serde_json::json!({ B64_KEY: base64::engine::general_purpose::STANDARD.encode(bytes) })
        }
    }
}

/// Inverse of [`value_to_json`].
fn json_to_value(v: &serde_json::Value) -> Vec<u8> {
    if let Some(obj) = v.as_object() {
        if obj.len() == 1 {
            if let Some(b64) = obj.get(B64_KEY).and_then(|x| x.as_str()) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    return bytes;
                }
            }
        }
    }
    serde_json::to_vec(v).unwrap_or_default()
}

/// idiom tags (string→string) → JSONB object, or `None` when empty (matching
/// the plugin's `dict(tags) if tags else None`).
fn tags_to_json(tags: &Tags) -> Option<serde_json::Value> {
    if tags.is_empty() {
        return None;
    }
    Some(serde_json::Value::Object(
        tags.iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
    ))
}

/// JSONB tags object → idiom string→string tags.
fn json_to_tags(v: Option<serde_json::Value>) -> Tags {
    let mut out = HashMap::new();
    if let Some(serde_json::Value::Object(map)) = v {
        for (k, val) in map {
            if let Some(s) = val.as_str() {
                out.insert(k, s.to_string());
            } else {
                out.insert(k, val.to_string());
            }
        }
    }
    out
}

pub(crate) fn map_sqlx(e: sqlx::Error) -> AgentError {
    AgentError::Storage(format!("kanon storage: {e}"))
}

/// Run idempotent DDL under a transaction-scoped advisory lock so concurrent
/// connects (multiple agent instances, or a DB shared with ACA-Py's plugin)
/// don't race on `CREATE TABLE IF NOT EXISTS` (which collide on `pg_type`).
/// Shared by the storage provider and the wallet provider.
pub(crate) async fn provision(pool: &PgPool, ddl: &str) -> Result<()> {
    let mut tx = pool.begin().await.map_err(map_sqlx)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(KANON_DDL_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    for stmt in ddl.split(';') {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        sqlx::query(stmt)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
    }
    tx.commit().await.map_err(map_sqlx)?;
    Ok(())
}

#[async_trait]
impl StorageProvider for KanonStorageProvider {
    async fn save(&self, record: &Record) -> Result<()> {
        let row_pk = uuid::Uuid::new_v4();
        let value = value_to_json(&record.value);
        let tags = tags_to_json(&record.tags);

        let res = sqlx::query(
            "INSERT INTO kanon_generic_record \
             (row_pk, id, profile_id, record_type, value, tags) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(row_pk)
        .bind(&record.name)
        .bind(&self.profile_id)
        .bind(&record.category)
        .bind(value)
        .bind(tags)
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Err(AgentError::Storage(
                format!("Record already exists: {}/{}", record.category, record.name),
            )),
            Err(e) => Err(map_sqlx(e)),
        }
    }

    async fn find(&self, category: &str, name: &str) -> Result<Option<Record>> {
        let row = sqlx::query(
            "SELECT value, tags FROM kanon_generic_record \
             WHERE profile_id = $1 AND record_type = $2 AND id = $3",
        )
        .bind(&self.profile_id)
        .bind(category)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.map(|row| {
            let value: serde_json::Value = row.get("value");
            let tags: Option<serde_json::Value> = row.get("tags");
            Record {
                category: category.to_string(),
                name: name.to_string(),
                value: json_to_value(&value),
                tags: json_to_tags(tags),
            }
        }))
    }

    async fn find_all(&self, category: &str, query: &Query) -> Result<Vec<Record>> {
        // Build positional SQL: tag containment only when tags are requested
        // (an empty `{}` filter would exclude NULL-tag rows under `@>`).
        let mut sql = String::from(
            "SELECT id, value, tags FROM kanon_generic_record \
             WHERE profile_id = $1 AND record_type = $2",
        );
        let mut n = 3;
        let tag_filter = tags_to_json(&query.tags);
        if tag_filter.is_some() {
            sql.push_str(&format!(" AND tags @> ${n}"));
            n += 1;
        }
        sql.push_str(" ORDER BY created_at");
        if query.limit.is_some() {
            sql.push_str(&format!(" LIMIT ${n}"));
            n += 1;
        }
        if query.skip.is_some() {
            sql.push_str(&format!(" OFFSET ${n}"));
        }

        let mut q = sqlx::query(&sql).bind(&self.profile_id).bind(category);
        if let Some(tf) = tag_filter {
            q = q.bind(tf);
        }
        if let Some(limit) = query.limit {
            q = q.bind(limit as i64);
        }
        if let Some(skip) = query.skip {
            q = q.bind(skip as i64);
        }

        let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let id: String = row.get("id");
                let value: serde_json::Value = row.get("value");
                let tags: Option<serde_json::Value> = row.get("tags");
                Record {
                    category: category.to_string(),
                    name: id,
                    value: json_to_value(&value),
                    tags: json_to_tags(tags),
                }
            })
            .collect())
    }

    async fn update(&self, record: &Record) -> Result<()> {
        let value = value_to_json(&record.value);
        let tags = tags_to_json(&record.tags);
        let res = sqlx::query(
            "UPDATE kanon_generic_record \
             SET value = $4, tags = $5, updated_at = now() \
             WHERE profile_id = $1 AND record_type = $2 AND id = $3",
        )
        .bind(&self.profile_id)
        .bind(&record.category)
        .bind(&record.name)
        .bind(value)
        .bind(tags)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        if res.rows_affected() == 0 {
            return Err(AgentError::Storage(format!(
                "Record not found: {}/{}",
                record.category, record.name
            )));
        }
        Ok(())
    }

    async fn delete(&self, category: &str, name: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM kanon_generic_record \
             WHERE profile_id = $1 AND record_type = $2 AND id = $3",
        )
        .bind(&self.profile_id)
        .bind(category)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_all(&self, category: &str) -> Result<()> {
        sqlx::query("DELETE FROM kanon_generic_record WHERE profile_id = $1 AND record_type = $2")
            .bind(&self.profile_id)
            .bind(category)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn count(&self, category: &str, query: &Query) -> Result<usize> {
        let mut sql = String::from(
            "SELECT count(*) AS n FROM kanon_generic_record \
             WHERE profile_id = $1 AND record_type = $2",
        );
        let tag_filter = tags_to_json(&query.tags);
        if tag_filter.is_some() {
            sql.push_str(" AND tags @> $3");
        }
        let mut q = sqlx::query(&sql).bind(&self.profile_id).bind(category);
        if let Some(tf) = tag_filter {
            q = q.bind(tf);
        }
        let row = q.fetch_one(&self.pool).await.map_err(map_sqlx)?;
        let n: i64 = row.get("n");
        Ok(n as usize)
    }
}
