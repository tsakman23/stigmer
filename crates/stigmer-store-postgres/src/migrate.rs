//! Applying the migrations: all pending ones in ONE transaction, under an advisory lock, so two
//! servers or admin commands migrating at once cannot both apply a step or see half a schema.

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, GENESIS_HASH};
use stigmer_store::StoreError;

use crate::error::db;
use crate::schema::{self, MigrationReport, MIGRATIONS, VERSION_TABLE};
use crate::{hash, pool};

/// One lock per schema: the key is derived from the schema the connection works in.
const LOCK: &str =
    "SELECT pg_advisory_xact_lock(hashtext('stigmer.migrate:' || COALESCE(current_schema(), '')))";

/// Brings the schema up to [`schema::latest`] and makes sure board `main` exists. A schema
/// newer than this build is refused and left as it is.
pub(crate) async fn migrate(pool: &Pool) -> Result<MigrationReport, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    tx.batch_execute(LOCK).await.map_err(db)?;
    tx.batch_execute(VERSION_TABLE).await.map_err(db)?;
    let from = schema::version(&tx).await?;
    let to = schema::latest();
    if from > to {
        return Err(StoreError::Backend(format!(
            "database schema version {from} is newer than this build supports ({to}): \
             this server is older than the database"
        )));
    }
    for (version, sql) in (1..).zip(MIGRATIONS) {
        if u32::try_from(version).is_ok_and(|v: u32| v <= from) {
            continue;
        }
        let version: i32 = version;
        tx.batch_execute(sql).await.map_err(db)?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES ($1)",
            &[&version],
        )
        .await
        .map_err(db)?;
    }
    tx.execute(
        "INSERT INTO boards (id, head_seq, head_hash, created_at_ms)
         VALUES ($1, 0, $2, $3) ON CONFLICT (id) DO NOTHING",
        &[
            &BoardId::main().as_str(),
            &hash::to_bytes(GENESIS_HASH)?,
            &stigmer_core::now_ms(),
        ],
    )
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(MigrationReport { from, to })
}
