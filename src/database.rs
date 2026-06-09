use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        let mut conn = SqliteConnection::connect_with(&opt).await?;
        // Enable WAL mode for better concurrent read performance
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&mut conn)
            .await
            .ok();
        // Reduce fsync overhead while keeping crash safety
        sqlx::query("PRAGMA synchronous=NORMAL")
            .execute(&mut conn)
            .await
            .ok();
        Ok(conn)
    }
    async fn recycle(
        &self,
        mut obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        // Use SELECT 1 instead of ping() — more reliable for SQLite
        sqlx::query("SELECT 1")
            .execute(obj.deref_mut())
            .await
            .map(|_| ())
            .map_err(deadpool::managed::RecycleError::Backend)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}
#[allow(dead_code)]
#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = std::env::var("MAX_DATABASE_CONNECTIONS")
            .unwrap_or_else(|_| "4".to_owned())
            .parse()
            .unwrap_or(4);
        log::info!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        // INSERT OR IGNORE: silently skip on duplicate id, avoids propagating
        // a UniqueViolation error when two tasks race to register the same peer.
        // We must check rows_affected() because if the insert is ignored (duplicate
        // id), the returned guid would not match what's in the database, causing
        // subsequent update_pk calls to silently fail (no rows matched).
        let result = sqlx::query!(
            "insert or ignore into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        if result.rows_affected() == 0 {
            // Race: another task already inserted a row for this id.
            // Fetch the real guid so the caller can update correctly.
            let real_guid: Vec<u8> =
                sqlx::query_scalar!("select guid from peer where id = ?", id)
                    .fetch_one(self.pool.get().await?.deref_mut())
                    .await?;
            Ok(real_guid)
        } else {
            Ok(guid)
        }
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        let result = sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        // If no row was updated, the in-memory guid may be stale (e.g. from a
        // prior INSERT OR IGNORE race that stored a guid not matching the DB).
        // This should no longer happen after the insert_peer fix, but we log it
        // as an error instead of silently losing the peer's updated data.
        if result.rows_affected() == 0 {
            log::error!(
                "update_pk affected 0 rows for id={}, guid may be stale — peer data NOT persisted",
                id
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}
