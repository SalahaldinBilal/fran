use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;
use sqlx::migrate::Migrator;

static SQLITE_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/sqlite");
static MYSQL_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/mysql");
static DRIVERS: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
    Sqlite,
    Mysql,
}

#[derive(Clone)]
pub struct Db {
    pub(crate) pool: AnyPool,
    pub kind: DbKind,
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs() as i64)
}

fn kind_of(url: &str) -> Result<DbKind, String> {
    match url.split(':').next().unwrap_or_default() {
        "sqlite" => Ok(DbKind::Sqlite),
        "mysql" | "mariadb" => Ok(DbKind::Mysql),
        other => Err(format!("DATABASE_URL must start with sqlite: or mysql:, not {other}:")),
    }
}

// sqlx only opens an existing SQLite file unless the URL says otherwise.
// "sqlite://C:/data/x.db" would be read as host "C", so the slashes after the scheme go.
fn with_create(url: &str) -> String {
    let url = match url.strip_prefix("sqlite://") {
        Some(path) => format!("sqlite:{path}"),
        None => url.to_string(),
    };
    let url = url.as_str();
    if url.contains("mode=") || url.contains(":memory:") {
        url.to_string()
    } else if url.contains('?') {
        format!("{url}&mode=rwc")
    } else {
        format!("{url}?mode=rwc")
    }
}

impl Db {
    pub async fn connect(url: &str) -> Result<Self, String> {
        DRIVERS.call_once(sqlx::any::install_default_drivers);
        let kind = kind_of(url)?;
        let failed = |error: sqlx::Error| format!("Can't open the database: {error}");
        let pool = match kind {
            DbKind::Sqlite => {
                AnyPoolOptions::new()
                    .max_connections(4)
                    .after_connect(|connection, _| {
                        Box::pin(async move {
                            sqlx::query("PRAGMA journal_mode = WAL").execute(&mut *connection).await?;
                            Ok(())
                        })
                    })
                    .connect(&with_create(url))
                    .await
            }
            DbKind::Mysql => AnyPoolOptions::new().max_connections(10).connect(url).await,
        }
        .map_err(failed)?;
        let migrations = match kind {
            DbKind::Sqlite => &SQLITE_MIGRATIONS,
            DbKind::Mysql => &MYSQL_MIGRATIONS,
        };
        migrations.run(&pool).await.map_err(|error| format!("Can't set up the database tables: {error}"))?;
        Ok(Self { pool, kind })
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_sqlite_file_is_created_and_other_urls_are_left_alone() {
        assert_eq!(with_create("sqlite://fran-sync.db"), "sqlite:fran-sync.db?mode=rwc");
        assert_eq!(with_create("sqlite://C:/data/Fran.db"), "sqlite:C:/data/Fran.db?mode=rwc");
        assert_eq!(with_create("sqlite:///var/lib/fran/sync.db"), "sqlite:/var/lib/fran/sync.db?mode=rwc");
        assert_eq!(with_create("sqlite:data.db?cache=shared"), "sqlite:data.db?cache=shared&mode=rwc");
        assert_eq!(with_create("sqlite://data.db?mode=ro"), "sqlite:data.db?mode=ro");
        assert!(kind_of("postgres://localhost/fran").is_err());
    }
}
