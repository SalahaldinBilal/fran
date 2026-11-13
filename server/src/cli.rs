use std::net::SocketAddr;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;
use sync_proto::Role;
use tokio::net::TcpListener;

use crate::auth::normalize_email;
use crate::config::Config;
use crate::crypto;
use crate::db::{Db, now};
use crate::state::AppState;

const PURGE_EVERY: Duration = Duration::from_secs(60 * 60);

const USAGE: &str = "\
Usage:
  fran-sync-server                       run the server
  fran-sync-server key                   print a new SERVER_KEY
  fran-sync-server users list            list the accounts
  fran-sync-server users create <email>  make room for one account, works with SIGNUP=closed too
  fran-sync-server users invite          make an invite anyone can use once (SIGNUP=invite)
  fran-sync-server users delete <email>  delete an account and everything it stored
  fran-sync-server users role <email> <user|admin|owner>
                                         change what an account may manage, owner hands the server over";

pub async fn run(args: Vec<String>) -> Result<(), String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["serve"] => serve(Config::load()?).await,
        ["key"] => {
            println!("{}", hex::encode(crypto::random::<32>()));
            Ok(())
        }
        ["--version"] => {
            println!("fran-sync-server {}", crate::VERSION);
            Ok(())
        }
        ["users", "list"] => list_users(&open_db().await?).await,
        ["users", "create", email] => invite(&open_db().await?, Some(email)).await,
        ["users", "invite"] => invite(&open_db().await?, None).await,
        ["users", "delete", email] => delete_user(&open_db().await?, email).await,
        ["users", "role", email, role] => set_role(&open_db().await?, email, role).await,
        _ => Err(USAGE.to_string()),
    }
}

async fn open_db() -> Result<Db, String> {
    Db::connect(&Config::load()?.database_url).await
}

fn failed(error: sqlx::Error) -> String {
    format!("The database refused that: {error}")
}

fn date(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

async fn list_users(db: &Db) -> Result<(), String> {
    let users = db.list_users().await.map_err(failed)?;
    if users.is_empty() {
        println!("No accounts yet.");
    }
    for user in users {
        println!("{}  {}  created {}  {} KiB stored", user.email, user.role.as_str(), date(user.created_at), user.used_bytes / 1024);
    }
    Ok(())
}

async fn set_role(db: &Db, email: &str, role: &str) -> Result<(), String> {
    let email = normalize_email(email).map_err(|error| error.body.message)?;
    let role = Role::parse(role).ok_or("The role is user, admin or owner")?;
    let user = db.user_by_email(&email).await.map_err(failed)?.ok_or_else(|| format!("No account for {email}"))?;
    if role == Role::Owner {
        db.transfer_owner(&user.id).await.map_err(failed)?;
    } else {
        db.set_role(&user.id, role).await.map_err(failed)?;
    }
    db.add_log("the server's command line", "role", &email, &format!("Now {}", role.as_str()), now()).await.map_err(failed)?;
    println!("{email} is now {}.", role.as_str());
    Ok(())
}

async fn invite(db: &Db, email: Option<&str>) -> Result<(), String> {
    let email = match email {
        Some(email) => normalize_email(email).map_err(|error| error.body.message)?,
        None => String::new(),
    };
    if !email.is_empty() && db.user_by_email(&email).await.map_err(failed)?.is_some() {
        return Err(format!("{email} already has an account"));
    }
    let code = crypto::invite_code();
    db.insert_invite(&crypto::invite_hash(&code), &email, now(), 0).await.map_err(failed)?;
    match email.as_str() {
        "" => println!("Invite code, good for one new account: {code}"),
        email => println!("Invite code for {email}: {code}\nThey enter it when they create the account in Fran."),
    }
    Ok(())
}

async fn delete_user(db: &Db, email: &str) -> Result<(), String> {
    let email = normalize_email(email).map_err(|error| error.body.message)?;
    let user = db.user_by_email(&email).await.map_err(failed)?.ok_or_else(|| format!("No account for {email}"))?;
    db.delete_user(&user.id).await.map_err(failed)?;
    println!("Deleted {email} and everything it stored.");
    Ok(())
}

fn purge_in_background(state: AppState) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(PURGE_EVERY);
        loop {
            timer.tick().await;
            let now = now();
            if let Err(error) = state.db.purge(now, now - state.config.rate.window_secs).await {
                eprintln!("error: cleanup: {error}");
            }
        }
    });
}

pub async fn serve(config: Config) -> Result<(), String> {
    let state = AppState::new(config).await?;
    if let Some(code) = state.setup_code() {
        eprintln!("This server has no owner yet. Claim it from Fran with this setup code: {code}");
        eprintln!("Sign in or create an account on this server in Fran, open its panel on the Sync page and pick Claim. A new code is made each time the server starts.");
    }
    purge_in_background(state.clone());
    let bind = state.config.bind;
    let app = crate::api::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let served = async {
        match &state.config.tls {
            Some(files) => {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let tls = RustlsConfig::from_pem_file(&files.cert, &files.key)
                    .await
                    .map_err(|error| format!("Can't read TLS_CERT and TLS_KEY: {error}"))?;
                println!("fran-sync-server {} on https://{bind}", crate::VERSION);
                axum_server::bind_rustls(bind, tls).serve(app).await.map_err(|error| format!("The server stopped: {error}"))
            }
            None => {
                let listener = TcpListener::bind(bind).await.map_err(|error| format!("Can't listen on {bind}: {error}"))?;
                println!("fran-sync-server {} on http://{bind}", crate::VERSION);
                axum::serve(listener, app).await.map_err(|error| format!("The server stopped: {error}"))
            }
        }
    };
    tokio::select! {
        result = served => result,
        _ = tokio::signal::ctrl_c() => {
            state.db.close().await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_come_out_right_around_leap_days() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_709_164_800), "2024-02-29");
        assert_eq!(date(1_709_251_200), "2024-03-01");
        assert_eq!(date(1_794_528_000), "2026-11-13");
    }
}
