mod harness;

use futures_util::StreamExt;
use harness::{Account, Backend, Server, error_of, record, record_id, start, start_with};
use reqwest::StatusCode;
use serde_json::json;
use sync_proto::{
    AccountInfo, AdminInvite, AdminLogEntry, AdminUsersPage, CreatedInvite, ErrorCode, Event, KdfParams, PROTOCOL_HEADER, PROTOCOL_VERSION, PushStatus,
    RecoveryStarted, Role, ServerInfo, ServerSettings, SessionInfo, SignedIn, SignupMode, TotpState,
};
use tokio_tungstenite::tungstenite::Message;

// MySQL and MariaDB only run when their env variable names a running server, see harness::server_url.
macro_rules! on_a_server {
    ($module:ident, $backend:expr, $($name:ident),*) => {
        mod $module {
            $(
                #[tokio::test]
                async fn $name() {
                    if super::harness::skipped($backend) {
                        return;
                    }
                    super::$name($backend).await
                }
            )*

            #[tokio::test]
            async fn its_migrations_make_the_same_tables_as_sqlites() {
                if super::harness::skipped($backend) {
                    return;
                }
                super::both_migration_sets_make_the_same_tables($backend).await
            }
        }
    };
}

macro_rules! on_every_database {
    ($($name:ident),* $(,)?) => {
        mod sqlite {
            $(
                #[tokio::test]
                async fn $name() {
                    super::$name(super::Backend::Sqlite).await
                }
            )*
        }

        on_a_server!(mysql, super::Backend::Mysql, $($name),*);
        on_a_server!(mariadb, super::Backend::Mariadb, $($name),*);
    };
}

on_every_database!(
    a_new_account_can_sign_in_elsewhere_and_gets_its_wrapped_key_back,
    a_revoked_device_is_signed_out_and_the_others_stay,
    only_the_hash_of_a_session_token_is_stored,
    a_wrong_password_and_an_unknown_email_look_the_same,
    the_kdf_answer_is_the_same_before_and_after_sign_up,
    too_many_wrong_passwords_lock_the_account_for_a_while,
    too_many_failures_from_one_address_lock_that_address,
    records_come_back_as_pushed_and_only_newer_ones_after_a_cursor,
    a_push_on_a_stale_revision_is_a_conflict_and_changes_nothing,
    a_delete_is_a_tombstone_other_devices_can_see,
    one_account_never_sees_another_accounts_records,
    of_many_pushes_at_the_same_revision_exactly_one_wins,
    record_size_and_account_quota_are_enforced_and_a_full_account_can_still_delete,
    a_batch_over_the_limit_and_bad_ids_are_refused,
    a_long_pull_pages_through_everything_once,
    the_socket_announces_pushes_with_a_cursor_and_no_data,
    the_socket_needs_a_session_and_closes_when_it_is_revoked,
    a_password_change_needs_the_old_one_and_signs_other_devices_out,
    the_recovery_key_sets_a_new_password,
    two_step_sign_in_asks_for_a_code_and_takes_each_code_once,
    a_closed_server_only_takes_an_invite_made_for_that_email,
    an_invite_works_once,
    deleting_an_account_removes_its_records_and_sessions,
    another_protocol_version_is_refused,
    the_instance_id_survives_a_restart,
    a_session_slides_while_it_is_used_and_ends_a_year_after_sign_in,
    a_request_that_is_too_big_is_refused,
    a_forwarded_address_only_counts_behind_a_trusted_proxy,
    the_setup_code_claims_an_unowned_server_once,
    a_closed_server_takes_its_first_account_with_the_setup_code,
    wrong_setup_codes_are_limited,
    only_admins_reach_admin_calls_and_only_the_owner_hands_out_roles,
    a_setting_changed_from_the_app_beats_the_servers_own_and_survives_a_restart,
    a_lowered_limit_blocks_growth_but_not_deletes_and_an_own_limit_beats_it,
    the_server_total_stops_growth_for_everyone,
    an_invite_from_the_app_expires_and_shows_who_used_it,
    deleting_someone_needs_the_admins_password_and_the_log_keeps_no_secrets,
);

const DAY: i64 = 24 * 60 * 60;

async fn a_session_slides_while_it_is_used_and_ends_a_year_after_sign_in(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let now = fran_sync_server::db::now();
    let id = &account.session_id;
    let expiry = |sessions: Vec<SessionInfo>| sessions[0].expires_at;

    server.execute(format!("UPDATE sessions SET last_seen_at = {}, expires_at = {} WHERE id = '{id}'", now - 29 * DAY, now + DAY)).await;
    let used_again: Vec<SessionInfo> = server.get("/sessions", &account.token).await.json().await.unwrap();
    assert!((expiry(used_again) - (now + 30 * DAY)).abs() < 60);

    let signed_in_at = now - 364 * DAY;
    server
        .execute(format!("UPDATE sessions SET created_at = {signed_in_at}, last_seen_at = {}, expires_at = {} WHERE id = '{id}'", now - DAY, now + 3600))
        .await;
    let near_the_end: Vec<SessionInfo> = server.get("/sessions", &account.token).await.json().await.unwrap();
    assert_eq!(expiry(near_the_end), signed_in_at + 365 * DAY);

    server.execute(format!("UPDATE sessions SET expires_at = {} WHERE id = '{id}'", now - 1)).await;
    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::UNAUTHORIZED);
}

async fn a_request_that_is_too_big_is_refused(backend: Backend) {
    let server = start(backend).await;
    let huge = server.sign_in(&"a".repeat(200 * 1024), &harness::key(), None).await;
    let (status, error) = error_of(huge).await;
    assert_eq!((status, error.code), (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge));
}

async fn a_forwarded_address_only_counts_behind_a_trusted_proxy(backend: Backend) {
    let direct = start_with(backend, |config| config.rate.per_ip = 3).await;
    for made_up in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
        assert_eq!(direct.failed_sign_in_from(made_up).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(direct.failed_sign_in_from("198.51.100.4").await, StatusCode::TOO_MANY_REQUESTS);

    let proxied = start_with(backend, |config| {
        config.rate.per_ip = 3;
        config.trust_proxy = true;
    })
    .await;
    for _ in 0..3 {
        assert_eq!(proxied.failed_sign_in_from("203.0.113.5").await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(proxied.failed_sign_in_from("203.0.113.5").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(proxied.failed_sign_in_from("203.0.113.9").await, StatusCode::UNAUTHORIZED);
    // What the client claims comes first, the proxy's own entry is last.
    assert_eq!(proxied.failed_sign_in_from("203.0.113.77, 203.0.113.5").await, StatusCode::TOO_MANY_REQUESTS);
}

async fn a_new_account_can_sign_in_elsewhere_and_gets_its_wrapped_key_back(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;

    let response = server.sign_in("Ada@Example.com ", &account.auth_key, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let second: SignedIn = response.json().await.unwrap();
    assert_eq!(second.wrapped_data_key.as_slice(), account.wrapped_data_key.as_slice());
    assert_eq!(second.account_id, account.id);
    assert_ne!(second.token, account.token);

    let info: AccountInfo = server.get("/account", &second.token).await.json().await.unwrap();
    assert_eq!(info.email, "ada@example.com");
    assert!(!info.totp_enabled);
}

async fn a_revoked_device_is_signed_out_and_the_others_stay(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let second: SignedIn = server.sign_in(&account.email, &account.auth_key, None).await.json().await.unwrap();

    let sessions: Vec<SessionInfo> = server.get("/sessions", &account.token).await.json().await.unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions.iter().filter(|session| session.current).map(|session| &session.id).collect::<Vec<_>>(), [&account.session_id]);

    let revoked = server.delete(&format!("/sessions/{}", second.session_id), &account.token).await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.get("/account", &second.token).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::OK);

    let other = server.sign_up("grace@example.com").await;
    let not_theirs = server.delete(&format!("/sessions/{}", account.session_id), &other.token).await;
    assert_eq!(not_theirs.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::OK);

    assert_eq!(server.delete("/sessions/current", &account.token).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::UNAUTHORIZED);
}

async fn only_the_hash_of_a_session_token_is_stored(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let stored = server.column("SELECT token_hash FROM sessions").await;
    assert_eq!(stored.len(), 1);
    assert_ne!(stored[0], account.token);
    assert!(!stored[0].contains(&account.token));
}

async fn a_wrong_password_and_an_unknown_email_look_the_same(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let wrong_password = error_of(server.sign_in(&account.email, &harness::key(), None).await).await;
    let unknown_email = error_of(server.sign_in("nobody@example.com", &harness::key(), None).await).await;
    assert_eq!(wrong_password.0, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_password.1.code, ErrorCode::InvalidCredentials);
    assert_eq!(wrong_password, unknown_email);
}

async fn the_kdf_answer_is_the_same_before_and_after_sign_up(backend: Backend) {
    let server = start(backend).await;
    let before: KdfParams = server.kdf("ada@example.com").await;
    let again: KdfParams = server.kdf("ada@example.com").await;
    let someone_else: KdfParams = server.kdf("grace@example.com").await;
    assert_eq!(before, again);
    assert_ne!(before.salt, someone_else.salt);
    assert_eq!((before.memory_kib, before.passes), (64 * 1024, 3));

    server.sign_up("ada@example.com").await;
    assert_eq!(server.kdf("ada@example.com").await, before);
}

async fn too_many_wrong_passwords_lock_the_account_for_a_while(backend: Backend) {
    let server = start_with(backend, |config| config.rate.per_account = 3).await;
    let account = server.sign_up("ada@example.com").await;
    let other = server.sign_up("grace@example.com").await;
    for _ in 0..3 {
        assert_eq!(server.sign_in(&account.email, &harness::key(), None).await.status(), StatusCode::UNAUTHORIZED);
    }
    let locked = server.sign_in(&account.email, &account.auth_key, None).await;
    assert!(locked.headers().contains_key("retry-after"));
    let (status, error) = error_of(locked).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error.code, ErrorCode::RateLimited);
    assert!(error.retry_after_secs.is_some_and(|seconds| seconds > 0 && seconds <= 15 * 60));

    assert_eq!(server.sign_in(&other.email, &other.auth_key, None).await.status(), StatusCode::OK);
}

async fn too_many_failures_from_one_address_lock_that_address(backend: Backend) {
    let server = start_with(backend, |config| config.rate.per_ip = 3).await;
    let account = server.sign_up("ada@example.com").await;
    for name in ["a", "b", "c"] {
        let response = server.sign_in(&format!("{name}@example.com"), &harness::key(), None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let (status, error) = error_of(server.sign_in(&account.email, &account.auth_key, None).await).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error.code, ErrorCode::RateLimited);
}

async fn records_come_back_as_pushed_and_only_newer_ones_after_a_cursor(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let big = vec![0xA5u8; 200 * 1024];
    let pushed = server.push(&account.token, vec![record(1, 0, b"first"), record(2, 0, &big)]).await;
    assert!(pushed.results.iter().all(|result| result.status == PushStatus::Accepted && result.revision == 1));

    let page = server.pull(&account.token, 0, None).await;
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].ciphertext.as_slice(), b"first");
    assert_eq!(page.records[1].ciphertext.as_slice(), big.as_slice());
    assert_eq!(page.cursor, pushed.cursor);
    assert!(!page.more);

    let nothing_new = server.pull(&account.token, page.cursor, None).await;
    assert!(nothing_new.records.is_empty());
    assert_eq!(nothing_new.cursor, page.cursor);

    server.push(&account.token, vec![record(1, 1, b"first, edited")]).await;
    let newer = server.pull(&account.token, page.cursor, None).await;
    assert_eq!(newer.records.len(), 1);
    assert_eq!((newer.records[0].id.as_str(), newer.records[0].revision), (record_id(1).as_str(), 2));
    assert_eq!(newer.records[0].ciphertext.as_slice(), b"first, edited");
}

async fn a_push_on_a_stale_revision_is_a_conflict_and_changes_nothing(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    server.push(&account.token, vec![record(1, 0, b"v1")]).await;
    let laptop = server.push(&account.token, vec![record(1, 1, b"from the laptop")]).await;
    assert_eq!(laptop.results[0].revision, 2);

    let desktop = server.push(&account.token, vec![record(1, 1, b"from the desktop"), record(2, 0, b"new")]).await;
    assert_eq!((desktop.results[0].status, desktop.results[0].revision), (PushStatus::Conflict, 2));
    assert_eq!((desktop.results[1].status, desktop.results[1].revision), (PushStatus::Accepted, 1));

    let page = server.pull(&account.token, 0, None).await;
    let kept = page.records.iter().find(|stored| stored.id == record_id(1)).unwrap();
    assert_eq!((kept.revision, kept.ciphertext.as_slice()), (2, b"from the laptop".as_slice()));

    let made_twice = server.push(&account.token, vec![record(2, 0, b"made again")]).await;
    assert_eq!(made_twice.results[0].status, PushStatus::Conflict);
}

async fn a_delete_is_a_tombstone_other_devices_can_see(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let first = server.push(&account.token, vec![record(1, 0, b"here")]).await;

    let mut tombstone = record(1, 1, b"moved");
    tombstone.deleted = true;
    assert_eq!(server.push(&account.token, vec![tombstone]).await.results[0].status, PushStatus::Accepted);

    let page = server.pull(&account.token, first.cursor, None).await;
    assert_eq!(page.records.len(), 1);
    assert!(page.records[0].deleted);
    assert_eq!((page.records[0].revision, page.records[0].ciphertext.as_slice()), (2, b"moved".as_slice()));
}

async fn one_account_never_sees_another_accounts_records(backend: Backend) {
    let server = start(backend).await;
    let ada = server.sign_up("ada@example.com").await;
    let grace = server.sign_up("grace@example.com").await;
    server.push(&ada.token, vec![record(1, 0, b"ada's")]).await;

    assert!(server.pull(&grace.token, 0, None).await.records.is_empty());
    let same_id = server.push(&grace.token, vec![record(1, 0, b"grace's")]).await;
    assert_eq!((same_id.results[0].status, same_id.results[0].revision), (PushStatus::Accepted, 1));
    assert_eq!(server.pull(&ada.token, 0, None).await.records[0].ciphertext.as_slice(), b"ada's");
    assert_eq!(server.pull(&grace.token, 0, None).await.records[0].ciphertext.as_slice(), b"grace's");

    let no_session = server.http.get(server.url("/records")).send().await.unwrap();
    assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
}

async fn of_many_pushes_at_the_same_revision_exactly_one_wins(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let pushes = (0..8u8).map(|writer| server.push(&account.token, vec![record(1, 0, &[writer])]));
    let results = futures_util::future::join_all(pushes).await;
    let accepted = results.iter().filter(|pushed| pushed.results[0].status == PushStatus::Accepted).count();
    let conflicts = results.iter().filter(|pushed| pushed.results[0].status == PushStatus::Conflict).count();
    assert_eq!((accepted, conflicts), (1, 7));

    let page = server.pull(&account.token, 0, None).await;
    assert_eq!((page.records.len(), page.records[0].revision, page.cursor), (1, 1, 1));
}

async fn record_size_and_account_quota_are_enforced_and_a_full_account_can_still_delete(backend: Backend) {
    let server = start_with(backend, |config| {
        config.limits.record_bytes = 1024;
        config.limits.account_bytes = 3000;
    })
    .await;
    let account = server.sign_up("ada@example.com").await;
    let kilobyte = vec![1u8; 1000];

    let too_big = server.push(&account.token, vec![record(9, 0, &vec![1u8; 1025])]).await;
    assert_eq!(too_big.results[0].status, PushStatus::TooLarge);

    let filled = server.push(&account.token, vec![record(1, 0, &kilobyte), record(2, 0, &kilobyte), record(3, 0, &kilobyte), record(4, 0, &kilobyte)]).await;
    let statuses: Vec<_> = filled.results.iter().map(|result| result.status).collect();
    assert_eq!(statuses, [PushStatus::Accepted, PushStatus::Accepted, PushStatus::Accepted, PushStatus::QuotaExceeded]);
    let info: AccountInfo = server.get("/account", &account.token).await.json().await.unwrap();
    assert_eq!(info.used_bytes, 3000);

    let mut tombstone = record(1, 1, b"");
    tombstone.deleted = true;
    assert_eq!(server.push(&account.token, vec![tombstone]).await.results[0].status, PushStatus::Accepted);
    assert_eq!(server.push(&account.token, vec![record(4, 0, &kilobyte)]).await.results[0].status, PushStatus::Accepted);
}

async fn a_batch_over_the_limit_and_bad_ids_are_refused(backend: Backend) {
    let server = start_with(backend, |config| config.limits.batch_records = 3).await;
    let account = server.sign_up("ada@example.com").await;

    let too_many = server.push_raw(&account.token, (1..=4).map(|number| record(number, 0, b"x")).collect()).await;
    assert_eq!(error_of(too_many).await.1.code, ErrorCode::TooLarge);

    let mut bad_id = record(1, 0, b"x");
    bad_id.id = "../../etc/passwd".to_string();
    assert_eq!(server.push_raw(&account.token, vec![bad_id]).await.status(), StatusCode::BAD_REQUEST);

    let twice = server.push_raw(&account.token, vec![record(1, 0, b"x"), record(1, 0, b"y")]).await;
    assert_eq!(twice.status(), StatusCode::BAD_REQUEST);
    assert!(server.pull(&account.token, 0, None).await.records.is_empty());
}

async fn a_long_pull_pages_through_everything_once(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    server.push(&account.token, (1..=5).map(|number| record(number, 0, &[number])).collect()).await;

    let mut seen = Vec::new();
    let mut cursor = 0;
    loop {
        let page = server.pull(&account.token, cursor, Some(2)).await;
        assert!(page.records.len() <= 2);
        seen.extend(page.records.iter().map(|stored| stored.ciphertext.as_slice()[0]));
        cursor = page.cursor;
        if !page.more {
            break;
        }
    }
    assert_eq!(seen, [1, 2, 3, 4, 5]);
}

async fn next_event(socket: &mut harness::Socket) -> Option<String> {
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next()).await.expect("the socket went quiet")?;
        match message {
            Ok(Message::Text(text)) => return Some(text.to_string()),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

async fn the_socket_announces_pushes_with_a_cursor_and_no_data(backend: Backend) {
    let server = start(backend).await;
    let ada = server.sign_up("ada@example.com").await;
    let grace = server.sign_up("grace@example.com").await;
    let mut socket = server.events(&ada.token).await.unwrap();
    assert_eq!(serde_json::from_str::<Event>(&next_event(&mut socket).await.unwrap()).unwrap(), Event::Changed { cursor: 0 });

    server.push(&grace.token, vec![record(1, 0, b"not ada's business")]).await;
    let pushed = server.push(&ada.token, vec![record(1, 0, b"top secret ciphertext"), record(2, 0, b"more")]).await;
    let text = next_event(&mut socket).await.unwrap();
    assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), Event::Changed { cursor: pushed.cursor });
    assert_eq!(text, format!(r#"{{"type":"changed","cursor":{}}}"#, pushed.cursor));
}

async fn the_socket_needs_a_session_and_closes_when_it_is_revoked(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    assert_eq!(server.events("not-a-token").await.unwrap_err(), StatusCode::UNAUTHORIZED);

    let second: SignedIn = server.sign_in(&account.email, &account.auth_key, None).await.json().await.unwrap();
    let mut socket = server.events(&second.token).await.unwrap();
    assert!(next_event(&mut socket).await.is_some());
    server.delete(&format!("/sessions/{}", second.session_id), &account.token).await;
    assert_eq!(next_event(&mut socket).await, None);
}

async fn a_password_change_needs_the_old_one_and_signs_other_devices_out(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let second: SignedIn = server.sign_in(&account.email, &account.auth_key, None).await.json().await.unwrap();
    let (new_key, new_wrapped) = (harness::key(), b"data key under the new master key".to_vec());

    let wrong = server.change_password(&account.token, &harness::key(), &new_key, &new_wrapped).await;
    assert_eq!(error_of(wrong).await.1.code, ErrorCode::InvalidCredentials);
    assert_eq!(server.sign_in(&account.email, &account.auth_key, None).await.status(), StatusCode::OK);

    let changed = server.change_password(&account.token, &account.auth_key, &new_key, &new_wrapped).await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.sign_in(&account.email, &account.auth_key, None).await.status(), StatusCode::UNAUTHORIZED);
    let signed_in: SignedIn = server.sign_in(&account.email, &new_key, None).await.json().await.unwrap();
    assert_eq!(signed_in.wrapped_data_key.as_slice(), new_wrapped.as_slice());
    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::OK);
    assert_eq!(server.get("/account", &second.token).await.status(), StatusCode::UNAUTHORIZED);
}

async fn the_recovery_key_sets_a_new_password(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    server.push(&account.token, vec![record(1, 0, b"kept")]).await;

    let wrong = server.recovery_start(&account.email, &harness::key()).await;
    assert_eq!(error_of(wrong).await.1.code, ErrorCode::InvalidCredentials);
    let unknown = server.recovery_start("nobody@example.com", &account.recovery_auth_key).await;
    assert_eq!(error_of(unknown).await.1.code, ErrorCode::InvalidCredentials);

    let started: RecoveryStarted = server.recovery_start(&account.email, &account.recovery_auth_key).await.json().await.unwrap();
    assert_eq!(started.recovery_wrapped_data_key.as_slice(), account.recovery_wrapped_data_key.as_slice());

    let (new_key, new_wrapped) = (harness::key(), b"rewrapped".to_vec());
    let finished = server.recovery_finish(&account.email, &account.recovery_auth_key, &new_key, &new_wrapped).await;
    assert_eq!(finished.status(), StatusCode::OK);
    let recovered: SignedIn = finished.json().await.unwrap();

    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.sign_in(&account.email, &account.auth_key, None).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.sign_in(&account.email, &new_key, None).await.status(), StatusCode::OK);
    assert_eq!(server.pull(&recovered.token, 0, None).await.records[0].ciphertext.as_slice(), b"kept");
}

async fn two_step_sign_in_asks_for_a_code_and_takes_each_code_once(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    let begun: TotpState = server.totp(&account.token, serde_json::json!({ "action": "begin" })).await.json().await.unwrap();
    let secret = harness::base32_decoded(begun.secret.as_deref().unwrap());
    assert!(begun.uri.unwrap().contains(begun.secret.as_deref().unwrap()));
    assert_eq!(server.sign_in(&account.email, &account.auth_key, None).await.status(), StatusCode::OK);

    // One step is fixed for the whole test, so a 30 second boundary passing mid-test changes nothing.
    let step = harness::totp_step();
    let wrong = server.totp(&account.token, serde_json::json!({ "action": "confirm", "code": harness::wrong_code(&secret, step) })).await;
    assert_eq!(error_of(wrong).await.1.code, ErrorCode::TotpInvalid);
    let confirmed = server.totp(&account.token, serde_json::json!({ "action": "confirm", "code": harness::code(&secret, step) })).await;
    assert!(confirmed.json::<TotpState>().await.unwrap().enabled);

    let without = error_of(server.sign_in(&account.email, &account.auth_key, None).await).await;
    assert_eq!((without.0, without.1.code), (StatusCode::UNAUTHORIZED, ErrorCode::TotpRequired));
    let replayed = server.sign_in(&account.email, &account.auth_key, Some(&harness::code(&secret, step))).await;
    assert_eq!(error_of(replayed).await.1.code, ErrorCode::TotpInvalid);

    let next_code = harness::code(&secret, step + 1);
    assert_eq!(server.sign_in(&account.email, &account.auth_key, Some(&next_code)).await.status(), StatusCode::OK);
    let used_again = server.sign_in(&account.email, &account.auth_key, Some(&next_code)).await;
    assert_eq!(error_of(used_again).await.1.code, ErrorCode::TotpInvalid);

    let disable = serde_json::json!({ "action": "disable", "authKey": harness::b64(&account.auth_key) });
    assert!(!server.totp(&account.token, disable).await.json::<TotpState>().await.unwrap().enabled);
    assert_eq!(server.sign_in(&account.email, &account.auth_key, None).await.status(), StatusCode::OK);
}

async fn a_closed_server_only_takes_an_invite_made_for_that_email(backend: Backend) {
    let server = start_with(backend, |config| config.signup = SignupMode::Closed).await;
    let info: ServerInfo = server.http.get(server.url("/info")).send().await.unwrap().json().await.unwrap();
    assert_eq!(info.signup, SignupMode::Closed);

    let no_invite = server.try_sign_up("ada@example.com", None).await;
    assert_eq!(error_of(no_invite).await.1.code, ErrorCode::SignupClosed);

    let for_anyone = server.invite("").await;
    let open_invite = server.try_sign_up("ada@example.com", Some(&for_anyone)).await;
    assert_eq!(error_of(open_invite).await.1.code, ErrorCode::InvalidInvite);

    let for_ada = server.invite("ada@example.com").await;
    let someone_else = server.try_sign_up("grace@example.com", Some(&for_ada)).await;
    assert_eq!(error_of(someone_else).await.1.code, ErrorCode::InvalidInvite);
    let lowercase = for_ada.to_lowercase();
    assert_eq!(server.try_sign_up("ada@example.com", Some(&format!(" {lowercase} "))).await.status(), StatusCode::CREATED);
}

async fn an_invite_works_once(backend: Backend) {
    let server = start_with(backend, |config| config.signup = SignupMode::Invite).await;
    assert_eq!(error_of(server.try_sign_up("ada@example.com", None).await).await.1.code, ErrorCode::InvalidInvite);
    assert_eq!(error_of(server.try_sign_up("ada@example.com", Some("MADEUPCODE")).await).await.1.code, ErrorCode::InvalidInvite);

    let code = server.invite("").await;
    assert_eq!(server.try_sign_up("ada@example.com", Some(&code)).await.status(), StatusCode::CREATED);
    assert_eq!(error_of(server.try_sign_up("grace@example.com", Some(&code)).await).await.1.code, ErrorCode::InvalidInvite);

    let second = server.invite("").await;
    let taken = server.try_sign_up("ada@example.com", Some(&second)).await;
    assert_eq!(error_of(taken).await.1.code, ErrorCode::EmailTaken);
    assert_eq!(server.try_sign_up("grace@example.com", Some(&second)).await.status(), StatusCode::CREATED);
}

async fn deleting_an_account_removes_its_records_and_sessions(backend: Backend) {
    let server = start(backend).await;
    let account = server.sign_up("ada@example.com").await;
    server.push(&account.token, vec![record(1, 0, b"gone soon")]).await;

    let wrong = server.delete_account(&account.token, &harness::key()).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.pull(&account.token, 0, None).await.records.len(), 1);

    assert_eq!(server.delete_account(&account.token, &account.auth_key).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.get("/account", &account.token).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.sign_in(&account.email, &account.auth_key, None).await.status(), StatusCode::UNAUTHORIZED);
    assert!(server.column("SELECT id FROM records").await.is_empty());

    let again: Account = server.sign_up("ada@example.com").await;
    assert!(server.pull(&again.token, 0, None).await.records.is_empty());
}

async fn another_protocol_version_is_refused(backend: Backend) {
    let server = start(backend).await;
    let newer = server.http.get(server.url("/info")).header(PROTOCOL_HEADER, (PROTOCOL_VERSION + 1).to_string()).send().await.unwrap();
    let (status, error) = error_of(newer).await;
    assert_eq!((status, error.code), (StatusCode::BAD_REQUEST, ErrorCode::UnsupportedProtocol));

    let same = server.http.get(server.url("/info")).header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string()).send().await.unwrap();
    let info: ServerInfo = same.json().await.unwrap();
    assert_eq!(info.protocol_version, PROTOCOL_VERSION);
}

async fn the_instance_id_survives_a_restart(backend: Backend) {
    let server = start(backend).await;
    let first: ServerInfo = server.http.get(server.url("/info")).send().await.unwrap().json().await.unwrap();
    let restarted: Server = server.restarted().await;
    let second: ServerInfo = restarted.http.get(restarted.url("/info")).send().await.unwrap().json().await.unwrap();
    assert_eq!(first.instance_id, second.instance_id);
    assert!(!first.instance_id.is_empty());

    let other = start(backend).await;
    let third: ServerInfo = other.http.get(other.url("/info")).send().await.unwrap().json().await.unwrap();
    assert_ne!(first.instance_id, third.instance_id);
}

async fn info_text(server: &Server) -> String {
    server.http.get(server.url("/info")).send().await.unwrap().text().await.unwrap()
}

async fn role_of(server: &Server, account: &Account) -> Role {
    server.get("/account", &account.token).await.json::<AccountInfo>().await.unwrap().role
}

/// The first account, signed up with the code the server printed, which makes it the owner.
async fn owner_of(server: &Server) -> Account {
    let code = server.setup_code().expect("a fresh server has a setup code");
    server.sign_up_with("owner@example.com", &code).await
}

async fn the_setup_code_claims_an_unowned_server_once(backend: Backend) {
    let server = start(backend).await;
    assert!(info_text(&server).await.contains(r#""owned":false"#));
    let ada = server.sign_up("ada@example.com").await;
    let grace = server.sign_up("grace@example.com").await;
    assert_eq!(role_of(&server, &ada).await, Role::User);

    let wrong = server.post("/admin/claim", &ada.token, json!({ "code": "AAAA-BBBB-CCCC" })).await;
    assert_eq!(error_of(wrong).await.1.code, ErrorCode::Forbidden);
    let typed = server.setup_code().unwrap().replace('-', " ").to_lowercase();
    assert_eq!(server.post("/admin/claim", &ada.token, json!({ "code": typed })).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(role_of(&server, &ada).await, Role::Owner);

    assert!(!info_text(&server).await.contains("owned"));
    assert_eq!(server.setup_code(), None);
    let again = server.post("/admin/claim", &grace.token, json!({ "code": typed })).await;
    assert_eq!(error_of(again).await.1.code, ErrorCode::Forbidden);

    let restarted = server.restarted().await;
    assert_eq!(restarted.setup_code(), None);
    assert!(!info_text(&restarted).await.contains("owned"));
}

async fn a_closed_server_takes_its_first_account_with_the_setup_code(backend: Backend) {
    let server = start_with(backend, |config| config.signup = SignupMode::Closed).await;
    let code = server.setup_code().unwrap();
    let owner = server.sign_up_with("owner@example.com", &code.to_lowercase()).await;
    assert_eq!(role_of(&server, &owner).await, Role::Owner);
    let reused = server.try_sign_up("grace@example.com", Some(&code)).await;
    assert_eq!(error_of(reused).await.1.code, ErrorCode::InvalidInvite);
}

async fn wrong_setup_codes_are_limited(backend: Backend) {
    let server = start_with(backend, |config| config.rate.per_account = 3).await;
    let ada = server.sign_up("ada@example.com").await;
    for _ in 0..3 {
        let wrong = server.post("/admin/claim", &ada.token, json!({ "code": "AAAA-BBBB-CCCC" })).await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    }
    let right_but_late = server.post("/admin/claim", &ada.token, json!({ "code": server.setup_code().unwrap() })).await;
    assert_eq!(right_but_late.status(), StatusCode::TOO_MANY_REQUESTS);
}

async fn only_admins_reach_admin_calls_and_only_the_owner_hands_out_roles(backend: Backend) {
    let server = start(backend).await;
    let owner = owner_of(&server).await;
    let ada = server.sign_up("ada@example.com").await;
    let grace = server.sign_up("grace@example.com").await;

    for path in ["/admin/overview", "/admin/users", "/admin/settings", "/admin/invites", "/admin/log"] {
        assert_eq!(error_of(server.get(path, &ada.token).await).await.1.code, ErrorCode::Forbidden, "{path}");
    }
    assert_eq!(server.put(&format!("/admin/users/{}/role", ada.id), &owner.token, json!({ "role": "admin" })).await.status(), StatusCode::NO_CONTENT);
    let page: AdminUsersPage = server.get("/admin/users?search=GRACE", &ada.token).await.json().await.unwrap();
    assert_eq!(page.users.iter().map(|user| user.email.as_str()).collect::<Vec<_>>(), ["grace@example.com"]);

    let promote = server.put(&format!("/admin/users/{}/role", grace.id), &ada.token, json!({ "role": "admin" })).await;
    assert_eq!(error_of(promote).await.1.code, ErrorCode::Forbidden);
    let takeover = server.post("/admin/transfer", &ada.token, json!({ "to": ada.id, "authKey": harness::b64(&ada.auth_key) })).await;
    assert_eq!(error_of(takeover).await.1.code, ErrorCode::Forbidden);
    let make_owner = server.put(&format!("/admin/users/{}/role", grace.id), &owner.token, json!({ "role": "owner" })).await;
    assert_eq!(make_owner.status(), StatusCode::BAD_REQUEST);
    let delete_owner = server.delete_with(&format!("/admin/users/{}", owner.id), &ada.token, json!({ "authKey": harness::b64(&ada.auth_key) })).await;
    assert_eq!(error_of(delete_owner).await.1.code, ErrorCode::Forbidden);

    let handed = server.post("/admin/transfer", &owner.token, json!({ "to": grace.id, "authKey": harness::b64(&owner.auth_key) })).await;
    assert_eq!(handed.status(), StatusCode::NO_CONTENT);
    assert_eq!((role_of(&server, &grace).await, role_of(&server, &owner).await), (Role::Owner, Role::Admin));
}

async fn a_setting_changed_from_the_app_beats_the_servers_own_and_survives_a_restart(backend: Backend) {
    let server = start_with(backend, |config| config.signup = SignupMode::Closed).await;
    let owner = owner_of(&server).await;
    assert_eq!(error_of(server.try_sign_up("ada@example.com", None).await).await.1.code, ErrorCode::SignupClosed);

    let changed = server.put("/admin/settings", &owner.token, json!({ "signup": "open", "accountBytes": 10 * 1024 * 1024 })).await;
    let shown: ServerSettings = changed.json().await.unwrap();
    assert_eq!((shown.signup, shown.account_bytes), (SignupMode::Open, 10 * 1024 * 1024));
    assert_eq!(server.try_sign_up("ada@example.com", None).await.status(), StatusCode::CREATED);

    let restarted = server.restarted().await;
    let info: ServerInfo = serde_json::from_str(&info_text(&restarted).await).unwrap();
    assert_eq!((info.signup, info.limits.account_bytes), (SignupMode::Open, 10 * 1024 * 1024));
}

async fn a_lowered_limit_blocks_growth_but_not_deletes_and_an_own_limit_beats_it(backend: Backend) {
    let server = start_with(backend, |config| config.limits.record_bytes = 1024).await;
    let owner = owner_of(&server).await;
    let ada = server.sign_up("ada@example.com").await;
    let kilobyte = vec![1u8; 1000];
    server.push(&ada.token, vec![record(1, 0, &kilobyte), record(2, 0, &kilobyte), record(3, 0, &kilobyte)]).await;

    assert_eq!(server.put("/admin/settings", &owner.token, json!({ "accountBytes": 2048 })).await.status(), StatusCode::OK);
    assert_eq!(server.push(&ada.token, vec![record(4, 0, &kilobyte)]).await.results[0].status, PushStatus::QuotaExceeded);
    assert_eq!(server.pull(&ada.token, 0, None).await.records.len(), 3);
    let mut tombstone = record(1, 1, b"");
    tombstone.deleted = true;
    assert_eq!(server.push(&ada.token, vec![tombstone]).await.results[0].status, PushStatus::Accepted);

    assert_eq!(server.put(&format!("/admin/users/{}/quota", ada.id), &owner.token, json!({ "quotaBytes": 10_000 })).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.push(&ada.token, vec![record(4, 0, &kilobyte), record(5, 0, &kilobyte)]).await.results[1].status, PushStatus::Accepted);
    let info: AccountInfo = server.get("/account", &ada.token).await.json().await.unwrap();
    assert_eq!(info.quota_bytes, 10_000);
}

async fn the_server_total_stops_growth_for_everyone(backend: Backend) {
    let server = start_with(backend, |config| {
        config.limits.record_bytes = 1024;
        config.server_bytes = 2500;
    })
    .await;
    let ada = server.sign_up("ada@example.com").await;
    let grace = server.sign_up("grace@example.com").await;
    let kilobyte = vec![1u8; 1000];
    server.push(&ada.token, vec![record(1, 0, &kilobyte), record(2, 0, &kilobyte)]).await;
    assert_eq!(server.push(&grace.token, vec![record(1, 0, &kilobyte)]).await.results[0].status, PushStatus::QuotaExceeded);
    assert_eq!(server.push(&grace.token, vec![record(1, 0, &[1u8; 400])]).await.results[0].status, PushStatus::Accepted);
}

async fn an_invite_from_the_app_expires_and_shows_who_used_it(backend: Backend) {
    let server = start_with(backend, |config| config.signup = SignupMode::Invite).await;
    let owner = owner_of(&server).await;
    let fresh: CreatedInvite = server.post("/admin/invites", &owner.token, json!({ "expiresInDays": 7 })).await.json().await.unwrap();
    let stale: CreatedInvite = server.post("/admin/invites", &owner.token, json!({ "expiresInDays": 7 })).await.json().await.unwrap();
    server.execute(format!("UPDATE invites SET expires_at = {} WHERE code_hash = '{}'", fran_sync_server::db::now() - 1, stale.invite.id)).await;

    assert_eq!(error_of(server.try_sign_up("grace@example.com", Some(&stale.code)).await).await.1.code, ErrorCode::InvalidInvite);
    assert_eq!(server.try_sign_up("ada@example.com", Some(&fresh.code)).await.status(), StatusCode::CREATED);
    let listed: Vec<AdminInvite> = server.get("/admin/invites", &owner.token).await.json().await.unwrap();
    let used = listed.iter().find(|invite| invite.id == fresh.invite.id).unwrap();
    assert_eq!(used.used_by, "ada@example.com");
    assert!(listed.iter().all(|invite| !serde_json::to_string(invite).unwrap().contains(&fresh.code)));

    assert_eq!(server.delete(&format!("/admin/invites/{}", stale.invite.id), &owner.token).await.status(), StatusCode::NO_CONTENT);
}

async fn deleting_someone_needs_the_admins_password_and_the_log_keeps_no_secrets(backend: Backend) {
    let server = start(backend).await;
    let owner = owner_of(&server).await;
    let ada = server.sign_up("ada@example.com").await;
    server.push(&ada.token, vec![record(1, 0, b"ada's sealed data")]).await;
    let invite: CreatedInvite = server.post("/admin/invites", &owner.token, json!({ "email": "grace@example.com" })).await.json().await.unwrap();

    let wrong = server.delete_with(&format!("/admin/users/{}", ada.id), &owner.token, json!({ "authKey": harness::b64(&harness::key()) })).await;
    assert_eq!(error_of(wrong).await.1.code, ErrorCode::InvalidCredentials);
    assert_eq!(server.get("/account", &ada.token).await.status(), StatusCode::OK);

    let deleted = server.delete_with(&format!("/admin/users/{}", ada.id), &owner.token, json!({ "authKey": harness::b64(&owner.auth_key) })).await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.get("/account", &ada.token).await.status(), StatusCode::UNAUTHORIZED);
    assert!(server.column("SELECT id FROM records").await.is_empty());

    let log = server.get("/admin/log", &owner.token).await.text().await.unwrap();
    let entries: Vec<AdminLogEntry> = serde_json::from_str(&log).unwrap();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert_eq!(actions, ["deleteUser", "inviteCreate", "claim"]);
    for secret in [invite.code.as_str(), &harness::b64(&owner.auth_key), "ada's sealed data"] {
        assert!(!log.contains(secret), "the log holds {secret}");
    }
}

async fn both_migration_sets_make_the_same_tables(mysql: Backend) {
    let sqlite = start(Backend::Sqlite).await;
    let mysql = start(mysql).await;
    let sqlite_columns = sqlite
        .pairs("SELECT m.name AS table_name, p.name AS column_name FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type = 'table' ORDER BY m.name, p.cid")
        .await;
    let mysql_columns = mysql
        .pairs("SELECT table_name AS table_name, column_name AS column_name FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY table_name, ordinal_position")
        .await;
    assert!(sqlite_columns.iter().any(|(table, column)| table == "records" && column == "ciphertext"));
    assert_eq!(sqlite_columns, mysql_columns);
}
