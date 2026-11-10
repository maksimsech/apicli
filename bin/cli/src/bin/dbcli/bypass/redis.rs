use apicli_policy::{Allow, Connection, ConnectionUrl};
use secrecy::SecretString;

use super::{Server, limited, run, server, store, vault};

fn redis() -> Option<Server> {
    server("DBCLI_TEST_REDIS")
}

fn allow(rules: &[(&str, Option<&str>)]) -> impl FnOnce(&mut Connection) {
    let rules = rules
        .iter()
        .map(|(action, target)| Allow {
            action: action.to_string(),
            target: target.map(String::from),
        })
        .collect::<Vec<_>>();
    move |connection| connection.allow = rules
}

#[tokio::test(flavor = "current_thread")]
async fn refused_flags_and_commands_never_connect() {
    let offline = Server {
        url: ConnectionUrl::parse("redis://127.0.0.1:1/0").unwrap(),
        password: "never-sent-123".into(),
    };
    let reader = vault(&offline, allow(&[("SET", Some("*"))]));
    let store = store("redis-refused");

    for args in [
        &["-h", "attacker.example", "GET", "k"][..],
        &["-a", "guess", "GET", "k"],
        &["-u", "redis://attacker.example", "GET", "k"],
        &["--tls", "GET", "k"],
        &["-r", "100", "SET", "k", "v"],
        &["--pipe"],
        &["--eval", "/tmp/script.lua"],
        &["MONITOR"],
        &["subscribe", "news"],
        &["MULTI"],
        &["AUTH", "admin", "guess"],
        &["HELLO", "3", "AUTH", "admin", "guess"],
        &["SYNC"],
    ] {
        let done = run(args, &reader, &store).await;

        assert_eq!(done.code, 2, "{args:?}: {}", done.err);
    }
    let interactive = run(&[], &reader, &store).await;
    assert_eq!(interactive.code, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn reads_run_and_writes_need_a_matching_rule() {
    let Some(server) = redis() else {
        return;
    };
    let writer = vault(&server, allow(&[("SET", Some("dbcli:rule:*"))]));
    let reader = vault(&server, |_| {});
    let store = store("redis-rule");

    let seeded = run(&["SET", "dbcli:rule:a", "one"], &writer, &store).await;
    let read = run(&["GET", "dbcli:rule:a"], &reader, &store).await;
    let denied = run(&["set", "dbcli:rule:a", "two"], &reader, &store).await;
    let outside = run(&["SET", "dbcli:other", "x"], &writer, &store).await;
    let after = run(&["GET", "dbcli:rule:a"], &reader, &store).await;

    assert_eq!(seeded.code, 0, "{}", seeded.err);
    assert_eq!(read.out, "one\n");
    assert_eq!(denied.code, 110);
    assert!(
        denied
            .err
            .contains("dbcli allow add test 'SET' 'dbcli:rule:a'"),
        "{}",
        denied.err
    );
    assert_eq!(outside.code, 110);
    assert_eq!(after.out, "one\n");
}

#[tokio::test(flavor = "current_thread")]
async fn every_key_must_match_the_rule() {
    let Some(server) = redis() else {
        return;
    };
    let writer = vault(&server, allow(&[("MSET", Some("dbcli:all:*"))]));
    let store = store("redis-all-keys");

    let mixed = run(
        &["MSET", "dbcli:all:1", "a", "dbcli:escape", "b"],
        &writer,
        &store,
    )
    .await;
    let inside = run(
        &["MSET", "dbcli:all:1", "a", "dbcli:all:2", "b"],
        &writer,
        &store,
    )
    .await;
    let escaped = run(&["GET", "dbcli:escape"], &writer, &store).await;

    assert_eq!(mixed.code, 110);
    assert_eq!(inside.code, 0, "{}", inside.err);
    assert_eq!(escaped.out, "\n");
}

#[tokio::test(flavor = "current_thread")]
async fn dangerous_and_scripting_reads_need_a_rule() {
    let Some(server) = redis() else {
        return;
    };
    let reader = vault(&server, |_| {});
    let store = store("redis-dangerous");

    for args in [
        &["KEYS", "*"][..],
        &["EVAL_RO", "return 1", "0"],
        &["FCALL_RO", "f", "0"],
        &["CONFIG", "GET", "requirepass"],
        &["CLIENT", "LIST"],
        &["DEBUG", "SLEEP", "0"],
        &["FLUSHALL"],
        &["NOSUCHCOMMAND", "x"],
    ] {
        let done = run(args, &reader, &store).await;

        assert_eq!(done.code, 110, "{args:?}: {}", done.err);
    }
    let ping = run(&["PING"], &reader, &store).await;
    assert_eq!(ping.out, "PONG\n");
}

#[tokio::test(flavor = "current_thread")]
async fn subcommand_rules_cover_only_their_subcommand() {
    let Some(server) = redis() else {
        return;
    };
    let narrow = vault(&server, allow(&[("CONFIG|GET", None)]));
    let wide = vault(&server, allow(&[("CONFIG", None)]));
    let store = store("redis-subcommand");

    let get = run(&["CONFIG", "GET", "maxmemory-samples"], &narrow, &store).await;
    let set = run(
        &["config", "set", "maxmemory-samples", "5"],
        &narrow,
        &store,
    )
    .await;
    let container = run(&["CONFIG", "SET", "maxmemory-samples", "5"], &wide, &store).await;

    assert_eq!(get.code, 0, "{}", get.err);
    assert_eq!(set.code, 110);
    assert_eq!(container.code, 0, "{}", container.err);
    assert_eq!(container.out, "OK\n");
}

#[tokio::test(flavor = "current_thread")]
async fn password_is_masked_in_output_errors_and_log() {
    let Some(server) = redis() else {
        return;
    };
    let password = server.password.clone();
    let writer = vault(
        &server,
        allow(&[("SET", Some("dbcli:mask")), ("NOSUCHCMD", None)]),
    );
    let store = store("redis-masked");

    let stored = run(&["SET", "dbcli:mask", &password], &writer, &store).await;
    let shown = run(&["GET", "dbcli:mask"], &writer, &store).await;
    let failed = run(&["-e", "NOSUCHCMD", &password], &writer, &store).await;

    assert_eq!(stored.code, 0, "{}", stored.err);
    assert!(!stored.entry.statements.concat().contains(&password));
    assert_eq!(shown.out, "[dbcli:redacted]\n");
    assert_eq!(failed.code, 1);
    assert!(!failed.err.contains(&password), "{}", failed.err);
    assert!(failed.err.contains("[dbcli:redacted]"), "{}", failed.err);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_password_fails_to_connect_with_a_hint() {
    let Some(server) = redis() else {
        return;
    };
    let mut wrong = vault(&server, |_| {});
    wrong.connections[0].password = SecretString::from("not-the-password");

    let done = run(&["PING"], &wrong, &store("redis-wrong")).await;

    assert_eq!(done.code, 7);
    assert!(
        done.err.contains("dbcli secret rotate test"),
        "{}",
        done.err
    );
}

#[tokio::test(flavor = "current_thread")]
async fn runaway_loop_is_cut_at_the_rate_limit() {
    let Some(server) = redis() else {
        return;
    };
    let capped = vault(&server, |connection| {
        allow(&[("INCR", Some("dbcli:rate"))])(connection);
        limited("3/min")(connection);
    });
    let writer = vault(&server, allow(&[("DEL", Some("dbcli:rate"))]));
    let bucket = store("redis-rate");
    run(&["DEL", "dbcli:rate"], &writer, &store("redis-rate-setup")).await;

    let mut codes = Vec::new();
    for _ in 0..5 {
        codes.push(run(&["INCR", "dbcli:rate"], &capped, &bucket).await.code);
    }
    let count = run(&["GET", "dbcli:rate"], &writer, &store("redis-rate-check")).await;

    assert_eq!(codes, [0, 0, 0, 111, 111]);
    assert_eq!(count.out, "3\n");
}
