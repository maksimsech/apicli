use apicli_policy::Vault;
use apicli_vault::Store;
use secrecy::SecretString;

use super::{Run, Server, allow, limited, run, server, store, vault};

const KEYSPACE: &str = "dbcli_test";

fn cassandra() -> Option<Server> {
    server("DBCLI_TEST_CASSANDRA")
}

async fn cql(cql: &str, vault: &Vault, store: &Store) -> Run {
    run(&["-e", cql], vault, store).await
}

async fn setup(server: &Server, table: &str) -> (Vault, Store) {
    let admin = vault(
        server,
        allow(&[
            ("CREATE", Some("*")),
            ("TRUNCATE", Some("*")),
            ("INSERT", Some("*")),
        ]),
    );
    let store = store(table);
    let done = cql(
        &format!(
            "CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}; CREATE TABLE IF NOT EXISTS {KEYSPACE}.{table} (id int PRIMARY KEY, note text); TRUNCATE {KEYSPACE}.{table}"
        ),
        &admin,
        &store,
    )
    .await;
    assert_eq!(done.code, 0, "{}", done.err);
    (admin, store)
}

async fn count(table: &str, vault: &Vault, store: &Store) -> usize {
    let done = cql(&format!("SELECT id FROM {KEYSPACE}.{table}"), vault, store).await;
    done.out
        .lines()
        .filter(|line| line.trim().parse::<i32>().is_ok())
        .count()
}

#[tokio::test(flavor = "current_thread")]
async fn refused_flags_and_cqlsh_commands_never_connect() {
    let offline = Server {
        url: "cassandra://agent@127.0.0.1:1".into(),
        password: "never-sent-123".into(),
    };
    let writer = vault(&offline, allow(&[("INSERT", Some("*")), ("SELEC", None)]));
    let store = store("cassandra-refused");

    for args in [
        &["-u", "cassandra", "-e", "SELECT * FROM system.local"][..],
        &["-p", "cassandra", "-e", "SELECT * FROM system.local"],
        &["--ssl", "-e", "SELECT * FROM system.local"],
        &["-f", "/tmp/script.cql"],
        &["10.0.0.9", "9042", "-e", "SELECT * FROM system.local"],
        &["-e", "COPY ks.t TO '/tmp/out.csv'"],
        &["-e", "SOURCE '/tmp/script.cql'"],
        &["-e", "CAPTURE '/tmp/out'"],
        &["-e", "LOGIN cassandra cassandra"],
        &["-e", "SELECT * FROM system.local; TRACING ON"],
    ] {
        let done = run(args, &writer, &store).await;

        assert_eq!(done.code, 2, "{args:?}: {}", done.err);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reads_run_and_writes_need_a_matching_rule() {
    let Some(server) = cassandra() else {
        return;
    };
    let table = "dbcli_rule";
    let (_, store) = setup(&server, table).await;
    let writer = vault(
        &server,
        allow(&[("INSERT", Some(&format!("{KEYSPACE}.dbcli_rule")))]),
    );
    let reader = vault(&server, |_| {});
    let insert = |id: i32| format!("INSERT INTO {KEYSPACE}.{table} (id) VALUES ({id})");

    let denied = cql(&insert(1), &reader, &store).await;
    let allowed = cql(&insert(2), &writer, &store).await;
    let quoted = cql(
        &format!("INSERT INTO \"{KEYSPACE}\".\"{table}\" (id) VALUES (3)"),
        &writer,
        &store,
    )
    .await;
    let elsewhere = cql(
        "INSERT INTO system_auth.roles (role) VALUES ('x')",
        &writer,
        &store,
    )
    .await;
    let switched = cql(
        &format!("USE system_auth; INSERT INTO {table} (id) VALUES (4)"),
        &writer,
        &store,
    )
    .await;
    let keyspace = run(
        &[
            "-k",
            "system_auth",
            "-e",
            &format!("INSERT INTO {table} (id) VALUES (5)"),
        ],
        &writer,
        &store,
    )
    .await;

    assert_eq!(denied.code, 110);
    assert!(
        denied.err.contains(&format!(
            "dbcli allow add test 'INSERT' '{KEYSPACE}.{table}'"
        )),
        "{}",
        denied.err
    );
    assert_eq!(allowed.code, 0, "{}", allowed.err);
    assert_eq!(quoted.code, 0, "{}", quoted.err);
    assert_eq!(elsewhere.code, 110);
    assert_eq!(switched.code, 110);
    assert_eq!(keyspace.code, 110);
    assert_eq!(count(table, &reader, &store).await, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn every_statement_in_a_batch_must_be_allowed() {
    let Some(server) = cassandra() else {
        return;
    };
    let table = "dbcli_batch";
    let (_, store) = setup(&server, table).await;
    let writer = vault(
        &server,
        allow(&[("INSERT", Some(&format!("{KEYSPACE}.{table}")))]),
    );

    let mixed = cql(
        &format!(
            "BEGIN BATCH INSERT INTO {KEYSPACE}.{table} (id) VALUES (1); DELETE FROM system_auth.roles WHERE role = 'x'; APPLY BATCH"
        ),
        &writer,
        &store,
    )
    .await;
    let unlogged = cql(
        &format!(
            "BEGIN UNLOGGED BATCH USING TIMESTAMP 1 INSERT INTO {KEYSPACE}.{table} (id) VALUES (2); INSERT INTO {KEYSPACE}.{table} (id) VALUES (3) APPLY BATCH"
        ),
        &writer,
        &store,
    )
    .await;

    assert_eq!(mixed.code, 110);
    assert_eq!(unlogged.code, 0, "{}", unlogged.err);
    assert_eq!(count(table, &writer, &store).await, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn a_denied_statement_stops_every_statement() {
    let Some(server) = cassandra() else {
        return;
    };
    let table = "dbcli_all";
    let (_, store) = setup(&server, table).await;
    let writer = vault(
        &server,
        allow(&[("INSERT", Some(&format!("{KEYSPACE}.{table}")))]),
    );

    let done = cql(
        &format!("INSERT INTO {KEYSPACE}.{table} (id) VALUES (1); TRUNCATE {KEYSPACE}.{table}"),
        &writer,
        &store,
    )
    .await;
    let unknown = cql(
        &format!(
            "BEGIN TRANSACTION INSERT INTO {KEYSPACE}.{table} (id) VALUES (2) COMMIT TRANSACTION"
        ),
        &writer,
        &store,
    )
    .await;

    assert_eq!(done.code, 110);
    assert_eq!(unknown.code, 110);
    assert_eq!(count(table, &writer, &store).await, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn password_is_masked_in_output_errors_and_log() {
    let Some(server) = cassandra() else {
        return;
    };
    let table = "dbcli_mask";
    let (admin, store) = setup(&server, table).await;
    let password = server.password.clone();

    let stored = cql(
        &format!("INSERT INTO {KEYSPACE}.{table} (id, note) VALUES (1, '{password}')"),
        &admin,
        &store,
    )
    .await;
    let shown = cql(
        &format!("SELECT note FROM {KEYSPACE}.{table}"),
        &admin,
        &store,
    )
    .await;
    let failed = cql(
        &format!("SELECT * FROM {KEYSPACE}.{table} WHERE id = '{password}'"),
        &admin,
        &store,
    )
    .await;

    assert_eq!(stored.code, 0, "{}", stored.err);
    assert!(!stored.entry.statements.concat().contains(&password));
    assert!(shown.out.contains("[dbcli:redacted]"), "{}", shown.out);
    assert!(!shown.out.contains(&password), "{}", shown.out);
    assert_eq!(failed.code, 1);
    assert!(!failed.err.contains(&password), "{}", failed.err);
    assert!(failed.err.contains("[dbcli:redacted]"), "{}", failed.err);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_password_fails_to_connect_with_a_hint() {
    let Some(server) = cassandra() else {
        return;
    };
    let mut wrong = vault(&server, |_| {});
    wrong.connections[0].password = SecretString::from("not-the-password");

    let done = cql(
        "SELECT * FROM system.local",
        &wrong,
        &store("cassandra-wrong"),
    )
    .await;

    assert_eq!(done.code, 7, "{}", done.err);
    assert!(
        done.err.contains("dbcli secret rotate test"),
        "{}",
        done.err
    );
}

#[tokio::test(flavor = "current_thread")]
async fn runaway_loop_is_cut_at_the_rate_limit() {
    let Some(server) = cassandra() else {
        return;
    };
    let table = "dbcli_rate";
    let (admin, setup_store) = setup(&server, table).await;
    let target = format!("{KEYSPACE}.{table}");
    let capped = vault(&server, |connection| {
        allow(&[("INSERT", Some(&target))])(connection);
        limited("3/min")(connection);
    });
    let store = store("cassandra-rate");
    let inserts = (1..=5)
        .map(|id| format!("INSERT INTO {target} (id) VALUES ({id})"))
        .collect::<Vec<_>>()
        .join("; ");

    let first = cql(&inserts, &capped, &store).await;
    let second = cql(
        &format!("INSERT INTO {target} (id) VALUES (9)"),
        &capped,
        &store,
    )
    .await;

    assert_eq!(first.code, 111);
    assert_eq!(second.code, 111);
    assert_eq!(count(table, &admin, &setup_store).await, 3);
}
