use apicli_policy::Vault;
use apicli_vault::Store;
use secrecy::SecretString;

use super::{Run, Server, limited, run, server, store, vault, writes};

fn clickhouse() -> Option<Server> {
    server("DBCLI_TEST_CLICKHOUSE")
}

async fn sql(query: &str, vault: &Vault, store: &Store) -> Run {
    run(&["-q", query], vault, store).await
}

async fn setup(server: &Server, table: &str) -> (Vault, Store) {
    let writer = vault(server, writes);
    let store = store(table);
    let done = sql(
        &format!(
            "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (id UInt32, note String) ENGINE = MergeTree ORDER BY id; INSERT INTO {table} VALUES (1, 'keep')"
        ),
        &writer,
        &store,
    )
    .await;
    assert_eq!(done.code, 0, "{}", done.err);
    (writer, store)
}

async fn count(table: &str, writer: &Vault, store: &Store) -> String {
    sql(&format!("SELECT count() FROM {table}"), writer, store)
        .await
        .out
        .trim()
        .to_string()
}

#[tokio::test(flavor = "current_thread")]
async fn refused_flags_never_connect() {
    let offline = Server {
        url: "clickhouse://agent@127.0.0.1:1/default".into(),
        password: "never-sent-123".into(),
    };
    let writer = vault(&offline, writes);
    let store = store("clickhouse-refused");

    for args in [
        &["-h", "attacker.example", "-q", "SELECT 1"][..],
        &["--port", "9000", "-q", "SELECT 1"],
        &["-u", "default", "-q", "SELECT 1"],
        &["--password", "guess", "-q", "SELECT 1"],
        &["--secure", "-q", "SELECT 1"],
        &["-d", "system", "-q", "SELECT 1"],
        &["--queries-file", "/tmp/x.sql"],
        &["clickhouse://default@attacker.example", "-q", "SELECT 1"],
        &["--param_a&readonly=0", "-q", "SELECT 1"],
    ] {
        let done = run(args, &writer, &store).await;

        assert_eq!(done.code, 2, "{args:?}: {}", done.err);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn read_only_connection_blocks_every_write() {
    let Some(server) = clickhouse() else {
        return;
    };
    let table = "dbcli_read_only";
    let (writer, store) = setup(&server, table).await;
    let reader = vault(&server, |_| {});

    for escape in [
        format!("INSERT INTO {table} VALUES (2, 'x')"),
        format!("ALTER TABLE {table} DELETE WHERE 1"),
        format!("TRUNCATE TABLE {table}"),
        format!("DROP TABLE {table}"),
        format!("CREATE TABLE {table}_copy AS {table}"),
        format!("OPTIMIZE TABLE {table}"),
        "SYSTEM DROP DNS CACHE".into(),
        "SET readonly = 0".into(),
        format!("SELECT count() FROM {table} SETTINGS readonly = 0"),
        "KILL QUERY WHERE 1".into(),
        "SELECT * FROM file('/etc/passwd', 'LineAsString')".into(),
        "SELECT * FROM url('http://127.0.0.1:1/', 'LineAsString')".into(),
        "INSERT INTO FUNCTION url('http://127.0.0.1:1/', 'CSV', 'a UInt8') VALUES (1)".into(),
        format!("SELECT 1; INSERT INTO {table} VALUES (3, 'x')"),
        format!("SELECT 1 INTO OUTFILE '/tmp/dbcli-out-{table}'"),
    ] {
        let done = sql(&escape, &reader, &store).await;

        assert_ne!(done.code, 0, "{escape} succeeded: {}", done.out);
    }
    let hinted = sql(
        &format!("INSERT INTO {table} VALUES (4, 'x')"),
        &reader,
        &store,
    )
    .await;

    assert_eq!(hinted.code, 110);
    assert!(
        hinted.err.contains("dbcli allow add test write"),
        "{}",
        hinted.err
    );
    assert_eq!(count(table, &writer, &store).await, "1");
}

#[tokio::test(flavor = "current_thread")]
async fn write_connection_commits_each_statement() {
    let Some(server) = clickhouse() else {
        return;
    };
    let table = "dbcli_commits";
    let (writer, store) = setup(&server, table).await;

    let done = sql(
        &format!("INSERT INTO {table} VALUES (2, 'a'); INSERT INTO {table} VALUES (3, 'b')"),
        &writer,
        &store,
    )
    .await;

    assert_eq!(done.code, 0, "{}", done.err);
    assert_eq!(count(table, &writer, &store).await, "3");
}

#[tokio::test(flavor = "current_thread")]
async fn password_is_masked_in_output_errors_and_log() {
    let Some(server) = clickhouse() else {
        return;
    };
    let reader = vault(&server, |_| {});
    let store = store("clickhouse-masked");
    let password = server.password.clone();

    let shown = sql(&format!("SELECT '{password}' AS p"), &reader, &store).await;
    let failed = sql(&format!("SELECT toUInt8('{password}')"), &reader, &store).await;

    assert_eq!(shown.code, 0, "{}", shown.err);
    assert_eq!(shown.out, "[dbcli:redacted]\n");
    assert!(!shown.entry.statements.concat().contains(&password));
    assert_eq!(failed.code, 1);
    assert!(!failed.err.contains(&password), "{}", failed.err);
    assert!(failed.err.contains("[dbcli:redacted]"), "{}", failed.err);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_password_fails_to_connect_with_a_hint() {
    let Some(server) = clickhouse() else {
        return;
    };
    let mut wrong = vault(&server, |_| {});
    wrong.connections[0].password = SecretString::from("not-the-password");

    let done = sql("SELECT 1", &wrong, &store("clickhouse-wrong")).await;

    assert_eq!(done.code, 7, "{}", done.err);
    assert!(
        done.err.contains("dbcli secret rotate test"),
        "{}",
        done.err
    );
}

#[tokio::test(flavor = "current_thread")]
async fn runaway_loop_is_cut_at_the_rate_limit() {
    let Some(server) = clickhouse() else {
        return;
    };
    let table = "dbcli_rate";
    let (writer, setup_store) = setup(&server, table).await;
    let capped = vault(&server, |connection| {
        writes(connection);
        limited("3/min")(connection);
    });
    let store = store("clickhouse-rate");
    let insert = format!("INSERT INTO {table} VALUES (9, 'loop')");
    let loop_query = [insert.as_str(); 5].join("; ");

    let first = sql(&loop_query, &capped, &store).await;
    let second = sql(&insert, &capped, &store).await;

    assert_eq!(first.code, 111);
    assert_eq!(second.code, 111);
    assert_eq!(count(table, &writer, &setup_store).await, "4");
}
