use std::{env, fs, process};

use apicli::Entry;
use apicli_policy::{Connection, ConnectionUrl, Rate, Vault};
use apicli_vault::Store;
use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use url::Url;

use crate::{call::perform, cli::parse};

struct Server {
    url: ConnectionUrl,
    password: String,
}

struct Run {
    code: u8,
    out: String,
    err: String,
    entry: Entry,
}

fn server() -> Option<Server> {
    let mut url = Url::parse(&env::var("DBCLI_TEST_POSTGRES").ok()?).unwrap();
    let password = percent_decode_str(url.password()?)
        .decode_utf8_lossy()
        .into_owned();
    url.set_password(None).unwrap();
    Some(Server {
        url: ConnectionUrl::parse(url.as_str()).unwrap(),
        password,
    })
}

fn vault(server: &Server, write: bool, rate: Option<&str>) -> Vault {
    Vault {
        connections: vec![Connection {
            name: "test".into(),
            url: server.url.clone(),
            password: SecretString::from(server.password.clone()),
            write,
            rate: rate.map(|rate| Rate::parse(rate).unwrap()),
            burst: None,
            daily: None,
        }],
        ..Vault::default()
    }
}

fn store(name: &str) -> Store {
    let dir = env::temp_dir().join(format!("dbcli-bypass-{}-{name}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    Store::at(dir)
}

async fn run(args: &[&str], vault: &Vault, store: &Store) -> Run {
    let cli = parse(
        ["dbcli", "test"]
            .iter()
            .chain(args)
            .map(|arg| arg.to_string())
            .collect(),
    )
    .unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut entry = Entry::default();
    let result = perform(&cli.run, store, vault, &mut out, &mut err, &mut entry).await;
    let mut err = String::from_utf8_lossy(&err).into_owned();
    let code = match result {
        Ok(code) => code,
        Err(failure) => {
            err.push_str(&failure.to_string());
            failure.code()
        }
    };
    Run {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err,
        entry,
    }
}

async fn setup(server: &Server, table: &str) -> (Vault, Store) {
    let writer = vault(server, true, None);
    let store = store(table);
    let done = run(
        &[
            "-c",
            &format!("DROP TABLE IF EXISTS {table} CASCADE"),
            "-c",
            &format!("CREATE TABLE {table} (id serial PRIMARY KEY, note text)"),
            "-c",
            &format!("INSERT INTO {table} (note) VALUES ('keep')"),
            "-c",
            &format!(
                "CREATE OR REPLACE FUNCTION {table}_wipe() RETURNS void LANGUAGE plpgsql AS $$ BEGIN DELETE FROM {table}; END $$"
            ),
        ],
        &writer,
        &store,
    )
    .await;
    assert_eq!(done.code, 0, "{}", done.err);
    (writer, store)
}

async fn count(table: &str, writer: &Vault, store: &Store) -> String {
    let done = run(
        &["-At", "-c", &format!("SELECT count(*) FROM {table}")],
        writer,
        store,
    )
    .await;
    done.out.trim().to_string()
}

#[tokio::test(flavor = "current_thread")]
async fn unconfigured_connection_is_refused() {
    let done = run(
        &["-c", "select 1"],
        &Vault::default(),
        &store("unconfigured"),
    )
    .await;

    assert_eq!(done.code, 112);
}

#[tokio::test(flavor = "current_thread")]
async fn read_only_connection_blocks_every_write() {
    let Some(server) = server() else {
        return;
    };
    let table = "dbcli_read_only";
    let (writer, store) = setup(&server, table).await;
    let reader = vault(&server, false, None);
    let escapes: Vec<Vec<String>> = [
        vec!["INSERT INTO {t} (note) VALUES ('x')"],
        vec!["DELETE FROM {t}"],
        vec!["TRUNCATE {t}"],
        vec!["WITH gone AS (DELETE FROM {t} RETURNING *) SELECT count(*) FROM gone"],
        vec!["DO $$ BEGIN DELETE FROM {t}; END $$"],
        vec!["SELECT {t}_wipe()"],
        vec!["SELECT nextval('{t}_id_seq')"],
        vec!["CREATE TABLE {t}_copy AS SELECT * FROM {t}"],
        vec!["COPY {t} FROM STDIN"],
        vec!["SET TRANSACTION READ WRITE; DELETE FROM {t}"],
        vec!["COMMIT; DELETE FROM {t}"],
        vec!["SET TRANSACTION READ WRITE", "DELETE FROM {t}"],
        vec!["COMMIT", "DELETE FROM {t}"],
        vec!["ROLLBACK", "DELETE FROM {t}"],
        vec![
            "COMMIT AND CHAIN",
            "SET TRANSACTION READ WRITE",
            "DELETE FROM {t}",
        ],
        vec![
            "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
            "COMMIT",
            "DELETE FROM {t}",
        ],
        vec![
            "SELECT set_config('default_transaction_read_only', 'off', false)",
            "DELETE FROM {t}",
        ],
        vec!["SET default_transaction_read_only = off", "DELETE FROM {t}"],
    ]
    .into_iter()
    .map(|statements| {
        statements
            .into_iter()
            .flat_map(|statement| ["-c".to_string(), statement.replace("{t}", table)])
            .collect()
    })
    .collect();

    for escape in &escapes {
        let args = escape.iter().map(String::as_str).collect::<Vec<_>>();
        let done = run(&args, &reader, &store).await;

        assert_ne!(done.code, 0, "{escape:?} succeeded: {}", done.out);
    }
    assert_eq!(count(table, &writer, &store).await, "1");
    let sequence = run(
        &[
            "-At",
            "-c",
            &format!("SELECT last_value FROM {table}_id_seq"),
        ],
        &writer,
        &store,
    )
    .await;
    assert_eq!(sequence.out.trim(), "1");
}

#[tokio::test(flavor = "current_thread")]
async fn writes_on_a_read_only_connection_are_denied_with_a_hint() {
    let Some(server) = server() else {
        return;
    };
    let table = "dbcli_denied";
    let (_, store) = setup(&server, table).await;

    let done = run(
        &["-c", &format!("UPDATE {table} SET note = 'x'")],
        &vault(&server, false, None),
        &store,
    )
    .await;

    assert_eq!(done.code, 110);
    assert!(
        done.err.contains("dbcli allow add test write"),
        "{}",
        done.err
    );
}

#[tokio::test(flavor = "current_thread")]
async fn one_command_runs_one_statement() {
    let Some(server) = server() else {
        return;
    };
    let table = "dbcli_one_statement";
    let (writer, store) = setup(&server, table).await;

    let done = run(
        &[
            "-c",
            &format!(
                "INSERT INTO {table} (note) VALUES ('a'); INSERT INTO {table} (note) VALUES ('b')"
            ),
        ],
        &writer,
        &store,
    )
    .await;

    assert_eq!(done.code, 1);
    assert_eq!(count(table, &writer, &store).await, "1");
}

#[tokio::test(flavor = "current_thread")]
async fn write_connection_commits_each_statement() {
    let Some(server) = server() else {
        return;
    };
    let table = "dbcli_commits";
    let (writer, store) = setup(&server, table).await;

    let done = run(
        &["-c", &format!("INSERT INTO {table} (note) VALUES ('new')")],
        &writer,
        &store,
    )
    .await;

    assert_eq!(done.code, 0, "{}", done.err);
    assert_eq!(done.out, "INSERT 0 1\n");
    assert_eq!(count(table, &writer, &store).await, "2");
}

#[tokio::test(flavor = "current_thread")]
async fn password_is_masked_in_output_errors_and_log() {
    let Some(server) = server() else {
        return;
    };
    let reader = vault(&server, false, None);
    let store = store("masked");
    let password = server.password.as_str();

    let shown = run(
        &["-c", &format!("SELECT '{password}' AS p")],
        &reader,
        &store,
    )
    .await;
    let failed = run(
        &["-c", &format!("SELECT '{password}'::int")],
        &reader,
        &store,
    )
    .await;

    assert_eq!(shown.code, 0, "{}", shown.err);
    assert!(!shown.out.contains(password), "{}", shown.out);
    assert!(shown.out.contains("[dbcli:redacted]"), "{}", shown.out);
    assert_eq!(failed.code, 1);
    assert!(!failed.err.contains(password), "{}", failed.err);
    assert!(failed.err.contains("[dbcli:redacted]"), "{}", failed.err);
    assert!(!failed.entry.statements.concat().contains(password));
}

#[tokio::test(flavor = "current_thread")]
async fn runaway_loop_is_cut_at_the_rate_limit() {
    let Some(server) = server() else {
        return;
    };
    let table = "dbcli_rate";
    let (writer, setup_store) = setup(&server, table).await;
    let limited = vault(&server, true, Some("3/min"));
    let store = store("rate");
    let insert = format!("INSERT INTO {table} (note) VALUES ('loop')");
    let args = [
        "-c", &insert, "-c", &insert, "-c", &insert, "-c", &insert, "-c", &insert,
    ];

    let first = run(&args, &limited, &store).await;
    let second = run(&["-c", &insert], &limited, &store).await;

    assert_eq!(first.code, 111);
    assert_eq!(second.code, 111);
    assert_eq!(count(table, &writer, &setup_store).await, "4");
}
