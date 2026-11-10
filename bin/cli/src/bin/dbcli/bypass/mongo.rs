use apicli_policy::Vault;
use apicli_vault::Store;
use secrecy::SecretString;

use super::{Run, Server, allow, limited, run, server, store, vault};

fn mongo() -> Option<Server> {
    server("DBCLI_TEST_MONGO")
}

fn eval(expressions: &[&str]) -> Vec<String> {
    expressions
        .iter()
        .flat_map(|expression| ["--eval".to_string(), expression.to_string()])
        .collect()
}

async fn evaluate(expressions: &[&str], vault: &Vault, store: &Store) -> Run {
    let args = eval(expressions);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    run(&args, vault, store).await
}

#[tokio::test(flavor = "current_thread")]
async fn javascript_and_refused_flags_never_connect() {
    let offline = Server {
        url: "mongodb://agent@127.0.0.1:1/shop".into(),
        password: "never-sent-123".into(),
    };
    let writer = vault(
        &offline,
        allow(&[("insert", Some("*")), ("delete", Some("*"))]),
    );
    let store = store("mongo-refused");

    for args in [
        &[
            "--eval",
            "db.orders.find().forEach(d => db.orders.deleteOne(d))",
        ][..],
        &["--eval", "let n = 0"],
        &["--eval", "require('child_process').execSync('id')"],
        &["--eval", "load('/tmp/x.js')"],
        &[
            "--eval",
            "db.orders.find({$where: function() { return true }})",
        ],
        &["--host", "attacker.example", "--eval", "db.orders.find()"],
        &["-u", "root", "--eval", "db.orders.find()"],
        &[
            "--tlsAllowInvalidCertificates",
            "--eval",
            "db.orders.find()",
        ],
        &[
            "mongodb://agent@attacker.example/shop",
            "--eval",
            "db.orders.find()",
        ],
        &["-f", "/tmp/x.js"],
        &[
            "--eval",
            "db.runCommand({insert: 'orders', documents: [{}], $db: 'admin'})",
        ],
    ] {
        let done = run(args, &writer, &store).await;

        assert_eq!(done.code, 2, "{args:?}: {}", done.err);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reads_run_and_writes_need_a_matching_rule() {
    let Some(server) = mongo() else {
        return;
    };
    let db = server.database();
    let writer = vault(
        &server,
        allow(&[
            ("insert", Some(&format!("{db}.dbcli_rule*"))),
            ("drop", Some("*")),
        ]),
    );
    let reader = vault(&server, |_| {});
    let store = store("mongo-rule");
    evaluate(&["db.dbcli_rule.drop()"], &writer, &store).await;

    let denied = evaluate(&["db.dbcli_rule.insertOne({_id: 1})"], &reader, &store).await;
    let allowed = evaluate(&["db.dbcli_rule.insertOne({_id: 1})"], &writer, &store).await;
    let elsewhere = evaluate(
        &["db.getSiblingDB('admin').dbcli_rule.insertOne({_id: 1})"],
        &writer,
        &store,
    )
    .await;
    let switched = evaluate(
        &["use admin", "db.dbcli_rule.insertOne({_id: 1})"],
        &writer,
        &store,
    )
    .await;
    let read = evaluate(&["db.dbcli_rule.find()"], &reader, &store).await;

    assert_eq!(denied.code, 110);
    assert!(
        denied
            .err
            .contains(&format!("dbcli allow add test 'insert' '{db}.dbcli_rule'")),
        "{}",
        denied.err
    );
    assert_eq!(allowed.code, 0, "{}", allowed.err);
    assert_eq!(elsewhere.code, 110);
    assert_eq!(switched.code, 110);
    assert_eq!(read.out, "[ { _id: 1 } ]\n");
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_out_and_run_command_writes_are_denied() {
    let Some(server) = mongo() else {
        return;
    };
    let reader = vault(&server, |_| {});
    let store = store("mongo-commands");

    for expression in [
        "db.dbcli_source.aggregate([{$match: {}}, {$out: 'dbcli_copy'}])",
        "db.dbcli_source.aggregate([{$facet: {a: [{$merge: {into: 'dbcli_copy'}}]}}])",
        "db.aggregate([{$documents: [{a: 1}]}, {$out: 'dbcli_copy'}])",
        "db.runCommand({insert: 'dbcli_copy', documents: [{a: 1}]})",
        "db.runCommand({explain: {delete: 'dbcli_copy', deletes: [{q: {}, limit: 0}]}, verbosity: 'executionStats'})",
        "db.adminCommand({dropDatabase: 1})",
        "db.runCommand({mapReduce: 'dbcli_source', map: 'function() {}', reduce: 'function() {}', out: 'dbcli_copy'})",
        "db.dbcli_copy.createIndex({a: 1})",
        "db.dbcli_copy.drop()",
    ] {
        let done = evaluate(&[expression], &reader, &store).await;

        assert_eq!(done.code, 110, "{expression}: {}", done.err);
    }
    let copy = evaluate(&["db.dbcli_copy.countDocuments()"], &reader, &store).await;
    assert_eq!(copy.out, "0\n");
}

#[tokio::test(flavor = "current_thread")]
async fn a_denied_expression_stops_every_expression() {
    let Some(server) = mongo() else {
        return;
    };
    let db = server.database();
    let writer = vault(
        &server,
        allow(&[
            ("insert", Some(&format!("{db}.dbcli_all"))),
            ("drop", Some("*")),
        ]),
    );
    let store = store("mongo-all");
    evaluate(&["db.dbcli_all.drop()"], &writer, &store).await;

    let done = evaluate(
        &[
            "db.dbcli_all.insertOne({_id: 1})",
            "db.dbcli_all.deleteMany({})",
        ],
        &writer,
        &store,
    )
    .await;
    let count = evaluate(&["db.dbcli_all.countDocuments()"], &writer, &store).await;

    assert_eq!(done.code, 110);
    assert_eq!(count.out, "0\n");
}

#[tokio::test(flavor = "current_thread")]
async fn password_is_masked_in_output_errors_and_log() {
    let Some(server) = mongo() else {
        return;
    };
    let db = server.database();
    let password = server.password.clone();
    let writer = vault(
        &server,
        allow(&[
            ("insert", Some(&format!("{db}.dbcli_mask"))),
            ("drop", Some("*")),
        ]),
    );
    let store = store("mongo-masked");
    evaluate(&["db.dbcli_mask.drop()"], &writer, &store).await;
    let insert = format!("db.dbcli_mask.insertOne({{_id: '{password}'}})");

    let stored = evaluate(&[&insert], &writer, &store).await;
    let shown = evaluate(&["db.dbcli_mask.findOne()"], &writer, &store).await;
    let failed = evaluate(&[&insert], &writer, &store).await;

    assert_eq!(stored.code, 0, "{}", stored.err);
    assert!(!stored.out.contains(&password), "{}", stored.out);
    assert!(!stored.entry.statements.concat().contains(&password));
    assert_eq!(shown.out, "{ _id: '[dbcli:redacted]' }\n");
    assert_eq!(failed.code, 1);
    assert!(!failed.err.contains(&password), "{}", failed.err);
    assert!(failed.err.contains("[dbcli:redacted]"), "{}", failed.err);
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_password_fails_to_connect_with_a_hint() {
    let Some(server) = mongo() else {
        return;
    };
    let mut wrong = vault(&server, |_| {});
    wrong.connections[0].password = SecretString::from("not-the-password");

    let done = evaluate(&["db.runCommand({ping: 1})"], &wrong, &store("mongo-wrong")).await;

    assert_eq!(done.code, 7, "{}", done.err);
    assert!(
        done.err.contains("dbcli secret rotate test"),
        "{}",
        done.err
    );
}

#[tokio::test(flavor = "current_thread")]
async fn runaway_loop_is_cut_at_the_rate_limit() {
    let Some(server) = mongo() else {
        return;
    };
    let db = server.database();
    let rules = [("insert", format!("{db}.dbcli_rate")), ("drop", "*".into())];
    let rules = rules
        .iter()
        .map(|(action, target)| (*action, Some(target.as_str())))
        .collect::<Vec<_>>();
    let capped = vault(&server, |connection| {
        allow(&rules)(connection);
        limited("3/min")(connection);
    });
    let writer = vault(&server, allow(&rules));
    evaluate(
        &["db.dbcli_rate.drop()"],
        &writer,
        &store("mongo-rate-setup"),
    )
    .await;
    let bucket = store("mongo-rate");
    let insert = "db.dbcli_rate.insertOne({})";

    let first = evaluate(&[insert, insert, insert, insert, insert], &capped, &bucket).await;
    let second = evaluate(&[insert], &capped, &bucket).await;
    let count = evaluate(
        &["db.dbcli_rate.countDocuments()"],
        &writer,
        &store("mongo-rate-check"),
    )
    .await;

    assert_eq!(first.code, 111);
    assert_eq!(second.code, 111);
    assert_eq!(count.out, "3\n");
}
