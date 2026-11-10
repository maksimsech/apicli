use std::time::Duration;

use apicli::Failure;
use apicli_policy::Connection;
use mongodb::{
    Client,
    bson::{Bson, Document, doc},
    error::{Error, ErrorKind, WriteFailure},
    options::ClientOptions,
};
use secrecy::ExposeSecret;

use super::{
    args::parse as arguments,
    inspect::inspect,
    parse::parse,
    plan::{Bulked, Plan, Shape, Step, check, plan},
};
use crate::{
    call::{Context, summary},
    secret::rotate_hint,
};

const TIMEOUT: Duration = Duration::from_secs(10);
const BATCH: usize = 20;
const NOT_FOUND: i32 = 26;

enum Output {
    Value(Bson),
    Text(String, Bson),
    Cursor(Vec<Bson>, bool),
}

pub async fn run(
    connection: &Connection,
    args: &[String],
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    let args = arguments(args)?;
    context.statements(&args.eval);
    let plans = plans(connection, &args.eval)?;
    let rules = plans
        .iter()
        .flat_map(|plan| &plan.steps)
        .map(|step| check(connection, step).map(|verdict| verdict.rule))
        .collect::<Result<Vec<_>, _>>()?;
    context.entry.rule = Some(summary(rules));
    let client = connect(connection).await?;
    let mut last = None;
    for plan in plans {
        if !plan.steps.is_empty() {
            context.take(connection, args.common.wait)?;
        }
        last = Some(
            execute(&client, plan)
                .await
                .map_err(|error| error.into_failure(connection))?,
        );
    }
    if let Some(output) = last {
        context.print(render(output, args.json.as_deref()).as_bytes())?;
    }
    Ok(0)
}

pub fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    let args = arguments(args)?;
    let mut lines = Vec::new();
    for plan in plans(connection, &args.eval)? {
        if let Shape::Switched(name, _) = &plan.shape {
            lines.push(format!("use {name}"));
        }
        for step in &plan.steps {
            let verdict = check(connection, step)?;
            lines.push(match verdict.rule {
                Some(rule) => format!(
                    "{} on {}: allowed by {rule}",
                    verdict.action, verdict.namespace
                ),
                None => format!(
                    "{} on {}: a read, so it runs",
                    verdict.action, verdict.namespace
                ),
            });
        }
    }
    Ok(lines)
}

fn plans(connection: &Connection, evals: &[String]) -> Result<Vec<Plan>, Failure> {
    let mut db = connection.url.database.clone();
    let mut plans = Vec::new();
    for eval in evals {
        for statement in parse(eval)? {
            plans.push(plan(statement, &mut db)?);
        }
    }
    Ok(plans)
}

async fn connect(connection: &Connection) -> Result<Client, Failure> {
    let mut options = ClientOptions::parse(connection.url.to_string())
        .await
        .map_err(|error| Problem::Driver(error).into_failure(connection))?;
    options.app_name = Some("dbcli".into());
    options.server_selection_timeout = Some(TIMEOUT);
    options.connect_timeout = Some(TIMEOUT);
    let mut credential = options.credential.take().unwrap_or_default();
    credential.username = Some(connection.url.user.clone());
    credential.password = Some(connection.password.expose_secret().to_string());
    options.credential = Some(credential);
    Client::with_options(options).map_err(|error| Problem::Driver(error).into_failure(connection))
}

enum Problem {
    Driver(Error),
    Server(String),
}

impl From<Error> for Problem {
    fn from(error: Error) -> Problem {
        Problem::Driver(error)
    }
}

impl Problem {
    fn into_failure(self, connection: &Connection) -> Failure {
        let error = match self {
            Problem::Server(message) => {
                return Failure::Database(format!("MongoServerError: {message}"));
            }
            Problem::Driver(error) => error,
        };
        match *error.kind {
            ErrorKind::Authentication { message, .. } => {
                Failure::Connect(format!("{message}\n{}", rotate_hint(&connection.name)))
            }
            ErrorKind::Command(error) => {
                Failure::Database(format!("MongoServerError: {}", error.message))
            }
            ErrorKind::Write(WriteFailure::WriteError(error)) => {
                Failure::Database(format!("MongoServerError: {}", error.message))
            }
            ErrorKind::Write(WriteFailure::WriteConcernError(error)) => {
                Failure::Database(format!("MongoServerError: {}", error.message))
            }
            ErrorKind::ServerSelection { message, .. } => Failure::Connect(message),
            ErrorKind::DnsResolve { message, .. } => Failure::Dns(message),
            ErrorKind::Io(error) => Failure::Network(error.to_string()),
            ErrorKind::InvalidTlsConfig { message, .. } => Failure::Tls(message),
            ErrorKind::InvalidArgument { message, .. } => Failure::Usage(message),
            kind => Failure::Database(format!("{kind}")),
        }
    }
}

async fn execute(client: &Client, plan: Plan) -> Result<Output, Problem> {
    let mut steps = plan.steps.into_iter();
    let mut next = || {
        steps
            .next()
            .ok_or_else(|| Problem::Server("nothing to run".into()))
    };
    let output = match plan.shape {
        Shape::Switched(name, already) => {
            let text = if already {
                format!("already on db {name}")
            } else {
                format!("switched to db {name}")
            };
            Output::Value(Bson::String(text))
        }
        Shape::Name(name) => Output::Value(Bson::String(name)),
        Shape::Databases => {
            let reply = command(client, next()?).await?;
            let databases = reply.get_array("databases").cloned().unwrap_or_default();
            let rows = databases
                .iter()
                .filter_map(Bson::as_document)
                .map(|database| {
                    vec![
                        database.get_str("name").unwrap_or_default().to_string(),
                        size(database.get("sizeOnDisk").and_then(float).unwrap_or(0.0)),
                    ]
                })
                .collect::<Vec<_>>();
            Output::Text(table(&rows, &[false, true]), Bson::Array(databases))
        }
        Shape::Collections => {
            let (collections, _) = cursor(client, next()?, None).await?;
            let mut rows = collections
                .iter()
                .filter_map(Bson::as_document)
                .map(|collection| {
                    let name = collection.get_str("name").unwrap_or_default().to_string();
                    let badge = match collection.get_str("type").unwrap_or_default() {
                        "view" => "[view]",
                        "timeseries" => "[time-series]",
                        _ => "",
                    };
                    vec![name, badge.to_string()]
                })
                .collect::<Vec<_>>();
            rows.sort_by_key(|row| {
                (
                    row[0].starts_with("system.") || row[0].starts_with("enxcol_."),
                    row[0].to_lowercase(),
                    row[0].clone(),
                )
            });
            let names = rows
                .iter()
                .map(|row| Bson::String(row[0].clone()))
                .collect();
            Output::Text(table(&rows, &[false, false]), Bson::Array(names))
        }
        Shape::Names => {
            let (collections, _) = cursor(client, next()?, None).await?;
            Output::Value(Bson::Array(
                collections
                    .iter()
                    .filter_map(Bson::as_document)
                    .filter_map(|collection| collection.get("name").cloned())
                    .collect(),
            ))
        }
        Shape::Cursor(all) => {
            let (documents, more) = cursor(client, next()?, (!all).then_some(BATCH)).await?;
            Output::Cursor(documents, more)
        }
        Shape::First => {
            let reply = command(client, next()?).await?;
            Output::Value(batch(&reply).first().cloned().unwrap_or(Bson::Null))
        }
        Shape::Count => {
            let reply = command(client, next()?).await?;
            let count = batch(&reply)
                .first()
                .and_then(Bson::as_document)
                .and_then(|group| group.get("n"))
                .cloned()
                .map_or(Bson::Int32(0), number);
            Output::Value(count)
        }
        Shape::Number => {
            let reply = command(client, next()?).await?;
            Output::Value(reply.get("n").cloned().map_or(Bson::Int32(0), number))
        }
        Shape::Values => {
            let reply = command(client, next()?).await?;
            Output::Value(
                reply
                    .get("values")
                    .cloned()
                    .unwrap_or(Bson::Array(Vec::new())),
            )
        }
        Shape::Inserted(ids, many) => {
            written(command(client, next()?).await?)?;
            if many {
                let ids = ids
                    .into_iter()
                    .enumerate()
                    .map(|(index, id)| (index.to_string(), id))
                    .collect::<Document>();
                Output::Value(Bson::Document(
                    doc! {"acknowledged": true, "insertedIds": ids},
                ))
            } else {
                let id = ids.into_iter().next().unwrap_or(Bson::Null);
                Output::Value(Bson::Document(
                    doc! {"acknowledged": true, "insertedId": id},
                ))
            }
        }
        Shape::Updated => {
            let update = updated(&written(command(client, next()?).await?)?);
            counts(doc! {
                "acknowledged": true,
                "insertedId": update.id.unwrap_or(Bson::Null),
                "matchedCount": update.matched,
                "modifiedCount": update.modified,
                "upsertedCount": update.upserted,
            })
        }
        Shape::Deleted => {
            let reply = written(command(client, next()?).await?)?;
            counts(doc! {"acknowledged": true, "deletedCount": count(&reply, "n")})
        }
        Shape::Modified => {
            let reply = command(client, next()?).await?;
            Output::Value(reply.get("value").cloned().unwrap_or(Bson::Null))
        }
        Shape::Bulk(kinds) => {
            let (mut inserted, mut matched, mut modified, mut deleted, mut upserted) =
                (0, 0, 0, 0, 0);
            let mut inserted_ids = Document::new();
            let mut upserted_ids = Document::new();
            for kind in kinds {
                let reply = written(command(client, next()?).await?)?;
                match kind {
                    Bulked::Insert(index, id) => {
                        inserted += count(&reply, "n");
                        inserted_ids.insert(index.to_string(), id);
                    }
                    Bulked::Update(index) => {
                        let update = updated(&reply);
                        matched += update.matched;
                        modified += update.modified;
                        upserted += update.upserted;
                        if let Some(id) = update.id {
                            upserted_ids.insert(index.to_string(), id);
                        }
                    }
                    Bulked::Delete => deleted += count(&reply, "n"),
                }
            }
            counts(doc! {
                "acknowledged": true,
                "insertedCount": inserted,
                "insertedIds": inserted_ids,
                "matchedCount": matched,
                "modifiedCount": modified,
                "deletedCount": deleted,
                "upsertedCount": upserted,
                "upsertedIds": upserted_ids,
            })
        }
        Shape::Index(name) => {
            command(client, next()?).await?;
            Output::Value(Bson::String(name))
        }
        Shape::Dropped => match command(client, next()?).await {
            Ok(_) => Output::Value(Bson::Boolean(true)),
            Err(Problem::Driver(error)) if matches!(&*error.kind, ErrorKind::Command(error) if error.code == NOT_FOUND) => {
                Output::Value(Bson::Boolean(false))
            }
            Err(problem) => return Err(problem),
        },
        Shape::Reply => Output::Value(Bson::Document(command(client, next()?).await?)),
    };
    Ok(output)
}

struct Update {
    matched: i64,
    modified: i64,
    upserted: i64,
    id: Option<Bson>,
}

fn updated(reply: &Document) -> Update {
    let upserted = reply
        .get_array("upserted")
        .map(Vec::as_slice)
        .unwrap_or_default();
    Update {
        matched: count(reply, "n") - upserted.len() as i64,
        modified: count(reply, "nModified"),
        upserted: upserted.len() as i64,
        id: upserted
            .first()
            .and_then(Bson::as_document)
            .and_then(|upsert| upsert.get("_id"))
            .cloned(),
    }
}

fn counts(document: Document) -> Output {
    Output::Value(Bson::Document(
        document
            .into_iter()
            .map(|(key, value)| (key, number(value)))
            .collect(),
    ))
}

async fn command(client: &Client, step: Step) -> Result<Document, Problem> {
    Ok(client.database(&step.db).run_command(step.command).await?)
}

async fn cursor(
    client: &Client,
    step: Step,
    limit: Option<usize>,
) -> Result<(Vec<Bson>, bool), Problem> {
    let mut cursor = client
        .database(&step.db)
        .run_cursor_command(step.command)
        .await?;
    let mut documents = Vec::new();
    while cursor.advance().await? {
        if limit.is_some_and(|limit| documents.len() == limit) {
            return Ok((documents, true));
        }
        documents.push(Bson::Document(cursor.deserialize_current()?));
    }
    Ok((documents, false))
}

fn written(reply: Document) -> Result<Document, Problem> {
    let message = reply
        .get_array("writeErrors")
        .ok()
        .and_then(|errors| errors.first())
        .and_then(Bson::as_document)
        .or_else(|| reply.get_document("writeConcernError").ok())
        .map(|error| error.get_str("errmsg").unwrap_or_default().to_string());
    match message {
        Some(message) => Err(Problem::Server(message)),
        None => Ok(reply),
    }
}

fn batch(reply: &Document) -> Vec<Bson> {
    reply
        .get_document("cursor")
        .and_then(|cursor| cursor.get_array("firstBatch"))
        .cloned()
        .unwrap_or_default()
}

fn count(reply: &Document, key: &str) -> i64 {
    match reply.get(key) {
        Some(Bson::Int32(value)) => i64::from(*value),
        Some(Bson::Int64(value)) => *value,
        Some(Bson::Double(value)) => *value as i64,
        _ => 0,
    }
}

fn number(value: Bson) -> Bson {
    match value {
        Bson::Int64(value) => i32::try_from(value).map_or(Bson::Double(value as f64), Bson::Int32),
        other => other,
    }
}

fn float(value: &Bson) -> Option<f64> {
    match value {
        Bson::Int32(value) => Some(f64::from(*value)),
        Bson::Int64(value) => Some(*value as f64),
        Bson::Double(value) => Some(*value),
        _ => None,
    }
}

fn size(bytes: f64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
    let mut power = 0;
    while power + 1 < units.len() && bytes >= 1024f64.powi(power as i32 + 1) {
        power += 1;
    }
    let value = (bytes / 1024f64.powi(power as i32) * 100.0 + 0.5).floor() / 100.0;
    format!("{value:.2} {}", units[power])
}

fn table(rows: &[Vec<String>], right: &[bool]) -> String {
    let columns = right.len();
    let widths = (0..columns)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    rows.iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(column, cell)| {
                    let fill = " ".repeat(widths[column] - cell.chars().count());
                    if right[column] {
                        format!("{fill}{cell}")
                    } else {
                        format!("{cell}{fill}")
                    }
                })
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render(output: Output, json: Option<&str>) -> String {
    if let Some(format) = json {
        let value = match output {
            Output::Value(value) | Output::Text(_, value) => value,
            Output::Cursor(documents, _) => Bson::Array(documents),
        };
        let value = if format == "relaxed" {
            value.into_relaxed_extjson()
        } else {
            value.into_canonical_extjson()
        };
        return serde_json::to_string_pretty(&value).unwrap_or_default() + "\n";
    }
    match output {
        Output::Value(Bson::String(text)) | Output::Text(text, _) => text + "\n",
        Output::Value(value) => inspect(&value) + "\n",
        Output::Cursor(documents, _) if documents.is_empty() => "\n".into(),
        Output::Cursor(documents, more) => {
            let mut text = inspect(&Bson::Array(documents)) + "\n";
            if more {
                text.push_str("Type \"it\" for more\n");
            }
            text
        }
    }
}
