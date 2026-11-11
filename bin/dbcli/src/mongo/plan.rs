use std::mem::take;

use fieldkit_common::Failure;
use mongodb::bson::{Bson, Document, doc, oid::ObjectId};

use super::{
    inspect::js_number,
    parse::{Segment, Statement},
    rules::find,
};
use crate::shared::{Connection, not_allowed};

const READS: [&str; 9] = [
    "find",
    "count",
    "distinct",
    "listCollections",
    "listIndexes",
    "listDatabases",
    "dbStats",
    "collStats",
    "ping",
];
const FIND: [&str; 15] = [
    "sort",
    "limit",
    "skip",
    "projection",
    "hint",
    "maxTimeMS",
    "collation",
    "batchSize",
    "comment",
    "allowDiskUse",
    "let",
    "min",
    "max",
    "returnKey",
    "showRecordId",
];
const AGGREGATE: [&str; 7] = [
    "allowDiskUse",
    "maxTimeMS",
    "collation",
    "hint",
    "comment",
    "let",
    "bypassDocumentValidation",
];
const WRITE: [&str; 4] = ["writeConcern", "bypassDocumentValidation", "comment", "let"];
const STATEMENT: [&str; 4] = ["upsert", "arrayFilters", "hint", "collation"];

pub struct Step {
    pub db: String,
    pub command: Document,
}

pub enum Bulked {
    Insert(usize, Bson),
    Update(usize),
    Delete,
}

pub enum Shape {
    Switched(String, bool),
    Name(String),
    Databases,
    Collections,
    Names,
    Cursor(bool),
    First,
    Count,
    Number,
    Values,
    Inserted(Vec<Bson>, bool),
    Updated,
    Deleted,
    Modified,
    Bulk(Vec<Bulked>),
    Index(String),
    Dropped,
    Reply,
}

pub struct Plan {
    pub steps: Vec<Step>,
    pub shape: Shape,
}

pub struct Verdict {
    pub action: String,
    pub namespace: String,
    pub rule: Option<String>,
}

pub fn plan(statement: Statement, db: &mut String) -> Result<Plan, Failure> {
    match statement {
        Statement::Use(name) => {
            if name.contains(['/', '\\', '.', '"', '$', '\0']) {
                return Err(Failure::Usage(format!(
                    "{name} is not a valid database name"
                )));
            }
            let already = *db == name;
            db.clone_from(&name);
            Ok(Plan {
                steps: Vec::new(),
                shape: Shape::Switched(name, already),
            })
        }
        Statement::Show(what) => match what.as_str() {
            "dbs" | "databases" => Ok(single("admin", doc! {"listDatabases": 1}, Shape::Databases)),
            "collections" | "tables" => Ok(single(
                db,
                doc! {"listCollections": 1, "nameOnly": true, "authorizedCollections": true},
                Shape::Collections,
            )),
            _ => Err(Failure::Usage(format!(
                "show {what} is not supported, use show dbs or show collections"
            ))),
        },
        Statement::Db(segments) => chain(segments, db),
    }
}

fn chain(segments: Vec<Segment>, current: &str) -> Result<Plan, Failure> {
    let mut db = current.to_string();
    let mut collection: Option<String> = None;
    let mut segments = segments.into_iter();
    let plan = loop {
        match segments.next() {
            None => {
                return Err(Failure::Usage(
                    "call a method, like db.orders.find() or db.getName()".into(),
                ));
            }
            Some(Segment::Property(name)) => {
                collection = Some(match collection {
                    Some(collection) => format!("{collection}.{name}"),
                    None => name,
                });
            }
            Some(Segment::Call(name, args)) => match (&collection, name.as_str()) {
                (None, "getSiblingDB") => db = text(&args, 0, &name)?,
                (None, "getCollection") => collection = Some(text(&args, 0, &name)?),
                (None, "getName") => {
                    break Plan {
                        steps: Vec::new(),
                        shape: Shape::Name(db.clone()),
                    };
                }
                (None, "getCollectionNames") => {
                    break single(
                        &db,
                        doc! {"listCollections": 1, "nameOnly": true, "authorizedCollections": true},
                        Shape::Names,
                    );
                }
                (None, "stats") => break single(&db, doc! {"dbStats": 1}, Shape::Reply),
                (None, "runCommand") => {
                    break single(&db, command(&args, &name)?, Shape::Reply);
                }
                (None, "adminCommand") => {
                    break single("admin", command(&args, &name)?, Shape::Reply);
                }
                (None, "aggregate") => {
                    let mut command = doc! {"aggregate": 1};
                    command.extend(aggregate(&args, &name)?);
                    break single(&db, command, Shape::Cursor(false));
                }
                (None, _) => {
                    return Err(Failure::Usage(format!(
                        "db.{name}() is not supported, dbcli supports getName, getCollectionNames, getSiblingDB, getCollection, stats, runCommand, adminCommand and aggregate"
                    )));
                }
                (Some(collection), _) => break method(&db, collection, &name, args)?,
            },
        }
    };
    modify(plan, segments.collect())
}

fn method(db: &str, collection: &str, name: &str, args: Vec<Bson>) -> Result<Plan, Failure> {
    let option = |index: usize| optional(&args, index, name);
    let plan = match name {
        "find" => {
            let mut command = doc! {"find": collection, "filter": option(0)?.unwrap_or_default()};
            if let Some(projection) = option(1)? {
                command.insert("projection", projection);
            }
            copy(&mut command, option(2)?, &FIND, name)?;
            single(db, command, Shape::Cursor(false))
        }
        "findOne" => {
            let mut command = doc! {"find": collection, "filter": option(0)?.unwrap_or_default()};
            if let Some(projection) = option(1)? {
                command.insert("projection", projection);
            }
            copy(&mut command, option(2)?, &FIND, name)?;
            command.insert("limit", 1);
            command.insert("singleBatch", true);
            single(db, command, Shape::First)
        }
        "aggregate" => {
            let mut command = doc! {"aggregate": collection};
            command.extend(aggregate(&args, name)?);
            single(db, command, Shape::Cursor(false))
        }
        "countDocuments" => {
            let options = option(1)?.unwrap_or_default();
            let mut pipeline = vec![Bson::Document(
                doc! {"$match": option(0)?.unwrap_or_default()},
            )];
            for stage in ["skip", "limit"] {
                if let Some(value) = options.get(stage) {
                    let mut step = Document::new();
                    step.insert(format!("${stage}"), value.clone());
                    pipeline.push(Bson::Document(step));
                }
            }
            pipeline.push(Bson::Document(
                doc! {"$group": {"_id": 1, "n": {"$sum": 1}}},
            ));
            let mut command = doc! {"aggregate": collection, "pipeline": pipeline, "cursor": {}};
            let rest = options
                .into_iter()
                .filter(|(key, _)| key != "skip" && key != "limit")
                .collect::<Document>();
            copy(
                &mut command,
                Some(rest),
                &["hint", "maxTimeMS", "collation", "comment"],
                name,
            )?;
            single(db, command, Shape::Count)
        }
        "estimatedDocumentCount" => {
            let mut command = doc! {"count": collection};
            copy(&mut command, option(0)?, &["maxTimeMS", "comment"], name)?;
            single(db, command, Shape::Number)
        }
        "count" => {
            let mut command = doc! {"count": collection, "query": option(0)?.unwrap_or_default()};
            copy(
                &mut command,
                option(1)?,
                &["limit", "skip", "hint", "maxTimeMS", "collation", "comment"],
                name,
            )?;
            single(db, command, Shape::Number)
        }
        "distinct" => {
            let mut command = doc! {"distinct": collection, "key": text(&args, 0, name)?};
            if let Some(query) = option(1)? {
                command.insert("query", query);
            }
            copy(
                &mut command,
                option(2)?,
                &["maxTimeMS", "collation", "comment"],
                name,
            )?;
            single(db, command, Shape::Values)
        }
        "getIndexes" | "getIndexSpecs" => {
            single(db, doc! {"listIndexes": collection}, Shape::Cursor(true))
        }
        "insertOne" => {
            let mut document = required(&args, 0, name)?;
            let id = identify(&mut document);
            let mut command = doc! {"insert": collection, "documents": [document], "ordered": true};
            copy(&mut command, option(1)?, &WRITE, name)?;
            single(db, command, Shape::Inserted(vec![id], false))
        }
        "insertMany" => {
            let Some(Bson::Array(documents)) = args.first() else {
                return Err(Failure::Usage(format!(
                    "{name}() takes an array of documents"
                )));
            };
            let mut ids = Vec::new();
            let mut list = Vec::new();
            for document in documents {
                let Bson::Document(document) = document else {
                    return Err(Failure::Usage(format!(
                        "{name}() takes an array of documents"
                    )));
                };
                let mut document = document.clone();
                ids.push(identify(&mut document));
                list.push(Bson::Document(document));
            }
            let options = option(1)?.unwrap_or_default();
            let ordered = options.get_bool("ordered").unwrap_or(true);
            let mut command = doc! {"insert": collection, "documents": list, "ordered": ordered};
            let rest = options
                .into_iter()
                .filter(|(key, _)| key != "ordered")
                .collect();
            copy(&mut command, Some(rest), &WRITE, name)?;
            single(db, command, Shape::Inserted(ids, true))
        }
        "updateOne" | "updateMany" | "replaceOne" => {
            let filter = required(&args, 0, name)?;
            let update = args.get(1).cloned().ok_or_else(|| missing(name, 2))?;
            atomic(&update, name != "replaceOne")?;
            let options = option(2)?.unwrap_or_default();
            let mut statement = doc! {"q": filter, "u": update, "multi": name == "updateMany"};
            let (inner, outer) = split(options, &STATEMENT);
            copy(&mut statement, Some(inner), &STATEMENT, name)?;
            let mut command = doc! {"update": collection, "updates": [statement], "ordered": true};
            copy(&mut command, Some(outer), &WRITE, name)?;
            single(db, command, Shape::Updated)
        }
        "deleteOne" | "deleteMany" => {
            let filter = required(&args, 0, name)?;
            let options = option(1)?.unwrap_or_default();
            let limit = i32::from(name == "deleteOne");
            let mut statement = doc! {"q": filter, "limit": limit};
            let (inner, outer) = split(options, &["hint", "collation"]);
            copy(&mut statement, Some(inner), &["hint", "collation"], name)?;
            let mut command = doc! {"delete": collection, "deletes": [statement], "ordered": true};
            copy(&mut command, Some(outer), &WRITE, name)?;
            single(db, command, Shape::Deleted)
        }
        "findOneAndUpdate" | "findOneAndReplace" | "findOneAndDelete" => {
            let mut command =
                doc! {"findAndModify": collection, "query": required(&args, 0, name)?};
            let options_index = if name == "findOneAndDelete" {
                command.insert("remove", true);
                1
            } else {
                let update = args.get(1).cloned().ok_or_else(|| missing(name, 2))?;
                atomic(&update, name == "findOneAndUpdate")?;
                command.insert("update", update);
                2
            };
            let mut options = option(options_index)?.unwrap_or_default();
            let returned = options.remove("returnDocument");
            let new = options.remove("returnNewDocument");
            let after =
                returned == Some(Bson::String("after".into())) || new == Some(Bson::Boolean(true));
            if name != "findOneAndDelete" {
                command.insert("new", after);
            }
            if let Some(projection) = options.remove("projection") {
                command.insert("fields", projection);
            }
            copy(
                &mut command,
                Some(options),
                &[
                    "sort",
                    "upsert",
                    "arrayFilters",
                    "collation",
                    "hint",
                    "maxTimeMS",
                    "bypassDocumentValidation",
                    "writeConcern",
                    "let",
                    "comment",
                ],
                name,
            )?;
            single(db, command, Shape::Modified)
        }
        "bulkWrite" => bulk(db, collection, &args)?,
        "createIndex" => {
            let keys = required(&args, 0, name)?;
            let mut options = option(1)?.unwrap_or_default();
            let index = match options.remove("name") {
                Some(Bson::String(index)) => index,
                _ => keys
                    .iter()
                    .map(|(key, value)| format!("{key}_{}", index_part(value)))
                    .collect::<Vec<_>>()
                    .join("_"),
            };
            let mut spec = doc! {"key": keys, "name": index.clone()};
            spec.extend(options);
            single(
                db,
                doc! {"createIndexes": collection, "indexes": [spec]},
                Shape::Index(index),
            )
        }
        "dropIndex" | "dropIndexes" => {
            let index = args
                .first()
                .cloned()
                .unwrap_or_else(|| Bson::String("*".into()));
            single(
                db,
                doc! {"dropIndexes": collection, "index": index},
                Shape::Reply,
            )
        }
        "drop" => single(db, doc! {"drop": collection}, Shape::Dropped),
        _ => {
            return Err(Failure::Usage(format!(
                "db.{collection}.{name}() is not supported, dbcli supports find, findOne, aggregate, countDocuments, estimatedDocumentCount, count, distinct, getIndexes, insertOne, insertMany, updateOne, updateMany, replaceOne, deleteOne, deleteMany, findOneAndUpdate, findOneAndReplace, findOneAndDelete, bulkWrite, createIndex, dropIndex, dropIndexes and drop"
            )));
        }
    };
    Ok(plan)
}

fn modify(mut plan: Plan, segments: Vec<Segment>) -> Result<Plan, Failure> {
    for segment in segments {
        let (name, args) = match segment {
            Segment::Call(name, args) => (name, args),
            Segment::Property(name) => {
                return Err(Failure::Usage(format!(".{name} is not supported here")));
            }
        };
        let finding =
            matches!(plan.shape, Shape::Cursor(_)) && plan.steps[0].command.contains_key("find");
        let aggregating = matches!(plan.shape, Shape::Cursor(_))
            && plan.steps[0].command.contains_key("aggregate");
        let field = match name.as_str() {
            "project" | "projection" => "projection",
            other => other,
        };
        match name.as_str() {
            "pretty" if finding || aggregating => {}
            "toArray" if finding || aggregating => plan.shape = Shape::Cursor(true),
            "explain" if finding || aggregating => {
                let verbosity = match args.first() {
                    Some(Bson::String(verbosity)) => verbosity.clone(),
                    Some(Bson::Boolean(true)) => "allPlansExecution".into(),
                    _ => "queryPlanner".into(),
                };
                let inner = plan.steps[0].command.clone();
                plan.steps[0].command = doc! {"explain": inner, "verbosity": verbosity};
                plan.shape = Shape::Reply;
            }
            "count" if finding => {
                let step = &mut plan.steps[0];
                let collection = step.command.get_str("find").unwrap_or_default().to_string();
                let filter = step
                    .command
                    .get_document("filter")
                    .cloned()
                    .unwrap_or_default();
                step.command = doc! {"count": collection, "query": filter};
                plan.shape = Shape::Number;
            }
            "sort" | "limit" | "skip" | "project" | "projection" | "hint" | "maxTimeMS"
            | "collation" | "batchSize" | "comment" | "min" | "max" | "returnKey"
            | "showRecordId" | "allowDiskUse"
                if finding =>
            {
                let value = match args.first() {
                    Some(value) => value.clone(),
                    None if name == "allowDiskUse"
                        || name == "returnKey"
                        || name == "showRecordId" =>
                    {
                        Bson::Boolean(true)
                    }
                    None => return Err(missing(&name, 1)),
                };
                plan.steps[0].command.insert(field, value);
            }
            _ => {
                return Err(Failure::Usage(format!(
                    ".{name}() is not supported here, cursors take sort, limit, skip, project, hint, maxTimeMS, collation, batchSize, comment, pretty, toArray, count and explain"
                )));
            }
        }
    }
    Ok(plan)
}

fn bulk(db: &str, collection: &str, args: &[Bson]) -> Result<Plan, Failure> {
    let name = "bulkWrite";
    let Some(Bson::Array(operations)) = args.first() else {
        return Err(Failure::Usage(format!(
            "{name}() takes an array of operations"
        )));
    };
    let options = optional(args, 1, name)?.unwrap_or_default();
    let ordered = options.get_bool("ordered").unwrap_or(true);
    let mut steps = Vec::new();
    let mut kinds = Vec::new();
    for (index, operation) in operations.iter().enumerate() {
        let invalid = || {
            Failure::Usage(format!(
                "{name}() operation {} must be one of insertOne, updateOne, updateMany, replaceOne, deleteOne or deleteMany",
                index + 1
            ))
        };
        let Bson::Document(operation) = operation else {
            return Err(invalid());
        };
        let Some((kind, Bson::Document(body))) = operation.iter().next() else {
            return Err(invalid());
        };
        let filter = || body.get_document("filter").cloned().unwrap_or_default();
        let command = match kind.as_str() {
            "insertOne" => {
                let mut document = body
                    .get_document("document")
                    .cloned()
                    .map_err(|_| invalid())?;
                let id = identify(&mut document);
                kinds.push(Bulked::Insert(index, id));
                doc! {"insert": collection, "documents": [document], "ordered": ordered}
            }
            "updateOne" | "updateMany" | "replaceOne" => {
                let field = if kind == "replaceOne" {
                    "replacement"
                } else {
                    "update"
                };
                let update = body.get(field).cloned().ok_or_else(invalid)?;
                atomic(&update, kind != "replaceOne")?;
                let mut statement =
                    doc! {"q": filter(), "u": update, "multi": kind == "updateMany"};
                for key in STATEMENT {
                    if let Some(value) = body.get(key) {
                        statement.insert(key, value.clone());
                    }
                }
                kinds.push(Bulked::Update(index));
                doc! {"update": collection, "updates": [statement], "ordered": ordered}
            }
            "deleteOne" | "deleteMany" => {
                let mut statement = doc! {"q": filter(), "limit": i32::from(kind == "deleteOne")};
                for key in ["hint", "collation"] {
                    if let Some(value) = body.get(key) {
                        statement.insert(key, value.clone());
                    }
                }
                kinds.push(Bulked::Delete);
                doc! {"delete": collection, "deletes": [statement], "ordered": ordered}
            }
            _ => return Err(invalid()),
        };
        steps.push(Step {
            db: db.to_string(),
            command,
        });
    }
    Ok(Plan {
        steps,
        shape: Shape::Bulk(kinds),
    })
}

pub fn check(connection: &Connection, step: &Step) -> Result<Verdict, Failure> {
    let (action, namespace, read) = classify(&step.db, &step.command);
    if read {
        return Ok(Verdict {
            action,
            namespace,
            rule: None,
        });
    }
    match find(&connection.allow, &action, &namespace) {
        Some(rule) => Ok(Verdict {
            rule: Some(rule.to_string()),
            action,
            namespace,
        }),
        None => Err(not_allowed(
            connection,
            "reads",
            &action,
            Some(&namespace),
            Some(&namespace),
        )),
    }
}

fn classify(db: &str, command: &Document) -> (String, String, bool) {
    let Some((name, value)) = command.iter().next() else {
        return (String::new(), db.to_string(), false);
    };
    let namespace = match value {
        Bson::String(collection) => format!("{db}.{collection}"),
        _ => db.to_string(),
    };
    match (name.as_str(), value) {
        ("aggregate", _) => match command
            .get("pipeline")
            .and_then(|pipeline| output(db, pipeline))
        {
            Some(target) => ("aggregate".into(), target, false),
            None => (name.clone(), namespace, true),
        },
        ("explain", Bson::Document(inner)) => {
            let (action, namespace, read) = classify(db, inner);
            if read {
                (name.clone(), namespace, true)
            } else {
                (action, namespace, false)
            }
        }
        _ => (name.clone(), namespace, READS.contains(&name.as_str())),
    }
}

fn output(db: &str, value: &Bson) -> Option<String> {
    match value {
        Bson::Array(items) => items.iter().find_map(|item| output(db, item)),
        Bson::Document(document) => document.iter().find_map(|(key, value)| match key.as_str() {
            "$out" | "$merge" => Some(target(db, value)),
            _ => output(db, value),
        }),
        _ => None,
    }
}

fn target(db: &str, value: &Bson) -> String {
    match value {
        Bson::String(collection) => format!("{db}.{collection}"),
        Bson::Document(spec) => match spec.get("into") {
            Some(into) => target(db, into),
            None => format!(
                "{}.{}",
                spec.get_str("db").unwrap_or(db),
                spec.get_str("coll").unwrap_or_default()
            ),
        },
        _ => db.to_string(),
    }
}

fn single(db: &str, command: Document, shape: Shape) -> Plan {
    Plan {
        steps: vec![Step {
            db: db.to_string(),
            command,
        }],
        shape,
    }
}

fn aggregate(args: &[Bson], name: &str) -> Result<Document, Failure> {
    let (pipeline, options) = match args.first() {
        Some(Bson::Array(pipeline)) => (pipeline.clone(), optional(args, 1, name)?),
        _ => (args.to_vec(), None),
    };
    if pipeline
        .iter()
        .any(|stage| !matches!(stage, Bson::Document(_)))
    {
        return Err(Failure::Usage(format!("{name}() takes an array of stages")));
    }
    let mut options = options.unwrap_or_default();
    let mut cursor = Document::new();
    if let Some(size) = options.remove("batchSize") {
        cursor.insert("batchSize", size);
    }
    let mut command = doc! {"pipeline": pipeline, "cursor": cursor};
    copy(&mut command, Some(options), &AGGREGATE, name)?;
    Ok(command)
}

fn command(args: &[Bson], name: &str) -> Result<Document, Failure> {
    let command = match args.first() {
        Some(Bson::Document(command)) => command.clone(),
        Some(Bson::String(command)) => {
            let mut document = Document::new();
            document.insert(command.clone(), 1);
            document
        }
        _ => return Err(Failure::Usage(format!("{name}() takes a command document"))),
    };
    if let Some(key) = command.keys().find(|key| key.starts_with('$')) {
        return Err(Failure::Usage(format!(
            "{name}() fields starting with $ are set by dbcli, remove {key}"
        )));
    }
    if command.is_empty() {
        return Err(Failure::Usage(format!("{name}() takes a command document")));
    }
    Ok(command)
}

fn copy(
    command: &mut Document,
    options: Option<Document>,
    allowed: &[&str],
    name: &str,
) -> Result<(), Failure> {
    for (key, value) in options.unwrap_or_default() {
        if !allowed.contains(&key.as_str()) {
            return Err(Failure::Usage(format!(
                "{name}() option {key} is not supported, use {}",
                allowed.join(", ")
            )));
        }
        command.insert(key, value);
    }
    Ok(())
}

fn split(options: Document, inner: &[&str]) -> (Document, Document) {
    options
        .into_iter()
        .partition(|(key, _)| inner.contains(&key.as_str()))
}

fn optional(args: &[Bson], index: usize, name: &str) -> Result<Option<Document>, Failure> {
    match args.get(index) {
        None | Some(Bson::Null) => Ok(None),
        Some(Bson::Document(document)) => Ok(Some(document.clone())),
        Some(_) => Err(Failure::Usage(format!(
            "{name}() takes a document as argument {}",
            index + 1
        ))),
    }
}

fn required(args: &[Bson], index: usize, name: &str) -> Result<Document, Failure> {
    optional(args, index, name)?.ok_or_else(|| missing(name, index + 1))
}

fn text(args: &[Bson], index: usize, name: &str) -> Result<String, Failure> {
    match args.get(index) {
        Some(Bson::String(text)) => Ok(text.clone()),
        _ => Err(Failure::Usage(format!(
            "{name}() takes a string as argument {}",
            index + 1
        ))),
    }
}

fn missing(name: &str, position: usize) -> Failure {
    Failure::Usage(format!("{name}() needs argument {position}"))
}

fn atomic(update: &Bson, operators: bool) -> Result<(), Failure> {
    let first = match update {
        Bson::Document(document) => document.keys().next().map(String::as_str),
        Bson::Array(_) if operators => return Ok(()),
        _ => return Err(Failure::Usage("the update must be a document".into())),
    };
    match (operators, first.is_some_and(|key| key.starts_with('$'))) {
        (true, false) => Err(Failure::Database(
            "MongoInvalidArgumentError: Update document requires atomic operators".into(),
        )),
        (false, true) => Err(Failure::Database(
            "MongoInvalidArgumentError: Replacement document must not contain atomic operators"
                .into(),
        )),
        _ => Ok(()),
    }
}

fn identify(document: &mut Document) -> Bson {
    match document.get("_id") {
        Some(id) => id.clone(),
        None => {
            let id = Bson::ObjectId(ObjectId::new());
            let mut identified = doc! {"_id": id.clone()};
            identified.extend(take(document));
            *document = identified;
            id
        }
    }
}

fn index_part(value: &Bson) -> String {
    match value {
        Bson::String(text) => text.clone(),
        Bson::Int32(number) => number.to_string(),
        Bson::Int64(number) => number.to_string(),
        Bson::Double(number) => js_number(*number),
        other => other.to_string(),
    }
}
