use std::time::Duration;

use fieldkit_common::Failure;
use fieldkit_policy::Connection;
use unicode_width::UnicodeWidthStr;

use super::{
    args::{CqlshArgs, parse},
    client::{Rows, ServerError, Session},
    cql::{Action, Local, Step, plan, protect},
    value::{format, text},
};
use crate::shared::{ConnectionUrl, Context, summary};

const LEVELS: [(&str, u16); 11] = [
    ("ANY", 0x0000),
    ("ONE", 0x0001),
    ("TWO", 0x0002),
    ("THREE", 0x0003),
    ("QUORUM", 0x0004),
    ("ALL", 0x0005),
    ("LOCAL_QUORUM", 0x0006),
    ("EACH_QUORUM", 0x0007),
    ("SERIAL", 0x0008),
    ("LOCAL_SERIAL", 0x0009),
    ("LOCAL_ONE", 0x000A),
];

type Level = (&'static str, u16);

struct State {
    consistency: Level,
    serial: Level,
    expand: bool,
    keyspace: Option<String>,
    errors: Vec<String>,
}

pub async fn run(
    connection: &Connection,
    url: &ConnectionUrl,
    args: &[String],
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    let args = parse(args)?;
    context.statements(&args.execute);
    let start = start(url, &args);
    let steps = plan(connection, &args.execute, start.clone())?;
    context.entry.rule = Some(summary(steps.iter().filter_map(
        |step| match &step.action {
            Action::Local(_) => None,
            Action::Write(rule) => Some(Some(rule.clone())),
            Action::Rows | Action::Describe(_) | Action::Use(_) => Some(None),
        },
    )));
    let mut session = Session::open(
        connection,
        url,
        seconds(args.connect_timeout),
        seconds(args.request_timeout),
    )
    .await?;
    let mut state = State {
        consistency: ("ONE", 0x0001),
        serial: ("SERIAL", 0x0008),
        expand: false,
        keyspace: None,
        errors: Vec::new(),
    };
    let wait = args.common.wait;
    let result = execute(
        &mut session,
        connection,
        wait,
        start,
        steps,
        &mut state,
        context,
    )
    .await;
    session.close().await;
    result?;
    if state.errors.is_empty() {
        Ok(0)
    } else {
        Err(Failure::Database(state.errors.join("\n")))
    }
}

pub fn explain(
    connection: &Connection,
    url: &ConnectionUrl,
    args: &[String],
) -> Result<Vec<String>, Failure> {
    let args = parse(args)?;
    let steps = plan(connection, &args.execute, start(url, &args))?;
    Ok(steps
        .iter()
        .map(|step| match &step.action {
            Action::Local(_) => format!(
                "{}: a cqlsh command, nothing reaches the server",
                step.label
            ),
            Action::Write(rule) => format!("{}: allowed by {rule}", step.label),
            Action::Rows | Action::Describe(_) | Action::Use(_) => {
                format!("{}: a read, so it runs", step.label)
            }
        })
        .collect())
}

fn start(url: &ConnectionUrl, args: &CqlshArgs) -> Option<String> {
    args.keyspace.clone().or_else(|| {
        let keyspace = &url.database;
        (!keyspace.is_empty()).then(|| keyspace.clone())
    })
}

fn seconds(value: f64) -> Duration {
    Duration::from_secs_f64(value.clamp(0.1, 3600.0))
}

async fn execute(
    session: &mut Session,
    connection: &Connection,
    wait: Option<f64>,
    start: Option<String>,
    steps: Vec<Step>,
    state: &mut State,
    context: &mut Context<'_>,
) -> Result<(), Failure> {
    if let Some(keyspace) = start {
        match session
            .query(
                &format!("USE {}", protect(&keyspace)),
                state.consistency.1,
                state.serial.1,
            )
            .await?
        {
            Ok(_) => state.keyspace = Some(keyspace),
            Err(error) => state
                .errors
                .push(format!("<stdin>:1:{}", describe_error(&error))),
        }
    }
    for step in steps {
        let mut out = String::new();
        match step.action {
            Action::Local(local) => local_command(local, step.line, state, &mut out),
            action => {
                context.take(connection, wait)?;
                let reply = session
                    .query(&step.text, state.consistency.1, state.serial.1)
                    .await?;
                match reply {
                    Err(error) => state.errors.push(format!(
                        "<stdin>:{}:{}",
                        step.line,
                        describe_error(&error)
                    )),
                    Ok(reply) => {
                        let rows = reply.rows;
                        match (action, &rows) {
                            (Action::Use(keyspace), _) => state.keyspace = Some(keyspace),
                            (Action::Describe(what), Some(rows)) => {
                                described(&what, rows, state, &mut out)
                            }
                            (Action::Rows, Some(rows)) => {
                                counted_rows(rows, state.expand, &mut out)
                            }
                            (_, Some(rows)) if !rows.rows.is_empty() => {
                                out.push('\n');
                                table(rows, state.expand, &mut out);
                            }
                            _ => {}
                        }
                        if !reply.warnings.is_empty() {
                            out.push_str(&format!(
                                "\nWarnings :\n{}\n\n",
                                reply.warnings.join("\n")
                            ));
                        }
                    }
                }
            }
        }
        context.print(out.as_bytes())?;
    }
    Ok(())
}

fn local_command(local: Local, line: usize, state: &mut State, out: &mut String) {
    match local {
        Local::Consistency(None) => {
            out.push_str(&format!(
                "Current consistency level is {}.\n",
                state.consistency.0
            ));
        }
        Local::Serial(None) => {
            out.push_str(&format!(
                "Current serial consistency level is {}.\n",
                state.serial.0
            ));
        }
        Local::Consistency(Some(wanted)) => match named(&wanted, false) {
            Some(level) => {
                state.consistency = level;
                out.push_str(&format!("Consistency level set to {}.\n", level.0));
            }
            None => state
                .errors
                .push(format!("<stdin>:{line}:Improper consistency command.")),
        },
        Local::Serial(Some(wanted)) => match named(&wanted, true) {
            Some(level) => {
                state.serial = level;
                out.push_str(&format!("Serial consistency level set to {}.\n", level.0));
            }
            None => state.errors.push(format!(
                "<stdin>:{line}:Improper serial consistency command."
            )),
        },
        Local::Expand(None) => {
            out.push_str(if state.expand {
                "EXPAND is ON\n"
            } else {
                "EXPAND is OFF\n"
            });
        }
        Local::Expand(Some(wanted)) => {
            let on = match wanted.to_ascii_uppercase().as_str() {
                "ON" => true,
                "OFF" => false,
                _ => {
                    state
                        .errors
                        .push(format!("<stdin>:{line}:Improper expand command."));
                    return;
                }
            };
            let word = if on { "ON" } else { "OFF" };
            if state.expand == on {
                out.push_str(&format!("EXPAND is already {word}\n"));
            } else {
                state.expand = on;
                out.push_str(&format!("EXPAND set to {word}\n"));
            }
        }
    }
}

fn named(wanted: &str, serial: bool) -> Option<Level> {
    LEVELS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .filter(|(name, _)| !serial || matches!(*name, "SERIAL" | "LOCAL_SERIAL"))
        .copied()
}

fn counted_rows(rows: &Rows, expand: bool, out: &mut String) {
    out.push('\n');
    if rows.rows.is_empty() {
        header(rows, &widths(rows, &[]), out);
        out.push_str("\n\n(0 rows)\n");
        return;
    }
    table(rows, expand, out);
    out.push_str(&format!("\n({} rows)\n", rows.rows.len()));
}

fn table(rows: &Rows, expand: bool, out: &mut String) {
    let cells = cells(rows);
    if expand {
        let name_width = rows
            .columns
            .iter()
            .map(|(name, _)| name.width())
            .max()
            .unwrap_or(0);
        let value_width = cells
            .iter()
            .flatten()
            .map(|(_, width)| *width)
            .max()
            .unwrap_or(0);
        for (index, row) in cells.iter().enumerate() {
            out.push_str(&format!("@ Row {}\n", index + 1));
            out.push_str(&format!(
                "-{}-+-{}-\n",
                "-".repeat(name_width),
                "-".repeat(value_width)
            ));
            for ((name, _), (cell, _)) in rows.columns.iter().zip(row) {
                out.push_str(&format!(
                    " {} | {cell}\n",
                    pad(name, name.width(), name_width, false)
                ));
            }
            out.push('\n');
        }
        return;
    }
    let widths = widths(rows, &cells);
    header(rows, &widths, out);
    for row in &cells {
        let line = row
            .iter()
            .zip(&widths)
            .map(|((cell, size), width)| pad(cell, *size, *width, true))
            .collect::<Vec<_>>()
            .join(" | ");
        out.push_str(&format!(" {line}\n"));
    }
}

fn header(rows: &Rows, widths: &[usize], out: &mut String) {
    let names = rows
        .columns
        .iter()
        .zip(widths)
        .map(|((name, _), width)| pad(name, name.width(), *width, false))
        .collect::<Vec<_>>()
        .join(" | ");
    out.push_str(&format!(" {}\n", names.trim_end()));
    let rule = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>()
        .join("-+-");
    out.push_str(&format!("-{rule}-\n"));
}

fn widths(rows: &Rows, cells: &[Vec<(String, usize)>]) -> Vec<usize> {
    rows.columns
        .iter()
        .enumerate()
        .map(|(index, (name, _))| {
            cells
                .iter()
                .map(|row| row[index].1)
                .chain([name.width()])
                .max()
                .unwrap_or(0)
        })
        .collect()
}

fn cells(rows: &Rows) -> Vec<Vec<(String, usize)>> {
    rows.rows
        .iter()
        .map(|row| {
            rows.columns
                .iter()
                .zip(row)
                .map(|((_, kind), value)| format(kind, value.as_deref(), false))
                .collect()
        })
        .collect()
}

fn pad(text: &str, size: usize, width: usize, right: bool) -> String {
    let fill = " ".repeat(width.saturating_sub(size));
    if right {
        format!("{fill}{text}")
    } else {
        format!("{text}{fill}")
    }
}

fn described(what: &str, rows: &Rows, state: &State, out: &mut String) {
    let column = |name: &str| rows.columns.iter().position(|(column, _)| column == name);
    let values = |name: &str| -> Vec<String> {
        column(name).map_or_else(Vec::new, |index| {
            rows.rows
                .iter()
                .map(|row| text(row[index].as_deref()))
                .collect()
        })
    };
    match what {
        "keyspaces" => {
            out.push('\n');
            columnize(&values("name"), out);
            out.push('\n');
        }
        "tables" | "columnfamilies" | "types" | "functions" | "aggregates" => {
            let keyspaces = values("keyspace_name");
            let names = values("name");
            let mut index = 0;
            while index < names.len() {
                let keyspace = &keyspaces[index];
                let end = keyspaces[index..]
                    .iter()
                    .position(|other| other != keyspace)
                    .map_or(names.len(), |offset| index + offset);
                out.push('\n');
                if state.keyspace.is_none() {
                    out.push_str(&format!(
                        "Keyspace {keyspace}\n---------{}\n",
                        "-".repeat(keyspace.len())
                    ));
                }
                columnize(&names[index..end], out);
                index = end;
            }
            if !names.is_empty() {
                out.push('\n');
            }
        }
        "cluster" => {
            for ((cluster, partitioner), snitch) in values("cluster")
                .iter()
                .zip(values("partitioner"))
                .zip(values("snitch"))
            {
                out.push_str(&format!(
                    "\nCluster: {cluster}\nPartitioner: {partitioner}\nSnitch: {snitch}\n\n"
                ));
            }
        }
        _ => {
            for statement in values("create_statement") {
                out.push('\n');
                out.push_str(&statement);
                out.push('\n');
            }
        }
    }
}

fn columnize(list: &[String], out: &mut String) {
    match list.len() {
        0 => {
            out.push_str("<empty>\n");
            return;
        }
        1 => {
            out.push_str(&format!("{}\n", list[0]));
            return;
        }
        _ => {}
    }
    let size = list.len();
    let mut layout = (size, 1, vec![0]);
    for rows in 1..size {
        let columns = size.div_ceil(rows);
        let mut widths = Vec::new();
        let mut total: isize = -2;
        for column in 0..columns {
            let width = (0..rows)
                .map(|row| row + rows * column)
                .take_while(|index| *index < size)
                .map(|index| list[index].chars().count())
                .max()
                .unwrap_or(0);
            widths.push(width);
            total += width as isize + 2;
            if total > 80 {
                break;
            }
        }
        if total <= 80 {
            layout = (rows, columns, widths);
            break;
        }
    }
    let (rows, columns, widths) = layout;
    for row in 0..rows {
        let mut texts = (0..columns)
            .map(|column| list.get(row + rows * column).cloned().unwrap_or_default())
            .collect::<Vec<_>>();
        while texts.last().is_some_and(String::is_empty) {
            texts.pop();
        }
        let line = texts
            .iter()
            .enumerate()
            .map(|(column, text)| format!("{text:<width$}", width = widths[column]))
            .collect::<Vec<_>>()
            .join("  ");
        out.push_str(&format!("{line}\n"));
    }
}

fn describe_error(error: &ServerError) -> String {
    let (class, summary) = match error.code {
        0x2000 => return format!("SyntaxException: {}", error.message),
        0x0000 => ("ServerError", "Server error"),
        0x000A => ("ProtocolException", "Protocol error"),
        0x0100 => ("AuthenticationFailed", "Bad credentials"),
        0x1000 => ("Unavailable", "Unavailable exception"),
        0x1001 => ("OverloadedErrorMessage", "Coordinator node overloaded"),
        0x1002 => (
            "IsBootstrappingErrorMessage",
            "Coordinator node is bootstrapping",
        ),
        0x1003 => ("TruncateError", "Error during truncate"),
        0x1100 => (
            "WriteTimeout",
            "Coordinator node timed out waiting for replica nodes' responses",
        ),
        0x1200 => (
            "ReadTimeout",
            "Coordinator node timed out waiting for replica nodes' responses",
        ),
        0x1300 => ("ReadFailure", "Replica(s) failed to execute read"),
        0x1400 => (
            "FunctionFailure",
            "User Defined Function failed during execution",
        ),
        0x1500 => ("WriteFailure", "Replica(s) failed to execute write"),
        0x2100 => ("Unauthorized", "Unauthorized"),
        0x2200 => ("InvalidRequest", "Invalid query"),
        0x2300 => (
            "ConfigurationException",
            "Query invalid because of configuration issue",
        ),
        0x2400 => ("AlreadyExists", "Keyspace or table already exists"),
        0x2500 => ("Unprepared", "Query not prepared"),
        _ => ("ServerError", "Unknown"),
    };
    format!(
        "{class}: Error from server: code={:04x} [{summary}] message=\"{}\"",
        error.code, error.message
    )
}
