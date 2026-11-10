use apicli::Failure;
use apicli_policy::Connection;

use super::{
    args::{PsqlArgs, parse},
    client::{READ_ONLY, Reply, ServerError, Session},
    meta::{self, Meta},
    output::{Options, Table, render},
};
use crate::call::{Context, mode, read_only, writes};

const TAGGED: [&str; 4] = ["INSERT", "UPDATE", "DELETE", "MERGE"];

enum Step {
    Sql(String),
    Meta(Meta),
}

pub async fn run(
    connection: &Connection,
    args: &[String],
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    let args = parse(args)?;
    context.statements(&args.commands);
    let options = args.check()?;
    let steps = steps(&args)?;
    context.entry.rule = Some(mode(connection).into());
    context.take(connection, args.common.wait)?;
    let mut session = Session::open(connection).await?;
    let mut result = Ok(0);
    for (index, step) in steps.iter().enumerate() {
        if index > 0
            && let Err(failure) = context.take(connection, args.common.wait)
        {
            result = Err(failure);
            break;
        }
        if let Err(failure) = run_step(&mut session, step, connection, &options, context).await {
            result = Err(failure);
            break;
        }
    }
    session.close().await;
    result
}

pub fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    let args = parse(args)?;
    args.check()?;
    Ok(writes(connection, steps(&args)?.len()))
}

async fn run_step(
    session: &mut Session,
    step: &Step,
    connection: &Connection,
    options: &Options,
    context: &mut Context<'_>,
) -> Result<(), Failure> {
    match step {
        Step::Sql(sql) => {
            let reply = session.query(sql).await;
            notices(session, context)?;
            let reply = reply?;
            if let Some(error) = &reply.error {
                return Err(server_failure(error, sql, connection));
            }
            context.print(&reply_text(reply, options))
        }
        Step::Meta(meta) => {
            let shown = meta::run(session, meta, connection).await;
            notices(session, context)?;
            let shown = shown?;
            if let Some(message) = shown.message {
                context.warn(format!("{message}\n").as_bytes())?;
            }
            for table in shown.tables {
                context.print(render(&table, options).as_bytes())?;
            }
            Ok(())
        }
    }
}

fn steps(args: &PsqlArgs) -> Result<Vec<Step>, Failure> {
    if args.commands.is_empty() {
        return Err(Failure::Usage(
            "pass SQL with -c, like: dbcli NAME -c 'select 1'. Interactive mode and stdin are not supported".into(),
        ));
    }
    args.commands
        .iter()
        .map(|command| {
            if command.trim_start().starts_with('\\') {
                meta::parse(command).map(Step::Meta)
            } else {
                Ok(Step::Sql(command.clone()))
            }
        })
        .collect()
}

fn reply_text(reply: Reply, options: &Options) -> Vec<u8> {
    if reply.copy_out {
        return reply.copy;
    }
    let tag = reply.tag.unwrap_or_default();
    let mut show_tag = !options.quiet && !tag.is_empty();
    let mut text = String::new();
    if let Some(columns) = reply.columns {
        let table = Table {
            title: None,
            columns,
            rows: reply.rows,
            footers: Vec::new(),
            count: true,
        };
        text.push_str(&render(&table, options));
        show_tag = show_tag && TAGGED.iter().any(|word| tag.starts_with(word));
    }
    if show_tag {
        text.push_str(&tag);
        text.push('\n');
    }
    text.into_bytes()
}

fn server_failure(error: &ServerError, sql: &str, connection: &Connection) -> Failure {
    let text = error.render(Some(sql));
    if error.code == READ_ONLY && !connection.write {
        read_only(connection, &format!("\n{text}"))
    } else {
        Failure::Database(text)
    }
}

fn notices(session: &mut Session, context: &mut Context<'_>) -> Result<(), Failure> {
    for notice in session.notices.drain(..) {
        context.warn(format!("{notice}\n").as_bytes())?;
    }
    Ok(())
}
