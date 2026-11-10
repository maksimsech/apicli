use apicli::Failure;
use apicli_policy::Connection;

use crate::{
    call::quote,
    split::{Lexed, Statement, Token, split, tokens, word},
};

const LOCAL_FILES: &str = "it reads or writes local files";
const WRITES: [&str; 10] = [
    "INSERT", "UPDATE", "DELETE", "TRUNCATE", "CREATE", "ALTER", "DROP", "GRANT", "REVOKE", "ADD",
];
const UNSUPPORTED: &str = "dbcli runs CQL and only the cqlsh commands USE, DESCRIBE, EXPAND, CONSISTENCY and SERIAL CONSISTENCY";

pub enum Local {
    Consistency(Option<String>),
    Serial(Option<String>),
    Expand(Option<String>),
}

pub enum Action {
    Local(Local),
    Server {
        counted: bool,
        describe: Option<String>,
        keyspace: Option<String>,
        rule: Option<String>,
    },
}

pub struct Step {
    pub text: String,
    pub line: usize,
    pub label: String,
    pub action: Action,
}

pub fn plan(
    connection: &Connection,
    sources: &[String],
    start: Option<String>,
) -> Result<Vec<Step>, Failure> {
    let mut keyspace = start;
    let mut steps = Vec::new();
    for source in sources {
        for statement in split(source, false, true) {
            steps.push(classify(connection, statement, &mut keyspace)?);
        }
    }
    Ok(steps)
}

fn classify(
    connection: &Connection,
    statement: Statement,
    keyspace: &mut Option<String>,
) -> Result<Step, Failure> {
    let lexed = tokens(&statement.text, false);
    let list = lexed.iter().map(|lexed| &lexed.token).collect::<Vec<_>>();
    let keyword = match list.first() {
        Some(Token::Word(word)) => word.to_ascii_uppercase(),
        _ => String::new(),
    };
    let next = |index: usize| match list.get(index) {
        Some(Token::Word(word)) => Some(word.clone()),
        _ => None,
    };
    let refused = |reason: &'static str| Failure::Refused {
        flag: keyword.clone(),
        reason,
    };
    let server = |counted, describe, switched, rule| Action::Server {
        counted,
        describe,
        keyspace: switched,
        rule,
    };
    let (label, action) = match keyword.as_str() {
        "SELECT" | "LIST" => (keyword.clone(), server(true, None, None, None)),
        "DESCRIBE" | "DESC" => {
            let what = next(1).unwrap_or_default().to_ascii_lowercase();
            (keyword.clone(), server(false, Some(what), None, None))
        }
        "USE" => {
            let name = identifier(list.get(1).copied()).ok_or_else(|| {
                Failure::Usage(format!(
                    "line {}: USE needs a keyspace name",
                    statement.line
                ))
            })?;
            *keyspace = Some(name.clone());
            (format!("USE {name}"), server(false, None, Some(name), None))
        }
        "CONSISTENCY" => (keyword.clone(), Action::Local(Local::Consistency(next(1)))),
        "SERIAL" if next(1).is_some_and(|word| word.eq_ignore_ascii_case("CONSISTENCY")) => {
            (keyword.clone(), Action::Local(Local::Serial(next(2))))
        }
        "EXPAND" => (keyword.clone(), Action::Local(Local::Expand(next(1)))),
        "COPY" | "SOURCE" | "CAPTURE" => return Err(refused(LOCAL_FILES)),
        "LOGIN" => return Err(refused("the connection name picks the user")),
        "TRACING" | "PAGING" | "SHOW" | "HELP" | "CLEAR" | "CLS" | "EXIT" | "QUIT" | "DEBUG"
        | "TIMING" | "SERIAL" => {
            return Err(refused(UNSUPPORTED));
        }
        "BEGIN"
            if next(1).is_some_and(|word| word.eq_ignore_ascii_case("BATCH"))
                || (next(1).is_some_and(|word| {
                    word.eq_ignore_ascii_case("UNLOGGED") || word.eq_ignore_ascii_case("COUNTER")
                }) && next(2).is_some_and(|word| word.eq_ignore_ascii_case("BATCH"))) =>
        {
            let mut rules = Vec::new();
            let mut labels = Vec::new();
            for inner in batch(&lexed) {
                let (action, target) = write(&inner, keyspace);
                if !matches!(action.as_str(), "INSERT" | "UPDATE" | "DELETE") {
                    return Err(Failure::Usage(format!(
                        "line {}: a BATCH holds only INSERT, UPDATE and DELETE",
                        statement.line
                    )));
                }
                rules.push(allowed(connection, &action, target.as_deref())?);
                labels.push(label(&action, target.as_deref()));
            }
            rules.dedup();
            (
                format!("BATCH {}", labels.join(", ")),
                server(false, None, None, Some(rules.join(", "))),
            )
        }
        _ if !WRITES.contains(&keyword.as_str()) => {
            let rule = connection.rule(&keyword, &[]).ok_or_else(|| {
                Failure::Denied(format!(
                    "denied: {keyword} is not a CQL statement dbcli knows, check the spelling\nif it is right, the user can allow it with: dbcli allow add {} {}",
                    connection.name,
                    quote(&keyword)
                ))
            })?;
            (
                keyword.clone(),
                server(false, None, None, Some(rule.to_string())),
            )
        }
        _ => {
            let tokens = list.into_iter().cloned().collect::<Vec<_>>();
            let (action, target) = write(&tokens, keyspace);
            let rule = allowed(connection, &action, target.as_deref())?;
            (
                label(&action, target.as_deref()),
                server(false, None, None, Some(rule)),
            )
        }
    };
    Ok(Step {
        text: statement.text,
        line: statement.line,
        label,
        action,
    })
}

fn batch(lexed: &[Lexed]) -> Vec<Vec<Token>> {
    let list = lexed
        .iter()
        .map(|lexed| lexed.token.clone())
        .collect::<Vec<_>>();
    let start = list
        .iter()
        .position(|token| word(token, "BATCH"))
        .map_or(list.len(), |index| index + 1);
    let end = list
        .iter()
        .rposition(|token| word(token, "APPLY"))
        .unwrap_or(list.len())
        .max(start);
    let mut body = &list[start..end];
    if body.first().is_some_and(|token| word(token, "USING")) {
        let skip = body
            .iter()
            .position(|token| {
                ["INSERT", "UPDATE", "DELETE"]
                    .iter()
                    .any(|keyword| word(token, keyword))
            })
            .unwrap_or(body.len());
        body = &body[skip..];
    }
    body.split(|token| *token == Token::Symbol(';'))
        .filter(|inner| !inner.is_empty())
        .map(<[Token]>::to_vec)
        .collect()
}

fn write(tokens: &[Token], keyspace: &Option<String>) -> (String, Option<String>) {
    let keyword = match tokens.first() {
        Some(Token::Word(word)) => word.to_ascii_uppercase(),
        _ => return (String::new(), Some("?".into())),
    };
    let after = |expected: &str| {
        tokens
            .iter()
            .position(|token| word(token, expected))
            .and_then(|index| name(tokens, index + 1, keyspace))
    };
    let table = |target: Option<String>| Some(target.unwrap_or_else(|| "?".into()));
    let target = match keyword.as_str() {
        "INSERT" => table(after("INTO")),
        "UPDATE" => table(name(tokens, 1, keyspace)),
        "DELETE" => table(after("FROM")),
        "TRUNCATE" => {
            let skip = usize::from(
                tokens
                    .get(1)
                    .is_some_and(|token| word(token, "TABLE") || word(token, "COLUMNFAMILY")),
            );
            table(name(tokens, 1 + skip, keyspace))
        }
        "CREATE" | "ALTER" | "DROP" => {
            let mut index = 1;
            if tokens.get(index).is_some_and(|token| word(token, "OR")) {
                index += 2;
            }
            let kind = match tokens.get(index) {
                Some(Token::Word(word)) => word.to_ascii_uppercase(),
                _ => String::new(),
            };
            index += 1;
            if kind == "MATERIALIZED" || kind == "CUSTOM" {
                index += 1;
            }
            index = exists(tokens, index);
            match kind.as_str() {
                "KEYSPACE" | "SCHEMA" => table(identifier(tokens.get(index))),
                "ROLE" | "USER" | "IDENTITY" => None,
                "INDEX" | "CUSTOM" if keyword == "CREATE" => table(after("ON")),
                "TRIGGER" => table(after("ON")),
                _ => table(name(tokens, index, keyspace)),
            }
        }
        _ => None,
    };
    (keyword, target)
}

fn exists(tokens: &[Token], mut index: usize) -> usize {
    if tokens.get(index).is_some_and(|token| word(token, "IF")) {
        index += 1;
        if tokens.get(index).is_some_and(|token| word(token, "NOT")) {
            index += 1;
        }
        index += 1;
    }
    index
}

fn name(tokens: &[Token], index: usize, keyspace: &Option<String>) -> Option<String> {
    let first = identifier(tokens.get(index))?;
    if tokens.get(index + 1) == Some(&Token::Symbol('.')) {
        let second = identifier(tokens.get(index + 2))?;
        return Some(format!("{first}.{second}"));
    }
    Some(match keyspace {
        Some(keyspace) => format!("{keyspace}.{first}"),
        None => first,
    })
}

fn identifier(token: Option<&Token>) -> Option<String> {
    match token? {
        Token::Word(word) => Some(word.to_ascii_lowercase()),
        Token::Quoted(name) => Some(name.clone()),
        _ => None,
    }
}

fn allowed(connection: &Connection, action: &str, target: Option<&str>) -> Result<String, Failure> {
    let targets = target.map(str::as_bytes).into_iter().collect::<Vec<_>>();
    if let Some(rule) = connection.rule(action, &targets) {
        return Ok(rule.to_string());
    }
    let name = &connection.name;
    let (on, hint) = match target {
        Some(target) => (
            format!(" on {target}"),
            format!("dbcli allow add {name} {} {}", quote(action), quote(target)),
        ),
        None => (
            String::new(),
            format!("dbcli allow add {name} {}", quote(action)),
        ),
    };
    Err(Failure::Denied(format!(
        "denied: {name} allows reads only, and no allow rule covers {action}{on}\nto allow it, the user can run: {hint}"
    )))
}

fn label(action: &str, target: Option<&str>) -> String {
    match target {
        Some(target) => format!("{action} {target}"),
        None => action.to_string(),
    }
}

pub fn protect(name: &str) -> String {
    let simple = name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
    if simple {
        name.to_string()
    } else {
        format!("\"{}\"", name.replace('"', "\"\""))
    }
}
