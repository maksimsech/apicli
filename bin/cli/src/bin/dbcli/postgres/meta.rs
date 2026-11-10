use std::mem::take;

use apicli::Failure;

use super::{
    client::Session,
    output::{Column, Table},
};
use crate::shared::ConnectionUrl;

const TEXT: u32 = 25;
const SUPPORTED: &str =
    "dbcli runs SQL and \\d, \\dt, \\dv, \\dm, \\di, \\ds, \\dn, \\df, \\l, \\du and \\conninfo";
const STORAGE: &str = ", CASE a.attstorage WHEN 'p' THEN 'plain' WHEN 'm' THEN 'main' WHEN 'e' THEN 'external' WHEN 'x' THEN 'extended' END AS \"Storage\"";
const STATS: &str = ", NULLIF(a.attstattarget, -1) AS \"Stats target\"";
const DESCRIPTION: &str = ", pg_catalog.col_description(a.attrelid, a.attnum) AS \"Description\"";
const COMPRESSION: &str =
    ", CASE a.attcompression WHEN 'p' THEN 'pglz' WHEN 'l' THEN 'lz4' END AS \"Compression\"";
const LOCAL: &[&str] = &[
    "!",
    "copy",
    "o",
    "out",
    "i",
    "include",
    "ir",
    "include_relative",
    "w",
    "write",
    "cd",
    "setenv",
    "lo_import",
    "lo_export",
    "g",
    "gx",
    "gexec",
    "gset",
    "s",
    "e",
    "edit",
    "ef",
    "ev",
];

pub enum Meta {
    Relations {
        kinds: &'static str,
        noun: &'static str,
        pattern: Option<String>,
    },
    Describe {
        pattern: String,
        verbose: bool,
    },
    Schemas(Option<String>),
    Functions(Option<String>),
    Databases(Option<String>),
    Roles(Option<String>),
    Conninfo,
}

pub struct Shown {
    pub tables: Vec<Table>,
    pub message: Option<String>,
}

pub fn parse(text: &str) -> Result<Meta, Failure> {
    let words = split(text.trim().trim_start_matches('\\'));
    let command = words.first().map(String::as_str).unwrap_or_default();
    let refused = |reason: &'static str| Failure::Refused {
        flag: format!("\\{command}"),
        reason,
    };
    if LOCAL.contains(&command) {
        return Err(refused("it reaches the shell or local files"));
    }
    if matches!(command, "c" | "connect") {
        return Err(refused("the connection name picks the database"));
    }
    let verbose = command.ends_with('+');
    let name = command.trim_end_matches('+');
    let pattern = words.get(1).cloned();
    let relations = |kinds, noun| Meta::Relations {
        kinds,
        noun,
        pattern: pattern.clone(),
    };
    let meta = match name {
        "d" => match &pattern {
            Some(pattern) => Meta::Describe {
                pattern: pattern.clone(),
                verbose,
            },
            None => relations("'r','p','v','m','S','f'", "relations"),
        },
        "dt" => relations("'r','p'", "tables"),
        "dv" => relations("'v'", "views"),
        "dm" => relations("'m'", "materialized views"),
        "di" => relations("'i','I'", "indexes"),
        "ds" => relations("'S'", "sequences"),
        "dn" => Meta::Schemas(pattern),
        "df" => Meta::Functions(pattern),
        "l" | "list" => Meta::Databases(pattern),
        "du" | "dg" => Meta::Roles(pattern),
        "conninfo" => Meta::Conninfo,
        _ => return Err(refused(SUPPORTED)),
    };
    if words.len() > 2 {
        return Err(Failure::Usage(format!(
            "\\{command} takes one pattern, got {}",
            words.len() - 1
        )));
    }
    Ok(meta)
}

pub async fn run(
    session: &mut Session,
    meta: &Meta,
    url: &ConnectionUrl,
) -> Result<Shown, Failure> {
    let table = match meta {
        Meta::Relations {
            kinds,
            noun,
            pattern,
        } => return relations(session, kinds, noun, pattern.as_deref()).await,
        Meta::Describe { pattern, verbose } => return describe(session, pattern, *verbose).await,
        Meta::Schemas(pattern) => {
            let filter = match pattern {
                Some(pattern) => matching("n.nspname", &parse_pattern(pattern).1),
                None => "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'".into(),
            };
            let sql = format!(
                "SELECT n.nspname AS \"Name\", pg_catalog.pg_get_userbyid(n.nspowner) AS \"Owner\" FROM pg_catalog.pg_namespace n WHERE true {filter} ORDER BY 1"
            );
            listing(session, &sql, "List of schemas", true).await?
        }
        Meta::Functions(pattern) => {
            let filter = filter(
                pattern.as_deref(),
                "n.nspname",
                "p.proname",
                "pg_catalog.pg_function_is_visible(p.oid)",
                "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'",
            );
            let sql = format!(
                "SELECT n.nspname AS \"Schema\", p.proname AS \"Name\", pg_catalog.pg_get_function_result(p.oid) AS \"Result data type\", pg_catalog.pg_get_function_arguments(p.oid) AS \"Argument data types\", CASE p.prokind WHEN 'a' THEN 'agg' WHEN 'w' THEN 'window' WHEN 'p' THEN 'proc' ELSE 'func' END AS \"Type\" FROM pg_catalog.pg_proc p LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE true {filter} ORDER BY 1, 2, 4"
            );
            listing(session, &sql, "List of functions", true).await?
        }
        Meta::Databases(pattern) => {
            let filter = pattern
                .as_deref()
                .map(|pattern| matching("d.datname", &parse_pattern(pattern).1))
                .unwrap_or_default();
            let version = session.major_version();
            let provider = if version >= 15 {
                ", CASE d.datlocprovider WHEN 'b' THEN 'builtin' WHEN 'c' THEN 'libc' WHEN 'i' THEN 'icu' END AS \"Locale Provider\""
            } else {
                ""
            };
            let locale = match version {
                17.. => ", d.datlocale AS \"Locale\"",
                15 | 16 => ", d.daticulocale AS \"ICU Locale\"",
                _ => "",
            };
            let rules = if version >= 16 {
                ", d.daticurules AS \"ICU Rules\""
            } else {
                ""
            };
            let sql = format!(
                "SELECT d.datname AS \"Name\", pg_catalog.pg_get_userbyid(d.datdba) AS \"Owner\", pg_catalog.pg_encoding_to_char(d.encoding) AS \"Encoding\"{provider}, d.datcollate AS \"Collate\", d.datctype AS \"Ctype\"{locale}{rules}, pg_catalog.array_to_string(d.datacl, E'\\n') AS \"Access privileges\" FROM pg_catalog.pg_database d WHERE true {filter} ORDER BY 1"
            );
            listing(session, &sql, "List of databases", true).await?
        }
        Meta::Roles(pattern) => {
            let filter = match pattern {
                Some(pattern) => matching("r.rolname", &parse_pattern(pattern).1),
                None => "AND r.rolname !~ '^pg_'".into(),
            };
            let sql = format!(
                "SELECT r.rolname AS \"Role name\", pg_catalog.array_to_string(ARRAY(SELECT a FROM (VALUES (1, CASE WHEN r.rolsuper THEN 'Superuser' END), (2, CASE WHEN NOT r.rolinherit THEN 'No inheritance' END), (3, CASE WHEN r.rolcreaterole THEN 'Create role' END), (4, CASE WHEN r.rolcreatedb THEN 'Create DB' END), (5, CASE WHEN NOT r.rolcanlogin THEN 'Cannot login' END), (6, CASE WHEN r.rolreplication THEN 'Replication' END), (7, CASE WHEN r.rolbypassrls THEN 'Bypass RLS' END)) AS t(i, a) WHERE a IS NOT NULL ORDER BY i), ', ') AS \"Attributes\" FROM pg_catalog.pg_roles r WHERE true {filter} ORDER BY 1"
            );
            listing(session, &sql, "List of roles", false).await?
        }
        Meta::Conninfo => conninfo(session, url),
    };
    Ok(Shown {
        tables: vec![table],
        message: None,
    })
}

async fn relations(
    session: &mut Session,
    kinds: &str,
    noun: &str,
    pattern: Option<&str>,
) -> Result<Shown, Failure> {
    let indexes = kinds.contains('i');
    let filter = filter(
        pattern,
        "n.nspname",
        "c.relname",
        "pg_catalog.pg_table_is_visible(c.oid)",
        "AND n.nspname <> 'pg_catalog' AND n.nspname !~ '^pg_toast' AND n.nspname <> 'information_schema'",
    );
    let (table_column, table_join) = if indexes {
        (
            ", c2.relname AS \"Table\"",
            "LEFT JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid LEFT JOIN pg_catalog.pg_class c2 ON i.indrelid = c2.oid",
        )
    } else {
        ("", "")
    };
    let sql = format!(
        "SELECT n.nspname AS \"Schema\", c.relname AS \"Name\", CASE c.relkind WHEN 'r' THEN 'table' WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' WHEN 'i' THEN 'index' WHEN 'S' THEN 'sequence' WHEN 't' THEN 'TOAST table' WHEN 'f' THEN 'foreign table' WHEN 'p' THEN 'partitioned table' WHEN 'I' THEN 'partitioned index' END AS \"Type\", pg_catalog.pg_get_userbyid(c.relowner) AS \"Owner\"{table_column} FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace {table_join} WHERE c.relkind IN ({kinds}) {filter} ORDER BY 1, 2"
    );
    let table = listing(session, &sql, &format!("List of {noun}"), true).await?;
    if !table.rows.is_empty() {
        return Ok(Shown {
            tables: vec![table],
            message: None,
        });
    }
    let message = match pattern {
        Some(pattern) => format!("Did not find any {noun} named \"{pattern}\"."),
        None => format!("Did not find any {noun}."),
    };
    Ok(Shown {
        tables: Vec::new(),
        message: Some(message),
    })
}

async fn describe(session: &mut Session, pattern: &str, verbose: bool) -> Result<Shown, Failure> {
    let filter = filter(
        Some(pattern),
        "n.nspname",
        "c.relname",
        "pg_catalog.pg_table_is_visible(c.oid)",
        "",
    );
    let sql = format!(
        "SELECT c.oid::pg_catalog.int8, n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE true {filter} ORDER BY 2, 3"
    );
    let (_, found) = select(session, &sql).await?;
    if found.is_empty() {
        return Err(Failure::Database(format!(
            "Did not find any relation named \"{pattern}\"."
        )));
    }
    let mut tables = Vec::new();
    for row in found {
        let [oid, schema, name, kind] = <[Option<String>; 4]>::try_from(row)
            .map_err(|_| Failure::Network("unexpected relation row".into()))?
            .map(Option::unwrap_or_default);
        let oid = oid
            .parse::<u64>()
            .map_err(|_| Failure::Network("unexpected relation oid".into()))?;
        let noun = match kind.as_str() {
            "r" => "Table",
            "p" => "Partitioned table",
            "v" => "View",
            "m" => "Materialized view",
            "S" => "Sequence",
            "i" => "Index",
            "I" => "Partitioned index",
            "f" => "Foreign table",
            "c" => "Composite type",
            _ => "TOAST table",
        };
        let title = format!("{noun} \"{schema}.{name}\"");
        let (sql, footers) = match kind.as_str() {
            "S" => (
                format!(
                    "SELECT pg_catalog.format_type(s.seqtypid, NULL) AS \"Type\", s.seqstart AS \"Start\", s.seqmin AS \"Minimum\", s.seqmax AS \"Maximum\", s.seqincrement AS \"Increment\", CASE WHEN s.seqcycle THEN 'yes' ELSE 'no' END AS \"Cycles?\", s.seqcache AS \"Cache\" FROM pg_catalog.pg_sequence s WHERE s.seqrelid = {oid}"
                ),
                lines(session, &format!(
                    "SELECT 'Owned by: ' || pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname) || '.' || pg_catalog.quote_ident(a.attname) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_depend d ON c.oid = d.refobjid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.refobjsubid WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.objid = {oid} AND d.deptype IN ('a', 'i')"
                ))
                .await?,
            ),
            "i" | "I" => (
                format!(
                    "SELECT a.attname AS \"Column\", pg_catalog.format_type(a.atttypid, a.atttypmod) AS \"Type\", CASE WHEN a.attnum <= (SELECT i.indnkeyatts FROM pg_catalog.pg_index i WHERE i.indexrelid = {oid}) THEN 'yes' ELSE 'no' END AS \"Key?\", pg_catalog.pg_get_indexdef(a.attrelid, a.attnum, true) AS \"Definition\"{} FROM pg_catalog.pg_attribute a WHERE a.attrelid = {oid} AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum",
                    verbose_columns(verbose, &kind)
                ),
                lines(session, &format!(
                    "SELECT pg_catalog.concat_ws(', ', CASE WHEN i.indisprimary THEN 'primary key' WHEN i.indisunique THEN 'unique' END, am.amname, 'for table \"' || n.nspname || '.' || c.relname || '\"') FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid JOIN pg_catalog.pg_am am ON am.oid = ic.relam JOIN pg_catalog.pg_class c ON c.oid = i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE i.indexrelid = {oid}"
                ))
                .await?
                .into_iter()
                .chain(tablespace(session, oid).await?)
                .collect(),
            ),
            _ => (
                format!(
                    "SELECT a.attname AS \"Column\", pg_catalog.format_type(a.atttypid, a.atttypmod) AS \"Type\", (SELECT co.collname FROM pg_catalog.pg_collation co, pg_catalog.pg_type t WHERE co.oid = a.attcollation AND t.oid = a.atttypid AND a.attcollation <> t.typcollation) AS \"Collation\", CASE WHEN a.attnotnull THEN 'not null' ELSE '' END AS \"Nullable\", COALESCE(CASE WHEN a.attidentity = 'a' THEN 'generated always as identity' WHEN a.attidentity = 'd' THEN 'generated by default as identity' WHEN a.attgenerated = 's' THEN 'generated always as (' || pg_catalog.pg_get_expr(d.adbin, d.adrelid, true) || ') stored' WHEN a.attgenerated <> '' THEN 'generated always as (' || pg_catalog.pg_get_expr(d.adbin, d.adrelid, true) || ')' ELSE pg_catalog.pg_get_expr(d.adbin, d.adrelid, true) END, '') AS \"Default\"{} FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum WHERE a.attrelid = {oid} AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum",
                    verbose_columns(verbose, &kind)
                ),
                table_footers(session, oid, &kind, verbose).await?,
            ),
        };
        let (mut columns, rows) = select(session, &sql).await?;
        if kind != "S" {
            for column in &mut columns {
                column.type_oid = TEXT;
            }
        }
        tables.push(Table {
            title: Some(title),
            columns,
            rows,
            footers,
            count: false,
        });
    }
    Ok(Shown {
        tables,
        message: None,
    })
}

fn verbose_columns(verbose: bool, kind: &str) -> String {
    if !verbose {
        return String::new();
    }
    let mut columns = vec![STORAGE];
    if matches!(kind, "r" | "p" | "m") {
        columns.push(COMPRESSION);
    }
    if matches!(kind, "r" | "p" | "m" | "f" | "i" | "I") {
        columns.push(STATS);
    }
    if !matches!(kind, "i" | "I") {
        columns.push(DESCRIPTION);
    }
    columns.concat()
}

async fn table_footers(
    session: &mut Session,
    oid: u64,
    kind: &str,
    verbose: bool,
) -> Result<Vec<String>, Failure> {
    let mut footers = Vec::new();
    if matches!(kind, "v" | "m") && verbose {
        let definition = lines(
            session,
            &format!("SELECT pg_catalog.pg_get_viewdef({oid}::pg_catalog.oid, true)"),
        )
        .await?;
        footers.push("View definition:".to_string());
        footers.extend(
            definition
                .iter()
                .flat_map(|text| text.lines().map(String::from)),
        );
    }
    if !matches!(kind, "r" | "p" | "m" | "f") {
        return Ok(footers);
    }
    let sections = [
        (
            "Indexes:",
            format!(
                "SELECT '\"' || c2.relname || '\" ' || CASE WHEN con.contype = 'x' THEN pg_catalog.pg_get_constraintdef(con.oid, true) ELSE pg_catalog.concat(CASE WHEN i.indisprimary THEN 'PRIMARY KEY, ' WHEN con.contype = 'u' THEN 'UNIQUE CONSTRAINT, ' WHEN i.indisunique THEN 'UNIQUE, ' END, pg_catalog.substring(pg_catalog.pg_get_indexdef(i.indexrelid, 0, true), ' USING (.*)$')) END || CASE WHEN NOT i.indisvalid THEN ' INVALID' ELSE '' END || CASE WHEN c2.reltablespace <> 0 THEN ', tablespace \"' || ts.spcname || '\"' ELSE '' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c2 ON c2.oid = i.indexrelid LEFT JOIN pg_catalog.pg_tablespace ts ON ts.oid = c2.reltablespace LEFT JOIN pg_catalog.pg_constraint con ON con.conrelid = i.indrelid AND con.conindid = i.indexrelid AND con.contype IN ('p', 'u', 'x') WHERE i.indrelid = {oid} ORDER BY i.indisprimary DESC, c2.relname"
            ),
        ),
        (
            "Check constraints:",
            format!(
                "SELECT '\"' || r.conname || '\" ' || pg_catalog.pg_get_constraintdef(r.oid, true) FROM pg_catalog.pg_constraint r WHERE r.conrelid = {oid} AND r.contype = 'c' ORDER BY r.conname"
            ),
        ),
        (
            "Foreign-key constraints:",
            format!(
                "SELECT '\"' || r.conname || '\" ' || pg_catalog.pg_get_constraintdef(r.oid, true) FROM pg_catalog.pg_constraint r WHERE r.conrelid = {oid} AND r.contype = 'f' AND r.conparentid = 0 ORDER BY r.conname"
            ),
        ),
        (
            "Referenced by:",
            format!(
                "SELECT pg_catalog.concat('TABLE \"', r.conrelid::pg_catalog.regclass, '\" CONSTRAINT \"', r.conname, '\" ', pg_catalog.pg_get_constraintdef(r.oid, true)) FROM pg_catalog.pg_constraint r WHERE r.confrelid = {oid} AND r.contype = 'f' AND r.conparentid = 0 ORDER BY r.conname"
            ),
        ),
        (
            if verbose { "Not-null constraints:" } else { "" },
            format!(
                "SELECT '\"' || r.conname || '\" NOT NULL \"' || a.attname || '\"' || CASE WHEN r.connoinherit THEN ' NO INHERIT' ELSE '' END FROM pg_catalog.pg_constraint r JOIN pg_catalog.pg_attribute a ON a.attrelid = r.conrelid AND a.attnum = r.conkey[1] WHERE r.conrelid = {oid} AND r.contype = 'n' ORDER BY a.attnum"
            ),
        ),
        (
            "Triggers:",
            format!(
                "SELECT pg_catalog.substring(pg_catalog.pg_get_triggerdef(t.oid, true), 'TRIGGER (.*)$') FROM pg_catalog.pg_trigger t WHERE t.tgrelid = {oid} AND NOT t.tgisinternal ORDER BY t.tgname"
            ),
        ),
    ];
    for (heading, sql) in sections {
        if heading.is_empty() {
            continue;
        }
        let found = lines(session, &sql).await?;
        if !found.is_empty() {
            footers.push(heading.to_string());
            footers.extend(found.iter().map(|line| format!("    {line}")));
        }
    }
    footers.extend(tablespace(session, oid).await?);
    if verbose {
        footers.extend(
            lines(
                session,
                &format!(
                    "SELECT 'Access method: ' || am.amname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_am am ON am.oid = c.relam WHERE c.oid = {oid}"
                ),
            )
            .await?,
        );
    }
    Ok(footers)
}

async fn tablespace(session: &mut Session, oid: u64) -> Result<Vec<String>, Failure> {
    lines(
        session,
        &format!(
            "SELECT 'Tablespace: \"' || ts.spcname || '\"' FROM pg_catalog.pg_class c JOIN pg_catalog.pg_tablespace ts ON ts.oid = c.reltablespace WHERE c.oid = {oid}"
        ),
    )
    .await
}

fn conninfo(session: &Session, url: &ConnectionUrl) -> Table {
    let parameter = |name: &str| session.parameters.get(name).cloned().unwrap_or_default();
    let rows = [
        ("Database", url.database.clone()),
        ("Client User", url.user.clone()),
        ("Host", url.host.clone()),
        ("Server Port", url.port.to_string()),
        ("Server Version", parameter("server_version")),
        ("Backend PID", session.pid.to_string()),
        ("SSL Connection", session.tls.to_string()),
        ("Superuser", parameter("is_superuser")),
        ("Hot Standby", parameter("in_hot_standby")),
        (
            "Read Only",
            if session.read_only() { "on" } else { "off" }.to_string(),
        ),
    ];
    Table {
        title: Some("Connection Information".into()),
        columns: ["Parameter", "Value"]
            .into_iter()
            .map(|name| Column {
                name: name.into(),
                type_oid: TEXT,
            })
            .collect(),
        rows: rows
            .into_iter()
            .map(|(name, value)| vec![Some(name.to_string()), Some(value)])
            .collect(),
        footers: Vec::new(),
        count: true,
    }
}

async fn listing(
    session: &mut Session,
    sql: &str,
    title: &str,
    count: bool,
) -> Result<Table, Failure> {
    let (columns, rows) = select(session, sql).await?;
    Ok(Table {
        title: Some(title.into()),
        columns,
        rows,
        footers: Vec::new(),
        count,
    })
}

type Rows = Vec<Vec<Option<String>>>;

async fn select(session: &mut Session, sql: &str) -> Result<(Vec<Column>, Rows), Failure> {
    let reply = session.query(sql).await?;
    if let Some(error) = reply.error {
        return Err(Failure::Database(error.render(None)));
    }
    Ok((reply.columns.unwrap_or_default(), reply.rows))
}

async fn lines(session: &mut Session, sql: &str) -> Result<Vec<String>, Failure> {
    let (_, rows) = select(session, sql).await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.into_iter().next().flatten())
        .collect())
}

fn filter(
    pattern: Option<&str>,
    schema_column: &str,
    name_column: &str,
    visible: &str,
    defaults: &str,
) -> String {
    let Some(pattern) = pattern else {
        return format!("{defaults} AND {visible}");
    };
    let (schema, name) = parse_pattern(pattern);
    let mut filter = matching(name_column, &name);
    match schema {
        Some(schema) => filter.push_str(&matching(schema_column, &schema)),
        None => filter.push_str(&format!(" AND {visible}")),
    }
    filter
}

fn matching(column: &str, regex: &str) -> String {
    if regex.is_empty() {
        return String::new();
    }
    format!(
        " AND {column} OPERATOR(pg_catalog.~) E'^({})$' COLLATE pg_catalog.default",
        regex.replace('\\', "\\\\").replace('\'', "''")
    )
}

fn parse_pattern(pattern: &str) -> (Option<String>, String) {
    let mut parts = vec![String::new()];
    let mut quoted = false;
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '.' && !quoted {
            parts.push(String::new());
            continue;
        }
        let Some(part) = parts.last_mut() else {
            break;
        };
        match character {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                part.push('"');
            }
            '"' => quoted = !quoted,
            '*' if !quoted => part.push_str(".*"),
            '?' if !quoted => part.push('.'),
            '$' if !quoted => part.push_str("\\$"),
            character if !quoted => part.extend(character.to_lowercase()),
            character if "|*+?()[]{}.^$\\".contains(character) => {
                part.push('\\');
                part.push(character);
            }
            character => part.push(character),
        }
    }
    let name = parts.pop().unwrap_or_default();
    (parts.pop(), name)
}

fn split(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for character in text.chars() {
        if character == '"' {
            quoted = !quoted;
        }
        if character.is_whitespace() && !quoted {
            if !word.is_empty() {
                words.push(take(&mut word));
            }
        } else {
            word.push(character);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_side_commands_are_refused() {
        for command in [
            "\\! rm -rf ~",
            "\\copy t to '/tmp/x'",
            "\\o /tmp/out",
            "\\i script.sql",
            "\\ir script.sql",
            "\\w /tmp/buffer",
            "\\gexec",
            "\\set ON_ERROR_STOP 0",
            "\\setenv PGHOST attacker.example",
            "\\lo_export 1 /tmp/x",
            "\\cd /",
            "\\c other",
            "\\connect postgres://attacker.example/x",
            "\\password",
            "\\x",
        ] {
            assert!(
                matches!(parse(command), Err(Failure::Refused { .. })),
                "{command} was accepted"
            );
        }
    }

    #[test]
    fn describe_commands_parse() {
        assert!(matches!(
            parse("\\d users"),
            Ok(Meta::Describe { verbose: false, .. })
        ));
        assert!(matches!(
            parse("\\d+ users"),
            Ok(Meta::Describe { verbose: true, .. })
        ));
        assert!(matches!(parse("\\dt"), Ok(Meta::Relations { .. })));
        assert!(parse("\\dt a b").is_err());
    }
}
