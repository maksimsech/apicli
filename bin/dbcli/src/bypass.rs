mod cassandra;
mod clickhouse;
mod mongo;
mod postgres;
mod redis;

use std::{env, fs, process};

use fieldkit_common::Entry;
use fieldkit_policy::{Allow, Connection, Rate, Vault};
use fieldkit_vault::Store;
use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use url::Url;

use crate::{
    call::{parse, perform},
    shared::Context,
};

struct Server {
    url: String,
    password: String,
}

impl Server {
    fn database(&self) -> String {
        parse(&self.url).unwrap().database
    }
}

struct Run {
    code: u8,
    out: String,
    err: String,
    entry: Entry,
}

fn server(variable: &str) -> Option<Server> {
    let mut url = Url::parse(&env::var(variable).ok()?).unwrap();
    let password = percent_decode_str(url.password()?)
        .decode_utf8_lossy()
        .into_owned();
    url.set_password(None).unwrap();
    Some(Server {
        url: url.to_string(),
        password,
    })
}

fn vault(server: &Server, configure: impl FnOnce(&mut Connection)) -> Vault {
    let mut connection = Connection::new(
        "test".into(),
        server.url.clone(),
        SecretString::from(server.password.clone()),
    );
    configure(&mut connection);
    Vault {
        connections: vec![connection],
        ..Vault::default()
    }
}

fn allow(rules: &[(&str, Option<&str>)]) -> impl FnOnce(&mut Connection) {
    let rules = rules
        .iter()
        .map(|(action, target)| Allow {
            action: action.to_string(),
            target: target.map(String::from),
        })
        .collect::<Vec<_>>();
    move |connection| connection.allow = rules
}

fn writes(connection: &mut Connection) {
    connection.write = true;
}

fn limited(rate: &str) -> impl FnOnce(&mut Connection) {
    let rate = Rate::parse(rate).unwrap();
    move |connection| connection.rate = Some(rate)
}

fn store(name: &str) -> Store {
    let dir = env::temp_dir().join(format!("dbcli-bypass-{}-{name}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    Store::at(dir)
}

async fn run(args: &[&str], vault: &Vault, store: &Store) -> Run {
    let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut entry = Entry::default();
    let mut context = Context::new(store, vault, &mut out, &mut err, &mut entry, false);
    let result = perform("test", &args, vault, &mut context).await;
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
