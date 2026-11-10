mod postgres;
mod redis;

use std::{env, fs, process};

use apicli::Entry;
use apicli_policy::{Connection, ConnectionUrl, Rate, Vault};
use apicli_vault::Store;
use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use url::Url;

use crate::call::{Context, perform};

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

fn server(variable: &str) -> Option<Server> {
    let mut url = Url::parse(&env::var(variable).ok()?).unwrap();
    let password = percent_decode_str(url.password()?)
        .decode_utf8_lossy()
        .into_owned();
    url.set_password(None).unwrap();
    Some(Server {
        url: ConnectionUrl::parse(url.as_str()).unwrap(),
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
