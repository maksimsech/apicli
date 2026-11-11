use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process,
    sync::{Arc, Mutex},
    thread,
};

use apicli::{Entry, Failure};
use fieldkit_policy::{Credential, HostPolicy, Origin, Rate, Rule, Vault};
use fieldkit_vault::Store;
use secrecy::SecretString;

use crate::{cli::parse, request::perform};

const SECRET: &str = "sk-test-1234567890";
const REPORTS_SECRET: &str = "tok-reports-0987654321";

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start(respond: impl Fn(&str) -> String + Send + 'static) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let request = read_request(&mut stream);
                seen.lock().unwrap().push(request.clone());
                let _ = stream.write_all(respond(&request).as_bytes());
            }
        });
        Server { origin, requests }
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn received(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .join("\n")
            .to_ascii_lowercase()
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream.read(&mut buffer).unwrap_or(0);
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&data).into_owned()
}

fn reply(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
}

fn ok(_: &str) -> String {
    reply("200 OK", "", "ok")
}

fn vault(origin: &str) -> Vault {
    vault_with(origin, HostPolicy::default())
}

fn vault_with(origin: &str, host: HostPolicy) -> Vault {
    let mut vault = Vault {
        credentials: vec![Credential {
            name: "test".into(),
            origin: Origin::parse(origin).unwrap(),
            paths: Vec::new(),
            header: "X-Api-Key".into(),
            template: "{secret}".into(),
            secret: SecretString::from(SECRET),
        }],
        ..Vault::default()
    };
    vault
        .policy
        .hosts
        .insert(Origin::parse(origin).unwrap(), host);
    vault
}

fn mixed(origin: &str) -> Vault {
    let mut vault = vault(origin);
    vault.credentials.push(Credential {
        name: "reports".into(),
        origin: Origin::parse(origin).unwrap(),
        paths: vec!["/v1/reports/**".into()],
        header: "Authorization".into(),
        template: "Bearer {secret}".into(),
        secret: SecretString::from(REPORTS_SECRET),
    });
    vault
}

fn allow(method: &str, path: &str) -> HostPolicy {
    HostPolicy {
        allow: vec![Rule {
            method: method.into(),
            path: path.into(),
            max_body: None,
            content_type: None,
            allow_body: false,
        }],
        ..HostPolicy::default()
    }
}

fn store(name: &str) -> Store {
    let dir = env::temp_dir().join(format!("apicli-bypass-{}-{name}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    Store::at(dir)
}

async fn run(args: &[&str], vault: &Vault, store: &Store) -> (Result<u8, Failure>, String, Entry) {
    let cli = parse(
        ["apicli"]
            .iter()
            .chain(args)
            .map(|arg| arg.to_string())
            .collect(),
    )
    .unwrap();
    let mut out = Vec::new();
    let mut entry = Entry::default();
    let result = perform(&cli.request, store, vault, &mut out, &mut entry).await;
    (result, String::from_utf8_lossy(&out).into_owned(), entry)
}

fn code(result: &Result<u8, Failure>) -> u8 {
    match result {
        Ok(code) => *code,
        Err(failure) => failure.code(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn echoed_key_is_redacted_everywhere() {
    let server =
        Server::start(|request| reply("200 OK", &format!("X-Echo: {SECRET}\r\n"), request));
    let url = format!("{}/v1/echo?key={SECRET}", server.origin);

    let (result, out, entry) = run(&["-i", &url], &vault(&server.origin), &store("echo")).await;

    assert_eq!(code(&result), 0);
    assert!(server.received().contains(&format!("x-api-key: {SECRET}")));
    assert!(!out.contains(SECRET), "{out}");
    assert!(out.contains("x-echo: [apicli:redacted]"), "{out}");
    assert!(!entry.url.contains(SECRET));
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_to_another_origin_is_not_followed() {
    let attacker = Server::start(ok);
    let location = format!("{}/collect", attacker.origin);
    let api = Server::start(move |_| reply("302 Found", &format!("Location: {location}\r\n"), ""));

    let (result, _, _) = run(
        &["-L", &format!("{}/v1/download", api.origin)],
        &vault(&api.origin),
        &store("redirect"),
    )
    .await;

    assert_eq!(code(&result), 112);
    assert_eq!(attacker.count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn unconfigured_host_receives_nothing() {
    let api = Server::start(ok);
    let other = Server::start(ok);

    let (result, _, _) = run(
        &[&other.origin],
        &vault(&api.origin),
        &store("unconfigured"),
    )
    .await;

    assert_eq!(code(&result), 112);
    assert_eq!(other.count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn writes_reach_the_server_only_through_an_allow_rule() {
    let api = Server::start(ok);
    let url = format!("{}/v1/orders/1/notes", api.origin);
    let args = ["-X", "POST", "--json", "{\"note\":\"x\"}", url.as_str()];

    let (denied, _, _) = run(&args, &vault(&api.origin), &store("write-denied")).await;

    assert_eq!(code(&denied), 110);
    assert_eq!(api.count(), 0);

    let allowed = vault_with(&api.origin, allow("POST", "/v1/orders/*/notes"));
    let (result, _, _) = run(&args, &allowed, &store("write-allowed")).await;

    assert_eq!(code(&result), 0);
    assert_eq!(api.count(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_to_a_denied_path_is_not_followed() {
    let api = Server::start(|request| {
        if request.starts_with("POST /v1/orders/1/notes ") {
            reply(
                "307 Temporary Redirect",
                "Location: /v1/orders/1/refund\r\n",
                "",
            )
        } else {
            ok(request)
        }
    });
    let allowed = vault_with(&api.origin, allow("POST", "/v1/orders/*/notes"));
    let url = format!("{}/v1/orders/1/notes", api.origin);

    let (result, _, _) = run(
        &["-L", "--json", "{}", &url],
        &allowed,
        &store("redirect-denied"),
    )
    .await;

    assert_eq!(code(&result), 110);
    assert_eq!(api.count(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn agent_cannot_set_the_credential_header() {
    let api = Server::start(ok);

    let (result, _, _) = run(
        &["-H", "x-api-key: guessed", &api.origin],
        &vault(&api.origin),
        &store("credential-header"),
    )
    .await;

    assert_eq!(code(&result), 2);
    assert_eq!(api.count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn path_scoped_key_is_sent_only_on_its_paths() {
    let api = Server::start(ok);
    let vault = mixed(&api.origin);
    let store = store("scoped");

    let (users, _, _) = run(&[&format!("{}/v1/users", api.origin)], &vault, &store).await;
    let (reports, _, _) = run(&[&format!("{}/v1/reports/1", api.origin)], &vault, &store).await;

    assert_eq!(code(&users), 0);
    assert_eq!(code(&reports), 0);
    let requests = api.requests.lock().unwrap().clone();
    assert!(requests[0].contains(SECRET));
    assert!(!requests[0].contains(REPORTS_SECRET));
    assert!(requests[1].contains(&format!("Bearer {REPORTS_SECRET}")));
    assert!(!requests[1].contains(SECRET));
}

#[tokio::test(flavor = "current_thread")]
async fn agent_cannot_set_another_credential_header_of_the_host() {
    let api = Server::start(ok);

    let (result, _, _) = run(
        &[
            "-H",
            "authorization: Bearer guessed",
            &format!("{}/v1/users", api.origin),
        ],
        &mixed(&api.origin),
        &store("other-credential-header"),
    )
    .await;

    assert_eq!(code(&result), 2);
    assert_eq!(api.count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_environment_is_ignored() {
    let proxy = Server::start(ok);
    let api = Server::start(ok);
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "ALL_PROXY"] {
        unsafe { env::set_var(name, &proxy.origin) };
    }

    let (result, _, _) = run(&[&api.origin], &vault(&api.origin), &store("proxy")).await;

    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "ALL_PROXY"] {
        unsafe { env::remove_var(name) };
    }
    assert_eq!(code(&result), 0);
    assert_eq!(api.count(), 1);
    assert_eq!(proxy.count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn runaway_loop_is_cut_at_the_rate_limit() {
    let api = Server::start(ok);
    let limited = vault_with(
        &api.origin,
        HostPolicy {
            rate: Some(Rate::parse("3/min").unwrap()),
            ..HostPolicy::default()
        },
    );
    let store = store("rate");
    let mut codes = Vec::new();

    for _ in 0..5 {
        let (result, _, _) = run(&[&api.origin], &limited, &store).await;
        codes.push(code(&result));
    }

    assert_eq!(codes, vec![0, 0, 0, 111, 111]);
    assert_eq!(api.count(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn upstream_429_blocks_the_host() {
    let api = Server::start(|_| reply("429 Too Many Requests", "Retry-After: 60\r\n", "slow down"));
    let store = store("429");

    let (first, _, _) = run(&[&api.origin], &vault(&api.origin), &store).await;
    let (second, _, _) = run(&[&api.origin], &vault(&api.origin), &store).await;

    assert_eq!(code(&first), 0);
    assert_eq!(code(&second), 111);
    assert_eq!(api.count(), 1);
}
