use std::{
    collections::HashSet,
    fs,
    io::{Read, Write, stdin, stdout},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use apicli_core::{
    Body, Credential, Denial, Grant, Limits, METHOD_OVERRIDES, Origin, Redactor, UNRESERVED, Vault,
    Wait, authorize,
};
use apicli_vault::Store;
use percent_encoding::percent_encode;
use reqwest::{
    Client, Method, Response, StatusCode,
    header::{
        ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION, REFERER, USER_AGENT,
    },
    redirect::Policy as Redirect,
};
use secrecy::ExposeSecret;
use url::{ParseError, Url};

use crate::{admin::add_hint, audit, audit::Entry, cli::RequestArgs, failure::Failure, response};

pub async fn send(args: RequestArgs) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let mut entry = Entry::start();
    let started = Instant::now();
    let result = perform(&args, &store, &vault, &mut stdout().lock(), &mut entry).await;
    entry.ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => entry.outcome = "sent".into(),
        Err(failure) => {
            entry.outcome = failure.outcome().into();
            entry.error = failure.to_string().lines().next().map(String::from);
        }
    }
    audit::record(&store, &entry, vault.policy.log_limit_mb);
    result
}

pub async fn perform(
    args: &RequestArgs,
    store: &Store,
    vault: &Vault,
    stdout: &mut dyn Write,
    entry: &mut Entry,
) -> Result<u8, Failure> {
    let mut url = parse_url(args.url.as_deref().unwrap_or_default())?;
    let form = form_parts(args)?;
    let json = if args.json.is_empty() {
        None
    } else {
        Some(json_body(args)?)
    };
    if json.is_some() && !form.is_empty() {
        return Err(Failure::Usage(
            "--json can't be combined with -d or --data-* options".into(),
        ));
    }
    let mut method = method(args, json.is_some() || !form.is_empty())?;
    let mut headers = default_headers(args)?;
    let mut body = match json {
        Some(json) => {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
            Some(json)
        }
        None if form.is_empty() => None,
        None if args.get => {
            append_query(&mut url, &form.join(&b'&'));
            None
        }
        None => {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            Some(form.join(&b'&'))
        }
    };
    apply_custom_headers(&mut headers, &args.headers)?;
    check_overrides(&headers)?;
    let client = client(args)?;
    let redactor = Redactor::new(vault.secrets());
    let started = Instant::now();
    let mut redirects = 0;
    loop {
        entry.method = method.to_string();
        entry.url = String::from_utf8_lossy(&redactor.redact(url.as_str().as_bytes())).into_owned();
        let view = body.as_ref().map(|bytes| Body {
            len: bytes.len(),
            content_type: headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
        });
        let (credential, grant) = authorize(&url, method.as_str(), view, vault)
            .map_err(|denial| denied(denial, &url, method.as_str(), vault))?;
        entry.rule = Some(match grant {
            Grant::Default => "default".into(),
            Grant::Rule(rule) => format!("allow {rule}"),
        });
        take(
            store,
            &credential.origin,
            &vault.policy.host(&credential.origin).limits(),
            args.wait,
        )?;
        let request_headers = with_credential(&headers, credential)?;
        if args.verbose {
            for line in request_lines(&method, &url, &request_headers) {
                eprintln!(
                    "{}",
                    String::from_utf8_lossy(&redactor.redact(line.as_bytes()))
                );
            }
        }
        let mut request = client
            .request(method.clone(), url.clone())
            .headers(request_headers);
        if let Some(body) = &body {
            request = request.body(body.clone());
        }
        let response = request.send().await?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let until = now().saturating_add(retry_after(&response));
            store.update_buckets(|buckets| {
                buckets
                    .entry(credential.origin.to_string())
                    .or_default()
                    .block(until)
            })?;
        }
        let next = if args.location {
            redirect_target(&response)
        } else {
            None
        };
        let Some(next) = next else {
            return response::write(response, args, &method, started, redactor, stdout, entry)
                .await;
        };
        if redirects == args.max_redirs {
            return Err(Failure::Redirects(redirects));
        }
        redirects += 1;
        if args.verbose {
            response::print_head(&response, &redactor);
        }
        let status = response.status().as_u16();
        if status == 303 && method != Method::HEAD
            || matches!(status, 301 | 302) && method == Method::POST
        {
            method = Method::GET;
            body = None;
        }
        url = next;
    }
}

fn take(store: &Store, origin: &Origin, limits: &Limits, wait: Option<f64>) -> Result<(), Failure> {
    let deadline = wait.map(|seconds| now().saturating_add((seconds.max(0.0) * 1000.0) as u64));
    loop {
        let current = now();
        let result = store.update_buckets(|buckets| {
            buckets
                .entry(origin.to_string())
                .or_default()
                .take(limits, current)
        })?;
        let Err(wait) = result else {
            return Ok(());
        };
        if deadline.is_some_and(|deadline| current.saturating_add(wait.millis()) <= deadline) {
            sleep(Duration::from_millis(wait.millis()));
            continue;
        }
        let seconds = wait.millis() as f64 / 1000.0;
        let reason = match wait {
            Wait::Rate(_) => format!("rate limited on {origin} ({limits}), retry in {seconds:.1}s"),
            Wait::Daily(_) => format!(
                "the daily limit for {origin} is used up ({limits}), it resets in {seconds:.0}s"
            ),
            Wait::Upstream(_) => {
                format!("{origin} answered 429 Too Many Requests, retry in {seconds:.0}s")
            }
        };
        return Err(Failure::Limited(format!(
            "{reason}\nrerun with --wait to wait for it"
        )));
    }
}

fn retry_after(response: &Response) -> u64 {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(60_000, |seconds| seconds.saturating_mul(1000))
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn redirect_target(response: &Response) -> Option<Url> {
    if !response.status().is_redirection() {
        return None;
    }
    let location = response.headers().get(LOCATION)?.to_str().ok()?;
    response.url().join(location).ok()
}

pub fn denied(denial: Denial, url: &Url, method: &str, vault: &Vault) -> Failure {
    let origin = Origin::of(url).map_or_else(|| url.to_string(), |origin| origin.to_string());
    let path = url.path();
    match denial {
        Denial::Userinfo => Failure::Url("credentials in the URL are not allowed".into()),
        Denial::EncodedSeparator => {
            Failure::Url("an encoded / or \\ in the URL path is not allowed".into())
        }
        Denial::MethodOverride(name) => Failure::Denied(format!(
            "denied: {name} is not allowed because apicli checks the real method. Use -X instead"
        )),
        Denial::Rule(rule) => Failure::Denied(format!(
            "denied: {method} {path} on {origin} matches deny {rule}"
        )),
        Denial::Body(reason) => {
            Failure::Denied(format!("denied: {method} {path} on {origin}: {reason}"))
        }
        Denial::NotAllowed => {
            let allowed = Origin::of(url)
                .map(|origin| vault.policy.host(&origin).summary())
                .unwrap_or_default();
            Failure::Denied(format!(
                "denied: {method} {path} on {origin}\nallowed here: {allowed}\nto allow it, the user can run: apicli allow add {origin} {method} '{path}'"
            ))
        }
        Denial::Unconfigured(origin) => {
            let configured = vault
                .credentials
                .iter()
                .map(|credential| credential.origin.to_string())
                .collect::<Vec<_>>();
            let known = if configured.is_empty() {
                "no hosts are configured yet".to_string()
            } else {
                format!("configured: {}", configured.join(", "))
            };
            Failure::Unconfigured(format!(
                "{origin} is not configured\n{known}\nto add it, the user can run: {}",
                add_hint(&origin)
            ))
        }
    }
}

fn check_overrides(headers: &HeaderMap) -> Result<(), Failure> {
    match METHOD_OVERRIDES
        .iter()
        .find(|name| headers.contains_key(**name))
    {
        Some(name) => Err(Failure::Denied(format!(
            "denied: {name} is not allowed because apicli checks the real method. Use -X instead"
        ))),
        None => Ok(()),
    }
}

fn with_credential(headers: &HeaderMap, credential: &Credential) -> Result<HeaderMap, Failure> {
    let name = HeaderName::from_bytes(credential.header.as_bytes()).map_err(|_| {
        Failure::Integrity(format!("{} has an invalid header name", credential.name))
    })?;
    if headers.contains_key(&name) {
        return Err(Failure::Usage(format!(
            "{} is added by apicli for {}, remove -H {}",
            credential.header, credential.origin, credential.header
        )));
    }
    let mut value = HeaderValue::from_str(credential.value().expose_secret()).map_err(|_| {
        Failure::Integrity(format!("{} has an invalid header value", credential.name))
    })?;
    value.set_sensitive(true);
    let mut headers = headers.clone();
    headers.insert(name, value);
    Ok(headers)
}

fn request_lines(method: &Method, url: &Url, headers: &HeaderMap) -> Vec<String> {
    let mut lines = vec![format!("> {method} {url}")];
    for (name, value) in headers {
        let shown = if value.is_sensitive() {
            "[redacted]".to_string()
        } else {
            String::from_utf8_lossy(value.as_bytes()).into_owned()
        };
        lines.push(format!("> {name}: {shown}"));
    }
    lines.push(">".into());
    lines
}

pub fn parse_url(raw: &str) -> Result<Url, Failure> {
    let url = Url::parse(raw).map_err(|error| match error {
        ParseError::RelativeUrlWithoutBase => {
            Failure::Url(format!("{raw} has no scheme, use https://{raw}"))
        }
        error => Failure::Url(format!("{raw}: {error}")),
    })?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        scheme => Err(Failure::Scheme(scheme.into())),
    }
}

fn method(args: &RequestArgs, has_data: bool) -> Result<Method, Failure> {
    match &args.method {
        Some(name) => Method::from_bytes(name.as_bytes())
            .map_err(|_| Failure::Usage(format!("invalid method {name}"))),
        None if args.head => Ok(Method::HEAD),
        None if has_data && !args.get => Ok(Method::POST),
        None => Ok(Method::GET),
    }
}

fn form_parts(args: &RequestArgs) -> Result<Vec<Vec<u8>>, Failure> {
    let mut parts = Vec::new();
    for value in &args.data {
        parts.push(match value.strip_prefix('@') {
            Some(path) => {
                let mut bytes = read_source(path)?;
                bytes.retain(|byte| !matches!(byte, b'\r' | b'\n'));
                bytes
            }
            None => value.as_bytes().to_vec(),
        });
    }
    for value in &args.data_raw {
        parts.push(value.as_bytes().to_vec());
    }
    for value in &args.data_binary {
        parts.push(file_or_value(value)?);
    }
    for value in &args.data_urlencode {
        parts.push(urlencode(value)?);
    }
    Ok(parts)
}

fn json_body(args: &RequestArgs) -> Result<Vec<u8>, Failure> {
    let mut body = Vec::new();
    for value in &args.json {
        body.extend(file_or_value(value)?);
    }
    Ok(body)
}

fn urlencode(value: &str) -> Result<Vec<u8>, Failure> {
    let (name, content) = match value.find('=').or_else(|| value.find('@')) {
        Some(index) if value.as_bytes()[index] == b'@' => {
            (&value[..index], read_source(&value[index + 1..])?)
        }
        Some(index) => (&value[..index], value.as_bytes()[index + 1..].to_vec()),
        None => ("", value.as_bytes().to_vec()),
    };
    let encoded = percent_encode(&content, UNRESERVED).to_string();
    Ok(if name.is_empty() {
        encoded
    } else {
        format!("{name}={encoded}")
    }
    .into_bytes())
}

fn file_or_value(value: &str) -> Result<Vec<u8>, Failure> {
    match value.strip_prefix('@') {
        Some(path) => read_source(path),
        None => Ok(value.as_bytes().to_vec()),
    }
}

fn read_source(path: &str) -> Result<Vec<u8>, Failure> {
    let result = if path == "-" {
        let mut bytes = Vec::new();
        stdin().read_to_end(&mut bytes).map(|_| bytes)
    } else {
        fs::read(path)
    };
    result.map_err(|error| Failure::Read(format!("{path}: {error}")))
}

fn append_query(url: &mut Url, data: &[u8]) {
    let data = String::from_utf8_lossy(data);
    let query = match url.query() {
        Some(query) if !query.is_empty() => format!("{query}&{data}"),
        _ => data.into_owned(),
    };
    url.set_query(Some(&query));
}

fn default_headers(args: &RequestArgs) -> Result<HeaderMap, Failure> {
    let mut headers = HeaderMap::new();
    let agent = args
        .user_agent
        .clone()
        .unwrap_or_else(|| format!("apicli/{}", env!("CARGO_PKG_VERSION")));
    headers.insert(USER_AGENT, header_value(&agent)?);
    if let Some(referer) = &args.referer {
        headers.insert(REFERER, header_value(referer)?);
    }
    Ok(headers)
}

fn apply_custom_headers(headers: &mut HeaderMap, custom: &[String]) -> Result<(), Failure> {
    let mut replaced = HashSet::new();
    for header in custom {
        let invalid = || Failure::Usage(format!("invalid header '{header}', use 'Name: value'"));
        let (name, value) = header.split_once(':').ok_or_else(invalid)?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| invalid())?;
        if replaced.insert(name.clone()) {
            headers.remove(&name);
        }
        let value = value.trim();
        if !value.is_empty() {
            headers.append(name, header_value(value)?);
        }
    }
    Ok(())
}

fn header_value(value: &str) -> Result<HeaderValue, Failure> {
    HeaderValue::from_str(value)
        .map_err(|_| Failure::Usage(format!("invalid header value '{value}'")))
}

fn client(args: &RequestArgs) -> Result<Client, Failure> {
    let mut builder = Client::builder().no_proxy().redirect(Redirect::none());
    if !args.compressed {
        builder = builder.no_gzip().no_brotli().no_zstd().no_deflate();
    }
    if let Some(seconds) = args.max_time {
        builder = builder.timeout(duration(seconds, "--max-time")?);
    }
    if let Some(seconds) = args.connect_timeout {
        builder = builder.connect_timeout(duration(seconds, "--connect-timeout")?);
    }
    Ok(builder.build()?)
}

fn duration(seconds: f64, flag: &str) -> Result<Duration, Failure> {
    Duration::try_from_secs_f64(seconds)
        .map_err(|_| Failure::Usage(format!("{flag} must be a positive number of seconds")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbose_lines_hide_injected_header() {
        let mut value = HeaderValue::from_static("Bearer sk_live_1234567890");
        value.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", value);

        let lines = request_lines(
            &Method::GET,
            &Url::parse("https://api.example.com/").unwrap(),
            &headers,
        );

        assert!(lines.contains(&"> authorization: [redacted]".to_string()));
        assert!(!lines.concat().contains("sk_live_1234567890"));
    }

    #[test]
    fn method_override_headers_are_denied() {
        for name in [
            "X-HTTP-Method-Override",
            "x-http-method",
            "X-Method-Override",
        ] {
            let mut headers = HeaderMap::new();
            apply_custom_headers(&mut headers, &[format!("{name}: DELETE")]).unwrap();

            assert!(
                matches!(check_overrides(&headers), Err(Failure::Denied(_))),
                "{name}"
            );
        }
    }
}
