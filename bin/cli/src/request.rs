use std::{
    collections::HashSet,
    fs,
    io::{Read, Write, stdin, stdout},
    time::{Duration, Instant},
};

use apicli_core::{Credential, Denial, READ_METHODS, Redactor, UNRESERVED, Vault, authorize};
use apicli_vault::Store;
use percent_encoding::percent_encode;
use reqwest::{
    Client, Method, Response,
    header::{
        ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION, REFERER, USER_AGENT,
    },
    redirect::Policy,
};
use secrecy::ExposeSecret;
use url::{ParseError, Url};

use crate::{admin::add_hint, cli::RequestArgs, failure::Failure, response};

pub async fn send(args: RequestArgs) -> Result<u8, Failure> {
    let vault = Store::open()?.load()?;
    perform(&args, &vault, &mut stdout().lock()).await
}

pub async fn perform(
    args: &RequestArgs,
    vault: &Vault,
    stdout: &mut dyn Write,
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
    let client = client(args)?;
    let redactor = Redactor::new(vault.secrets());
    let started = Instant::now();
    let mut redirects = 0;
    loop {
        let credential = authorize(&url, method.as_str(), &vault.credentials)
            .map_err(|denial| denied(denial, vault))?;
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
        let next = if args.location {
            redirect_target(&response)
        } else {
            None
        };
        let Some(next) = next else {
            return response::write(response, args, &method, started, redactor, stdout).await;
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

fn redirect_target(response: &Response) -> Option<Url> {
    if !response.status().is_redirection() {
        return None;
    }
    let location = response.headers().get(LOCATION)?.to_str().ok()?;
    response.url().join(location).ok()
}

fn denied(denial: Denial, vault: &Vault) -> Failure {
    match denial {
        Denial::Userinfo => Failure::Url("credentials in the URL are not allowed".into()),
        Denial::EncodedSeparator => {
            Failure::Url("an encoded / or \\ in the URL path is not allowed".into())
        }
        Denial::Method { method, origin } => Failure::Denied(format!(
            "denied: {method} is not allowed on {origin}. Allowed: {}",
            READ_METHODS.join(", ")
        )),
        Denial::Unconfigured(origin) => {
            let configured = vault
                .credentials
                .iter()
                .map(|credential| credential.origin.to_string())
                .collect::<Vec<_>>();
            let known = if configured.is_empty() {
                "No hosts are configured yet.".to_string()
            } else {
                format!("Configured: {}.", configured.join(", "))
            };
            Failure::Unconfigured(format!(
                "{origin} is not configured. {known} The user can add it with: {}",
                add_hint(&origin)
            ))
        }
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

fn parse_url(raw: &str) -> Result<Url, Failure> {
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
    let mut builder = Client::builder().no_proxy().redirect(Policy::none());
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
}
