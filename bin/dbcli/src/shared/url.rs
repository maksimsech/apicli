use percent_encoding::percent_decode_str;
use url::{Host, Url, form_urlencoded};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    Disable,
    Prefer,
    Require,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionUrl {
    pub host: String,
    pub port: u16,
    pub hosts: Vec<(String, u16)>,
    pub user: String,
    pub database: String,
    pub tls: Tls,
    pub root_cert: Option<String>,
    pub text: String,
}

pub struct Parts {
    pub user: String,
    pub hosts: Vec<(String, u16)>,
    pub path: String,
    pub query: String,
}

pub fn multiple(text: &str, default_port: u16, srv: bool, example: &str) -> Result<Parts, String> {
    let (_, rest) = text.split_once("://").unwrap_or_default();
    let (authority, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    let Some((userinfo, list)) = authority.rsplit_once('@') else {
        return Err(format!("{text} has no user, {example}"));
    };
    if userinfo.contains(':') {
        return Err("leave the password out of the URL, dbcli asks for it".into());
    }
    let user = decode(userinfo);
    if user.is_empty() {
        return Err(format!("{text} has no user, {example}"));
    }
    let mut hosts = Vec::new();
    for entry in list.split(',') {
        let (host, port) = match entry.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(']') || entry.starts_with('[') => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| format!("{entry} has an invalid port, {example}"))?;
                (host, Some(port))
            }
            _ => (entry, None),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.contains(['/', '@', '?', '#']) {
            return Err(format!("{text} has an invalid host, {example}"));
        }
        if srv && port.is_some() {
            return Err("mongodb+srv:// URLs take a host name without a port".into());
        }
        hosts.push((host.to_string(), port.unwrap_or(default_port)));
    }
    if srv && hosts.len() > 1 {
        return Err("mongodb+srv:// URLs take one host name".into());
    }
    if tail.contains('#') {
        return Err(format!("{text} has a #fragment, remove it"));
    }
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.contains('/') {
        return Err(format!("{text} has more than a database name in its path"));
    }
    Ok(Parts {
        user,
        hosts,
        path: decode(path),
        query: query.to_string(),
    })
}

pub fn encryption(query: &str, flag: &str, scheme: &str) -> Result<(Tls, Option<String>), String> {
    let mut tls = Tls::Disable;
    let mut root_cert = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        match name.as_ref() {
            _ if name == flag => {
                tls = match value.as_ref() {
                    "true" | "1" => Tls::Require,
                    "false" | "0" => Tls::Disable,
                    _ => return Err(format!("{flag}={value} is not true or false")),
                }
            }
            "cacert" => root_cert = Some(value.into_owned()),
            _ => {
                return Err(format!(
                    "the {name} parameter is not supported, {scheme}:// URLs take only {flag} and cacert"
                ));
            }
        }
    }
    if root_cert.is_some() && tls == Tls::Disable {
        return Err(format!("cacert needs {flag}=true"));
    }
    Ok((tls, root_cert))
}

pub fn authority(url: &Url, text: &str, example: &str) -> Result<(String, String), String> {
    if url.password().is_some() {
        return Err("leave the password out of the URL, dbcli asks for it".into());
    }
    let host = match url.host() {
        Some(Host::Ipv6(ip)) => ip.to_string(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Domain(domain)) if !domain.is_empty() => decode(domain),
        _ => return Err(format!("{text} has no host, {example}")),
    };
    if host.contains(',') {
        return Err("only one host is supported".into());
    }
    if url.fragment().is_some() {
        return Err(format!("{text} has a #fragment, remove it"));
    }
    Ok((host, decode(url.username())))
}

pub fn single_path(url: &Url, text: &str) -> Result<String, String> {
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    if path.contains('/') {
        return Err(format!("{text} has more than a database in its path"));
    }
    Ok(decode(path))
}

pub fn decode(text: &str) -> String {
    percent_decode_str(text).decode_utf8_lossy().into_owned()
}
